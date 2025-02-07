use crate::{
    errors::TeeTlsError,
    types::{DummyToken, EKM_CONTEXT, EKM_LABEL, MAGIC_BYTES},
};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A connector for establishing a TLS connection with TEE attestation verification.
///
/// The `TeeTlsConnector` struct is responsible for creating a TLS connection to a server
/// and verifying the TEE attestation token provided by the server. It uses a custom
/// certificate verifier to accept self-signed certificates and performs the necessary
/// steps to ensure the connection is securely terminated in the TEE.
///
/// # Type Parameters
///
/// * `T` - A type that implements the `VerifyToken` trait, used for verifying the TEE attestation token.
pub struct TeeTlsConnector<T: VerifyToken> {
    /// The hostname to verify during the TLS handshake.
    verify_hostname: String,
    /// The token verifier used to verify the TEE attestation token.
    token_verifier: T,
}

impl<T: VerifyToken> TeeTlsConnector<T> {
    /// Creates a new `TeeTlsConnector` instance.
    ///
    /// This function initializes a `TeeTlsConnector` with the provided token verifier and hostname.
    ///
    /// # Arguments
    ///
    /// * `token_verifier` - An instance of a type that implements the `VerifyToken` trait. This is used to verify the TEE attestation token.
    /// * `verify_hostname` - A string slice that holds the hostname to verify during the TLS handshake.
    ///
    /// # Returns
    ///
    /// A new instance of `TeeTlsConnector`.
    pub fn new(token_verifier: T, verify_hostname: &str) -> Self {
        TeeTlsConnector {
            verify_hostname: verify_hostname.to_string(),
            token_verifier,
        }
    }
    /// Establishes a TLS connection to a server using an existing IO stream.
    ///
    /// This function creates a TLS connection on top of the provided IO stream, accepting self-signed certificates.
    /// Once the connection is established, it sends the TEETLS magic bytes to the server, signaling it to initiate
    /// the TEE attestation token verification flow.
    ///
    /// The server will respond with a TEE attestation token, which this function verifies. If the TEE attestation token
    /// fails verification, the connection is aborted. Otherwise, this function returns an IO stream that can be used
    /// like a regular TLS connection.
    ///
    /// # Arguments
    ///
    /// * `stream` - An IO stream that implements the `AsyncRead`, `AsyncWrite`, and `Unpin` traits.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `tokio_rustls::client::TlsStream<IO>` if the connection is successfully established and
    /// the TEE attestation token is verified, or a `TeeTlsError` if an error occurs.
    ///
    /// # Errors
    ///
    /// This function will return a `TeeTlsError` if the TEE attestation token verification fails or if there
    /// is an error during the TLS handshake or IO operations.
    pub async fn connect<IO>(
        &self,
        stream: IO,
    ) -> Result<tokio_rustls::client::TlsStream<IO>, TeeTlsError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // let _root_cert_store = rustls::RootCertStore::empty(); // TODO
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new(
                &self.verify_hostname.clone(),
            ))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let domain =
            rustls_pki_types::ServerName::try_from(self.verify_hostname.clone())?.to_owned();
        let mut inner_tls_stream = connector.connect(domain, stream).await?;

        let ekm: [u8; 32] = export_key_material(&inner_tls_stream, EKM_LABEL, Some(EKM_CONTEXT))?;

        // Send TEETLS magic bytes to server
        inner_tls_stream.write_all(MAGIC_BYTES).await?;

        // Expect the server to reply with a TEE attestation token

        // Read version (2 bytes)
        let mut buffer = [0u8; 2];
        inner_tls_stream.read_exact(&mut buffer).await?;
        let version = u16::from_be_bytes(buffer);
        dbg!(version); // TODO remove

        // TODO check version number
        assert_eq!(version, 1);

        // Read payload size (4 bytes)
        let mut buffer = [0u8; 4];
        inner_tls_stream.read_exact(&mut buffer).await?;
        let size = u32::from_be_bytes(buffer);
        dbg!(size); // TODO remove

        // Read the actual TEE token payload
        let mut token = vec![0u8; size.try_into()?];
        inner_tls_stream.read_exact(&mut token).await?;

        // Verify token
        self.token_verifier.verify_token(&token, &ekm).await?;

        Ok(inner_tls_stream)
    }
}

/// A trait for verifying TEE attestation tokens.
pub trait VerifyToken {
    /// Verifies the provided TEE attestation token.
    ///
    /// # Arguments
    ///
    /// * `token` - A byte slice representing the TEE attestation token.
    /// * `ekm` - A byte slice representing the Extracted Key Material (EKM) used for channel binding.
    ///
    /// # Returns
    ///
    /// An asynchronous future that resolves to a `Result` indicating the success or failure of the token verification.
    fn verify_token(
        &self,
        token: &[u8],
        ekm: &[u8],
    ) -> impl std::future::Future<Output = Result<(), TeeTlsError>>;
}

/// A dummy token verifier used for testing purposes.
///
/// This struct is used to verify TEE attestation tokens by comparing them
/// against an expected token value.
pub struct DummyTokenVerifier {
    /// The expected token value that the verifier will compare against.
    pub expect_token: String,
}

impl VerifyToken for DummyTokenVerifier {
    async fn verify_token(&self, token: &[u8], _ekm: &[u8]) -> Result<(), TeeTlsError> {
        let token: DummyToken = serde_cbor::from_slice(token)?;
        assert!(token.body == self.expect_token);
        Ok(())
    }
}

/// A struct to skip server certificate verification.
///
/// This struct is used to bypass the default server certificate verification
/// process in the TLS handshake. It allows for custom verification logic
/// based on the provided hostname and supported algorithms.
#[derive(Debug)]
pub struct SkipServerVerification {
    /// The hostname to verify against.
    verify_hostname: String,
    /// The supported algorithms for signature verification.
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl SkipServerVerification {
    /// Creates a new `SkipServerVerification` instance.
    ///
    /// This function initializes a `SkipServerVerification` with the provided hostname
    /// and supported algorithms.
    pub fn new(verify_hostname: &str) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            verify_hostname: verify_hostname.to_string(),
            supported_algs: Arc::new(CryptoProvider::get_default().unwrap()) // this unwrap is safe with default provider
                .clone()
                .signature_verification_algorithms,
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if server_name.to_str() != self.verify_hostname {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        }

        // TODO what else do we need to check here?

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())

        // TODO
        // verify_tls13_signature_with_raw_key(
        //     message,
        //     &rustls_pki_types::SubjectPublicKeyInfoDer::from(cert.as_ref()),
        //     dss,
        //     &self.supported_algs,
        // )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }

    // TODO do we need this?!
    // fn requires_raw_public_keys(&self) -> bool {
    //     true
    // }
}

fn export_key_material<const L: usize, IO>(
    tls_stream: &tokio_rustls::client::TlsStream<IO>,
    label: &[u8],
    context: Option<&[u8]>,
) -> Result<[u8; L], rustls::Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let conn = tls_stream.get_ref().1;

    if conn.is_handshaking() {
        // TODO maybe return OtherError with custom message?
        return Err(rustls::Error::HandshakeNotComplete);
    }

    let mut buf = [0u8; L];
    let buf = conn.export_keying_material(&mut buf, label, context)?;
    Ok(*buf)
}
