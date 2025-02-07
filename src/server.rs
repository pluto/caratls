use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::io::{split, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::CaraTlsError;
use crate::types::{DummyToken, EKM_CONTEXT, EKM_LABEL, MAGIC_BYTES};

/// A struct representing a TLS acceptor with TEE attestation.
///
/// The `TeeTlsAcceptor` struct is responsible for accepting incoming TLS connections
/// and performing TEE attestation. It uses a self-signed certificate and a token generator
/// to create a secure TLS connection with TEE attestation.
///
/// # Type Parameters
///
/// * `T` - A type that implements the `GenerateToken` trait, used for generating TEE attestation tokens.
pub struct TeeTlsAcceptor<T: GenerateToken> {
    /// The certificate chain used for the TLS connection.
    /// This must be a static reference because `rustls::ServerConfig::builder` requires it.
    cert_chain: Vec<CertificateDer<'static>>,
    /// The private key used for the TLS connection.
    /// This must be a static reference because `rustls::ServerConfig::builder` requires it.
    key_der: PrivateKeyDer<'static>,
    /// The token generator used to generate TEE attestation tokens.
    token_generator: T,
}

impl<T: GenerateToken> TeeTlsAcceptor<T> {
    /// Creates a new `TeeTlsAcceptor` instance.
    ///
    /// This function initializes a `TeeTlsAcceptor` with the provided token generator,
    /// certificate chain, and private key.
    ///
    /// # Arguments
    ///
    /// * `token_generator` - An instance of a type that implements the `GenerateToken` trait. This is used to generate TEE attestation tokens.
    /// * `cert_chain` - A vector of `CertificateDer` representing the certificate chain used for the TLS connection.
    /// * `key_der` - A `PrivateKeyDer` representing the private key used for the TLS connection.
    ///
    /// # Returns
    ///
    /// A new instance of `TeeTlsAcceptor`.
    pub fn new(
        token_generator: T,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Self {
        TeeTlsAcceptor {
            cert_chain,
            key_der,
            token_generator,
        }
    }

    /// Creates a new `TeeTlsAcceptor` instance with an ephemeral certificate.
    ///
    /// This function generates a self-signed certificate for the provided hostname
    /// and initializes a `TeeTlsAcceptor` with the generated certificate, private key,
    /// and the provided token generator.
    ///
    /// # Arguments
    ///
    /// * `token_generator` - An instance of a type that implements the `GenerateToken` trait. This is used to generate TEE attestation tokens.
    /// * `hostname` - A string slice that holds the hostname for which the self-signed certificate will be generated.
    ///
    /// # Returns
    ///
    /// A new instance of `TeeTlsAcceptor` with an ephemeral certificate.
    pub fn new_with_ephemeral_cert(
        token_generator: T,
        hostname: &str,
    ) -> Result<Self, CaraTlsError> {
        let (cert, key) = generate_cert(hostname)?;
        Ok(TeeTlsAcceptor {
            cert_chain: vec![cert],
            key_der: key,
            token_generator,
        })
    }

    /// Accepts an incoming IO stream and creates a TLS stream on top of it.
    ///
    /// This function checks whether the client sent the TEETLS magic bytes. If the magic bytes
    /// are detected, the TEE attestation flow is initiated, and the server sends a
    /// TEE attestation token for the client to verify. The client should terminate
    /// the connection if the TEE attestation fails.
    ///
    /// If no TEETLS magic bytes were sent, `accept` simply passes the IO stream through.
    ///
    /// # Arguments
    ///
    /// * `stream` - An IO stream that implements the `AsyncRead`, `AsyncWrite`, and `Unpin` traits.
    ///
    /// # Returns
    ///
    /// A `Result` containing an IO stream that implements `AsyncRead`, `AsyncWrite`, and `Unpin` if the connection is successfully established and
    /// the TEE attestation token is verified, or a `TeeTlsError` if an error occurs.
    ///
    /// # Errors
    ///
    /// This function will return a `TeeTlsError` if there is an error during the TLS handshake, IO operations, or TEE attestation token generation.
    pub async fn accept<IO>(
        &self,
        stream: IO,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin, CaraTlsError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // listen for second TLS connection with self signed cert to come through
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert_chain.clone().to_vec(), self.key_der.clone_key())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        // TODO test if this is actually a TLS connection? if not, just passthrough.
        let inner_tls_stream = acceptor.accept(stream).await?;

        let ekm: [u8; 32] = export_key_material(&inner_tls_stream, EKM_LABEL, Some(EKM_CONTEXT))?;

        let (read, mut write) = split(inner_tls_stream);
        let mut bufread = BufReader::new(read);

        // TODO fill_buf() has no garantuee it will read at least 6 bytes.
        // Here is a crate that maybe helps:
        // https://docs.rs/peekread/latest/peekread/struct.BufPeekReader.html#method.peek_read_exact
        let peek_buf = bufread.fill_buf().await?;
        if peek_buf.len() >= MAGIC_BYTES.len() && peek_buf[..MAGIC_BYTES.len()].eq(MAGIC_BYTES) {
            bufread.consume(MAGIC_BYTES.len());

            // generate token with EKM
            let token = self.token_generator.generate_token(&ekm).await?;

            // write version
            let version: u16 = 1; // u16 = 2 bytes
            write.write_all(&version.to_be_bytes()).await?;

            // write size
            let size: u32 = token.len().try_into()?; // u32 = 4 bytes
            write.write_all(&size.to_be_bytes()).await?;

            // write payload
            write.write_all(&token).await?;
        }

        Ok(tokio::io::join(bufread, write))
    }
}

/// Generates a self-signed certificate and private key.
///
/// This function creates a self-signed certificate for the provided subject alternative names
/// and returns the certificate and private key in DER format.
///
/// # Arguments
///
/// * `subject_alt_names` - A string slice that holds the subject alternative names for the certificate.
///
/// # Returns
///
/// A `Result` containing a tuple with the certificate and private key in DER format, or a `CaraTlsError` if an error occurs.
///
/// # Errors
///
/// This function will return a `CaraTlsError` if there is an error during the certificate or key generation.
fn generate_cert(
    subject_alt_names: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CaraTlsError> {
    let rcgen::CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![subject_alt_names.to_string()])?;

    Ok((
        cert.der().clone(),
        PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
    ))
}
/// Exports key material from a TLS stream.
///
/// This function extracts key material from an established TLS stream using the provided label and context.
/// The key material is used for cryptographic operations such as channel binding.
///
/// # Arguments
///
/// * `tls_stream` - A reference to a `tokio_rustls::server::TlsStream` representing the established TLS connection.
/// * `label` - A byte slice representing the label used for key extraction.
/// * `context` - An optional byte slice representing the context used for key extraction.
///
/// # Returns
///
/// A `Result` containing an array of extracted key material of length `L`, or a `rustls::Error` if an error occurs.
///
/// # Errors
///
/// This function will return a `rustls::Error::HandshakeNotComplete` if the TLS handshake is not complete.
fn export_key_material<const L: usize, IO>(
    tls_stream: &tokio_rustls::server::TlsStream<IO>,
    label: &[u8],
    context: Option<&[u8]>,
) -> Result<[u8; L], rustls::Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let conn = tls_stream.get_ref().1;

    if conn.is_handshaking() {
        return Err(rustls::Error::HandshakeNotComplete);
    }

    let mut buf = [0u8; L];
    let buf = conn.export_keying_material(&mut buf, label, context)?;
    Ok(*buf)
}

/// A trait for generating TEE attestation tokens.
///
/// This trait defines a method for generating TEE attestation tokens based on the provided
/// Extracted Key Material (EKM). Implementors of this trait are responsible for creating
/// the token and returning it as a byte vector.
///
/// # Type Parameters
///
/// * `T` - A type that implements the `GenerateToken` trait, used for generating the TEE attestation token.
pub trait GenerateToken {
    /// Generates a TEE attestation token.
    ///
    /// This method generates a TEE attestation token using the provided EKM. The token is returned
    /// as a byte vector wrapped in a `Result`.
    ///
    /// # Arguments
    ///
    /// * `ekm` - A byte slice representing the Extracted Key Material (EKM) used for token generation.
    ///
    /// # Returns
    ///
    /// An asynchronous future that resolves to a `Result` containing the generated token as a byte vector,
    /// or a `TeeTlsError` if an error occurs during token generation.
    fn generate_token(
        &self,
        ekm: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, CaraTlsError>> + Send;
}

/// A dummy token generator used for testing purposes.
///
/// This struct is used to generate TEE attestation tokens by providing a predefined token value.
pub struct DummyTokenGenerator {
    /// The token value that the generator will use to create the TEE attestation token.
    pub token: String,
}

impl GenerateToken for DummyTokenGenerator {
    async fn generate_token(&self, _ekm: &[u8]) -> Result<Vec<u8>, CaraTlsError> {
        let token = DummyToken {
            body: self.token.clone(),
        };
        Ok(serde_cbor::to_vec(&token)?)
    }
}
