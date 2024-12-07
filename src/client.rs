use crate::{attestation::Token, MAGIC_BYTES};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Error, Debug)]
pub enum TeeTlsConnectorError {
    // TODO
}

pub struct TeeTlsConnector {
    verify_hostname: String,
}

impl TeeTlsConnector {
    pub fn new(verify_hostname: &str) -> Self {
        TeeTlsConnector {
            verify_hostname: verify_hostname.to_string(),
        }
    }

    // `connect` establishes a connection to a server using an existing IO stream.
    // It creates a TLS connection on top of the stream, accepting self-signed certificates.
    // Once the connection is established, it sends the TEETLS magic bytes to the server,
    // signaling it to initiate the TEE attestation token verification flow.
    //
    // The server will respond with a TEE attestation token, which this function verifies.
    // If the TEE attestation token fails verification, the connection is aborted.
    // Otherwise, this function returns an IO stream that can be used like a regular TLS connection.
    pub async fn connect<IO>(
        &self,
        stream: IO,
    ) -> Result<tokio_rustls::client::TlsStream<IO>, TeeTlsConnectorError>
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
        let domain = rustls_pki_types::ServerName::try_from(self.verify_hostname.clone())
            .unwrap()
            .to_owned();
        let mut inner_tls_stream = connector.connect(domain, stream).await.unwrap();

        // Send TEETLS magic bytes to server
        inner_tls_stream.write_all(&MAGIC_BYTES).await.unwrap();

        // Expect the server to reply with a TEE attestation token

        // Read version (2 bytes)
        let mut buffer = [0u8; 2];
        inner_tls_stream.read_exact(&mut buffer).await.unwrap();
        let version = u16::from_be_bytes(buffer);
        dbg!(version); // TODO remove

        // TODO check version number
        assert_eq!(version, 1);

        // Read payload size (4 bytes)
        let mut buffer = [0u8; 4];
        inner_tls_stream.read_exact(&mut buffer).await.unwrap();
        let size = u32::from_be_bytes(buffer);
        dbg!(size); // TODO remove

        // Read the actual TEE token payload
        let mut buffer = vec![0u8; size.try_into().unwrap()];
        inner_tls_stream.read_exact(&mut buffer).await.unwrap();

        let token: Token = serde_cbor::from_slice(&buffer).unwrap();
        dbg!(token); // TODO remove

        // TODO verify token

        Ok(inner_tls_stream)
    }
}

#[derive(Debug)]
pub struct SkipServerVerification {
    verify_hostname: String,
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl SkipServerVerification {
    pub fn new(verify_hostname: &str) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            verify_hostname: verify_hostname.to_string(),
            supported_algs: Arc::new(CryptoProvider::get_default().unwrap())
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
