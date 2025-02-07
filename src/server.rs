use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::BufReader;
use tokio::io::{split, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::types::{DummyToken, EKM_CONTEXT, EKM_LABEL, MAGIC_BYTES};

pub struct TeeTlsAcceptor<T: GenerateToken> {
    cert_chain: Vec<CertificateDer<'static>>, // rustls::ServerConfig::builder requires static
    key_der: PrivateKeyDer<'static>,          // see above
    token_generator: T,
}

#[derive(Error, Debug)]
pub enum TeeTlsAcceptorError {
    // TODO
    #[error(transparent)]
    RustlsError(#[from] rustls::Error),

    #[error(transparent)]
    SerdeCborError(#[from] serde_cbor::Error),
}

impl<T: GenerateToken> TeeTlsAcceptor<T> {
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

    pub fn new_with_ephemeral_cert(token_generator: T, hostname: &str) -> Self {
        let (cert, key) = generate_cert(hostname).unwrap();
        TeeTlsAcceptor {
            cert_chain: vec![cert],
            key_der: key,
            token_generator,
        }
    }

    // `accept` takes an IO stream and creates a TLS stream on top of it.
    // It checks whether the client sent the TEETLS magic bytes. If the magic bytes
    // are detected, the TEE attestation flow is initiated, and the server sends a
    // TEE attestation token for the client to verify. The client should terminate
    // the connection if the TEE attestation fails.
    //
    // If no TEETLS magic bytes were sent, `accept` simply passes the IO stream through.
    pub async fn accept<IO>(
        &self,
        stream: IO,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin, TeeTlsAcceptorError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // listen for second TLS connection with self signed cert to come through
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert_chain.clone().to_vec(), self.key_der.clone_key())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        // TODO test if this is actually a TLS connection? if not, just passthrough.
        let inner_tls_stream = acceptor.accept(stream).await.unwrap();

        let ekm: [u8; 32] = export_key_material(&inner_tls_stream, EKM_LABEL, Some(EKM_CONTEXT))?;

        let (read, mut write) = split(inner_tls_stream);
        let mut bufread = BufReader::new(read);

        // TODO fill_buf() has no garantuee it will read at least 6 bytes.
        // Here is a crate that maybe helps:
        // https://docs.rs/peekread/latest/peekread/struct.BufPeekReader.html#method.peek_read_exact
        let peek_buf = bufread.fill_buf().await.unwrap();
        if peek_buf.len() >= MAGIC_BYTES.len() && peek_buf[..MAGIC_BYTES.len()].eq(MAGIC_BYTES) {
            bufread.consume(MAGIC_BYTES.len());

            // generate token with EKM
            let token = self.token_generator.generate_token(&ekm).await.unwrap();

            // write version
            let version: u16 = 1; // u16 = 2 bytes
            write.write_all(&version.to_be_bytes()).await.unwrap();

            // write size
            let size: u32 = token.len().try_into().unwrap(); // u32 = 4 bytes
            write.write_all(&size.to_be_bytes()).await.unwrap();

            // write payload
            write.write_all(&token).await.unwrap();
        }

        Ok(tokio::io::join(bufread, write))
    }
}

fn generate_cert(
    subject_alt_names: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    let rcgen::CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![subject_alt_names.to_string()]).unwrap();

    Ok((
        cert.der().clone(),
        PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
    ))
}

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
        // TODO maybe return OtherError with custom message?
        return Err(rustls::Error::HandshakeNotComplete);
    }

    let mut buf = [0u8; L];
    let buf = conn.export_keying_material(&mut buf, label, context)?;
    Ok(*buf)
}

pub trait GenerateToken {
    fn generate_token(
        &self,
        ekm: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, TeeTlsAcceptorError>> + Send;
}

pub struct DummyTokenGenerator {
    pub token: String,
}

impl GenerateToken for DummyTokenGenerator {
    async fn generate_token(&self, _ekm: &[u8]) -> Result<Vec<u8>, TeeTlsAcceptorError> {
        let token = DummyToken {
            body: self.token.clone(),
        };
        Ok(serde_cbor::to_vec(&token)?)
    }
}

#[cfg(test)]
mod tests {
}
