mod attestation;
pub mod client;
pub mod server;

const MAGIC_BYTES: &[u8; 6] = b"TEETLS";
const EKM_LABEL: &[u8; 21] = b"EXPORTER-pluto-notary";
const EKM_CONTEXT: &[u8; 3] = b"tee";

#[cfg(test)]
mod tests {
    use crate::{client::TeeTlsConnector, server::TeeTlsAcceptor};
    use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn test_server_client() {
        // Create a temporary server with a self-signed certificate.
        // The client will later trust this certificate as a root Certificate Authority (CA).
        let certs = CertificateDer::pem_file_iter("tests/certs/chain.pem")
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file("tests/certs/end.key").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            // Configure the "outer" TLS listener on the temporary server
            // and accept an incoming connection.
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let (stream, _peer_addr) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(stream).await.unwrap();

            // Listen for the "inner" TEE TLS connection
            let tee_tls_acceptor = TeeTlsAcceptor::new_with_ephemeral_cert("example.com");
            let mut tee_tls_stream = tee_tls_acceptor.accept(tls_stream).await.unwrap();

            // The `tee_tls_stream` connection can now be used like a regular TLS stream,
            // for example, it can be passed into Axum for handling HTTP routes.

            // In this test, we expect the client to send a "Hello world" string.
            let mut buffer = Vec::new();
            tee_tls_stream.read_to_end(&mut buffer).await.unwrap();
            assert_eq!("Hello world", String::from_utf8_lossy(&buffer));
        });

        // Configure a client to connect to the temporary server.

        // First, set up the "outer" TLS connection.
        let mut root_cert_store = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter("tests/certs/root.pem").unwrap() {
            root_cert_store.add(cert.unwrap()).unwrap();
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(&server_addr).await.unwrap();
        let domain = rustls_pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let tls_stream = connector.connect(domain, stream).await.unwrap();

        // Second, create the "inner" TEE TLS connection.
        let tee_tls_connector = TeeTlsConnector::new("example.com");
        let mut tee_tls_stream = tee_tls_connector.connect(tls_stream).await.unwrap();

        // The `tee_tls_stream` can now be used as a regular TLS stream,
        // for example, to send an HTTP GET request to an endpoint served by Axum.

        // In this test, the client just sends a "Hello world" test string.
        tee_tls_stream
            .write_all("Hello world".as_bytes())
            .await
            .unwrap();

        // Close the connection and wait for the server to shutdown as well.
        tee_tls_stream.shutdown().await.unwrap();
        server_handle.await.unwrap();
    }
}
