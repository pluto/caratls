use ekm_server::GenerateToken;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};

pub struct GoogleConfidentialSpaceTokenGenerator {
    audience: String,
}

impl GoogleConfidentialSpaceTokenGenerator {
    pub fn new(audience: &str) -> Self {
        GoogleConfidentialSpaceTokenGenerator {
            audience: audience.to_owned(),
        }
    }
}

impl GenerateToken for GoogleConfidentialSpaceTokenGenerator {
    async fn generate_token(&self, ekm: &[u8]) -> Result<Vec<u8>, ekm_server::TeeTlsAcceptorError> {
        let stream = tokio::net::UnixStream::connect("/run/container_launcher/teeserver.sock")
            .await
            .unwrap(); // TODO unwrap
        let stream = TokioIo::new(stream);

        let token_request = CustomTokenRequest {
            audience: self.audience.clone(),
            token_type: "OIDC".to_string(),
            nonces: vec![hex::encode(ekm)],
        };
        let token_request = serde_json::to_string(&token_request).unwrap();

        let (mut client, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, Full<Bytes>>(stream)
            .await
            .unwrap(); // TODO unwrap

        tokio::task::spawn(conn); // TODO handle error

        let request = hyper::Request::builder()
            .uri("http://localhost/v1/token")
            .method("POST")
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(token_request)))
            .unwrap(); // TODO unwrap

        let response = client.send_request(request).await.unwrap(); // TODO unwrap
        assert!(response.status().is_success()); // TODO return Err instead

        let body = response.collect().await.unwrap().to_bytes().to_vec();

        // TODO verify body is a valid JWT?

        Ok(body)
    }
}

#[derive(Serialize, Deserialize)]
struct CustomTokenRequest {
    audience: String,
    token_type: String,
    nonces: Vec<String>,
}
