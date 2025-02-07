use crate::{error::TeeTlsError, server::GenerateToken};
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};

/// A struct representing a token generator for Google Confidential Space.
///
/// The `GoogleConfidentialSpaceTokenGenerator` struct is used to generate tokens
/// for Google Confidential Space by providing the expected audience for the token.
pub struct GoogleConfidentialSpaceTokenGenerator {
    /// The expected audience for the token.
    audience: String,
}

impl GoogleConfidentialSpaceTokenGenerator {
    /// Creates a new instance of `GoogleConfidentialSpaceTokenGenerator`.
    ///
    /// # Arguments
    ///
    /// * `audience` - A string slice that holds the expected audience for the token.
    ///
    /// # Returns
    ///
    /// A new `GoogleConfidentialSpaceTokenGenerator` instance with the specified audience.
    pub fn new(audience: &str) -> Self {
        GoogleConfidentialSpaceTokenGenerator {
            audience: audience.to_owned(),
        }
    }
}

impl GenerateToken for GoogleConfidentialSpaceTokenGenerator {
    async fn generate_token(&self, ekm: &[u8]) -> Result<Vec<u8>, TeeTlsError> {
        let stream =
            tokio::net::UnixStream::connect("/run/container_launcher/teeserver.sock").await?;
        let stream = TokioIo::new(stream);

        let token_request = CustomTokenRequest {
            audience: self.audience.clone(),
            token_type: "OIDC".to_string(),
            nonces: vec![hex::encode(ekm)],
        };
        let token_request = serde_json::to_string(&token_request)?;

        let (mut client, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, Full<Bytes>>(stream)
            .await?;

        tokio::task::spawn(conn);

        let request = hyper::Request::builder()
            .uri("http://localhost/v1/token")
            .method("POST")
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(token_request)))?;

        let response = client.send_request(request).await?;
        assert!(response.status().is_success()); // TODO return Err instead

        let body = response.collect().await?.to_bytes().to_vec();

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
