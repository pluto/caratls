use ekm_client::VerifyToken;
use ekm_gcs_types::JwtToken;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

pub struct GoogleConfidentialSpaceTokenVerifier {
    expect_audience: String,
    jwks: JwkSet,
}

impl GoogleConfidentialSpaceTokenVerifier {
    pub async fn new(audience: &str) -> Self {
        let mut v = GoogleConfidentialSpaceTokenVerifier {
            expect_audience: audience.to_owned(),
            jwks: JwkSet { keys: vec![] },
        };
        v.reload_jwks().await;
        v
    }

    pub async fn reload_jwks(&mut self) {
        // OIDC flow ...
        // https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
        // https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com
        let jwks_response = reqwest::get("https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com").await.unwrap();
        let body = jwks_response.bytes().await.unwrap();
        let jwks: JwkSet = serde_json::from_slice(&body).unwrap();
        self.jwks = jwks;
    }
}

impl VerifyToken for GoogleConfidentialSpaceTokenVerifier {
    async fn verify_token(
        &self,
        token: &[u8],
        ekm: &[u8],
    ) -> Result<(), ekm_client::TeeTlsConnectorError> {
        // token is base64 encoded string
        let token = std::str::from_utf8(&token).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();

        let alg = header.alg;
        if alg != Algorithm::RS256 {
            panic!("unsupported JWT alg")
        }

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        let Some(kid) = header.kid else {
            panic!("Token doesn't have a `kid` header field");
        };

        let Some(jwk) = self.jwks.find(&kid) else {
            panic!("No matching JWK found for the given kid");
        };

        let decoding_key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap()
            }
            _ => unreachable!("algorithm should be a RSA in this example"),
        };

        let validation = {
            let mut validation = Validation::new(header.alg);
            validation.set_audience(&[self.expect_audience.clone()]);
            validation.validate_exp = true;
            validation
        };

        let decoded_token =
            jsonwebtoken::decode::<JwtToken>(token, &decoding_key, &validation).unwrap();

        assert_eq!(decoded_token.claims.eat_nonce[0], hex::encode(&ekm));

        // PKI flow... (broken)
        // key:
        // https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
        // https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt
        // https://github.com/GoogleCloudPlatform/confidential-space/blob/main/codelabs/health_data_analysis_codelab/src/uwear/workload.go#L84
        //
        // let cert_request = reqwest::get(
        //   "https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt",
        // )
        // .await
        // .unwrap();
        // let cert = cert_request.bytes().await.unwrap();
        // let decoding_key = &DecodingKey::from_rsa_pem(&cert).unwrap();
        // let token_data = decode::<Claims>(tee_token, decoding_key, &validation).unwrap();
        // dbg!(token_data);

        Ok(())
    }
}
