# caratls

**tldr**: caratls (Certificate Authority trusted Remote Attestation TLS) lets a browser connect directly to a TEE using a Root CA-signed certificate (e.g., from Let's Encrypt), then encapsulates a second TLS session inside the outer session. This inner TLS session is bootstrapped with TEE-generated self-signed certificates and supports channel binding, ensuring strong trust with the TEE even if the outer certificate is compromised.

```
Outer TLS session trusted by Root CA (ie Let's Encrypt)
..encapsulates TLS session with TEE bootstrapped self-signed certificate
...verifies TEE attestation token inline
...use TlsStream<TlsStream<TcpStream>> for regular client/server comms
```


## Motivation

- **Direct Browser Compatibility**: Browsers only trust CA-signed certificates by default. Hence, we first establish a standard HTTPS/WSS connection using a Let's Encrypt certificate.
- **TEE Bootstrapping**: Once the outer TLS session is set up, we initiate an inner TLS session with self-signed, TEE-generated keys. This inner session includes remote attestation to verify the TEE identity.
- **Secure "Inner" TLS**: If the outer certificate is compromised or reused across multiple TEEs, the inner session still provides end-to-end security anchored in the TEE.
- **Scalability**: Managing a single CA-signed cert per domain (e.g., `api.example.com`) avoids [Let's Encrypt rate-limit issues](https://letsencrypt.org/docs/rate-limits/) and complicated certificate distribution across many TEEs.


## Concept

1. **Outer TLS**  
   - Negotiated using a Let's Encrypt cert (or any other Root CA-signed certificate).  
   - Allows standard HTTPS/WSS connections from browsers.

2. **Inner TLS**  
   - Encapsulated inside the outer TLS stream (`TlsStream<TlsStream<TcpStream>>`).  
   - Uses self-signed, TEE-bootstrapped certificates.  
   - Performs channel binding (EKM or key attestation) to prove the session is securely terminated in the TEE.

3. **TEE Attestation**  
   - Verified inline during the inner TLS handshake.  
   - Confirms the TEE’s authenticity and ties it to the self-signed cert.


## Approaches

- **EKM-Based**:  
  The TEE attestation includes an Extracted Key Material (EKM) nonce derived from the inner TLS handshake, thereby binding the attestation to that specific session.

- **Key Attestation**:  
  The TEE directly attests the ephemeral key used in the inner TLS session, typically by signing the public key or embedding it in the TEE's quote/report.

Both approaches ensure a strong channel binding between the TEE and the client.
Currently this crate only implements an EKM-based approach for Google Confidential Space.


## Usage

```rust
// Server/ TEE side
let token_generator = DummyTokenGenerator::new()
let tee_tls_acceptor = TeeTlsAcceptor::new(token_generator, ...);
let tee_tls_stream = tee_tls_acceptor.accept(tls_stream).await?;

// Client side
let token_verifier = DummyTokenVerifier::new()
let tee_tls_connector = TeeTlsConnector::new(token_verifier, ...);
let tee_tls_stream = tee_tls_connector.connect(tls_stream).await?;
```

The `tls_stream` in both cases is already an outer TLS connection (e.g., from Let's Encrypt) which then encapsulates the secure TEE-bootstrapped inner TLS connection.


## Development

caratls is organized into multiple crates:

* `server & client`: Split for better dependency control (e.g., WASM/iOS target support on the client side).
* `ekm` and `key`: Different crates implement either EKM-based or Key-Attestation based channel binding.
