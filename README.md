# WORK IN PROGRESS

# caratls

... stands for Certificate Authority trusted Remote Attestation TLS

aka Let's Encrypt for TEEs.

Idea is:

```
TLS session trusted by Root CA (Let's Encrypt)
..encapsulates TLS session with TEE bootstrapped self-signed certificate
....verifies TEE attestation token inline
......use TlsStream<TlsStream<TcpStream>> for regular client/server comms
```

Also supports WASM.

```
cargo test
```

## Usage

```rust
// client
let tee_tls_connector = TeeTlsConnector::new(...);
let tee_tls_stream = tee_tls_connector.connect(stream).await?;

// server
let tee_tls_acceptor = TeeTlsAcceptor::new(...);
let tee_tls_stream = tee_tls_acceptor.accept(stream).await?;
```
