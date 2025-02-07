#![deny(missing_docs)]
//! Caratls (Certificate Authority trusted Remote Attestation TLS) lets a browser connect
//! directly to a TEE using a Root CA-signed certificate (e.g., from Let's Encrypt),
//! then encapsulates a second TLS session inside the outer session.
//! This inner TLS session is bootstrapped with TEE-generated self-signed certificates
//! and supports channel binding, ensuring strong trust with the TEE even if the outer certificate is compromised.

/// Client-related functionality.
pub mod client;
/// Error types for the library.
pub mod errors;
/// Providers for the library.
pub mod providers;
/// Server-related functionality.
pub mod server;
/// Types and constants used throughout the library.
pub mod types;
