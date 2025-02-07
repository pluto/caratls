#![warn(missing_docs, clippy::missing_docs_in_private_items)]
//! Caratls (Certificate Authority trusted Remote Attestation TLS) lets a browser connect
//! directly to a TEE using a Root CA-signed certificate (e.g., from Let's Encrypt),
//! then encapsulates a second TLS session inside the outer session.
//! This inner TLS session is bootstrapped with TEE-generated self-signed certificates
//! and supports channel binding, ensuring strong trust with the TEE even if the outer certificate is compromised.

pub mod client;
pub mod error;
pub mod providers;
pub mod server;
pub mod types;
