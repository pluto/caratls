use thiserror::Error;

/// Error types for the library.
#[derive(Error, Debug)]
pub enum TeeTlsError {
    /// Error from the Rustls library.
    #[error(transparent)]
    RustlsError(#[from] rustls::Error),

    /// Error from the Serde CBOR library.
    #[error(transparent)]
    SerdeCborError(#[from] serde_cbor::Error),

    /// Error from standard IO operations.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Error from DNS name validation.
    #[error("DNS name validation error: {0}")]
    DnsNameError(#[from] rustls_pki_types::InvalidDnsNameError),

    /// Error from integer conversion failures.
    #[error("Integer conversion error: {0}")]
    IntConversionError(#[from] std::num::TryFromIntError),

    /// RCGen error.
    #[error(transparent)]
    RcgenError(#[from] rcgen::Error),

    /// Request error.
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),

    /// Serde JSON error.
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    /// String conversion error.
    #[error(transparent)]
    StringConversionError(#[from] core::str::Utf8Error),

    /// JWT error.
    #[error(transparent)]
    JwtError(#[from] jsonwebtoken::errors::Error),

    /// Hyper error.
    #[error(transparent)]
    HyperError(#[from] hyper::Error),

    /// Error from the Hyper HTTP library.
    #[error(transparent)]
    HyperHttpError(#[from] hyper::http::Error),

    /// Other error.
    #[error("Other error: {0}")]
    Other(String),
}
