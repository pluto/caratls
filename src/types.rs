use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Magic bytes used to signal the start of the TEE attestation process.
pub const MAGIC_BYTES: &[u8; 6] = b"TEETLS";

/// Label used for exporting key material in the TEE attestation process.
pub const EKM_LABEL: &[u8; 21] = b"EXPORTER-pluto-notary";

/// Context used for exporting key material in the TEE attestation process.
pub const EKM_CONTEXT: &[u8; 3] = b"tee";

/// A struct representing a dummy token used for testing purposes.
///
/// The `DummyToken` struct is used to generate TEE attestation tokens by providing a predefined token value.
/// It contains a single field, `body`, which holds the token value as a string.
#[derive(Serialize, Deserialize, Debug)]
pub struct DummyToken {
    /// The token value that the generator will use to create the TEE attestation token.
    pub body: String,
}

/// A struct representing a JSON Web Token (JWT) used for TEE attestation.
///
/// The `JwtToken` struct contains various fields that represent the claims and attributes
/// of a JWT used in the TEE attestation process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    /// The audience claim identifies the recipients that the JWT is intended for.
    pub aud: String,
    /// The expiration time claim identifies the expiration time on or after which the JWT must not be accepted for processing.
    pub exp: u64,
    /// The issued at claim identifies the time at which the JWT was issued.
    pub iat: u64,
    /// The issuer claim identifies the principal that issued the JWT.
    pub iss: String,
    /// The not before claim identifies the time before which the JWT must not be accepted for processing.
    pub nbf: u64,
    /// The subject claim identifies the principal that is the subject of the JWT.
    pub sub: String,
    /// The nonce used in the Entity Attestation Token (EAT) for preventing replay attacks.
    pub eat_nonce: EatNonce,
    /// The profile used in the EAT.
    pub eat_profile: String,
    /// A boolean indicating whether secure boot is enabled.
    pub secboot: bool,
    /// The OEM ID of the device.
    pub oemid: u32,
    /// The hardware model of the device.
    pub hwmodel: String,
    /// The name of the software running on the device.
    pub swname: String,
    /// The version of the software running on the device.
    pub swversion: Vec<String>,
    /// The attester's Trusted Computing Base (TCB) information.
    pub attester_tcb: Vec<String>,
    /// The debug status of the device.
    pub dbgstat: String,
    /// The submodules included in the JWT.
    pub submods: SubModules,
    /// The Google service accounts associated with the JWT.
    pub google_service_accounts: Vec<String>,
}

/// An enum representing the nonce used in the Entity Attestation Token (EAT).
///
/// The `EatNonce` enum can either be a single string value or multiple string values.
/// This is used to prevent replay attacks in the TEE attestation process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EatNonce {
    /// A single nonce value.
    Single(String),
    /// Multiple nonce values.
    Multiple(Vec<String>),
}

/// A struct representing the submodules included in the JWT.
///
/// The `SubModules` struct contains information about various submodules
/// that are part of the JWT. These submodules include confidential space,
/// container, and GCE (Google Compute Engine) information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubModules {
    /// Information about the confidential space.
    pub confidential_space: ConfidentialSpace,
    /// Information about the container.
    pub container: Container,
    /// Information about the Google Compute Engine (GCE).
    pub gce: Gce,
}
/// A struct representing the confidential space information.
///
/// The `ConfidentialSpace` struct contains information about the confidential space
/// in the JWT. This includes whether monitoring is enabled for the confidential space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialSpace {
    /// A boolean indicating whether monitoring is enabled.
    pub monitoring_enabled: bool,
}

/// A struct representing a container.
///
/// The `Container` struct contains its
/// image reference, image digest, restart policy, image ID, environment variables,
/// and arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    /// The reference to the container image.
    pub image_reference: String,
    /// The digest of the container image.
    pub image_digest: String,
    /// The policy for restarting the container.
    pub restart_policy: String,
    /// The ID of the container image.
    pub image_id: String,
    /// A map of environment variables for the container.
    pub env: HashMap<String, String>,
    /// A list of arguments for the container.
    pub args: Vec<String>,
}

/// A struct representing Google Compute Engine (GCE) information.
///
/// The `Gce` struct contains information about a GCE instance, including its zone,
/// project ID, project number, instance name, and instance ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gce {
    /// The zone where the GCE instance is located.
    pub zone: String,
    /// The ID of the project that the GCE instance belongs to.
    pub project_id: String,
    /// The number of the project that the GCE instance belongs to.
    pub project_number: String,
    /// The name of the GCE instance.
    pub instance_name: String,
    /// The ID of the GCE instance.
    pub instance_id: String,
}
