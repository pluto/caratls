use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
    pub nbf: u64,
    pub sub: String,
    pub eat_nonce: Vec<String>,
    pub eat_profile: String,
    pub secboot: bool,
    pub oemid: u32,
    pub hwmodel: String,
    pub swname: String,
    pub swversion: Vec<String>,
    pub attester_tcb: Vec<String>,
    pub dbgstat: String,
    pub submods: SubModules,
    pub google_service_accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubModules {
    pub confidential_space: ConfidentialSpace,
    pub container: Container,
    pub gce: Gce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialSpace {
    pub monitoring_enabled: MonitoringEnabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringEnabled {
    pub memory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    pub image_reference: String,
    pub image_digest: String,
    pub restart_policy: String,
    pub image_id: String,
    pub env: HashMap<String, String>,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gce {
    pub zone: String,
    pub project_id: String,
    pub project_number: String,
    pub instance_name: String,
    pub instance_id: String,
}
