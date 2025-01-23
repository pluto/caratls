use serde::{Deserialize, Serialize};

pub const MAGIC_BYTES: &[u8; 6] = b"TEETLS";
pub const EKM_LABEL: &[u8; 21] = b"EXPORTER-pluto-notary";
pub const EKM_CONTEXT: &[u8; 3] = b"tee";

#[derive(Serialize, Deserialize, Debug)]
pub struct DummyToken {
    pub body: String,
}
