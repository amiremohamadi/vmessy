use anyhow::{anyhow, Result};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub inbound: Inbound,
    pub outbound: Outbound,
}

#[derive(Debug, Deserialize)]
pub struct Inbound {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct Outbound {
    pub address: String,
    pub uuid: Uuid,
    pub aead: bool,
}

impl Config {
    pub fn new(config: &str) -> Result<Self> {
        match toml::from_str(config) {
            Ok(c) => Ok(c),
            Err(e) => Err(anyhow!("could not parse config file {}", e)),
        }
    }
}
