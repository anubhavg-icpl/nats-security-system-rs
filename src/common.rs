use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentCommand {
    pub action: String,
    pub parameters: HashMap<String, String>,
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandResponse {
    pub command_id: String,
    pub agent_id: String,
    pub status: String,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityEvent {
    pub agent_id: String,
    pub timestamp: u64,
    pub event_type: String,
    pub severity: u8,
    pub description: String,
    pub details: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentRegistration {
    pub agent_id: String,
    pub hostname: String,
    pub os: String,
    pub ip: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentHeartbeat {
    pub agent_id: String,
    pub timestamp: u64,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityAlert {
    pub id: String,
    pub timestamp: u64,
    pub rule_id: String,
    pub rule_name: String,
    pub agent_id: String,
    pub event_type: String,
    pub severity: u8,
    pub description: String,
    pub details: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileIntegrityResult {
    pub path: String,
    pub status: String,
    pub current_hash: Option<String>,
    pub previous_hash: Option<String>,
    pub modified_time: u64,
}