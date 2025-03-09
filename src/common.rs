use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Command to be executed on an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCommand {
    /// Command unique identifier
    pub id: String,
    /// Action to perform: "exec", "scan", etc.
    pub action: String,
    /// Command parameters
    pub parameters: HashMap<String, String>,
}

/// Response to a command from an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    /// Original command ID
    pub command_id: String,
    /// ID of the agent that executed the command
    pub agent_id: String,
    /// Command execution status: "success", "error", etc.
    pub status: String,
    /// Output data or error message
    pub data: String,
}

/// Security event detected by an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// ID of the agent that detected the event
    pub agent_id: String,
    /// Unix timestamp when the event was detected
    pub timestamp: u64,
    /// Type of event: "file_integrity", "log_alert", etc.
    pub event_type: String,
    /// Severity level (0-10, with 10 being most severe)
    pub severity: u8,
    /// Human-readable description
    pub description: String,
    /// Additional event details
    pub details: HashMap<String, String>,
}

/// Registration message sent by agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistration {
    /// Agent unique identifier
    pub agent_id: String,
    /// Agent hostname
    pub hostname: String,
    /// Operating system information
    pub os: String,
    /// Agent IP address
    pub ip: String,
    /// Agent version
    pub version: String,
}

/// Heartbeat message sent by agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHeartbeat {
    /// Agent unique identifier
    pub agent_id: String,
    /// Unix timestamp of the heartbeat
    pub timestamp: u64,
    /// Agent status: "active", "idle", etc.
    pub status: String,
}

/// Alert generated when security rules match events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    /// Alert unique identifier
    pub id: String,
    /// Unix timestamp when the alert was generated
    pub timestamp: u64,
    /// ID of the rule that triggered the alert
    pub rule_id: String,
    /// Name of the rule that triggered the alert
    pub rule_name: String,
    /// ID of the agent that detected the event
    pub agent_id: String,
    /// Type of the triggering event
    pub event_type: String,
    /// Alert severity level (0-10)
    pub severity: u8,
    /// Human-readable description
    pub description: String,
    /// Additional alert details
    pub details: HashMap<String, String>,
}

/// File integrity check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityResult {
    /// Path of the file
    pub path: String,
    /// Status of the check: "unchanged", "modified", "created", "deleted"
    pub status: String,
    /// Current file hash (if available)
    pub current_hash: Option<String>,
    /// Previous file hash (if available)
    pub previous_hash: Option<String>,
    /// Unix timestamp of the modification
    pub modified_time: u64,
}

/// Agent information for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Agent unique identifier
    pub agent_id: String,
    /// Agent hostname
    pub hostname: String,
    /// Operating system information
    pub os: String,
    /// Agent IP address
    pub ip: String,
    /// Agent version
    pub version: String,
    /// Unix timestamp of last seen heartbeat
    pub last_seen: u64,
    /// Current agent status
    pub status: String,
    /// Time since last heartbeat (seconds)
    pub uptime: u64,
    /// Agent capabilities
    pub capabilities: Vec<String>,
}

/// Get current Unix timestamp in seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Standard error codes for consistent error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Authentication failure
    AuthenticationFailed,
    /// Authorization failure
    PermissionDenied,
    /// Invalid parameters
    InvalidParameters,
    /// Resource not found
    NotFound,
    /// Agent connection failure
    AgentNotConnected,
    /// Internal system error
    InternalError,
    /// Communication error
    CommunicationError,
    /// Configuration error
    ConfigurationError,
    /// Invalid file path
    InvalidPath,
    /// Command execution failure
    CommandExecutionFailed,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::AuthenticationFailed => write!(f, "Authentication failed"),
            ErrorCode::PermissionDenied => write!(f, "Permission denied"),
            ErrorCode::InvalidParameters => write!(f, "Invalid parameters"),
            ErrorCode::NotFound => write!(f, "Resource not found"),
            ErrorCode::AgentNotConnected => write!(f, "Agent not connected"),
            ErrorCode::InternalError => write!(f, "Internal error"),
            ErrorCode::CommunicationError => write!(f, "Communication error"),
            ErrorCode::ConfigurationError => write!(f, "Configuration error"),
            ErrorCode::InvalidPath => write!(f, "Invalid path"),
            ErrorCode::CommandExecutionFailed => write!(f, "Command execution failed"),
        }
    }
}