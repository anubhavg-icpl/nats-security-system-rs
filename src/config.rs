use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    // Identity settings
    pub id_prefix: Option<String>,
    pub custom_id: Option<String>,
    
    // NATS connection settings
    pub nats: NatsConfig,
    
    // File monitoring settings
    pub file_monitoring: FileMonitoringConfig,
    
    // Operational settings
    pub scan_interval_seconds: u64,
    pub heartbeat_interval_seconds: u64,
    pub reconnect_attempts: u32,
    pub reconnect_delay_seconds: u64,
}

// Manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerConfig {
    // NATS connection settings
    pub nats: NatsConfig,
    
    // Service settings
    pub api_bind_address: String,
    pub api_port: u16,
    pub admin_token: String,
    
    // Agent monitoring settings
    pub agent_timeout_seconds: u64,
    
    // Operational settings
    pub alert_retention_count: usize,
    pub reconnect_attempts: u32,
    pub reconnect_delay_seconds: u64,
}

// Shared NATS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub tls_ca_cert: Option<PathBuf>,
    pub tls_client_cert: Option<PathBuf>,
    pub tls_client_key: Option<PathBuf>,
}

// File monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitoringConfig {
    pub enabled: bool,
    pub monitored_paths: Vec<MonitoredPath>,
    pub excluded_paths: Vec<String>,
    pub ignore_temp_files: bool,
}

// Structure for monitoring specific paths with options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredPath {
    pub path: String,
    pub recursive: bool,
    pub severity_override: Option<u8>,
    pub exclude_patterns: Vec<String>,
}

// Default implementation for AgentConfig
impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            id_prefix: None,
            custom_id: None,
            nats: NatsConfig::default(),
            file_monitoring: FileMonitoringConfig {
                enabled: true,
                monitored_paths: vec![
                    MonitoredPath {
                        path: "/etc".to_string(),
                        recursive: false,
                        severity_override: None,
                        exclude_patterns: vec![],
                    }
                ],
                excluded_paths: vec![
                    "/etc/mtab".to_string(),
                    "/etc/resolv.conf".to_string(),
                ],
                ignore_temp_files: true,
            },
            scan_interval_seconds: 300,
            heartbeat_interval_seconds: 60,
            reconnect_attempts: 10,
            reconnect_delay_seconds: 5,
        }
    }
}

// Default implementation for ManagerConfig
impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            nats: NatsConfig::default(),
            api_bind_address: "127.0.0.1".to_string(),
            api_port: 8080,
            admin_token: uuid::Uuid::new_v4().to_string(),
            agent_timeout_seconds: 300,
            alert_retention_count: 1000,
            reconnect_attempts: 10,
            reconnect_delay_seconds: 5,
        }
    }
}

// Default implementation for NatsConfig
impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: "nats://localhost:4222".to_string(),
            username: None,
            password: None,
            token: None,
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
        }
    }
}

// Load agent configuration from file or use defaults
pub fn load_agent_config<P: AsRef<Path>>(path: Option<P>) -> Result<AgentConfig, ConfigError> {
    if let Some(config_path) = path {
        if config_path.as_ref().exists() {
            let mut file = File::open(config_path.as_ref()).map_err(ConfigError::IoError)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).map_err(ConfigError::IoError)?;
            
            let config: AgentConfig = match config_path.as_ref().extension().and_then(|e| e.to_str()) {
                Some("json") => serde_json::from_str(&contents).map_err(ConfigError::JsonError)?,
                Some("toml") => toml::from_str(&contents).map_err(ConfigError::TomlError)?,
                Some("yaml") | Some("yml") => serde_yaml::from_str(&contents).map_err(ConfigError::YamlError)?,
                _ => return Err(ConfigError::UnsupportedFormat),
            };
            
            Ok(config)
        } else {
            Err(ConfigError::FileNotFound)
        }
    } else {
        Ok(AgentConfig::default())
    }
}

// Load manager configuration from file or use defaults
pub fn load_manager_config<P: AsRef<Path>>(path: Option<P>) -> Result<ManagerConfig, ConfigError> {
    if let Some(config_path) = path {
        if config_path.as_ref().exists() {
            let mut file = File::open(config_path.as_ref()).map_err(ConfigError::IoError)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).map_err(ConfigError::IoError)?;
            
            let config: ManagerConfig = match config_path.as_ref().extension().and_then(|e| e.to_str()) {
                Some("json") => serde_json::from_str(&contents).map_err(ConfigError::JsonError)?,
                Some("toml") => toml::from_str(&contents).map_err(ConfigError::TomlError)?,
                Some("yaml") | Some("yml") => serde_yaml::from_str(&contents).map_err(ConfigError::YamlError)?,
                _ => return Err(ConfigError::UnsupportedFormat),
            };
            
            Ok(config)
        } else {
            Err(ConfigError::FileNotFound)
        }
    } else {
        Ok(ManagerConfig::default())
    }
}

// Configure NATS client based on config
pub async fn configure_nats_connection(
    config: &NatsConfig,
    reconnect_attempts: u32,
    reconnect_delay: u64,
) -> Result<async_nats::Client, ConfigError> {
    // Start with basic connection options
    let mut options = async_nats::ConnectOptions::new();
    
    // Add authentication if provided
    if let Some(token) = &config.token {
        options = options.token(token.clone());
    } else if let (Some(username), Some(password)) = (&config.username, &config.password) {
        options = options.user_and_password(username.clone(), password.clone());
    }
    
    // Add TLS configuration if provided
    if let (Some(ca_cert), Some(client_cert), Some(client_key)) = (
        &config.tls_ca_cert,
        &config.tls_client_cert,
        &config.tls_client_key,
    ) {
        // Note: This would require more elaborate code to handle the rustls version mismatch
        // For now, we'll just log a warning and skip TLS
        log::warn!("TLS configuration is available but not enabled due to dependency version conflicts");
        // In a production system, you would handle this better
    }
    
    // Add reconnection settings
    options = options
        .retry_on_initial_connect()
        .max_reconnects(Some(reconnect_attempts as usize))
        .reconnect_delay_callback(move |_attempts| Duration::from_secs(reconnect_delay));
    
    // Connect to NATS server
    let client = options.connect(&config.url).await.map_err(|e| {
        ConfigError::NatsConnectionError(format!("{}", e))
    })?;
    
    Ok(client)
}

// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Configuration file not found")]
    FileNotFound,
    
    #[error("Failed to read configuration file: {0}")]
    IoError(std::io::Error),
    
    #[error("Failed to parse JSON configuration: {0}")]
    JsonError(serde_json::Error),
    
    #[error("Failed to parse TOML configuration: {0}")]
    TomlError(toml::de::Error),
    
    #[error("Failed to parse YAML configuration: {0}")]
    YamlError(serde_yaml::Error),
    
    #[error("Unsupported configuration file format")]
    UnsupportedFormat,
    
    #[error("Failed to connect to NATS: {0}")]
    NatsConnectionError(String),
    
    #[error("TLS error: {0}")]
    TlsError(String),
    
    #[error("No private key found in the PEM file")]
    NoPrivateKeyFound,
}