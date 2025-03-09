use crate::common::{
    AgentCommand, AgentHeartbeat, AgentRegistration, CommandResponse, FileIntegrityResult, SecurityEvent,
    current_timestamp,
};
use crate::config::{AgentConfig, configure_nats_connection};
use async_nats::Client as NatsClient;
use anyhow::{Context, Result};
use futures::StreamExt;
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::sleep;

// Structure to track monitored file metadata
struct MonitoredFile {
    path: PathBuf,
    hash: String,
    last_check: u64,
    size: u64,
    modified: u64,
}

// Main agent structure
pub struct Agent {
    /// Agent unique identifier
    agent_id: String,
    /// Agent configuration
    config: AgentConfig,
    /// NATS client for messaging
    nats_client: NatsClient,
    /// Files being monitored
    monitored_files: Arc<Mutex<HashMap<String, MonitoredFile>>>,
}

impl Agent {
    /// Create a new agent instance
    pub async fn new(config: AgentConfig) -> Result<Self> {
        // Generate agent ID
        let agent_id = if let Some(custom_id) = &config.custom_id {
            custom_id.clone()
        } else {
            let username = whoami::username();
            // Using hostname() is deprecated but still functional for now
            let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
            let prefix = config.id_prefix.as_deref().unwrap_or("");
            
            if !prefix.is_empty() {
                format!("{}-{}.{}", prefix, username, hostname)
            } else {
                format!("{}.{}", username, hostname)
            }
        };
        
        // Connect to NATS server
        let nats_client = configure_nats_connection(
            &config.nats,
            config.reconnect_attempts,
            config.reconnect_delay_seconds,
        ).await.context("Failed to connect to NATS server")?;
        
        info!("Agent created with ID: {}", agent_id);
        
        Ok(Self {
            agent_id,
            config,
            nats_client,
            monitored_files: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    
    /// Register the agent with the manager
    async fn register(&self) -> Result<()> {
        // Build registration message
        let registration = AgentRegistration {
            agent_id: self.agent_id.clone(),
            hostname: whoami::hostname(),
            os: format!("{:?}", whoami::platform()),
            ip: "127.0.0.1".to_string(), // In a real agent, detect the actual IP
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        
        // Convert to JSON and publish
        let registration_data = serde_json::to_vec(&registration)
            .context("Failed to serialize registration data")?;
        
        self.nats_client.publish("security.register", registration_data.into()).await
            .context("Failed to publish registration message")?;
        
        info!("Agent registered with manager: {}", self.agent_id);
        Ok(())
    }
    
    /// Start command listener to process incoming commands
    async fn start_command_listener(&self) -> Result<()> {
        let command_subject = format!("security.command.{}", self.agent_id);
        let mut command_sub = self.nats_client.subscribe(command_subject).await
            .context("Failed to subscribe to command subject")?;
        
        let client = self.nats_client.clone();
        let agent_id = self.agent_id.clone();
        
        tokio::spawn(async move {
            while let Some(msg) = command_sub.next().await {
                if let Ok(command) = serde_json::from_slice::<AgentCommand>(&msg.payload) {
                    info!("Received command: {} (ID: {})", command.action, command.id);
                    debug!("Command parameters: {:?}", command.parameters);
                    
                    // Process command in a separate task
                    let command_client = client.clone();
                    let command_agent_id = agent_id.clone();
                    
                    tokio::spawn(async move {
                        let response = handle_command(&command, &command_agent_id).await;
                        
                        if let Ok(response_data) = serde_json::to_vec(&response) {
                            let response_subject = format!("security.response.{}", command_agent_id);
                            if let Err(e) = command_client.publish(response_subject, response_data.into()).await {
                                error!("Failed to send command response: {}", e);
                            } else {
                                debug!("Sent response for command ID: {}", command.id);
                            }
                        } else {
                            error!("Failed to serialize command response");
                        }
                    });
                } else {
                    warn!("Received invalid command message");
                }
            }
        });
        
        Ok(())
    }
    
    /// Calculate file hash
    fn calculate_file_hash(path: &Path) -> Result<String> {
        let content = fs::read(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();
        
        Ok(format!("{:x}", hash))
    }
    
    /// Check file integrity for a set of monitored paths
    async fn check_file_integrity(&self) -> Result<Vec<FileIntegrityResult>> {
        let mut results = Vec::new();
        let now = current_timestamp();
        
        for monitored_path in &self.config.file_monitoring.monitored_paths {
            let path = Path::new(&monitored_path.path);
            
            // Skip if path doesn't exist or isn't readable
            if !path.exists() || !path.is_dir() {
                debug!("Monitored path does not exist or is not a directory: {}", path.display());
                continue;
            }
            
            // Process files in this directory
            let mut files_to_check = Vec::new();
            
            if monitored_path.recursive {
                // Collect all files recursively
                for entry in walkdir::WalkDir::new(path)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if entry.file_type().is_file() {
                        files_to_check.push(entry.path().to_path_buf());
                    }
                }
            } else {
                // Collect only files in this directory
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                            files_to_check.push(entry.path());
                        }
                    }
                }
            }
            
            // Process files
            for file_path in files_to_check {
                // Convert to string for comparison and storage
                let file_path_str = file_path.to_string_lossy().to_string();
                
                // Skip excluded paths
                let should_skip = self.config.file_monitoring.excluded_paths.iter()
                    .any(|excluded| file_path_str.contains(excluded));
                
                if should_skip {
                    continue;
                }
                
                // Skip temporary files if configured
                if self.config.file_monitoring.ignore_temp_files {
                    let file_name = file_path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    
                    if file_name.ends_with(".tmp") || file_name.ends_with("~") || file_name.starts_with(".#") {
                        continue;
                    }
                }
                
                // Check file integrity
                self.check_single_file_integrity(&file_path, now, monitored_path.severity_override)
                    .await
                    .map(|result| {
                        if let Some(result) = result {
                            results.push(result);
                        }
                    })
                    .unwrap_or_else(|e| {
                        error!("Error checking file integrity for {}: {}", file_path.display(), e);
                    });
            }
        }
        
        Ok(results)
    }
    
    /// Check integrity of a single file
    async fn check_single_file_integrity(
        &self,
        file_path: &Path,
        now: u64,
        _severity_override: Option<u8>, // Prefix with _ to avoid unused variable warning
    ) -> Result<Option<FileIntegrityResult>> {
        let file_path_str = file_path.to_string_lossy().to_string();
        
        // Get file metadata
        let metadata = fs::metadata(file_path)
            .with_context(|| format!("Failed to get metadata for file: {}", file_path.display()))?;
        
        let modified = metadata.modified()
            .map(|time| time.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
            .unwrap_or(0);
        
        let size = metadata.len();
        
        // Lock for access to monitored files
        let mut monitored_files = self.monitored_files.lock().unwrap();
        
        if let Some(existing) = monitored_files.get(&file_path_str) {
            // File is already monitored, check if changed
            if existing.size != size || existing.modified != modified {
                // Calculate new hash
                match Self::calculate_file_hash(file_path) {
                    Ok(current_hash) => {
                        if existing.hash != current_hash {
                            // File has changed
                            let result = FileIntegrityResult {
                                path: file_path_str.clone(),
                                status: "modified".to_string(),
                                current_hash: Some(current_hash.clone()),
                                previous_hash: Some(existing.hash.clone()),
                                modified_time: now,
                            };
                            
                            // Update stored info
                            monitored_files.insert(file_path_str, MonitoredFile {
                                path: file_path.to_path_buf(),
                                hash: current_hash,
                                last_check: now,
                                size,
                                modified,
                            });
                            
                            return Ok(Some(result));
                        }
                    }
                    Err(e) => {
                        error!("Failed to calculate hash for file {}: {}", file_path.display(), e);
                    }
                }
            }
            
            // Update last_check time even if file hasn't changed
            if let Some(file) = monitored_files.get_mut(&file_path_str) {
                file.last_check = now;
            }
            
            // No changes detected
            Ok(None)
        } else {
            // New file to monitor
            match Self::calculate_file_hash(file_path) {
                Ok(current_hash) => {
                    let result = FileIntegrityResult {
                        path: file_path_str.clone(),
                        status: "created".to_string(),
                        current_hash: Some(current_hash.clone()),
                        previous_hash: None,
                        modified_time: now,
                    };
                    
                    // Store file info
                    monitored_files.insert(file_path_str, MonitoredFile {
                        path: file_path.to_path_buf(),
                        hash: current_hash,
                        last_check: now,
                        size,
                        modified,
                    });
                    
                    Ok(Some(result))
                }
                Err(e) => {
                    error!("Failed to calculate hash for new file {}: {}", file_path.display(), e);
                    Ok(None)
                }
            }
        }
    }
    
    /// Convert file integrity results to security events
    fn convert_to_security_events(&self, results: Vec<FileIntegrityResult>) -> Vec<SecurityEvent> {
        results.into_iter().map(|result| {
            let mut details = HashMap::new();
            details.insert("path".to_string(), result.path.clone());
            details.insert("status".to_string(), result.status.clone());
            
            if let Some(hash) = &result.current_hash {
                details.insert("current_hash".to_string(), hash.clone());
            }
            
            if let Some(hash) = &result.previous_hash {
                details.insert("previous_hash".to_string(), hash.clone());
            }
            
            // Determine severity based on file and change type
            let severity = match result.status.as_str() {
                "deleted" => 8,
                "modified" => {
                    if result.path.contains("shadow") || result.path.contains("passwd") {
                        9
                    } else {
                        6
                    }
                },
                "created" => 5,
                _ => 3,
            };
            
            SecurityEvent {
                agent_id: self.agent_id.clone(),
                timestamp: current_timestamp(),
                event_type: "file_integrity".to_string(),
                severity,
                description: format!("File integrity change detected: {} was {}", result.path, result.status),
                details,
            }
        }).collect()
    }
    
    /// Run integrity checks and send events
    async fn run_integrity_scan(&self) -> Result<()> {
        if !self.config.file_monitoring.enabled {
            debug!("File integrity monitoring is disabled, skipping scan");
            return Ok(());
        }
        
        debug!("Starting file integrity scan");
        let start_time = std::time::Instant::now();
        
        // Run integrity checks
        let integrity_results = self.check_file_integrity().await?;
        
        // If we have results, convert them to events and send
        if !integrity_results.is_empty() {
            info!("Found {} file integrity changes", integrity_results.len());
            let events = self.convert_to_security_events(integrity_results);
            
            // Send each event
            for event in events {
                self.send_security_event(&event).await
                    .with_context(|| format!("Failed to send security event for {}", event.details.get("path").unwrap_or(&"unknown".to_string())))?;
            }
        } else {
            debug!("No file integrity changes detected");
        }
        
        debug!("File integrity scan completed in {:?}", start_time.elapsed());
        Ok(())
    }
    
    /// Send a security event to the manager
    async fn send_security_event(&self, event: &SecurityEvent) -> Result<()> {
        let event_data = serde_json::to_vec(event)
            .context("Failed to serialize security event")?;
        
        let event_subject = format!("security.event.{}", self.agent_id);
        self.nats_client.publish(event_subject, event_data.into()).await
            .context("Failed to publish security event")?;
        
        debug!("Security event sent: {} (severity {})", event.description, event.severity);
        Ok(())
    }
    
    /// Send heartbeat to manager
    async fn send_heartbeat(&self) -> Result<()> {
        let heartbeat = AgentHeartbeat {
            agent_id: self.agent_id.clone(),
            timestamp: current_timestamp(),
            status: "active".to_string()
        };
        
        let heartbeat_data = serde_json::to_vec(&heartbeat)
            .context("Failed to serialize heartbeat")?;
        
        self.nats_client.publish("security.heartbeat", heartbeat_data.into()).await
            .context("Failed to publish heartbeat")?;
        
        debug!("Heartbeat sent");
        Ok(())
    }
    
    /// Run the agent's main loop
    pub async fn run(&mut self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
        // Register with the manager
        self.register().await?;
        
        // Start command listener
        self.start_command_listener().await?;
        
        // Initialize last scan and heartbeat times
        let mut last_scan_time = std::time::Instant::now();
        let mut last_heartbeat_time = std::time::Instant::now();
        
        let scan_interval = Duration::from_secs(self.config.scan_interval_seconds);
        let heartbeat_interval = Duration::from_secs(self.config.heartbeat_interval_seconds);
        
        // Main agent loop
        loop {
            // Check for shutdown signal
            if let Ok(()) = shutdown_rx.try_recv() {
                info!("Shutdown signal received, terminating agent");
                break;
            }
            
            // Send heartbeat if interval elapsed
            if last_heartbeat_time.elapsed() >= heartbeat_interval {
                if let Err(e) = self.send_heartbeat().await {
                    warn!("Failed to send heartbeat: {}", e);
                }
                last_heartbeat_time = std::time::Instant::now();
            }
            
            // Run integrity scan if interval elapsed
            if last_scan_time.elapsed() >= scan_interval {
                if let Err(e) = self.run_integrity_scan().await {
                    error!("Failed to run integrity scan: {}", e);
                }
                last_scan_time = std::time::Instant::now();
            }
            
            // Sleep a bit to avoid tight loop
            tokio::select! {
                _ = sleep(Duration::from_millis(100)) => {}
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received, terminating agent");
                    break;
                }
            }
        }
        
        info!("Agent terminating");
        Ok(())
    }
}

// Handle command execution
async fn handle_command(command: &AgentCommand, agent_id: &str) -> CommandResponse {
    match command.action.as_str() {
        "exec" => {
            if let Some(cmd) = command.parameters.get("command") {
                // Validate command before execution
                if !is_command_allowed(cmd) {
                    return CommandResponse {
                        command_id: command.id.clone(),
                        agent_id: agent_id.to_string(),
                        status: "error".to_string(),
                        data: "Command not allowed for security reasons".to_string(),
                    };
                }
                
                match execute_command(cmd).await {
                    Ok(output) => CommandResponse {
                        command_id: command.id.clone(),
                        agent_id: agent_id.to_string(),
                        status: "success".to_string(),
                        data: output,
                    },
                    Err(e) => CommandResponse {
                        command_id: command.id.clone(),
                        agent_id: agent_id.to_string(),
                        status: "error".to_string(),
                        data: e.to_string(),
                    },
                }
            } else {
                CommandResponse {
                    command_id: command.id.clone(),
                    agent_id: agent_id.to_string(),
                    status: "error".to_string(),
                    data: "No command parameter provided".to_string(),
                }
            }
        },
        "scan" => {
            // Trigger an immediate scan - this is just a success response
            // The actual scan would be triggered in the main loop
            CommandResponse {
                command_id: command.id.clone(),
                agent_id: agent_id.to_string(),
                status: "success".to_string(),
                data: "Scan initiated".to_string(),
            }
        },
        "get_config" => {
            // Return agent configuration
            let config = serde_json::json!({
                "agent_id": agent_id,
                "scan_interval": 300,
                "monitored_paths": ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/ssh/sshd_config"],
                "log_paths": ["/var/log/syslog", "/var/log/auth.log", "/var/log/secure"]
            });
            
            CommandResponse {
                command_id: command.id.clone(),
                agent_id: agent_id.to_string(),
                status: "success".to_string(),
                data: config.to_string(),
            }
        },
        _ => CommandResponse {
            command_id: command.id.clone(),
            agent_id: agent_id.to_string(),
            status: "error".to_string(),
            data: format!("Unknown command: {}", command.action),
        },
    }
}

/// Validate if a command is allowed to execute
fn is_command_allowed(cmd: &str) -> bool {
    // Blocked commands that could be harmful or leak sensitive info
    let blocked_commands = [
        "rm -rf", "mkfs", "dd if=/dev/", ":(){ :|:& };:", "wget", "curl -o",
        ">", ">>", "chmod 777", "passwd", "/dev/null", "shutdown", "reboot",
    ];
    
    // Check if command contains any blocked patterns
    for blocked in &blocked_commands {
        if cmd.contains(blocked) {
            warn!("Blocked potentially harmful command: {}", cmd);
            return false;
        }
    }
    
    true
}

/// Execute system command securely
async fn execute_command(cmd: &str) -> Result<String> {
    // Set execution timeout
    let timeout = Duration::from_secs(30);
    
    // Execute with appropriate shell based on OS
    let future = async {
        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(&["/C", cmd])
                .output()?
        } else {
            Command::new("sh")
                .args(&["-c", cmd])
                .output()?
        };
        
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(anyhow::anyhow!("Command failed: {}", 
                String::from_utf8_lossy(&output.stderr).trim()))
        }
    };
    
    // Execute with timeout
    tokio::time::timeout(timeout, future).await
        .context("Command execution timed out")?
}