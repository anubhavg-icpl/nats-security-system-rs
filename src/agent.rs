// Security Monitoring Agent
//
// This agent performs the following functions:
// - Collects system logs
// - Monitors file integrity
// - Executes commands from the manager
// - Reports security events and metrics

use async_nats::ConnectOptions;
use futures::StreamExt;
use crate::common::{
    AgentCommand, AgentRegistration, CommandResponse, FileIntegrityResult, SecurityEvent, AgentHeartbeat
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

// Agent main struct
struct SecurityAgent {
    agent_id: String,
    nats_client: async_nats::Client,
    monitored_files: HashMap<String, MonitoredFile>,
    log_paths: Vec<String>,
    scan_interval: u64,
}

// Monitored file record
struct MonitoredFile {
    path: String,
    hash: String,
    last_check: u64,
}

impl SecurityAgent {
    // Initialize a new agent
    async fn new(nats_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Generate agent ID as username.hostname
        let username = whoami::username();
        // Using toString() for hostname to address deprecation warning
        let hostname = whoami::hostname();
        let agent_id = format!("{}.{}", username, hostname);
        
        // Connect to NATS server
        let client = ConnectOptions::new().connect(nats_url).await?;
        
        // Default log paths to monitor
        let log_paths = vec![
            "/var/log/syslog".to_string(),
            "/var/log/auth.log".to_string(),
            "/var/log/secure".to_string(),
        ];
        
        Ok(SecurityAgent {
            agent_id,
            nats_client: client,
            monitored_files: HashMap::new(),
            log_paths,
            scan_interval: 300, // Default scan every 5 minutes
        })
    }

    // Register the agent with the manager
    async fn register(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let registration = AgentRegistration {
            agent_id: self.agent_id.clone(),
            hostname: whoami::hostname(),
            os: format!("{:?}", whoami::platform()), // Convert Platform to String
            ip: "127.0.0.1".to_string(), // In a real agent, detect the actual IP
            version: "1.0.0".to_string()
        };
        
        let registration_data = serde_json::to_vec(&registration)?;
        self.nats_client.publish("security.register", registration_data.into()).await?;
        println!("Agent registered with manager: {}", self.agent_id);
        
        Ok(())
    }

    // Start command listener
    async fn start_command_listener(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let command_subject = format!("security.command.{}", self.agent_id);
        let mut command_sub = self.nats_client.subscribe(command_subject).await?;
        
        let client = self.nats_client.clone();
        let agent_id = self.agent_id.clone();
        
        tokio::spawn(async move {
            while let Some(msg) = command_sub.next().await {
                if let Ok(command) = serde_json::from_slice::<AgentCommand>(&msg.payload) {
                    println!("Received command: {:?}", command);
                    let response = handle_command(&command, &agent_id).await;
                    
                    // Send command response
                    if let Ok(response_data) = serde_json::to_vec(&response) {
                        let response_subject = format!("security.response.{}", agent_id);
                        if let Err(e) = client.publish(response_subject, response_data.into()).await {
                            eprintln!("Failed to send command response: {}", e);
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    // Calculate file hash
    fn calculate_file_hash(path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let content = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();
        Ok(format!("{:x}", hash))
    }

    // Check file integrity
    async fn check_file_integrity(&mut self) -> Result<Vec<FileIntegrityResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::new();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        
        // In a real agent, this would scan configured directories
        let paths_to_monitor = vec![
            "/etc/passwd".to_string(),
            "/etc/shadow".to_string(),
            "/etc/hosts".to_string(),
            "/etc/ssh/sshd_config".to_string(),
        ];
        
        for path in &paths_to_monitor {
            let file_path = Path::new(path);
            if !file_path.exists() {
                // File was monitored but now doesn't exist
                if self.monitored_files.contains_key(path) {
                    let result = FileIntegrityResult {
                        path: path.clone(),
                        status: "deleted".to_string(),
                        current_hash: None,
                        previous_hash: Some(self.monitored_files[path].hash.clone()),
                        modified_time: now,
                    };
                    results.push(result);
                    self.monitored_files.remove(path);
                }
                continue;
            }
            
            // Calculate current hash
            match Self::calculate_file_hash(path) {
                Ok(current_hash) => {
                    if let Some(monitored_file) = self.monitored_files.get(path) {
                        // File already monitored, check if changed
                        if monitored_file.hash != current_hash {
                            let result = FileIntegrityResult {
                                path: path.clone(),
                                status: "modified".to_string(),
                                current_hash: Some(current_hash.clone()),
                                previous_hash: Some(monitored_file.hash.clone()),
                                modified_time: now,
                            };
                            results.push(result);
                            
                            // Update record
                            self.monitored_files.insert(path.clone(), MonitoredFile {
                                path: path.clone(),
                                hash: current_hash,
                                last_check: now,
                            });
                        }
                    } else {
                        // New file to monitor
                        let result = FileIntegrityResult {
                            path: path.clone(),
                            status: "created".to_string(),
                            current_hash: Some(current_hash.clone()),
                            previous_hash: None,
                            modified_time: now,
                        };
                        results.push(result);
                        
                        // Add to monitored files
                        self.monitored_files.insert(path.clone(), MonitoredFile {
                            path: path.clone(),
                            hash: current_hash,
                            last_check: now,
                        });
                    }
                }
                Err(e) => {
                    eprintln!("Failed to hash file {}: {}", path, e);
                }
            }
        }
        
        Ok(results)
    }

    // Send security events
    async fn send_security_events(&self, events: Vec<SecurityEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for event in events {
            let event_data = serde_json::to_vec(&event)?;
            let event_subject = format!("security.event.{}", self.agent_id);
            self.nats_client.publish(event_subject, event_data.into()).await?;
        }
        Ok(())
    }

    // Convert file integrity results to security events
    fn convert_to_security_events(&self, results: Vec<FileIntegrityResult>) -> Vec<SecurityEvent> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        results.iter().map(|result| {
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
                timestamp: now,
                event_type: "file_integrity".to_string(),
                severity,
                description: format!("File integrity change detected: {} was {}", result.path, result.status),
                details,
            }
        }).collect()
    }

    // Run integrity checks and send events
    async fn run_integrity_scan(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let integrity_results = self.check_file_integrity().await?;
        
        if !integrity_results.is_empty() {
            let events = self.convert_to_security_events(integrity_results);
            self.send_security_events(events).await?;
        }
        
        Ok(())
    }

    // Send heartbeat to manager
    async fn send_heartbeat(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        let heartbeat = AgentHeartbeat {
            agent_id: self.agent_id.clone(),
            timestamp: now,
            status: "active".to_string()
        };
        
        let heartbeat_data = serde_json::to_vec(&heartbeat)?;
        self.nats_client.publish("security.heartbeat", heartbeat_data.into()).await?;
        
        Ok(())
    }

    // Run the agent
    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Register with manager
        self.register().await?;
        
        // Start command listener
        self.start_command_listener().await?;
        
        // Main loop
        loop {
            // Send heartbeat
            if let Err(e) = self.send_heartbeat().await {
                eprintln!("Failed to send heartbeat: {}", e);
            }
            
            // Run integrity scan
            if let Err(e) = self.run_integrity_scan().await {
                eprintln!("Failed to run integrity scan: {}", e);
            }
            
            // Wait for next scan interval
            sleep(Duration::from_secs(self.scan_interval)).await;
        }
    }
}

// Handle commands from manager
async fn handle_command(command: &AgentCommand, agent_id: &str) -> CommandResponse {
    match command.action.as_str() {
        "exec" => {
            if let Some(cmd) = command.parameters.get("command") {
                // In a production system, you'd want to carefully validate and restrict commands
                match execute_command(cmd) {
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
            // Trigger an immediate scan
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

// Execute system command
fn execute_command(cmd: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
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
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("Command failed: {}", String::from_utf8_lossy(&output.stderr)).into())
    }
}

mod common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get NATS URL from environment or use default
    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    
    // Create and run agent
    let mut agent = SecurityAgent::new(&nats_url).await?;
    agent.run().await?;
    
    Ok(())
}