// Security Monitoring Manager
//
// This manager performs the following functions:
// - Receives and processes security events from agents
// - Maintains agent statuses and configurations
// - Sends commands to agents
// - Provides an API for monitoring and administration

use async_nats::ConnectOptions;
use futures::StreamExt;
use crate::common::{
    AgentCommand, AgentHeartbeat, AgentRegistration, CommandResponse, SecurityAlert, SecurityEvent
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::task;
use tokio::time::sleep;
use uuid::Uuid;

// Agent status tracking
#[derive(Debug, Clone, Serialize)]
struct AgentStatus {
    agent_id: String,
    hostname: String,
    os: String,
    ip: String,
    version: String,
    last_seen: u64,
    status: String,
}

// Rule for event matching and alerting
#[derive(Debug, Clone)]
struct SecurityRule {
    id: String,
    name: String,
    description: String,
    event_type: String,
    conditions: HashMap<String, String>,
    severity: u8,
    action: String,
}

// Manager struct to coordinate everything
struct SecurityManager {
    nats_client: async_nats::Client,
    agents: Arc<Mutex<HashMap<String, AgentStatus>>>,
    rules: Arc<Mutex<Vec<SecurityRule>>>,
    alerts: Arc<Mutex<Vec<SecurityAlert>>>,
}

impl SecurityManager {
    // Initialize a new manager
    async fn new(nats_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Connect to NATS server
        let client = ConnectOptions::new().connect(nats_url).await?;
        
        // Initialize with default rules
        let mut default_rules = Vec::new();
        
        // Rule for detecting file integrity changes in sensitive files
        let mut sensitive_file_conditions = HashMap::new();
        sensitive_file_conditions.insert("path".to_string(), ".*passwd|.*shadow".to_string());
        sensitive_file_conditions.insert("status".to_string(), "modified|deleted".to_string());
        
        default_rules.push(SecurityRule {
            id: Uuid::new_v4().to_string(),
            name: "Sensitive File Modified".to_string(),
            description: "Critical system file was modified or deleted".to_string(),
            event_type: "file_integrity".to_string(),
            conditions: sensitive_file_conditions,
            severity: 9,
            action: "alert".to_string(),
        });
        
        // Rule for detecting SSH configuration changes
        let mut ssh_config_conditions = HashMap::new();
        ssh_config_conditions.insert("path".to_string(), ".*sshd_config".to_string());
        ssh_config_conditions.insert("status".to_string(), "modified".to_string());
        
        default_rules.push(SecurityRule {
            id: Uuid::new_v4().to_string(),
            name: "SSH Configuration Changed".to_string(),
            description: "SSH server configuration was modified".to_string(),
            event_type: "file_integrity".to_string(),
            conditions: ssh_config_conditions,
            severity: 7,
            action: "alert".to_string(),
        });
        
        Ok(SecurityManager {
            nats_client: client,
            agents: Arc::new(Mutex::new(HashMap::new())),
            rules: Arc::new(Mutex::new(default_rules)),
            alerts: Arc::new(Mutex::new(Vec::new())),
        })
    }

    // Start the manager services
    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Subscribe to agent registrations
        self.start_registration_listener().await?;
        
        // Subscribe to agent heartbeats
        self.start_heartbeat_listener().await?;
        
        // Subscribe to security events
        self.start_event_listener().await?;
        
        // Subscribe to command responses
        self.start_response_listener().await?;
        
        // Start agent status monitor (check for inactive agents)
        self.start_agent_monitor().await?;
        
        println!("Security manager started successfully");
        
        // Keep the manager running
        loop {
            sleep(Duration::from_secs(60)).await;
        }
    }

    // Start listener for agent registrations
    async fn start_registration_listener(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut registration_sub = self.nats_client.subscribe("security.register").await?;
        
        let agents = self.agents.clone();
        
        tokio::spawn(async move {
            while let Some(msg) = registration_sub.next().await {
                if let Ok(registration) = serde_json::from_slice::<AgentRegistration>(&msg.payload) {
                    println!("Agent registered: {}", registration.agent_id);
                    
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs();
                    
                    let agent_status = AgentStatus {
                        agent_id: registration.agent_id.clone(),
                        hostname: registration.hostname.clone(),
                        os: registration.os.clone(),
                        ip: registration.ip.clone(),
                        version: registration.version.clone(),
                        last_seen: now,
                        status: "active".to_string(),
                    };
                    
                    let mut agents_lock = agents.lock().unwrap();
                    agents_lock.insert(registration.agent_id.clone(), agent_status);
                }
            }
        });
        
        Ok(())
    }

    // Start listener for agent heartbeats
    async fn start_heartbeat_listener(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut heartbeat_sub = self.nats_client.subscribe("security.heartbeat").await?;
        
        let agents = self.agents.clone();
        
        tokio::spawn(async move {
            while let Some(msg) = heartbeat_sub.next().await {
                if let Ok(heartbeat) = serde_json::from_slice::<AgentHeartbeat>(&msg.payload) {
                    let mut agents_lock = agents.lock().unwrap();
                    
                    if let Some(agent) = agents_lock.get_mut(&heartbeat.agent_id) {
                        agent.last_seen = heartbeat.timestamp;
                        agent.status = heartbeat.status.clone();
                    }
                    // MutexGuard dropped here
                }
            }
        });
        
        Ok(())
    }

    // Start listener for security events
    async fn start_event_listener(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut event_sub = self.nats_client.subscribe("security.event.*").await?;
        
        let rules = self.rules.clone();
        let alerts = self.alerts.clone();
        let client = self.nats_client.clone();
        
        tokio::spawn(async move {
            while let Some(msg) = event_sub.next().await {
                if let Ok(event) = serde_json::from_slice::<SecurityEvent>(&msg.payload) {
                    println!("Received security event from {}: {}", event.agent_id, event.description);
                    
                    // Check event against rules
                    let triggered_alerts = check_event_against_rules(&event, &rules);
                    
                    // Process each alert separately to avoid holding mutex during await
                    for alert in triggered_alerts {
                        // First, store the alert
                        {
                            let mut alerts_lock = alerts.lock().unwrap();
                            alerts_lock.push(alert.clone());
                        } // alerts_lock is dropped here
                        
                        // Then publish it (with await)
                        if let Ok(alert_data) = serde_json::to_vec(&alert) {
                            if let Err(e) = client.publish("security.alert", alert_data.into()).await {
                                eprintln!("Failed to publish alert: {}", e);
                            }
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    // Start listener for command responses
    async fn start_response_listener(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut response_sub = self.nats_client.subscribe("security.response.*").await?;
        
        tokio::spawn(async move {
            while let Some(msg) = response_sub.next().await {
                if let Ok(response) = serde_json::from_slice::<CommandResponse>(&msg.payload) {
                    println!("Received command response from {}: {} - {}", 
                        response.agent_id, response.status, response.data);
                    
                    // In a real system, you would store responses and correlate with commands
                }
            }
        });
        
        Ok(())
    }

    // Start agent monitor to detect inactive agents
    async fn start_agent_monitor(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let agents = self.agents.clone();
        
        tokio::spawn(async move {
            loop {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();
                
                // Scope the MutexGuard to avoid holding it across await points
                {
                    let mut agents_lock = agents.lock().unwrap();
                    
                    for (_, agent) in agents_lock.iter_mut() {
                        // If no heartbeat received for more than 5 minutes, mark as inactive
                        if now - agent.last_seen > 300 && agent.status != "inactive" {
                            println!("Agent {} marked as inactive", agent.agent_id);
                            agent.status = "inactive".to_string();
                            
                            // In a real system, you might want to generate an alert here
                        }
                    }
                } // MutexGuard is dropped here before the await point
                
                sleep(Duration::from_secs(60)).await;
            }
        });
        
        Ok(())
    }

    // Send command to specific agent
    async fn send_command_to_agent(&self, agent_id: &str, action: &str, 
                                   parameters: HashMap<String, String>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Generate command ID
        let command_id = Uuid::new_v4().to_string();
        
        let command = AgentCommand {
            action: action.to_string(),
            parameters,
            id: command_id.clone(),
        };
        
        let command_data = serde_json::to_vec(&command)?;
        let command_subject = format!("security.command.{}", agent_id);
        
        self.nats_client.publish(command_subject, command_data.into()).await?;
        
        println!("Command sent to agent {}: {} (ID: {})", agent_id, action, command_id);
        
        Ok(command_id)
    }

    // Get agent statuses
    fn get_agent_statuses(&self) -> Vec<AgentStatus> {
        let agents_lock = self.agents.lock().unwrap();
        agents_lock.values().cloned().collect()
    }

    // Get recent alerts
    fn get_recent_alerts(&self, limit: usize) -> Vec<SecurityAlert> {
        let alerts_lock = self.alerts.lock().unwrap();
        alerts_lock.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    // Add a new security rule
    fn add_rule(&self, rule: SecurityRule) {
        let mut rules_lock = self.rules.lock().unwrap();
        rules_lock.push(rule);
    }
}

// Check if a security event matches any rules
fn check_event_against_rules(event: &SecurityEvent, 
                            rules: &Arc<Mutex<Vec<SecurityRule>>>) -> Vec<SecurityAlert> {
    let rules_lock = rules.lock().unwrap();
    let mut triggered_alerts = Vec::new();
    
    for rule in rules_lock.iter() {
        // Check if event type matches
        if rule.event_type != event.event_type {
            continue;
        }
        
        // Check if conditions match
        let mut match_found = true;
        
        for (key, pattern) in &rule.conditions {
            if let Some(value) = event.details.get(key) {
                // In a real implementation, use proper regex matching
                if !value.contains(pattern) {
                    match_found = false;
                    break;
                }
            } else {
                match_found = false;
                break;
            }
        }
        
        if match_found {
            // Create alert
            let alert = SecurityAlert {
                id: Uuid::new_v4().to_string(),
                timestamp: event.timestamp,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                agent_id: event.agent_id.clone(),
                event_type: event.event_type.clone(),
                severity: rule.severity,
                description: format!("{}: {}", rule.name, event.description),
                details: event.details.clone(),
            };
            
            triggered_alerts.push(alert);
        }
    }
    
    triggered_alerts
}

// Example REST API handler (simplified)
async fn handle_api_request(manager: Arc<SecurityManager>, request: &str) -> String {
    match request {
        "get_agents" => {
            let agents = manager.get_agent_statuses();
            serde_json::to_string(&agents).unwrap_or_else(|_| "Error serializing agents".to_string())
        },
        "get_alerts" => {
            let alerts = manager.get_recent_alerts(100);
            serde_json::to_string(&alerts).unwrap_or_else(|_| "Error serializing alerts".to_string())
        },
        _ if request.starts_with("send_command:") => {
            let parts: Vec<&str> = request.split(':').collect();
            if parts.len() >= 3 {
                let agent_id = parts[1];
                let action = parts[2];
                
                let mut parameters = HashMap::new();
                if parts.len() >= 4 {
                    parameters.insert("command".to_string(), parts[3].to_string());
                }
                
                match manager.send_command_to_agent(agent_id, action, parameters).await {
                    Ok(command_id) => format!("Command sent successfully, ID: {}", command_id),
                    Err(e) => format!("Error sending command: {}", e),
                }
            } else {
                "Invalid command format".to_string()
            }
        },
        _ => "Unknown request".to_string(),
    }
}

// Simple "web server" to handle API requests (for demonstration)
async fn simple_api_server(manager: Arc<SecurityManager>) {
    loop {
        // In a real implementation, this would be a proper web framework like warp or actix-web
        // For demonstration, we'll just handle a few hardcoded requests
        
        println!("\nAvailable commands:");
        println!("1. get_agents");
        println!("2. get_alerts");
        println!("3. send_command:<agent_id>:exec:ls -la");
        println!("4. send_command:<agent_id>:scan");
        println!("5. exit");
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();
        
        if input == "exit" {
            break;
        }
        
        let response = handle_api_request(manager.clone(), input).await;
        println!("Response: {}", response);
    }
}

mod common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get NATS URL from environment or use default
    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    
    // Create manager
    let manager = Arc::new(SecurityManager::new(&nats_url).await?);
    
    // Start manager services
    let manager_clone = manager.clone();
    let manager_task = task::spawn(async move {
        if let Err(e) = manager_clone.start().await {
            eprintln!("Manager error: {}", e);
        }
    });
    
    // Start API server
    let api_task = task::spawn(async move {
        simple_api_server(manager).await
    });
    
    // Wait for both tasks to complete
    let _ = tokio::try_join!(manager_task, api_task);
    
    Ok(())
}