use crate::api::ManagerInterface;
use crate::common::{
    AgentCommand, AgentHeartbeat, AgentRegistration, AgentInfo, CommandResponse, SecurityAlert, SecurityEvent,
    current_timestamp,
};
use crate::config::{ManagerConfig, configure_nats_connection};
use async_nats::Client as NatsClient;
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use uuid::Uuid;

/// Rule for security event matching and alert generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    /// Rule unique identifier
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Type of events this rule applies to
    pub event_type: String,
    /// Conditions to match in event details
    pub conditions: HashMap<String, String>,
    /// Severity level for alerts (0-10)
    pub severity: u8,
    /// Action to take when rule matches
    pub action: String,
}

/// Manager state for agent and alert management
pub struct Manager {
    /// NATS client for messaging
    nats_client: NatsClient,
    /// Configuration
    config: ManagerConfig,
    /// Known agents and their status
    agents: Arc<RwLock<HashMap<String, AgentInfo>>>,
    /// Security rules
    rules: Arc<RwLock<Vec<SecurityRule>>>,
    /// Generated alerts
    alerts: Arc<Mutex<Vec<SecurityAlert>>>,
}

#[async_trait]
impl ManagerInterface for Manager {
    type Agent = AgentInfo;
    
    /// Get all registered agents
    async fn get_agents(&self) -> Result<Vec<AgentInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let agents = self.agents.read().unwrap();
        let result = agents.values().cloned().collect();
        Ok(result)
    }
    
    /// Get recent alerts
    async fn get_alerts(
        &self,
        limit: usize,
    ) -> Result<Vec<SecurityAlert>, Box<dyn std::error::Error + Send + Sync>> {
        let alerts = self.alerts.lock().unwrap();
        let result = alerts
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(result)
    }
    
    /// Send a command to an agent
    async fn send_command(
        &self,
        agent_id: &str,
        action: &str,
        parameters: HashMap<String, String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Check if agent exists and is active
        {
            let agents = self.agents.read().unwrap();
            if let Some(agent) = agents.get(agent_id) {
                if agent.status != "active" {
                    return Err(format!("Agent {} is not active (status: {})", agent_id, agent.status).into());
                }
            } else {
                return Err(format!("Agent {} not found", agent_id).into());
            }
        }
        
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
        
        info!("Command sent to agent {}: {} (ID: {})", agent_id, action, command_id);
        
        Ok(command_id)
    }
}

impl Manager {
    /// Create a new manager instance
    pub async fn new(config: ManagerConfig) -> Result<Self> {
        // Connect to NATS server
        let nats_client = configure_nats_connection(
            &config.nats,
            config.reconnect_attempts,
            config.reconnect_delay_seconds,
        ).await.context("Failed to connect to NATS server")?;
        
        // Create default rules
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
        
        info!("Manager created with {} default rules", default_rules.len());
        
        Ok(Self {
            nats_client,
            config,
            agents: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(default_rules)),
            alerts: Arc::new(Mutex::new(Vec::new())),
        })
    }
    
    /// Start the manager's main loop
    pub async fn run(&self, mut shutdown_rx: mpsc::Receiver<()>) -> Result<()> {
        // Start listeners
        self.start_registration_listener().await?;
        self.start_heartbeat_listener().await?;
        self.start_event_listener().await?;
        self.start_response_listener().await?;
        self.start_agent_monitor().await?;
        
        info!("Manager started successfully");
        
        // Wait for shutdown signal
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received, terminating manager");
            }
        }
        
        info!("Manager terminating");
        Ok(())
    }
    
    /// Start listener for agent registrations
    async fn start_registration_listener(&self) -> Result<()> {
        let mut registration_sub = self.nats_client.subscribe("security.register").await
            .context("Failed to subscribe to registration subject")?;
        
        let agents = self.agents.clone();
        
        tokio::spawn(async move {
            while let Some(msg) = registration_sub.next().await {
                if let Ok(registration) = serde_json::from_slice::<AgentRegistration>(&msg.payload) {
                    info!("Agent registered: {}", registration.agent_id);
                    
                    let now = current_timestamp();
                    
                    let agent_info = AgentInfo {
                        agent_id: registration.agent_id.clone(),
                        hostname: registration.hostname.clone(),
                        os: registration.os.clone(),
                        ip: registration.ip.clone(),
                        version: registration.version.clone(),
                        last_seen: now,
                        status: "active".to_string(),
                        uptime: 0,
                        capabilities: vec!["file_integrity".to_string()],
                    };
                    
                    let mut agents_write = agents.write().unwrap();
                    agents_write.insert(registration.agent_id.clone(), agent_info);
                    
                    debug!("Currently tracking {} agents", agents_write.len());
                } else {
                    warn!("Received invalid registration message");
                }
            }
        });
        
        Ok(())
    }
    
    /// Start listener for agent heartbeats
    async fn start_heartbeat_listener(&self) -> Result<()> {
        let mut heartbeat_sub = self.nats_client.subscribe("security.heartbeat").await
            .context("Failed to subscribe to heartbeat subject")?;
        
        let agents = self.agents.clone();
        
        tokio::spawn(async move {
            while let Some(msg) = heartbeat_sub.next().await {
                if let Ok(heartbeat) = serde_json::from_slice::<AgentHeartbeat>(&msg.payload) {
                    debug!("Heartbeat from agent: {}", heartbeat.agent_id);
                    
                    let mut agents_write = agents.write().unwrap();
                    
                    if let Some(agent) = agents_write.get_mut(&heartbeat.agent_id) {
                        // Calculate uptime based on previous last_seen
                        let previous_last_seen = agent.last_seen;
                        agent.last_seen = heartbeat.timestamp;
                        agent.status = heartbeat.status.clone();
                        
                        if previous_last_seen > 0 {
                            let uptime_delta = heartbeat.timestamp.saturating_sub(previous_last_seen);
                            agent.uptime += uptime_delta;
                        }
                    } else {
                        // We got a heartbeat from an unknown agent, request registration
                        debug!("Heartbeat from unknown agent: {}", heartbeat.agent_id);
                        // In a production system, we might want to send a command to this agent
                        // to re-register, but we'll skip that for this example
                    }
                } else {
                    warn!("Received invalid heartbeat message");
                }
            }
        });
        
        Ok(())
    }
    
    /// Start listener for security events
    async fn start_event_listener(&self) -> Result<()> {
        let mut event_sub = self.nats_client.subscribe("security.event.*").await
            .context("Failed to subscribe to event subject")?;
        
        let rules = self.rules.clone();
        let alerts = self.alerts.clone();
        let client = self.nats_client.clone();
        let alert_retention = self.config.alert_retention_count;
        
        tokio::spawn(async move {
            while let Some(msg) = event_sub.next().await {
                if let Ok(event) = serde_json::from_slice::<SecurityEvent>(&msg.payload) {
                    info!("Received security event from {}: {} (severity: {})", 
                         event.agent_id, event.description, event.severity);
                    
                    // Check event against rules
                    let triggered_alerts = Self::check_event_against_rules(&event, &rules);
                    
                    // Process each alert separately
                    for alert in triggered_alerts {
                        debug!("Rule triggered: {}", alert.rule_name);
                        
                        // First, store the alert with retention limit
                        {
                            let mut alerts_lock = alerts.lock().unwrap();
                            
                            // Add the new alert
                            alerts_lock.push(alert.clone());
                            
                            // Enforce retention limit
                            if alerts_lock.len() > alert_retention {
                                let new_start = alerts_lock.len().saturating_sub(alert_retention);
                                let mut new_alerts = Vec::new();
                                
                                // Copy the most recent alerts (up to alert_retention count)
                                for i in new_start..alerts_lock.len() {
                                    if let Some(alert) = alerts_lock.get(i) {
                                        new_alerts.push(alert.clone());
                                    }
                                }
                                
                                // Replace the alerts with just the most recent ones
                                *alerts_lock = new_alerts;
                            }
                        }
                        
                        // Then publish it
                        if let Ok(alert_data) = serde_json::to_vec(&alert) {
                            if let Err(e) = client.publish("security.alert", alert_data.into()).await {
                                error!("Failed to publish alert: {}", e);
                            } else {
                                debug!("Alert published: {}", alert.id);
                            }
                        } else {
                            error!("Failed to serialize alert");
                        }
                    }
                } else {
                    warn!("Received invalid security event message");
                }
            }
        });
        
        Ok(())
    }
    
    /// Start listener for command responses
    async fn start_response_listener(&self) -> Result<()> {
        let mut response_sub = self.nats_client.subscribe("security.response.*").await
            .context("Failed to subscribe to response subject")?;
        
        tokio::spawn(async move {
            while let Some(msg) = response_sub.next().await {
                if let Ok(response) = serde_json::from_slice::<CommandResponse>(&msg.payload) {
                    info!("Command response from {}: {} - {}", 
                         response.agent_id, response.status, response.data);
                    
                    // In a production system, we would store command responses and
                    // correlate them with issued commands, notify waiting clients, etc.
                } else {
                    warn!("Received invalid command response message");
                }
            }
        });
        
        Ok(())
    }
    
    /// Start agent monitor to detect inactive agents
    async fn start_agent_monitor(&self) -> Result<()> {
        let agents = self.agents.clone();
        let agent_timeout = self.config.agent_timeout_seconds;
        
        tokio::spawn(async move {
            loop {
                let now = current_timestamp();
                
                // Check agent status periodically
                {
                    let mut agents_write = agents.write().unwrap();
                    
                    for (_, agent) in agents_write.iter_mut() {
                        // If no heartbeat received for more than the configured timeout, mark as inactive
                        if now.saturating_sub(agent.last_seen) > agent_timeout && agent.status != "inactive" {
                            info!("Agent {} marked as inactive (no heartbeat for {} seconds)",
                                 agent.agent_id, now.saturating_sub(agent.last_seen));
                            agent.status = "inactive".to_string();
                            
                            // In a real system, we might want to generate an alert here
                        }
                    }
                }
                
                // Check every 10 seconds
                sleep(Duration::from_secs(10)).await;
            }
        });
        
        Ok(())
    }
    
    /// Check if a security event matches any rules
    fn check_event_against_rules(
        event: &SecurityEvent,
        rules: &Arc<RwLock<Vec<SecurityRule>>>,
    ) -> Vec<SecurityAlert> {
        let rules_read = rules.read().unwrap();
        let mut triggered_alerts = Vec::new();
        
        for rule in rules_read.iter() {
            // Check if event type matches
            if rule.event_type != event.event_type {
                continue;
            }
            
            // Check if conditions match
            let mut match_found = true;
            
            for (key, pattern) in &rule.conditions {
                if let Some(value) = event.details.get(key) {
                    // In a real implementation, use proper regex matching
                    // Here we just use a simple contains check for demonstration
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
                    timestamp: current_timestamp(),
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
    
    /// Add a new security rule
    pub fn add_rule(&self, rule: SecurityRule) -> Result<()> {
        let mut rules_write = self.rules.write().unwrap();
        rules_write.push(rule);
        Ok(())
    }
    
    /// Get a specific agent by ID
    pub fn get_agent(&self, agent_id: &str) -> Option<AgentInfo> {
        let agents_read = self.agents.read().unwrap();
        agents_read.get(agent_id).cloned()
    }
}