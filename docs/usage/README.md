# NATS Security System - Complete User Guide

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running the System](#running-the-system)
5. [Verifying the System](#verifying-the-system)
6. [Using the API](#using-the-api)
7. [Troubleshooting](#troubleshooting)

## Overview

This NATS-based security monitoring system provides real-time security monitoring for distributed systems. It consists of two main components:

- **Security Agent**: Runs on endpoints to monitor file integrity and execute commands
- **Security Manager**: Central server that processes events, manages agents, and provides an API

The system uses NATS as the messaging backbone for efficient communication between components.

## Installation

### Prerequisites
- Rust and Cargo installed
- [NATS Server](https://docs.nats.io/running-a-nats-service/introduction/installation)

### Installation Steps
1. Clone the repository
```bash
git clone https://github.com/yourusername/nats-security-system.git
cd nats-security-system
```

2. Build the project
```bash
cargo build --release
```

## Configuration

The system uses configuration files for both the agent and manager. Default configurations are provided, but you can customize them:

### Creating Configuration Files

#### Agent Configuration (agent-config.toml)
```toml
# NATS connection settings
[nats]
url = "nats://localhost:4222"

# File monitoring settings
[file_monitoring]
enabled = true
monitored_paths = [
    { path = "/etc", recursive = false, severity_override = 5 }
]
excluded_paths = ["/etc/mtab", "/etc/resolv.conf"]
ignore_temp_files = true

# Operational settings
scan_interval_seconds = 300
heartbeat_interval_seconds = 60
```

#### Manager Configuration (manager-config.toml)
```toml
# NATS connection settings
[nats]
url = "nats://localhost:4222"

# API settings
api_bind_address = "127.0.0.1"
api_port = 8080
admin_token = "your-secure-token-here"  # Set this to a secure random string

# Agent monitoring settings
agent_timeout_seconds = 300
alert_retention_count = 1000
```

## Running the System

### 1. Start the NATS Server
```bash
nats-server
```

### 2. Start the Security Manager
```bash
# Using default configuration
cargo run --bin security-manager

# Using custom configuration
cargo run --bin security-manager -- --config manager-config.toml
```

### 3. Start the Security Agent
```bash
# Using default configuration
cargo run --bin security-agent

# Using custom configuration
cargo run --bin security-agent -- --config agent-config.toml
```

## Verifying the System

You can verify the system is working through several methods:

### 1. Check Agent Registration

When an agent starts, it should register with the manager. You should see a log message in the manager output:
```
INFO nats_security_system::manager - Agent registered: [agent-id]
```

### 2. Triggering File Integrity Event

Create a test file in a monitored directory:
```bash
sudo touch /etc/test-security-file
sudo rm /etc/test-security-file
```

The agent should detect the creation and deletion, sending events to the manager.

### 3. Send Test Command to Agent

Use the API to send a command to an agent:
```bash
# Replace [agent-id] with the actual agent ID from the logs
# Replace [admin-token] with your token

curl -X POST http://localhost:8080/api/agents/[agent-id]/command \
  -H "Authorization: Bearer [admin-token]" \
  -H "Content-Type: application/json" \
  -d '{"action":"exec","parameters":{"command":"ls -la"}}'
```

## Using the API

The manager provides a REST API for interacting with the system.

### Getting the API Token

The API token is generated automatically when the manager starts. You can find it in two ways:

1. **From the configuration file**: If you specified an `admin_token` in the manager config file, use that value.

2. **From the manager logs**: Look for a line similar to:
```
DEBUG nats_security_system::manager - API token generated: [token]
```

If you're using the default configuration, a random token is generated each time. To get this token, modify the `src/bin/manager.rs` file to print it:

```rust
// Add at the beginning of the main function in src/bin/manager.rs
// After loading the configuration:
info!("API Token: {}", config.admin_token);
```

Then rebuild and run the manager:
```bash
cargo build --bin security-manager
cargo run --bin security-manager
```

Look for the token in the log output.

### API Endpoints

All API requests (except health check) require the Bearer token in the Authorization header:

```
Authorization: Bearer [your-token]
```

#### GET /api/health
Health check endpoint (no authentication required)

#### GET /api/agents
List all registered agents

```bash
curl -X GET http://localhost:8080/api/agents \
  -H "Authorization: Bearer [your-token]"
```

#### GET /api/alerts
List recent security alerts

```bash
curl -X GET http://localhost:8080/api/alerts?limit=50 \
  -H "Authorization: Bearer [your-token]"
```

#### POST /api/agents/{agent_id}/command
Send a command to an agent

```bash
curl -X POST http://localhost:8080/api/agents/[agent-id]/command \
  -H "Authorization: Bearer [your-token]" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "exec",
    "parameters": {
      "command": "ls -la"
    }
  }'
```

## Troubleshooting

### Common Issues

#### NATS Connection Error
Ensure the NATS server is running and accessible:
```bash
telnet localhost 4222
```

#### Permission Issues with File Monitoring
For monitoring system files, the agent must run with appropriate permissions:
```bash
sudo cargo run --bin security-agent
```

#### API Connection Refused
Check that the manager is running and the API server is bound to the correct address:
```bash
curl http://localhost:8080/api/health
```

If you need to access the API from other machines, set the `api_bind_address` to "0.0.0.0" in the manager configuration.

### Logging

Both the agent and manager support file-based logging:

```bash
SECURITY_AGENT_LOG_FILE=/var/log/security-agent.log cargo run --bin security-agent
SECURITY_MANAGER_LOG_FILE=/var/log/security-manager.log cargo run --bin security-manager
```

You can set the log level in the code or modify the `init_logging` call to use a different level.

---

## Quick Start Guide for Testing

To quickly verify your system is working properly:

1. **Start all components**:
   ```bash
   # Terminal 1
   nats-server
   
   # Terminal 2
   cargo run --bin security-manager
   
   # Terminal 3
   cargo run --bin security-agent
   ```

2. **Check agent registration**:
   - Look for "Agent registered" message in the manager logs

3. **Get the API token**:
   - Modify src/bin/manager.rs to print the token as described above
   - Or set a fixed token in a config file

4. **Test the API**:
   ```bash
   # Get agent list
   curl -X GET http://localhost:8080/api/agents \
     -H "Authorization: Bearer [your-token]"
   
   # Send a command to the agent
   curl -X POST http://localhost:8080/api/agents/[agent-id]/command \
     -H "Authorization: Bearer [your-token]" \
     -H "Content-Type: application/json" \
     -d '{"action":"exec","parameters":{"command":"echo Hello"}}'
   ```

5. **Check agent output**:
   - Look for "Received command" in the agent logs
   - Look for "Command response" in the manager logs

That's it! Your system is working correctly if all these steps succeed.