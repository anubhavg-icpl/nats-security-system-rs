# NATS Security Monitoring System

## Overview

The NATS Security Monitoring System is a comprehensive security monitoring solution that leverages the NATS messaging system for communication between agents and the manager. It is designed to monitor system integrity, detect security events, and generate alerts based on predefined rules.

## Features

- **Agent Monitoring**: Monitors system files, logs, and other resources for changes.
- **Event Propagation**: Detects security events and propagates them to the manager.
- **Rule-Based Alerting**: Generates alerts based on customizable security rules.
- **API Server**: Provides RESTful API endpoints for managing agents and retrieving alerts.
- **External Integrations**: Integrates with SIEM systems, notification systems, and incident response tools.

## Architecture

The system consists of the following components:

1. **Security Agent**: Monitors the system and reports security events.
2. **Security Manager**: Processes security events, applies rules, and generates alerts.
3. **NATS Server**: Facilitates communication between agents and the manager.
4. **API Server**: Provides endpoints for managing agents and retrieving alerts.
5. **External Integrations**: Interfaces with external systems for further processing and notifications.

## Diagrams

### Architecture Diagrams

1. **System Architecture Overview**
2. **Component Diagram**
3. **Deployment Architecture Diagram**
4. **Network Flow Diagram**

### Communication Flow Diagrams

5. **Agent-Manager Communication Flow**
6. **NATS Message Structure and Topics**
7. **Security Event Propagation Flow**

### Sequence Diagrams

8. **Agent Registration and Heartbeat**
9. **Command Execution Flow**
10. **File Integrity Monitoring Process**
11. **Rule-Based Alert Generation**
12. **API Request Handling**

### State Diagrams

13. **Agent Lifecycle States**
14. **Security Event Processing States**
15. **File Monitoring State Machine**

### Entity Relationship Diagrams

16. **Data Model Overview**

### Process Diagrams

17. **Security Rule Evaluation Process**
18. **Agent Monitoring Process**

## Configuration

### Agent Configuration

The agent configuration file (`agent-config.toml`) includes settings for identity, NATS connection, file monitoring, and operational parameters.

### Manager Configuration

The manager configuration file (`manager-config.toml`) includes settings for NATS connection, API server, agent monitoring, and operational parameters.

### Example Configuration Files

Example configuration files are provided in the `config` directory.

## Usage

### Running the NATS Server

Start a NATS server:

```sh
nats-server
```

### Running the Security Manager

Start the security manager:

```sh
cargo run --bin security-manager --config /path/to/manager-config.toml
```

### Running the Security Agent

Start one or more security agents:

```sh
cargo run --bin security-agent --config /path/to/agent-config.toml
```

### API Endpoints

The API server provides the following endpoints:

- `GET /api/health`: Health check endpoint.
- `GET /api/agents`: Retrieve a list of registered agents.
- `GET /api/alerts`: Retrieve recent alerts.
- `POST /api/agents/:agent_id/command`: Send a command to a specific agent.

## Development

### Building the Project

Build the project using Cargo:

```sh
cargo build
```

### Running Tests

Run the tests using Cargo:

```sh
cargo test
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Authors

- Anubhav Gain <imanubhavgain@gmail.com>
