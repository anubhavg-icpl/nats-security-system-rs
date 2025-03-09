# Example Configuration Files

## Agent Configuration (agent-config.toml)

```toml
# Optional custom identity settings
id_prefix = "prod"
custom_id = "web-server-01"  # Leave empty to use auto-generated ID

# NATS Connection settings
[nats]
url = "nats://nats.example.com:4222"
username = "agent_user"
password = "secure_password"
# If using TLS, uncomment these lines and provide proper paths
# tls_ca_cert = "/etc/nats-security/ca.pem"
# tls_client_cert = "/etc/nats-security/client-cert.pem"
# tls_client_key = "/etc/nats-security/client-key.pem"

# File monitoring configuration
[file_monitoring]
enabled = true

# Define paths to monitor
[[file_monitoring.monitored_paths]]
path = "/etc"
recursive = false
severity_override = 5
exclude_patterns = [".bak$", ".tmp$"]

[[file_monitoring.monitored_paths]]
path = "/var/www/html"
recursive = true
severity_override = 8
exclude_patterns = [".log$", ".tmp$"]

# Paths to explicitly exclude
excluded_paths = [
  "/etc/mtab",
  "/etc/resolv.conf"
]

# Ignore temporary files (ending with .tmp, ~, etc.)
ignore_temp_files = true

# Timing settings
scan_interval_seconds = 300     # 5 minutes
heartbeat_interval_seconds = 60 # 1 minute

# Connection resilience
reconnect_attempts = 10
reconnect_delay_seconds = 5
```

## Manager Configuration (manager-config.toml)

```toml
# NATS Connection settings
[nats]
url = "nats://nats.example.com:4222"
username = "manager_user"
password = "secure_manager_password"
# If using TLS, uncomment these lines and provide proper paths
# tls_ca_cert = "/etc/nats-security/ca.pem"
# tls_client_cert = "/etc/nats-security/client-cert.pem"
# tls_client_key = "/etc/nats-security/client-key.pem"

# API Server settings
api_bind_address = "0.0.0.0"  # Bind to all interfaces
api_port = 8080
admin_token = "your-secure-api-token-here"  # Change this!

# Agent monitoring settings
agent_timeout_seconds = 300  # Consider agent inactive after 5 minutes

# System settings
alert_retention_count = 10000
reconnect_attempts = 10
reconnect_delay_seconds = 5
```

## TLS Configuration

To properly secure your system with TLS, you need to:

1. Generate a CA certificate
2. Generate server certificates for NATS
3. Generate client certificates for each agent and the manager

Here's a basic script to generate these certificates using OpenSSL:

```bash
#!/bin/bash
# Create directory for certificates
mkdir -p certs
cd certs

# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 1826 -key ca.key -out ca.pem -subj "/CN=NATS Security CA"

# Generate server key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=nats.example.com"

# Sign the server certificate
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem

# Generate a client key and certificate for the manager
openssl genrsa -out manager.key 2048
openssl req -new -key manager.key -out manager.csr -subj "/CN=security-manager"
openssl x509 -req -days 365 -in manager.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out manager.pem

# Generate a client key and certificate for an agent
openssl genrsa -out agent.key 2048
openssl req -new -key agent.key -out agent.csr -subj "/CN=security-agent"
openssl x509 -req -days 365 -in agent.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out agent.pem

echo "TLS certificates generated successfully."
```

## Systemd Service Files

### Agent Service (nats-security-agent.service)

```ini
[Unit]
Description=NATS Security Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/security-agent --config /etc/nats-security/agent-config.toml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Manager Service (nats-security-manager.service)

```ini
[Unit]
Description=NATS Security Manager
After=network.target

[Service]
Type=simple
User=nats-security
ExecStart=/usr/local/bin/security-manager --config /etc/nats-security/manager-config.toml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```