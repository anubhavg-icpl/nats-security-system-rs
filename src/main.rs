use anyhow::Result;
use std::env;

// Export modules for binary targets to use
pub mod agent;
pub mod api;
pub mod common;
pub mod config;
pub mod logging;
pub mod manager;

fn main() -> Result<()> {
    // Display information about the available binaries
    println!("NATS Security Monitoring System");
    println!("==============================");
    println!();
    println!("This package contains two binaries:");
    println!();
    println!("1. Agent binary: Monitors systems and reports security events");
    println!("   Run with: cargo run --bin security-agent [--config <path>]");
    println!();
    println!("2. Manager binary: Processes security events and manages agents");
    println!("   Run with: cargo run --bin security-manager [--config <path>]");
    println!();
    println!("Setup Instructions:");
    println!("------------------");
    println!("1. Start a NATS server:");
    println!("   nats-server");
    println!();
    println!("2. Start the manager:");
    println!("   cargo run --bin security-manager");
    println!();
    println!("3. Start one or more agents:");
    println!("   cargo run --bin security-agent");
    println!();
    println!("For production use, create configuration files and use:");
    println!("   cargo run --bin security-manager --config manager-config.toml");
    println!("   cargo run --bin security-agent --config agent-config.toml");
    println!();
    
    // Get version information
    let version = env!("CARGO_PKG_VERSION");
    println!("Version: {}", version);
    
    Ok(())
}