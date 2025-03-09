// Main entry point for the NATS-based Security Monitoring System
// This file simply provides information about the available binaries

fn main() {
    println!("NATS-based Security Monitoring System");
    println!("=====================================");
    println!("This package contains two binaries:");
    println!("1. security-agent: Run with 'cargo run --bin security-agent'");
    println!("2. security-manager: Run with 'cargo run --bin security-manager'");
    println!("\nTo use this system:");
    println!("1. Start a NATS server: nats-server");
    println!("2. Run the manager: cargo run --bin security-manager");
    println!("3. Run one or more agents: cargo run --bin security-agent");
}

// Define common module that will be shared with other binaries
pub mod common;