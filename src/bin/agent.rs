use anyhow::{Context, Result};
use log::{error, info, debug};
use nats_security_system::agent::Agent;
use nats_security_system::config::{load_agent_config, AgentConfig};
use nats_security_system::logging::init_logging;
use std::env;
use std::path::PathBuf;
use tokio::sync::oneshot;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    let mut config_path = None;

    // Simple argument parsing
    for i in 1..args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if i + 1 < args.len() {
                config_path = Some(PathBuf::from(&args[i + 1]));
            }
        }
    }

    // Load configuration
    let config = load_agent_config(config_path.as_ref())
        .context("Failed to load agent configuration")?;

    // Initialize logging
    let log_file = env::var("SECURITY_AGENT_LOG_FILE")
        .ok()
        .map(PathBuf::from);
    init_logging("agent", log::LevelFilter::Info, log_file.as_deref())
        .context("Failed to initialize logging")?;

    info!("Starting NATS Security Agent");
    debug!("Using configuration: {:?}", config);

    // Set up shutdown signal handler
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let handle_shutdown = tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("Shutdown signal received, starting graceful shutdown");
                let _ = shutdown_tx.send(());
            }
            Err(err) => {
                error!("Failed to listen for shutdown signal: {}", err);
            }
        }
    });

    // Create and run the agent
    let mut agent = Agent::new(config).await
        .context("Failed to create agent")?;
    
    let agent_task = tokio::spawn(async move {
        match agent.run(shutdown_rx).await {
            Ok(()) => info!("Agent shutdown successfully"),
            Err(e) => error!("Agent error: {}", e),
        }
    });

    // Wait for tasks to complete
    let _ = tokio::try_join!(handle_shutdown, agent_task);
    info!("NATS Security Agent terminated");

    Ok(())
}