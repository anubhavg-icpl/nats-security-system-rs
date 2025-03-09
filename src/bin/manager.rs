use anyhow::{Context, Result};
use log::{error, info, debug};
use nats_security_system::api::{start_api_server, ApiState};
use nats_security_system::config::{load_manager_config, ManagerConfig};
use nats_security_system::logging::init_logging;
use nats_security_system::manager::Manager;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

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
    let config = load_manager_config(config_path.as_ref())
        .context("Failed to load manager configuration")?;

    // Initialize logging
    let log_file = env::var("SECURITY_MANAGER_LOG_FILE")
        .ok()
        .map(PathBuf::from);
    init_logging("manager", log::LevelFilter::Info, log_file.as_deref())
        .context("Failed to initialize logging")?;

    info!("Starting NATS Security Manager");
    debug!("Using configuration: {:?}", config);

    // Set up shutdown signal handler
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
    let (api_shutdown_tx, api_shutdown_rx) = tokio::sync::mpsc::channel(1);
    
    // Handle Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    let handle_shutdown = tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("Shutdown signal received, starting graceful shutdown");
                let _ = shutdown_tx_clone.send(()).await;
                let _ = api_shutdown_tx.send(()).await;
            }
            Err(err) => {
                error!("Failed to listen for shutdown signal: {}", err);
            }
        }
    });

    // Create the manager
    let manager = Arc::new(Manager::new(config.clone()).await
        .context("Failed to create manager")?);
    
    // Create API state
    let api_state = Arc::new(ApiState {
        manager: manager.clone(),
        admin_token: config.admin_token.clone(),
    });

    // Start the manager
    let manager_clone = manager.clone();
    let manager_task = tokio::spawn(async move {
        match manager_clone.run(shutdown_rx).await {
            Ok(()) => info!("Manager shutdown successfully"),
            Err(e) => error!("Manager error: {}", e),
        }
    });

    // Start the API server
    let api_task = tokio::spawn(async move {
        match start_api_server(
            &config.api_bind_address,
            config.api_port,
            api_state,
            api_shutdown_rx,
        ).await {
            Ok(()) => info!("API server shutdown successfully"),
            Err(e) => error!("API server error: {}", e),
        }
    });

    // Wait for tasks to complete
    let _ = tokio::try_join!(handle_shutdown, manager_task, api_task);
    info!("NATS Security Manager terminated");

    Ok(())
}