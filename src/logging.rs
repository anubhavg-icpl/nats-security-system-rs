use log::{info, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::path::Path;

// Initialize logging with both console and file output
pub fn init_logging(
    component: &str,
    log_level: LevelFilter,
    log_file: Option<&Path>,
) -> Result<(), log::SetLoggerError> {
    // Create console appender
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d(%Y-%m-%d %H:%M:%S)}] {h({l})} {t} - {m}{n}",
        )))
        .build();

    // Start building the config with console appender
    let mut config_builder = Config::builder()
        .appender(Appender::builder().build("console", Box::new(console)));

    // Add file appender if specified
    let mut root_builder = Root::builder().appender("console");

    if let Some(log_path) = log_file {
        if let Ok(file) = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(
                "[{d(%Y-%m-%d %H:%M:%S)}] {l} {t} - {m}{n}",
            )))
            .build(log_path)
        {
            config_builder = config_builder.appender(Appender::builder().build("file", Box::new(file)));
            root_builder = root_builder.appender("file");
        } else {
            eprintln!("Warning: Could not create log file at {:?}. Logging to console only.", log_path);
        }
    }

    // Build the config
    let config = config_builder
        .build(root_builder.build(log_level))
        .unwrap_or_else(|e| {
            eprintln!("Error configuring logger: {}", e);
            // Fallback to a basic console-only config
            Config::builder()
                .appender(Appender::builder().build("console", Box::new(ConsoleAppender::builder().build())))
                .build(Root::builder().appender("console").build(log_level))
                .unwrap()
        });

    // Initialize the logger
    log4rs::init_config(config)?;

    info!("{} logging initialized at level {}", component, log_level);
    
    Ok(())
}

// Macros to help with consistent error logging
#[macro_export]
macro_rules! log_error {
    ($result:expr, $message:expr) => {
        if let Err(err) = $result {
            log::error!("{}: {}", $message, err);
            Err(err)
        } else {
            $result
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($result:expr, $message:expr) => {
        if let Err(err) = $result {
            log::warn!("{}: {}", $message, err);
            Err(err)
        } else {
            $result
        }
    };
}