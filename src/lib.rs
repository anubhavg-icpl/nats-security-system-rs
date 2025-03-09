// Export modules for binary targets to use
pub mod agent;
pub mod api;
pub mod common;
pub mod config;
pub mod logging;
pub mod manager;

// Main entry point for the library
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}