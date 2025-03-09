use crate::common::SecurityAlert;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, Method, Request};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{self, TraceLayer};

// API server state
pub struct ApiState<T> {
    pub manager: T,
    pub admin_token: String,
}

// Error response
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = Json(self);
        (status, body).into_response()
    }
}

// Standard API response
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

// Command request
#[derive(Debug, Deserialize)]
pub struct CommandRequest {
    pub action: String,
    pub parameters: Option<HashMap<String, String>>,
}

// Start the API server
pub async fn start_api_server<T>(
    addr: &str,
    port: u16,
    state: Arc<ApiState<T>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
where 
    T: ManagerInterface + 'static + Clone + Send + Sync,
{
    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any);

    // Configure API routes
    let router = Router::new()
        .route("/api/health", get(health_check))
        .route("/api/agents", get(get_agents::<T>))
        .route("/api/alerts", get(get_alerts::<T>))
        .route("/api/agents/:agent_id/command", post(send_command::<T>))
        .layer(TraceLayer::new_for_http()
            .make_span_with(trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
            .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO)))
        .layer(cors)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::<T>,
        ))
        .with_state(state);

    // Bind API server to address
    let socket_addr: SocketAddr = format!("{}:{}", addr, port)
        .parse()
        .expect("Invalid address or port");

    info!("Starting API server on {}", socket_addr);
    
    // Start server with graceful shutdown
    let server = axum::Server::bind(&socket_addr)
        .serve(router.into_make_service());

    let graceful = server.with_graceful_shutdown(async {
        if shutdown_rx.recv().await.is_some() {
            info!("API server shutting down");
        }
    });

    graceful.await?;
    
    Ok(())
}

// Authentication middleware
async fn auth_middleware<T>(
    State(state): State<Arc<ApiState<T>>>,
    headers: HeaderMap,
    request: Request<axum::body::Body>,
    next: middleware::Next<axum::body::Body>,
) -> Response 
where 
    T: Clone + Send + Sync + 'static,
{
    // Skip auth for health check endpoint
    if request.uri().path() == "/api/health" {
        return next.run(request).await;
    }

    // Check for authorization header
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = auth_str.trim_start_matches("Bearer ");
                if token == state.admin_token {
                    // Token is valid, continue with the request
                    debug!("Authenticated request to {}", request.uri().path());
                    return next.run(request).await;
                }
            }
        }
    }

    // If we get here, authentication failed
    warn!("Unauthorized request to {}", request.uri().path());
    ApiError {
        status: 401,
        message: "Unauthorized".to_string(),
    }
    .into_response()
}

// Endpoint handlers

async fn health_check() -> impl IntoResponse {
    Json(ApiResponse {
        success: true,
        data: Some("Security Monitoring System operational"),
        error: None,
    })
}

async fn get_agents<T: ManagerInterface>(
    State(state): State<Arc<ApiState<T>>>,
) -> Response {
    match state.manager.get_agents().await {
        Ok(agents) => Json(ApiResponse {
            success: true,
            data: Some(agents),
            error: None,
        }).into_response(),
        Err(e) => ApiError {
            status: 500,
            message: format!("Failed to retrieve agents: {}", e),
        }
        .into_response(),
    }
}

async fn get_alerts<T: ManagerInterface>(
    State(state): State<Arc<ApiState<T>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // Parse limit parameter
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100);

    match state.manager.get_alerts(limit).await {
        Ok(alerts) => Json(ApiResponse {
            success: true,
            data: Some(alerts),
            error: None,
        }).into_response(),
        Err(e) => ApiError {
            status: 500,
            message: format!("Failed to retrieve alerts: {}", e),
        }
        .into_response(),
    }
}

async fn send_command<T: ManagerInterface>(
    State(state): State<Arc<ApiState<T>>>,
    Path(agent_id): Path<String>,
    result: Result<Json<CommandRequest>, JsonRejection>,
) -> Response {
    // Check for valid JSON payload
    let command = match result {
        Ok(Json(cmd)) => cmd,
        Err(e) => {
            return ApiError {
                status: 400,
                message: format!("Invalid request: {}", e),
            }
            .into_response()
        }
    };

    // Ensure parameters are provided
    let parameters = command.parameters.unwrap_or_default();

    // Send command to agent
    match state
        .manager
        .send_command(&agent_id, &command.action, parameters)
        .await
    {
        Ok(command_id) => Json(ApiResponse {
            success: true,
            data: Some(command_id),
            error: None,
        }).into_response(),
        Err(e) => ApiError {
            status: 500,
            message: format!("Failed to send command: {}", e),
        }
        .into_response(),
    }
}

// Interface for manager operations
#[async_trait::async_trait]
pub trait ManagerInterface: Send + Sync {
    type Agent: Serialize;
    
    async fn get_agents(&self) -> Result<Vec<Self::Agent>, Box<dyn std::error::Error + Send + Sync>>;
    
    async fn get_alerts(
        &self,
        limit: usize,
    ) -> Result<Vec<SecurityAlert>, Box<dyn std::error::Error + Send + Sync>>;
    
    async fn send_command(
        &self,
        agent_id: &str,
        action: &str,
        parameters: HashMap<String, String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;
}

// Implement ManagerInterface for Arc<T> where T already implements ManagerInterface
#[async_trait::async_trait]
impl<T: ManagerInterface + Send + Sync> ManagerInterface for Arc<T> {
    type Agent = T::Agent;

    async fn get_agents(&self) -> Result<Vec<Self::Agent>, Box<dyn std::error::Error + Send + Sync>> {
        (**self).get_agents().await
    }

    async fn get_alerts(
        &self,
        limit: usize,
    ) -> Result<Vec<SecurityAlert>, Box<dyn std::error::Error + Send + Sync>> {
        (**self).get_alerts(limit).await
    }

    async fn send_command(
        &self,
        agent_id: &str,
        action: &str,
        parameters: HashMap<String, String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        (**self).send_command(agent_id, action, parameters).await
    }
}