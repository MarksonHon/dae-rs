//! REST API control interface
//!
//! This module implements an Axum-based REST API server providing the dae-rs control plane's
//! HTTP management interface. All requests require Bearer Token authentication.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                    ApiServer                         │
//! │                                                     │
//! │  ┌──────────────┐  ┌────────────────────────────┐   │
//! │  │  Middleware stack     │  │  Router table                    │   │
//! │  │              │  │                            │   │
//! │  │ · Auth         │  │ GET  /api/v1/status        │   │
//! │  │ · CORS       │  │ GET  /api/v1/metrics       │   │
//! │  │ · Logging      │  │ GET  /api/v1/nodes         │   │
//! │  │              │  │ GET  /api/v1/nodes/{name}  │   │
//! │  │              │  │ GET  /api/v1/groups        │   │
//! │  │              │  │ GET  /api/v1/groups/{name} │   │
//! │  │              │  │ PUT  /api/v1/groups/...    │   │
//! │  │              │  │ GET  /api/v1/routing       │   │
//! │  │              │  │ POST /api/v1/reload        │   │
//! │  └──────────────┘  └────────────────────────────┘   │
//! └──────────────────────┬──────────────────────────────┘
//!                        │
//!                 Arc<RwLock<ControlPlane>>
//! ```

use crate::config::{self, ApiConfig};
use crate::ControlPlane;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Json},
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

// ============================================================================
// API status and configuration
// ============================================================================

/// API server shared state
///
/// Injected into each handler via Axum's State extractor.
pub struct ApiState {
    /// Control plane reference
    pub control: Arc<RwLock<ControlPlane>>,
    /// API configuration
    pub config: ApiConfig,
    /// Server startup time (for calculating uptime)
    pub start_time: std::time::Instant,
}

/// Axum Router holds state (for State extractor)
#[derive(Clone)]
struct AppState {
    /// API state, wrapped in Arc for cross-thread sharing
    inner: Arc<ApiState>,
}

// ============================================================================
// ApiServer
// ============================================================================

/// REST API server
///
/// Encapsulates Axum application and listen address, providing unified start/stop interface.
///
/// # Examples
///
/// ```no_run
/// use control::api::{ApiServer, ApiState};
/// use control::ControlPlane;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// # async fn example() {
/// let state = ApiState {
///     control: Arc::new(RwLock::new(ControlPlane::new(Default::default()))),
///     config: control::config::ApiConfig {
///         enabled: true,
///         listen: "127.0.0.1:9090".into(),
///         tls: false,
///         cert: None,
///         key: None,
///         token: "secret".into(),
///     },
///     start_time: std::time::Instant::now(),
/// };
/// let server = ApiServer::new(state);
/// server.start().await;
/// # }
/// ```
pub struct ApiServer {
    /// Axum application (Router)
    app: Router,
    /// Listen address
    listen_addr: String,
}

impl ApiServer {
    /// Create a new API server
    ///
    /// Build complete Axum Router, Includes:
    /// - Authentication middleware (Bearer Token)
    /// - CORS middleware
    /// - Request logging middleware
    /// - All REST endpoint Routing
    ///
    /// # Parameters
    ///
    /// * `state` — API shared state, includes control plane reference and configuration
    pub fn new(state: ApiState) -> Self {
        let listen_addr = state.config.listen.clone();

        // Build AppState (Axum requires State to implement Clone)
        let app_state = AppState {
            inner: Arc::new(state),
        };

        // Build routing
        let app = Router::new()
            // ── System state ──
            .route("/api/v1/status", get(status_handler))
            .route("/api/v1/metrics", get(metrics_handler))
            // ── Nodes ──
            .route("/api/v1/nodes", get(nodes_list_handler))
            .route("/api/v1/nodes/{name}", get(node_detail_handler))
            // ── Outbound groups ──
            .route("/api/v1/groups", get(groups_list_handler))
            .route("/api/v1/groups/{name}", get(group_detail_handler))
            .route("/api/v1/groups/{name}/policy", put(group_policy_handler))
            .route(
                "/api/v1/groups/{name}/selected",
                put(group_selected_handler),
            )
            // ── Routing rules ──
            .route("/api/v1/routing", get(routing_handler))
            // ── Configuration reload ──
            .route("/api/v1/reload", post(reload_handler))
            // ── Shared state ──
            .with_state(app_state)
            // ── Middleware (outside to inside: CORS → logging → auth → Routing) ──
            .layer(middleware::from_fn(auth_middleware))
            .layer(tower_http::cors::CorsLayer::permissive().allow_origin(tower_http::cors::Any))
            .layer(
                tower_http::trace::TraceLayer::new_for_http()
                    .make_span_with(
                        tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
                    )
                    .on_response(
                        tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
                    ),
            );

        Self { app, listen_addr }
    }

    /// Start API server (non-blocking)
    ///
    /// Binds to configured listen address and starts HTTP service on current tokio runtime.
    /// Returns a JoinHandle that can be used to wait for server exit or cancel the task.
    ///
    /// # Returns
    ///
    /// Returns `tokio::task::JoinHandle<()>`, server runtime holds this handle.
    /// Server lifecycle can be managed via `handle.abort()` or by waiting for it to complete.
    pub async fn start(self) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
        let addr: std::net::SocketAddr = self
            .listen_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        info!(
            listen_addr = %addr,
            "REST API server starting"
        );

        let listener = tokio::net::TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;

        info!(
            listen_addr = %actual_addr,
            "REST API server listening"
        );

        let handle = tokio::spawn(async move {
            axum::serve(listener, self.app)
                .await
                .expect("REST API server exited with error");
        });

        Ok(handle)
    }
}

// ============================================================================
// Authentication middleware
// ============================================================================

/// Bearer Token authentication middleware
///
/// Extract Bearer Token from `Authorization` request header, compare with configured
/// `api.token`. Returns `401 Unauthorized` if missing or invalid.
async fn auth_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    // Extract Authorization header and inject into request extensions
    let token: Option<String> = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| t.to_string());

    if let Some(token) = token {
        req.extensions_mut().insert(AuthInfo { token });
    }

    next.run(req).await
}

/// Authentication info extracted from request
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct AuthInfo {
    #[allow(dead_code)]
    token: String,
}

/// Verify request's Bearer Token
///
/// Call this function in every handler that requires authentication.
/// If token is invalid, returns `ApiError::Unauthorized`.
fn verify_auth(state: &ApiState, headers: &HeaderMap) -> Result<(), ApiError> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(ApiError::Unauthorized)?;

    if token != state.config.token {
        return Err(ApiError::Unauthorized);
    }

    Ok(())
}

// ============================================================================
// Unified error type
// ============================================================================

/// API unified error type
///
/// Implements `IntoResponse`, can return errors in standard format `{ "code": "E_XXXX", "message": "..." }`
/// Return to client.
#[derive(Debug)]
pub enum ApiError {
    /// 401 — Authentication failed
    Unauthorized,
    /// 404 — Resource not found
    NotFound(String),
    /// 422 — Request semantic error
    Unprocessable(String),
    /// 500 — Internal server error
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "E_UNAUTHORIZED", "Unauthorized"),
            ApiError::NotFound(ref msg) => (StatusCode::NOT_FOUND, "E_NOT_FOUND", msg.as_str()),
            ApiError::Unprocessable(ref msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "E_UNPROCESSABLE",
                msg.as_str(),
            ),
            ApiError::Internal(ref msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "E_INTERNAL",
                msg.as_str(),
            ),
        };

        let body = serde_json::json!({
            "code": code,
            "message": message,
        });

        (status, Json(body)).into_response()
    }
}

// ============================================================================
// Response types
// ============================================================================

/// Status endpoint response
#[derive(Serialize)]
struct StatusResponse {
    version: String,
    uptime_sec: u64,
    ebpf: EbpfStatus,
    tproxy_port: u16,
    netns: String,
}

/// eBPF state sub-object
#[derive(Serialize)]
struct EbpfStatus {
    loaded: bool,
    programs: Vec<String>,
}

/// Metrics endpoint response
#[derive(Serialize)]
struct MetricsResponse {
    total_packets: u64,
    direct_decisions: u64,
    proxy_decisions: u64,
    bypass_count: u64,
    conntrack_hits: u64,
    active_connections: u64,
}

/// Node info response
#[derive(Serialize, Clone)]
struct NodeInfo {
    name: String,
    protocol: String,
    address: String,
    alive: bool,
    latency_ms: LatencyInfo,
}

/// Latency info
#[derive(Serialize, Clone)]
struct LatencyInfo {
    #[serde(rename = "last")]
    last_ms: u64,
    avg10: u64,
    moving_avg: u64,
}

/// Outbound group info
#[derive(Serialize)]
#[serde(untagged)]
enum GroupInfo {
    /// auto group
    Auto {
        name: String,
        #[serde(rename = "type")]
        group_type: String,
        policy: String,
        active_node: String,
        nodes: Vec<String>,
    },
    /// select group
    Select {
        name: String,
        #[serde(rename = "type")]
        group_type: String,
        selected: String,
        nodes: Vec<String>,
    },
}

/// Routing rules response
#[derive(Serialize)]
struct RoutingResponse {
    rules: Vec<RuleInfo>,
    fallback: String,
}

/// Routing rule entry
#[derive(Serialize)]
struct RuleInfo {
    #[serde(rename = "match")]
    match_expr: String,
    action: String,
}

/// Reload response
#[derive(Serialize)]
struct ReloadResponse {
    status: String,
    config_ts: u64,
}

/// Policy update request body
#[derive(Deserialize)]
struct PolicyUpdate {
    policy: String,
}

/// Selected update request body
#[derive(Deserialize)]
struct SelectedUpdate {
    selected: String,
}

// ============================================================================
// Handler — system status
// ============================================================================

/// `GET /api/v1/status`
///
/// Returns dae-rs runtime status, including version, uptime, eBPF loading status,
/// TProxy port and Network namespace state.
async fn status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let control = api_state.control.read().await;

    let uptime = api_state.start_time.elapsed().as_secs();

    let ebpf_loaded = control.ebpf_mgr.lock().unwrap().is_loaded();
    let tc_attached = control.ebpf_mgr.lock().unwrap().is_attached();

    let mut programs = Vec::new();
    if tc_attached {
        programs.push("tc_ingress".to_string());
        programs.push("tc_egress".to_string());
    }

    let netns_status = if control.netns_mgr.is_created() {
        "active".to_string()
    } else {
        "inactive".to_string()
    };

    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_sec: uptime,
        ebpf: EbpfStatus {
            loaded: ebpf_loaded,
            programs,
        },
        tproxy_port: control.config.tproxy_port,
        netns: netns_status,
    }))
}

/// `GET /api/v1/metrics`
///
/// Returns basic metrics read from eBPF STATS_MAP, including total packets,
/// direct/proxy decision counts, bypass count, conntrack hits, and active connections.
async fn metrics_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MetricsResponse>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let control = api_state.control.write().await;

    // Read metrics from eBPF STATS_MAP, return zero values if eBPF not loaded
    let stats = control
        .ebpf_mgr
        .lock()
        .unwrap()
        .read_stats()
        .unwrap_or([0u64; crate::net::ebpf::STATS_MAP_SIZE as usize]);

    // bpf_stats_map in tproxy.c has 2 entries: UdpConnOverflow and TcpConnOverflow.
    // Map them to the API response; set detailed counters to 0 for now.
    Ok(Json(MetricsResponse {
        total_packets: stats[crate::net::ebpf::StatIndex::UdpConnOverflow as usize]
            + stats[crate::net::ebpf::StatIndex::TcpConnOverflow as usize],
        direct_decisions: 0,   // tproxy.c tracks overflow, not per-decision stats
        proxy_decisions: 0,    // tproxy.c tracks overflow, not per-decision stats
        bypass_count: 0,       // tproxy.c tracks overflow, not per-decision stats
        conntrack_hits: 0,     // tproxy.c tracks overflow, not per-decision stats
        active_connections: 0, // TODO: count from conn_state_map
    }))
}

// ============================================================================
// Handler — nodes
// ============================================================================

/// `GET /api/v1/nodes`
///
/// List all configured outbound nodes and their current latency snapshots.
///
/// Phase 1: read node info from configuration, latency data uses default value (0),
/// real latency will be returned after health probe integration in subsequent phases.
async fn nodes_list_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NodeInfo>>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let control = api_state.control.read().await;
    let daefile_config = &control.daefile_config;

    let nodes: Vec<NodeInfo> = daefile_config
        .as_ref()
        .map(|dc| {
            dc.outbounds
                .nodes
                .iter()
                .map(|n| NodeInfo {
                    name: n.name.clone(),
                    protocol: n.protocol.clone(),
                    address: n.address.clone(),
                    // Phase 1: all nodes marked as alive
                    alive: true,
                    // Phase 1: latency data uses default values
                    latency_ms: LatencyInfo {
                        last_ms: 0,
                        avg10: 0,
                        moving_avg: 0,
                    },
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(nodes))
}

/// `GET /api/v1/nodes/{name}`
///
/// Query details of a single outbound node.
async fn node_detail_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<NodeInfo>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let control = api_state.control.read().await;
    let daefile_config = &control.daefile_config;

    let node = daefile_config
        .as_ref()
        .and_then(|dc| dc.outbounds.nodes.iter().find(|n| n.name == name))
        .ok_or_else(|| ApiError::NotFound(format!("node '{}' not found", name)))?;

    Ok(Json(NodeInfo {
        name: node.name.clone(),
        protocol: node.protocol.clone(),
        address: node.address.clone(),
        alive: true,
        latency_ms: LatencyInfo {
            last_ms: 0,
            avg10: 0,
            moving_avg: 0,
        },
    }))
}

// ============================================================================
// Handler — outbound groups
// ============================================================================

/// `GET /api/v1/groups`
///
/// List all outbound groups and their details.
async fn groups_list_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<GroupInfo>>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let control = api_state.control.read().await;
    let daefile_config = &control.daefile_config;

    let groups: Vec<GroupInfo> = daefile_config
        .as_ref()
        .map(|dc| {
            dc.outbounds
                .groups
                .iter()
                .map(|g| {
                    // Collect reachable node names for group
                    let node_names: Vec<String> = collect_group_node_names(g, &dc.outbounds.nodes);

                    match g.group_type {
                        config::GroupType::Auto => GroupInfo::Auto {
                            name: g.name.clone(),
                            group_type: "auto".to_string(),
                            policy: g
                                .policy
                                .as_ref()
                                .map(|p| format!("{:?}", p))
                                .unwrap_or_else(|| "fixed".to_string())
                                .to_lowercase(),
                            active_node: g
                                .selected
                                .clone()
                                .or_else(|| node_names.first().cloned())
                                .unwrap_or_default(),
                            nodes: node_names,
                        },
                        config::GroupType::Select => GroupInfo::Select {
                            name: g.name.clone(),
                            group_type: "select".to_string(),
                            selected: g
                                .selected
                                .clone()
                                .or_else(|| node_names.first().cloned())
                                .unwrap_or_default(),
                            nodes: node_names,
                        },
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(groups))
}

/// `GET /api/v1/groups/{name}`
///
/// Query details of a single outbound group.
async fn group_detail_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<GroupInfo>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let control = api_state.control.read().await;
    let daefile_config = &control.daefile_config;

    let group = daefile_config
        .as_ref()
        .and_then(|dc| dc.outbounds.groups.iter().find(|g| g.name == name))
        .ok_or_else(|| ApiError::NotFound(format!("outbound group '{}' not found", name)))?;

    let node_names: Vec<String> = collect_group_node_names(group, {
        if let Some(ref dc) = daefile_config {
            &dc.outbounds.nodes
        } else {
            &[]
        }
    });

    let info = match group.group_type {
        config::GroupType::Auto => GroupInfo::Auto {
            name: group.name.clone(),
            group_type: "auto".to_string(),
            policy: group
                .policy
                .as_ref()
                .map(|p| format!("{:?}", p))
                .unwrap_or_else(|| "fixed".to_string())
                .to_lowercase(),
            active_node: group
                .selected
                .clone()
                .or_else(|| node_names.first().cloned())
                .unwrap_or_default(),
            nodes: node_names,
        },
        config::GroupType::Select => GroupInfo::Select {
            name: group.name.clone(),
            group_type: "select".to_string(),
            selected: group
                .selected
                .clone()
                .or_else(|| node_names.first().cloned())
                .unwrap_or_default(),
            nodes: node_names,
        },
    };

    Ok(Json(info))
}

/// `PUT /api/v1/groups/{name}/policy`
///
/// Modify the node selection strategy for auto groups.
///
/// Only effective for `type: auto` groups; returns `422 Unprocessable Entity` for `select` groups.
async fn group_policy_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PolicyUpdate>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let mut control = api_state.control.write().await;
    let daefile_config = &mut control.daefile_config;

    let daefile = daefile_config
        .as_mut()
        .ok_or_else(|| ApiError::Internal("configuration not loaded".to_string()))?;

    let group = daefile
        .outbounds
        .groups
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("outbound group '{}' not found", name)))?;

    // Only auto groups support policy modification
    if group.group_type != config::GroupType::Auto {
        return Err(ApiError::Unprocessable(format!(
            "group '{}' is of type select, policy modification is not supported",
            name
        )));
    }

    // Parse policy value
    let policy = match body.policy.as_str() {
        "fixed" => config::PolicyType::Fixed,
        "random" => config::PolicyType::Random,
        "min" => config::PolicyType::Min,
        "min_avg10" => config::PolicyType::MinAvg10,
        "min_moving_avg" => config::PolicyType::MinMovingAvg,
        _ => {
            return Err(ApiError::Unprocessable(format!(
                "unknown policy '{}', expected fixed/random/min/min_avg10/min_moving_avg",
                body.policy
            )));
        }
    };

    group.policy = Some(policy);

    info!(
        group = %name,
        policy = %body.policy,
        "Policy updated via API"
    );

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

/// `PUT /api/v1/groups/{name}/selected`
///
/// Modify the currently selected node for select groups.
///
/// Only effective for `type: select` groups; returns `422` for `auto` groups.
/// `selected` node must be within the group's reachable set, otherwise returns `422`.
async fn group_selected_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SelectedUpdate>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let mut control = api_state.control.write().await;
    let daefile_config = &mut control.daefile_config;

    let daefile = daefile_config
        .as_mut()
        .ok_or_else(|| ApiError::Internal("configuration not loaded".to_string()))?;

    let group = daefile
        .outbounds
        .groups
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("outbound group '{}' not found", name)))?;

    // Only select groups support selected modification
    if group.group_type != config::GroupType::Select {
        return Err(ApiError::Unprocessable(format!(
            "group '{}' is of type auto, selected modification is not supported",
            name
        )));
    }

    // Check if selected node is within the group's reachable set
    let node_names: Vec<String> = collect_group_node_names(group, &daefile.outbounds.nodes);
    if !node_names.contains(&body.selected) {
        return Err(ApiError::Unprocessable(format!(
            "node '{}' is not in the reachable set of group '{}'",
            body.selected, name
        )));
    }

    group.selected = Some(body.selected.clone());

    info!(
        group = %name,
        selected = %body.selected,
        "Selected node updated via API"
    );

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

// ============================================================================
// Handler — Routing rules
// ============================================================================

/// `GET /api/v1/routing`
///
/// Returns the current active rule list and fallback action.
async fn routing_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RoutingResponse>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let control = api_state.control.read().await;
    let daefile_config = &control.daefile_config;

    let routing = daefile_config
        .as_ref()
        .map(|dc| {
            let rules: Vec<RuleInfo> = dc
                .routing
                .rules
                .iter()
                .map(|r| RuleInfo {
                    match_expr: r.r#match.clone(),
                    action: r.action.clone(),
                })
                .collect();

            RoutingResponse {
                rules,
                fallback: dc.routing.fallback.clone(),
            }
        })
        .unwrap_or_else(|| RoutingResponse {
            rules: Vec::new(),
            fallback: "direct".to_string(),
        });

    Ok(Json(routing))
}

// ============================================================================
// Handler — configuration reload
// ============================================================================

/// `POST /api/v1/reload`
///
/// Trigger configuration hot-reload. Re-parse daefile, atomically replace JSON configuration,
/// without interrupting existing connections. Returns `500` on failure, original config continues running.
async fn reload_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ReloadResponse>, ApiError> {
    let api_state = &state.inner;

    // Verify authentication
    verify_auth(api_state, &headers)?;

    let mut control = api_state.control.write().await;

    // Get daefile content (clone to release the immutable borrow)
    let content = control
        .daefile_content
        .clone()
        .ok_or_else(|| ApiError::Internal("No daefile content available for reload".into()))?;

    // Use the new hot-reload method
    control
        .reload_config(&content)
        .map_err(|e| ApiError::Internal(format!("Config reload failed: {}", e)))?;

    info!("Config reload completed successfully via API");

    let config_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(Json(ReloadResponse {
        status: "reloaded".to_string(),
        config_ts,
    }))
}

// ============================================================================
// Helper function
// ============================================================================

/// Collect list of reachable node names for outbound group
///
/// Filter matching node names from all nodes based on the group's selector (list or regex).
fn collect_group_node_names(
    group: &config::OutboundGroupConfig,
    all_nodes: &[config::OutboundNodeConfig],
) -> Vec<String> {
    let all_node_names: Vec<&str> = all_nodes.iter().map(|n| n.name.as_str()).collect();
    let mut result = Vec::new();

    for selector in &group.selectors {
        match selector {
            config::NodeSelector::List { nodes } => {
                for name in nodes {
                    if !result.contains(name) {
                        result.push(name.clone());
                    }
                }
            }
            config::NodeSelector::Regex { pattern } => {
                let pat = if pattern == "*" {
                    ".*"
                } else {
                    pattern.as_str()
                };
                if let Ok(re) = regex::Regex::new(pat) {
                    for name in &all_node_names {
                        if re.is_match(name) && !result.contains(&name.to_string()) {
                            result.push(name.to_string());
                        }
                    }
                }
            }
        }
    }

    result
}

// ============================================================================
// Unit test
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlPlane;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use tower::ServiceExt;

    /// Create ApiState for testing
    fn test_state() -> ApiState {
        let mut cp = ControlPlane::new(crate::Config::default());
        let example = crate::config::default_config_example();
        cp.daefile_content = Some(example.to_string());
        if let Ok(parsed) = crate::config::parse_daefile(example) {
            cp.daefile_config = Some(parsed);
        }

        ApiState {
            control: Arc::new(RwLock::new(cp)),
            config: ApiConfig {
                enabled: true,
                listen: "127.0.0.1:9090".to_string(),
                tls: false,
                cert: None,
                key: None,
                token: "test-token".to_string(),
            },
            start_time: std::time::Instant::now(),
        }
    }

    /// Create test application (with authentication)
    fn test_app() -> Router {
        let state = test_state();
        let server = ApiServer::new(state);
        server.app
    }

    /// Create test application (without authentication — for testing unauthenticated scenarios)
    fn test_app_no_auth() -> Router {
        let state = test_state();
        // Remove authentication middleware
        let app_state = AppState {
            inner: Arc::new(state),
        };

        Router::new()
            .route("/api/v1/status", get(status_handler))
            .route("/api/v1/metrics", get(metrics_handler))
            .route("/api/v1/nodes", get(nodes_list_handler))
            .route("/api/v1/nodes/{name}", get(node_detail_handler))
            .route("/api/v1/groups", get(groups_list_handler))
            .route("/api/v1/groups/{name}", get(group_detail_handler))
            .route("/api/v1/groups/{name}/policy", put(group_policy_handler))
            .route(
                "/api/v1/groups/{name}/selected",
                put(group_selected_handler),
            )
            .route("/api/v1/routing", get(routing_handler))
            .route("/api/v1/reload", post(reload_handler))
            .with_state(app_state)
    }

    /// Helper function to add Authorization header
    fn authed_request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("Authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_auth_no_token_returns_401() {
        let app = test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_wrong_token_returns_401() {
        let app = test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header("Authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_status_endpoint_returns_200() {
        let app = test_app_no_auth();

        let response = app.oneshot(authed_request("/api/v1/status")).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(body.get("version").is_some());
        assert!(body.get("uptime_sec").is_some());
        assert!(body.get("ebpf").is_some());
        assert!(body.get("tproxy_port").is_some());
        assert!(body.get("netns").is_some());
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_200() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(authed_request("/api/v1/metrics"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_nodes_endpoint_returns_200() {
        let app = test_app_no_auth();

        let response = app.oneshot(authed_request("/api/v1/nodes")).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_groups_endpoint_returns_200() {
        let app = test_app_no_auth();

        let response = app.oneshot(authed_request("/api/v1/groups")).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_routing_endpoint_returns_200() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(authed_request("/api/v1/routing"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_reload_endpoint_returns_200() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/reload")
                    .method(http::Method::POST)
                    .header("Authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_unknown_route_returns_404() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(authed_request("/api/v1/unknown"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_node_detail_not_found() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(authed_request("/api/v1/nodes/nonexistent"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_group_detail_not_found() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(authed_request("/api/v1/groups/nonexistent"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
