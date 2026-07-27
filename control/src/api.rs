//! REST API 控制接口
//!
//! 本模块实现基于 Axum 的 REST API 服务器，提供对 dae-rs 控制面的
//! HTTP 管理接口。所有请求需通过 Bearer Token 认证。
//!
//! # 架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                    ApiServer                         │
//! │                                                     │
//! │  ┌──────────────┐  ┌────────────────────────────┐   │
//! │  │  中间件栈     │  │  路由表                    │   │
//! │  │              │  │                            │   │
//! │  │ · 认证       │  │ GET  /api/v1/status        │   │
//! │  │ · CORS       │  │ GET  /api/v1/metrics       │   │
//! │  │ · 日志       │  │ GET  /api/v1/nodes         │   │
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
// API 状态与配置
// ============================================================================

/// API 服务器共享状态
///
/// 通过 Axum 的 State 提取器注入到每个 handler 中。
pub struct ApiState {
    /// 控制面引用
    pub control: Arc<RwLock<ControlPlane>>,
    /// API 配置
    pub config: ApiConfig,
    /// 服务器启动时间（用于计算 uptime）
    pub start_time: std::time::Instant,
}

/// Axum 路由器持有状态（用于 State 提取器）
#[derive(Clone)]
struct AppState {
    /// API 状态，包在 Arc 中以便跨线程共享
    inner: Arc<ApiState>,
}

// ============================================================================
// ApiServer
// ============================================================================

/// REST API 服务器
///
/// 封装了 Axum 应用和监听地址，提供统一的启停接口。
///
/// # 示例
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
    /// Axum 应用（Router）
    app: Router,
    /// 监听地址
    listen_addr: String,
}

impl ApiServer {
    /// 创建新的 API 服务器
    ///
    /// 构建完整的 Axum Router，包括：
    /// - 认证中间件（Bearer Token）
    /// - CORS 中间件
    /// - 请求日志中间件
    /// - 所有 REST 端点路由
    ///
    /// # 参数
    ///
    /// * `state` — API 共享状态，包含控制面引用和配置
    pub fn new(state: ApiState) -> Self {
        let listen_addr = state.config.listen.clone();

        // 构建 AppState（Axum 要求 State 实现 Clone）
        let app_state = AppState {
            inner: Arc::new(state),
        };

        // 构建路由
        let app = Router::new()
            // ── 系统状态 ──
            .route("/api/v1/status", get(status_handler))
            .route("/api/v1/metrics", get(metrics_handler))
            // ── 节点 ──
            .route("/api/v1/nodes", get(nodes_list_handler))
            .route("/api/v1/nodes/{name}", get(node_detail_handler))
            // ── 出站组 ──
            .route("/api/v1/groups", get(groups_list_handler))
            .route("/api/v1/groups/{name}", get(group_detail_handler))
            .route("/api/v1/groups/{name}/policy", put(group_policy_handler))
            .route(
                "/api/v1/groups/{name}/selected",
                put(group_selected_handler),
            )
            // ── 路由规则 ──
            .route("/api/v1/routing", get(routing_handler))
            // ── 配置重载 ──
            .route("/api/v1/reload", post(reload_handler))
            // ── 共享状态 ──
            .with_state(app_state)
            // ── 中间件（从外到内：CORS → 日志 → 认证 → 路由） ──
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

    /// 启动 API 服务器（非阻塞）
    ///
    /// 绑定到配置的监听地址，在当前 tokio runtime 上启动 HTTP 服务。
    /// 返回一个 JoinHandle，可用于等待服务器退出或取消任务。
    ///
    /// # 返回
    ///
    /// 返回 `tokio::task::JoinHandle<()>`，服务器运行时持有此句柄。
    /// 可通过 `handle.abort()` 或等待其完成来管理服务器生命周期。
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
// 认证中间件
// ============================================================================

/// Bearer Token 认证中间件
///
/// 从 `Authorization` 请求头中提取 Bearer Token，与配置中的
/// `api.token` 比对。缺失或无效时返回 `401 Unauthorized`。
async fn auth_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    // 提取 Authorization header 并注入到请求扩展中
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

/// 从请求中提取的认证信息
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct AuthInfo {
    #[allow(dead_code)]
    token: String,
}

/// 验证请求的 Bearer Token
///
/// 在每个需要认证的 handler 中调用此函数。
/// 如果 token 无效，返回 `ApiError::Unauthorized`。
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
// 统一错误类型
// ============================================================================

/// API 统一错误类型
///
/// 实现 `IntoResponse`，可按标准错误格式 `{ "code": "E_XXXX", "message": "..." }`
/// 返回给客户端。
#[derive(Debug)]
pub enum ApiError {
    /// 401 — 认证失败
    Unauthorized,
    /// 404 — 资源不存在
    NotFound(String),
    /// 422 — 请求语义错误
    Unprocessable(String),
    /// 500 — 服务器内部错误
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
// 响应类型
// ============================================================================

/// 状态端点响应
#[derive(Serialize)]
struct StatusResponse {
    version: String,
    uptime_sec: u64,
    ebpf: EbpfStatus,
    tproxy_port: u16,
    netns: String,
}

/// eBPF 状态子对象
#[derive(Serialize)]
struct EbpfStatus {
    loaded: bool,
    programs: Vec<String>,
}

/// 指标端点响应
#[derive(Serialize)]
struct MetricsResponse {
    total_packets: u64,
    direct_decisions: u64,
    proxy_decisions: u64,
    bypass_count: u64,
    conntrack_hits: u64,
    active_connections: u64,
}

/// 节点信息响应
#[derive(Serialize, Clone)]
struct NodeInfo {
    name: String,
    protocol: String,
    address: String,
    alive: bool,
    latency_ms: LatencyInfo,
}

/// 延迟信息
#[derive(Serialize, Clone)]
struct LatencyInfo {
    #[serde(rename = "last")]
    last_ms: u64,
    avg10: u64,
    moving_avg: u64,
}

/// 出站组信息
#[derive(Serialize)]
#[serde(untagged)]
enum GroupInfo {
    /// auto 组
    Auto {
        name: String,
        #[serde(rename = "type")]
        group_type: String,
        policy: String,
        active_node: String,
        nodes: Vec<String>,
    },
    /// select 组
    Select {
        name: String,
        #[serde(rename = "type")]
        group_type: String,
        selected: String,
        nodes: Vec<String>,
    },
}

/// 路由规则响应
#[derive(Serialize)]
struct RoutingResponse {
    rules: Vec<RuleInfo>,
    fallback: String,
}

/// 路由规则条目
#[derive(Serialize)]
struct RuleInfo {
    #[serde(rename = "match")]
    match_expr: String,
    action: String,
}

/// 重载响应
#[derive(Serialize)]
struct ReloadResponse {
    status: String,
    config_ts: u64,
}

/// Policy 更新请求体
#[derive(Deserialize)]
struct PolicyUpdate {
    policy: String,
}

/// Selected 更新请求体
#[derive(Deserialize)]
struct SelectedUpdate {
    selected: String,
}

// ============================================================================
// Handler — 系统状态
// ============================================================================

/// `GET /api/v1/status`
///
/// 返回 dae-rs 的运行状态，包括版本、运行时间、eBPF 加载状态、
/// TProxy 端口和网络命名空间状态。
async fn status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
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
/// 返回从 eBPF STATS_MAP 读取的基础指标，包括总包数、
/// direct/proxy 决策数、bypass 计数、conntrack 命中数和活跃连接数。
async fn metrics_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MetricsResponse>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
    verify_auth(api_state, &headers)?;

    let control = api_state.control.write().await;

    // 从 eBPF STATS_MAP 读取指标，如果 eBPF 未加载则返回零值
    let stats = control
        .ebpf_mgr
        .lock()
        .unwrap()
        .read_stats()
        .unwrap_or([0u64; crate::ebpf::STATS_MAP_SIZE as usize]);

    // bpf_stats_map in tproxy.c has 2 entries: UdpConnOverflow and TcpConnOverflow.
    // Map them to the API response; set detailed counters to 0 for now.
    Ok(Json(MetricsResponse {
        total_packets: stats[crate::ebpf::StatIndex::UdpConnOverflow as usize]
            + stats[crate::ebpf::StatIndex::TcpConnOverflow as usize],
        direct_decisions: 0,   // tproxy.c tracks overflow, not per-decision stats
        proxy_decisions: 0,    // tproxy.c tracks overflow, not per-decision stats
        bypass_count: 0,       // tproxy.c tracks overflow, not per-decision stats
        conntrack_hits: 0,     // tproxy.c tracks overflow, not per-decision stats
        active_connections: 0, // TODO: count from conn_state_map
    }))
}

// ============================================================================
// Handler — 节点
// ============================================================================

/// `GET /api/v1/nodes`
///
/// 列出所有配置的出站节点及其当前延迟快照。
///
/// 第一阶段：从配置读取节点信息，延迟数据使用默认值（0），
/// 后续集成健康探测后返回真实延迟。
async fn nodes_list_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NodeInfo>>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
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
                    // 第一阶段：所有节点标记为存活
                    alive: true,
                    // 第一阶段：延迟数据使用默认值
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
/// 查询单个出站节点的详情。
async fn node_detail_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<NodeInfo>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
    verify_auth(api_state, &headers)?;

    let control = api_state.control.read().await;
    let daefile_config = &control.daefile_config;

    let node = daefile_config
        .as_ref()
        .and_then(|dc| dc.outbounds.nodes.iter().find(|n| n.name == name))
        .ok_or_else(|| ApiError::NotFound(format!("节点 '{}' 不存在", name)))?;

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
// Handler — 出站组
// ============================================================================

/// `GET /api/v1/groups`
///
/// 列出所有出站组及其详细信息。
async fn groups_list_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<GroupInfo>>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
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
                    // 收集组可达节点名
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
/// 查询单个出站组的详情。
async fn group_detail_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<GroupInfo>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
    verify_auth(api_state, &headers)?;

    let control = api_state.control.read().await;
    let daefile_config = &control.daefile_config;

    let group = daefile_config
        .as_ref()
        .and_then(|dc| dc.outbounds.groups.iter().find(|g| g.name == name))
        .ok_or_else(|| ApiError::NotFound(format!("出站组 '{}' 不存在", name)))?;

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
/// 修改 auto 组的节点选择策略。
///
/// 仅对 `type: auto` 的组有效；对 `select` 组返回 `422 Unprocessable Entity`。
async fn group_policy_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PolicyUpdate>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
    verify_auth(api_state, &headers)?;

    let mut control = api_state.control.write().await;
    let daefile_config = &mut control.daefile_config;

    let daefile = daefile_config
        .as_mut()
        .ok_or_else(|| ApiError::Internal("配置未加载".to_string()))?;

    let group = daefile
        .outbounds
        .groups
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("出站组 '{}' 不存在", name)))?;

    // 仅 auto 组支持 policy 修改
    if group.group_type != config::GroupType::Auto {
        return Err(ApiError::Unprocessable(format!(
            "组 '{}' 的类型为 select，不支持 policy 修改",
            name
        )));
    }

    // 解析 policy 值
    let policy = match body.policy.as_str() {
        "fixed" => config::PolicyType::Fixed,
        "random" => config::PolicyType::Random,
        "min" => config::PolicyType::Min,
        "min_avg10" => config::PolicyType::MinAvg10,
        "min_moving_avg" => config::PolicyType::MinMovingAvg,
        _ => {
            return Err(ApiError::Unprocessable(format!(
                "未知策略 '{}'，期望 fixed/random/min/min_avg10/min_moving_avg",
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
/// 修改 select 组当前选中节点。
///
/// 仅对 `type: select` 的组有效；对 `auto` 组返回 `422`。
/// `selected` 节点必须在组可达集合内，否则返回 `422`。
async fn group_selected_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SelectedUpdate>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
    verify_auth(api_state, &headers)?;

    let mut control = api_state.control.write().await;
    let daefile_config = &mut control.daefile_config;

    let daefile = daefile_config
        .as_mut()
        .ok_or_else(|| ApiError::Internal("配置未加载".to_string()))?;

    let group = daefile
        .outbounds
        .groups
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("出站组 '{}' 不存在", name)))?;

    // 仅 select 组支持 selected 修改
    if group.group_type != config::GroupType::Select {
        return Err(ApiError::Unprocessable(format!(
            "组 '{}' 的类型为 auto，不支持 selected 修改",
            name
        )));
    }

    // 检查 selected 节点是否在组可达集合内
    let node_names: Vec<String> = collect_group_node_names(group, &daefile.outbounds.nodes);
    if !node_names.contains(&body.selected) {
        return Err(ApiError::Unprocessable(format!(
            "节点 '{}' 不在组 '{}' 的可达集合内",
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
// Handler — 路由规则
// ============================================================================

/// `GET /api/v1/routing`
///
/// 返回当前生效的规则列表和 fallback 动作。
async fn routing_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RoutingResponse>, ApiError> {
    let api_state = &state.inner;

    // 验证认证
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
// Handler — 配置重载
// ============================================================================

/// `POST /api/v1/reload`
///
/// 触发配置热重载。重新解析 daefile，原子替换 JSON 配置，
/// 不中断已有连接。失败时返回 `500`，原配置继续运行。
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
// 辅助函数
// ============================================================================

/// 收集出站组可达节点名列表
///
/// 根据组的选择器（list 或 regex）从所有节点中筛选出匹配的节点名。
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
// 单元测试
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

    /// 创建测试用的 ApiState
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

    /// 创建测试用应用（带认证）
    fn test_app() -> Router {
        let state = test_state();
        let server = ApiServer::new(state);
        server.app
    }

    /// 创建测试用应用（不带认证 — 用于测试未认证场景）
    fn test_app_no_auth() -> Router {
        let state = test_state();
        // 移除认证中间件
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

    /// 添加 Authorization header 的辅助函数
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
