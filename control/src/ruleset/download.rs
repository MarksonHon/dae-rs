//! Ruleset downloader (design §4.2 / §4.3).
//!
//! - Direct connection + optional SOCKS5 proxy (reqwest `socks` feature; `socks5h://` resolves remotely).
//! - Single-request timeout of 30s, exponential backoff retries (3 by default, 2s/4s/8s).
//! - ETag / Last-Modified conditional requests: a 304 response means no update is needed.
//! - Computes sha256 after download; when an expected sha256 is provided, verification is enforced; on mismatch, deletes the temp file and returns an error.
//!
//! "Download via the first proxy group" is wired in by a later sub-task: this layer only receives a `proxy_socks5` address.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;
use tracing::{info, warn};

use crate::ruleset::store::{DataDir, RuleSetMeta, RuleSetState, StoreError};
use crate::ruleset::types::{RuleSetConfig, RuleSetData};
use crate::ruleset::{parse_rule_set_data, RuleSetError};

/// Download options.
#[derive(Debug, Clone)]
pub struct DownloadOptions {
    /// Per-request timeout.
    pub timeout: Duration,
    /// Exponential-backoff retry count (3 by default, intervals 2s/4s/8s).
    pub max_retries: u32,
    /// Base retry delay (2s by default).
    pub retry_base_delay: Duration,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_base_delay: Duration::from_secs(2),
        }
    }
}

/// Download result information.
#[derive(Debug, Clone)]
pub struct DownloadedInfo {
    /// File size (bytes).
    pub size: u64,
    /// Content sha256 (lowercase hex).
    pub sha256: String,
    /// Server ETag (if any).
    pub etag: Option<String>,
    /// Server Last-Modified (if any).
    pub last_modified: Option<String>,
    /// Conditional request hit (304); content unchanged.
    pub not_modified: bool,
}

/// Download error.
#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("invalid proxy url '{url}': {detail}")]
    InvalidProxy { url: String, detail: String },
    #[error("failed to build http client: {0}")]
    ClientBuild(String),
    #[error("http request failed for '{url}': {source}")]
    Request { url: String, source: reqwest::Error },
    #[error("http status {status} for '{url}'")]
    HttpStatus { url: String, status: u16 },
    #[error("checksum mismatch for '{url}': expected {expected}, got {actual}")]
    ChecksumMismatch { url: String, expected: String, actual: String },
    #[error("io error writing '{path}': {source}")]
    Io { path: String, source: std::io::Error },
}

/// Update outcome.
#[derive(Debug)]
pub enum UpdateOutcome {
    /// Updated: carries new parsed data for the caller to rebuild its in-memory cache.
    Updated(RuleSetData),
    /// Not changed (304 or sha256 identical to the last recorded value).
    NotModified,
}

/// Download a rule set file to `dest_tmp` (a temporary path).
///
/// * `url` — data source address (http/https).
/// * `proxy_socks5` — optional SOCKS5 proxy address; `None` means direct connection.
/// * `dest_tmp` — temporary destination file path (not written to the official directory until verification passes).
/// * `expected_sha256` — if provided, verification is enforced; on failure, the temp file is deleted and an error is returned.
///
/// Note: the caller must ensure `dest_tmp`'s parent directory exists (e.g. by pairing
/// [`DataDir::tmp_file_path`] with [`DataDir::ensure_dirs`]).
pub async fn download(
    url: &str,
    proxy_socks5: Option<SocketAddr>,
    dest_tmp: PathBuf,
    expected_sha256: Option<&str>,
) -> Result<DownloadedInfo, DownloadError> {
    download_impl(DownloadRequest {
        url: url.to_string(),
        proxy_socks5,
        dest_tmp,
        expected_sha256: expected_sha256.map(str::to_string),
        etag: None,
        last_modified: None,
        options: DownloadOptions::default(),
    })
    .await
}

/// Download with conditional requests and custom options (used by [`update_rule_set`]).
pub(crate) async fn download_with_meta(
    url: &str,
    proxy_socks5: Option<SocketAddr>,
    dest_tmp: PathBuf,
    etag: Option<&str>,
    last_modified: Option<&str>,
    expected_sha256: Option<&str>,
    options: &DownloadOptions,
) -> Result<DownloadedInfo, DownloadError> {
    download_impl(DownloadRequest {
        url: url.to_string(),
        proxy_socks5,
        dest_tmp,
        expected_sha256: expected_sha256.map(str::to_string),
        etag: etag.map(str::to_string),
        last_modified: last_modified.map(str::to_string),
        options: options.clone(),
    })
    .await
}

#[derive(Debug, Clone)]
struct DownloadRequest {
    url: String,
    proxy_socks5: Option<SocketAddr>,
    dest_tmp: PathBuf,
    expected_sha256: Option<String>,
    etag: Option<String>,
    last_modified: Option<String>,
    options: DownloadOptions,
}

async fn download_impl(req: DownloadRequest) -> Result<DownloadedInfo, DownloadError> {
    let client = build_client(req.proxy_socks5, req.options.timeout)?;
    let total_attempts = req.options.max_retries + 1;
    for attempt in 0..total_attempts {
        match attempt_once(&client, &req).await {
            Ok(info) => return Ok(info),
            Err(e) if is_retryable(&e) && attempt + 1 < total_attempts => {
                let delay = req.options.retry_base_delay * 2u32.pow(attempt);
                warn!(url = %req.url, attempt, retry_in_ms = delay.as_millis(), error = %e,
                    "rule set download attempt failed; retrying");
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("download retry loop always returns")
}

async fn attempt_once(
    client: &reqwest::Client,
    req: &DownloadRequest,
) -> Result<DownloadedInfo, DownloadError> {
    let mut builder = client.get(&req.url);
    if let Some(etag) = &req.etag {
        builder = builder.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    if let Some(lm) = &req.last_modified {
        builder = builder.header(reqwest::header::IF_MODIFIED_SINCE, lm);
    }

    let resp = builder
        .send()
        .await
        .map_err(|source| DownloadError::Request { url: req.url.clone(), source })?;
    let status = resp.status();

    // Conditional request hit → content unchanged
    if status == reqwest::StatusCode::NOT_MODIFIED {
        let etag = header_str(resp.headers(), reqwest::header::ETAG);
        let last_modified = header_str(resp.headers(), reqwest::header::LAST_MODIFIED);
        return Ok(DownloadedInfo {
            size: 0,
            sha256: String::new(),
            etag,
            last_modified,
            not_modified: true,
        });
    }

    if !status.is_success() {
        return Err(DownloadError::HttpStatus { url: req.url.clone(), status: status.as_u16() });
    }

    let etag = header_str(resp.headers(), reqwest::header::ETAG);
    let last_modified = header_str(resp.headers(), reqwest::header::LAST_MODIFIED);

    let bytes = resp
        .bytes()
        .await
        .map_err(|source| DownloadError::Request { url: req.url.clone(), source })?;
    let size = bytes.len() as u64;
    let sha256 = crate::ruleset::sha256_hex(&bytes);

    if let Some(expected) = &req.expected_sha256 {
        if !sha256.eq_ignore_ascii_case(expected) {
            let _ = std::fs::remove_file(&req.dest_tmp);
            return Err(DownloadError::ChecksumMismatch {
                url: req.url.clone(),
                expected: expected.clone(),
                actual: sha256,
            });
        }
    }

    tokio::fs::write(&req.dest_tmp, &bytes)
        .await
        .map_err(|source| DownloadError::Io { path: req.dest_tmp.display().to_string(), source })?;

    Ok(DownloadedInfo { size, sha256, etag, last_modified, not_modified: false })
}

fn header_str(headers: &reqwest::header::HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn is_retryable(e: &DownloadError) -> bool {
    match e {
        // Network/timeout errors are retryable
        DownloadError::Request { .. } => true,
        // Only 5xx server errors are retryable; 4xx / verification failures etc. are not
        DownloadError::HttpStatus { status, .. } => *status >= 500,
        _ => false,
    }
}

fn build_client(
    proxy_socks5: Option<SocketAddr>,
    timeout: Duration,
) -> Result<reqwest::Client, DownloadError> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(format!("dae-rs/{}", env!("CARGO_PKG_VERSION")));
    if let Some(addr) = proxy_socks5 {
        // socks5h: resolve the target domain name via the proxy (the proxy side resolves the target URL's host)
        let proxy_url = format!("socks5h://{addr}");
        let proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| DownloadError::InvalidProxy { url: proxy_url, detail: e.to_string() })?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| DownloadError::ClientBuild(e.to_string()))
}

/// Update a rule set: download → checksum → parse (failure marks it corrupt) → atomic replace →
/// update `.meta`/`.checksum` → return the new data (for the caller to rebuild its in-memory cache).
///
/// * `config` — the rule set configuration entry (filled in by the phase 2 Configuration subsystem).
/// * `dir` — the data directory.
/// * `proxy_socks5` — optional SOCKS5 proxy address (a later sub-task resolves it from the "first proxy group" and passes it in).
pub async fn update_rule_set(
    config: &RuleSetConfig,
    dir: &DataDir,
    proxy_socks5: Option<SocketAddr>,
) -> Result<UpdateOutcome, RuleSetError> {
    dir.ensure_dirs().await?;

    let prev_meta = dir.read_meta(&config.name).await?;
    let prev_sha = dir.read_checksum(&config.name).await?;
    let etag = prev_meta.as_ref().and_then(|m| m.etag.clone());
    let last_modified = prev_meta.as_ref().and_then(|m| m.last_modified.clone());

    let tmp_path = dir.tmp_file_path(&config.name);
    let info = download_with_meta(
        &config.url,
        proxy_socks5,
        tmp_path.clone(),
        etag.as_deref(),
        last_modified.as_deref(),
        config.expected_sha256.as_deref(),
        &DownloadOptions::default(),
    )
    .await?;

    if info.not_modified {
        info!(name = %config.name, "rule set not modified (304); skipping update");
        return Ok(UpdateOutcome::NotModified);
    }

    // Compare with the previously recorded checksum: if identical, the content is unchanged and no replace is needed
    if let Some(prev) = &prev_sha {
        if prev.eq_ignore_ascii_case(&info.sha256) {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            info!(name = %config.name, "rule set content unchanged (sha256 identical); skipping update");
            return Ok(UpdateOutcome::NotModified);
        }
    }

    // Parse verification (dat decode / text parse failure marks the file corrupt; delete the temp file)
    let bytes = tokio::fs::read(&tmp_path).await.map_err(|source| {
        RuleSetError::Store(StoreError::Io { path: tmp_path.display().to_string(), source })
    })?;
    let parsed = {
        let ty = config.r#type;
        let tmp = tmp_path.clone();
        match tokio::task::spawn_blocking(move || parse_rule_set_data(ty, &bytes)).await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e);
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(RuleSetError::Store(StoreError::Corrupt(format!(
                    "parse task join failed: {e}"
                ))));
            }
        }
    };

    // Atomic replace: .tmp → official file
    let dest = dir.data_file_path(&config.name, config.r#type);
    dir.atomic_replace(&tmp_path, &dest).await?;

    // Update checksum and meta
    dir.write_checksum(&config.name, &info.sha256).await?;
    let meta = RuleSetMeta {
        name: config.name.clone(),
        url: config.url.clone(),
        r#type: config.r#type,
        last_updated: Some(chrono::Utc::now().to_rfc3339()),
        etag: info.etag.clone(),
        last_modified: info.last_modified.clone(),
        sha256: Some(info.sha256.clone()),
        size: info.size,
        state: RuleSetState::Ready,
    };
    dir.write_meta(&config.name, &meta).await?;

    info!(name = %config.name, size = info.size, "rule set updated");
    Ok(UpdateOutcome::Updated(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::store::DataDir;
    use crate::ruleset::types::RuleSetType;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    // ── Minimal HTTP test server (local TcpListener, deterministic tests, no external dependencies) ──

    struct MockResponse {
        status: u16,
        body: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
        delay: Option<Duration>,
    }

    struct MockServer {
        addr: SocketAddr,
        shutdown: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl MockServer {
        fn start(responses: HashMap<String, MockResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_flag = shutdown.clone();
            let handle = thread::spawn(move || {
                // Poll accept: exit after receiving the shutdown flag, avoiding a hung join at Drop
                while !shutdown_flag.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => handle_conn(stream, &responses),
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self { addr, shutdown, handle: Some(handle) }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.addr, path)
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            // Set the shutdown flag → accept loop exits → join can return
            self.shutdown.store(true, Ordering::Release);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn handle_conn(mut stream: TcpStream, responses: &HashMap<String, MockResponse>) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = request_line.split_whitespace();
        let _method = parts.next();
        let path = parts.next().unwrap_or("/").to_string();

        let mut headers: HashMap<String, String> = HashMap::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let Some(resp) = responses.get(&path) else {
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return;
        };

        if let Some(delay) = resp.delay {
            thread::sleep(delay);
        }

        let not_modified = (resp.etag.is_some()
            && headers.get("if-none-match").map(String::as_str) == resp.etag.as_deref())
            || (resp.last_modified.is_some()
                && headers.get("if-modified-since").map(String::as_str)
                    == resp.last_modified.as_deref());

        if not_modified {
            let mut out = String::from("HTTP/1.1 304 Not Modified\r\nConnection: close\r\n");
            if let Some(e) = &resp.etag {
                out.push_str(&format!("ETag: {e}\r\n"));
            }
            out.push_str("\r\n");
            let _ = stream.write_all(out.as_bytes());
            return;
        }

        let mut out = format!(
            "HTTP/1.1 {} OK\r\nConnection: close\r\nContent-Length: {}\r\n",
            resp.status,
            resp.body.len()
        );
        if let Some(e) = &resp.etag {
            out.push_str(&format!("ETag: {e}\r\n"));
        }
        if let Some(lm) = &resp.last_modified {
            out.push_str(&format!("Last-Modified: {lm}\r\n"));
        }
        out.push_str("\r\n");
        let _ = stream.write_all(out.as_bytes());
        let _ = stream.write_all(&resp.body);
    }

    // ── Download tests ──

    #[test]
    fn test_mock_server_raw() {
        let server = MockServer::start(HashMap::from([(
            "/x".to_string(),
            MockResponse {
                status: 200,
                body: b"hi".to_vec(),
                etag: None,
                last_modified: None,
                delay: None,
            },
        )]));
        let mut conn = std::net::TcpStream::connect(server.addr).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        conn.write_all(b"GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.starts_with("HTTP/1.1 200"), "unexpected response: {s}");
        assert!(s.ends_with("hi"), "missing body: {s}");
    }

    #[tokio::test]
    async fn test_download_success() {
        let server = MockServer::start(HashMap::from([(
            "/file".to_string(),
            MockResponse {
                status: 200,
                body: b"hello world".to_vec(),
                etag: Some("etag-1".into()),
                last_modified: Some("Wed, 01 Jan 2026 00:00:00 GMT".into()),
                delay: None,
            },
        )]));
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("file.tmp");

        let info = download(&server.url("/file"), None, dest.clone(), None).await.unwrap();
        assert!(!info.not_modified);
        assert_eq!(info.size, 11);
        assert_eq!(info.sha256, crate::ruleset::sha256_hex(b"hello world"));
        assert_eq!(info.etag.as_deref(), Some("etag-1"));
        assert!(info.last_modified.is_some());
        let written = std::fs::read(&dest).unwrap();
        assert_eq!(written, b"hello world");
    }

    #[tokio::test]
    async fn test_download_not_modified_304() {
        let server = MockServer::start(HashMap::from([(
            "/file".to_string(),
            MockResponse {
                status: 200,
                body: b"hello".to_vec(),
                etag: Some("etag-1".into()),
                last_modified: None,
                delay: None,
            },
        )]));
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("file.tmp");

        // Conditional request with the previous etag → 304
        let info = download_with_meta(
            &server.url("/file"),
            None,
            dest.clone(),
            Some("etag-1"),
            None,
            None,
            &DownloadOptions::default(),
        )
        .await
        .unwrap();
        assert!(info.not_modified);
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn test_download_checksum_mismatch() {
        let server = MockServer::start(HashMap::from([(
            "/file".to_string(),
            MockResponse {
                status: 200,
                body: b"hello world".to_vec(),
                etag: None,
                last_modified: None,
                delay: None,
            },
        )]));
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("file.tmp");

        let err = download(&server.url("/file"), None, dest.clone(), Some("deadbeef"))
            .await
            .unwrap_err();
        assert!(matches!(err, DownloadError::ChecksumMismatch { .. }));
        // Verification failure → temp file deleted
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn test_download_http_error() {
        let server = MockServer::start(HashMap::new());
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("file.tmp");
        let opts = DownloadOptions {
            timeout: Duration::from_secs(5),
            max_retries: 0,
            retry_base_delay: Duration::from_secs(1),
        };
        let err = download_with_meta(
            &server.url("/nope"),
            None,
            dest,
            None,
            None,
            None,
            &opts,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DownloadError::HttpStatus { status: 404, .. }));
    }

    #[tokio::test]
    async fn test_download_timeout() {
        let server = MockServer::start(HashMap::from([(
            "/slow".to_string(),
            MockResponse {
                status: 200,
                body: b"x".to_vec(),
                etag: None,
                last_modified: None,
                delay: Some(Duration::from_secs(2)),
            },
        )]));
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("file.tmp");
        let opts = DownloadOptions {
            timeout: Duration::from_millis(100),
            max_retries: 0,
            retry_base_delay: Duration::from_millis(10),
        };
        let err = download_with_meta(
            &server.url("/slow"),
            None,
            dest,
            None,
            None,
            None,
            &opts,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DownloadError::Request { .. }));
    }

    // ── Updating a rule set (end-to-end) ──

    #[tokio::test]
    async fn test_update_rule_set() {
        let body = b"1.1.1.0/24\n2.2.2.2\n# comment\n";
        let sha = crate::ruleset::sha256_hex(body);
        let server = MockServer::start(HashMap::from([(
            "/chinaip.txt".to_string(),
            MockResponse {
                status: 200,
                body: body.to_vec(),
                etag: Some("etag-1".into()),
                last_modified: None,
                delay: None,
            },
        )]));
        let dir = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(dir.path());
        let cfg = RuleSetConfig {
            name: "chinaip".into(),
            r#type: RuleSetType::IpList,
            url: server.url("/chinaip.txt"),
            expected_sha256: Some(sha.clone()),
            update: None,
            update_on_start: false,
            proxy: None,
        };

        // First: download → parse → atomic replace → write checksum/meta
        let outcome = update_rule_set(&cfg, &data_dir, None).await.unwrap();
        match outcome {
            UpdateOutcome::Updated(RuleSetData::IpList(nets)) => {
                assert_eq!(nets.len(), 2);
                assert_eq!(nets[0].to_string(), "1.1.1.0/24");
                assert_eq!(nets[1].to_string(), "2.2.2.2/32");
            }
            other => panic!("expected Updated(IpList), got {other:?}"),
        }

        let data_path = data_dir.data_file_path("chinaip", RuleSetType::IpList);
        assert!(data_path.exists());
        assert_eq!(
            data_dir.read_checksum("chinaip").await.unwrap().as_deref(),
            Some(sha.as_str())
        );
        let meta = data_dir.read_meta("chinaip").await.unwrap().unwrap();
        assert_eq!(meta.state, RuleSetState::Ready);
        assert_eq!(meta.r#type, RuleSetType::IpList);
        assert_eq!(meta.sha256.as_deref(), Some(sha.as_str()));
        assert_eq!(meta.url, cfg.url);
        assert!(meta.last_updated.is_some());

        // Second: conditional request (with etag) → 304 → NotModified
        let outcome2 = update_rule_set(&cfg, &data_dir, None).await.unwrap();
        assert!(matches!(outcome2, UpdateOutcome::NotModified));
    }

    #[tokio::test]
    async fn test_update_rule_set_unchanged_skips_replace() {
        let body = b"1.1.1.0/24\n";
        let sha = crate::ruleset::sha256_hex(body);
        // No etag: always returns 200
        let server = MockServer::start(HashMap::from([(
            "/a.txt".to_string(),
            MockResponse {
                status: 200,
                body: body.to_vec(),
                etag: None,
                last_modified: None,
                delay: None,
            },
        )]));
        let dir = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(dir.path());
        let cfg = RuleSetConfig {
            name: "a".into(),
            r#type: RuleSetType::IpList,
            url: server.url("/a.txt"),
            expected_sha256: Some(sha.clone()),
            update: None,
            update_on_start: false,
            proxy: None,
        };

        let out1 = update_rule_set(&cfg, &data_dir, None).await.unwrap();
        assert!(matches!(out1, UpdateOutcome::Updated(_)));

        let data_path = data_dir.data_file_path("a", RuleSetType::IpList);
        let mtime1 = std::fs::metadata(&data_path).unwrap().modified().unwrap();

        // Content identical (sha matches the previous one) → NotModified, and the file is not replaced
        std::thread::sleep(Duration::from_millis(1100));
        let out2 = update_rule_set(&cfg, &data_dir, None).await.unwrap();
        assert!(matches!(out2, UpdateOutcome::NotModified));
        let mtime2 = std::fs::metadata(&data_path).unwrap().modified().unwrap();
        assert_eq!(mtime1, mtime2);
    }

    #[tokio::test]
    async fn test_update_rule_set_corrupt_rejected() {
        // Server returns garbage bytes that cannot be parsed as an IP list → marked corrupt, temp file deleted
        let server = MockServer::start(HashMap::from([(
            "/bad.txt".to_string(),
            MockResponse {
                status: 200,
                body: b"this is not an ip\n".to_vec(),
                etag: None,
                last_modified: None,
                delay: None,
            },
        )]));
        let dir = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(dir.path());
        let cfg = RuleSetConfig {
            name: "bad".into(),
            r#type: RuleSetType::IpList,
            url: server.url("/bad.txt"),
            expected_sha256: None,
            update: None,
            update_on_start: false,
            proxy: None,
        };

        let err = update_rule_set(&cfg, &data_dir, None).await.unwrap_err();
        assert!(matches!(err, RuleSetError::List(_)));
        // The official file was not created, and the temp file was cleaned up
        assert!(!data_dir.data_file_path("bad", RuleSetType::IpList).exists());
        assert!(dir.path().join(".tmp").read_dir().unwrap().next().is_none());
    }
}
