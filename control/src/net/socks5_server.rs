//! Minimal SOCKS5 server that forwards through an [`OutboundDialer`].
//!
//! Listens on a local TCP port, accepts SOCKS5 CONNECT requests, and relays
//! data through the configured outbound dialer. Used to provide a local SOCKS5
//! proxy endpoint for rule set downloads before the TProxy listener is started.

use std::net::SocketAddr;
use std::sync::Arc;

use protocols::{OutboundDialer, ProxyStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// SOCKS5 server handle.
///
/// When dropped, the background accept loop is signalled to shut down.
pub struct Socks5LocalServer {
    shutdown: Option<oneshot::Sender<()>>,
    addr: SocketAddr,
}

impl Drop for Socks5LocalServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Socks5LocalServer {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }

    /// Start a local SOCKS5 server on the given address.
    ///
    /// Each accepted connection is handled in a separate tokio task:
    /// 1. SOCKS5 handshake (no-auth)
    /// 2. Parse CONNECT target
    /// 3. `dialer.dial(target)` → relay
    pub async fn start(
        dialer: Arc<dyn OutboundDialer>,
        listen_addr: SocketAddr,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;
        info!(addr = %actual_addr, "Local SOCKS5 server started");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        info!("Local SOCKS5 server shutting down");
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer)) => {
                                debug!(peer = %peer, "SOCKS5 client connected");
                                let d = dialer.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_client(stream, d).await {
                                        warn!(peer = %peer, error = %e, "SOCKS5 client error");
                                    }
                                });
                            }
                            Err(e) => {
                                error!("SOCKS5 accept error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            addr: actual_addr,
        })
    }
}

async fn handle_client(
    mut stream: tokio::net::TcpStream,
    dialer: Arc<dyn OutboundDialer>,
) -> Result<(), anyhow::Error> {
    // 1. Read auth methods: [ver, nmethods, methods...]
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        anyhow::bail!("invalid SOCKS version: {}", header[0]);
    }
    let nmethods = header[1] as usize;
    if nmethods > 0 {
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;
    }

    // 2. Respond with no-auth (0x00)
    stream.write_all(&[0x05, 0x00]).await?;

    // 3. Read CONNECT request: [ver, cmd, rsv, atyp, addr, port]
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;
    if req_header[0] != 0x05 {
        anyhow::bail!("invalid SOCKS version in request");
    }
    if req_header[1] != 0x01 {
        // Only CONNECT is supported
        send_socks5_reply(&mut stream, 0x07).await?;
        anyhow::bail!("unsupported command: {}", req_header[1]);
    }
    let atyp = req_header[3];

    let target = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = std::net::Ipv4Addr::from(addr);
            format!("{}:{}", ip, u16::from_be_bytes(port))
        }
        0x03 => {
            // Domain name
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let domain_len = len_buf[0] as usize;
            let mut domain = vec![0u8; domain_len];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let host = String::from_utf8_lossy(&domain);
            format!("{}:{}", host, u16::from_be_bytes(port))
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = std::net::Ipv6Addr::from(addr);
            format!("[{}]:{}", ip, u16::from_be_bytes(port))
        }
        _ => {
            send_socks5_reply(&mut stream, 0x08).await?;
            anyhow::bail!("unsupported address type: {}", atyp);
        }
    };

    debug!(target = %target, "SOCKS5 CONNECT");

    // 4. Dial through the outbound dialer
    let outbound = match dialer.dial(&target).await {
        Ok(conn) => conn,
        Err(e) => {
            warn!(target = %target, error = %e, "SOCKS5 dial failed");
            send_socks5_reply(&mut stream, 0x05).await?;
            return Err(e);
        }
    };

    // 5. Send success response
    send_socks5_reply(&mut stream, 0x00).await?;

    // 6. Bidirectional relay — destructure ProxyConn to get the inner stream.
    //    TcpStream and Box<dyn AsyncDuplex> both implement AsyncRead + AsyncWrite + Unpin,
    //    so copy_bidirectional works directly with &mut TcpStream and &mut Boxed.
    match outbound.stream {
        ProxyStream::Tcp(mut outbound_stream) => {
            let (up, down) = tokio::io::copy_bidirectional(&mut stream, &mut outbound_stream).await?;
            debug!(target = %target, up_bytes = up, down_bytes = down, "SOCKS5 client connection closed");
        }
        ProxyStream::Boxed(mut outbound_stream) => {
            let (up, down) = tokio::io::copy_bidirectional(&mut stream, &mut outbound_stream).await?;
            debug!(target = %target, up_bytes = up, down_bytes = down, "SOCKS5 client connection closed");
        }
    }
    Ok(())
}

async fn send_socks5_reply(
    stream: &mut tokio::net::TcpStream,
    status: u8,
) -> Result<(), std::io::Error> {
    stream
        .write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}