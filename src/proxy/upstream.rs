//! The resident proxy's UPSTREAM (forward-hop) connector.
//!
//! hudsucker's built-in `with_rustls_connector` dials every intercepted host
//! DIRECTLY, ignoring the device egress proxy (`sprott config set proxy`) that reqwest
//! honours natively via `*_PROXY` env. On a host whose only outbound route is a
//! corporate / on-demand HTTP proxy (direct egress firewalled), the MITM
//! forward hop then hangs/times out even though the OAuth mint (reqwest) reached
//! the provider through the proxy — the exact "Gmail via `sc run` times out"
//! failure, where GitHub still works only because it is directly reachable.
//!
//! This connector closes that gap. It reads the SAME effective egress proxy the
//! reqwest clients use (`egress_proxy::effective()` — a real shell proxy wins,
//! else the stored file), and for each forward connection either dials the
//! target directly or tunnels to it through the proxy via HTTP `CONNECT`. The
//! resulting TCP stream is handed to hyper-rustls, which performs TLS to the
//! ORIGINAL host — so SNI and certificate validation are unchanged; only the
//! transport path moves.
//!
//! The proxy lives in a shared, swappable [`EgressProxyCell`] (also held by
//! `AppState`) that the connector reads PER-CONNECTION, so `sprott config set/unset proxy`
//! HOT-reloads it via `/proxy/reload` ([`reload_cell`]) — the forward hop
//! re-points on its next connection with NO daemon restart, and so no vault
//! re-unlock.
//!
//! Scope: HTTP proxies (the corporate / local norm, and what `sprott config set proxy`
//! documents). A non-HTTP proxy URL (https/socks) is logged and ignored — the
//! forward hop then dials direct, i.e. exactly the pre-change behaviour, never
//! worse. Loopback and any `NO_PROXY` host always dial direct.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use hudsucker::hyper::Uri;
use hudsucker::hyper_util::rt::TokioIo;
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::rustls::ClientConfig;
use hyper_rustls::{ConfigBuilderExt, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::dns::GaiResolver;
use hyper_util::client::legacy::connect::HttpConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tower_service::Service;

/// Fail-fast bound on the whole forward-hop connect (TCP + CONNECT handshake).
/// Mirrors the daemon's shared reqwest client (`core::forward::http_client`,
/// 8s): a wrong/dead egress proxy or a black-holed route surfaces as a clean
/// "couldn't reach the provider" instead of hanging for the OS default (~75s).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A live, swappable egress-proxy cell shared by `AppState` and the resident
/// proxy's forward connector. `None` inside = dial upstream directly. Swapped in
/// place by [`reload_cell`] on `/proxy/reload` (after `sprott config set/unset proxy`), so
/// the forward hop re-points on its next connection with NO daemon restart (and
/// so no vault re-unlock).
pub type EgressProxyCell = Arc<RwLock<Option<Upstream>>>;

/// How the forward hop reaches the internet when it does not dial direct.
#[derive(Clone)]
pub enum Upstream {
    /// The proxy Sprott was given (live shell proxy or `sprott config set proxy`).
    Given(Arc<ProxyCfg>),
    /// Nothing given: this computer's proxy settings, matched per destination
    /// by the same community implementation reqwest uses (hyper-util
    /// `Matcher::from_system`: `*_PROXY` variables, then macOS System Settings
    /// or Windows Internet Settings).
    System(Arc<hyper_util::client::proxy::matcher::Matcher>),
}

/// How often the daemon re-reads this computer's proxy settings. This polls:
/// the platforms also offer change notifications (macOS SCDynamicStore,
/// Windows registry change events), which this does not use yet. The read is
/// cheap (env vars, one SCDynamicStore lookup on macOS, one registry key on
/// Windows), so a change takes effect within this interval.
const SYSTEM_PROXY_POLL: Duration = Duration::from_secs(5);

/// Follow this computer's proxy settings while the daemon runs: when they
/// change and nothing was given to Sprott, rebuild the shared reqwest client
/// and this cell, so the next request and the next forward connection use the
/// new settings. Per-call clients (`egress_proxy::client`) read them at build.
pub fn spawn_system_proxy_watch(cell: EgressProxyCell) {
    tokio::spawn(async move {
        let mut last = system_settings_snapshot();
        loop {
            tokio::time::sleep(SYSTEM_PROXY_POLL).await;
            let now = system_settings_snapshot();
            if now == last {
                continue;
            }
            last = now;
            if crate::cli::egress_proxy::effective().is_none() {
                tracing::info!("this computer's proxy settings changed; Sprott follows them");
                crate::core::forward::reload_egress_proxy();
                reload_cell(&cell);
            }
        }
    });
}

/// A comparable snapshot of the computer's proxy settings. Compared in memory
/// only, never logged: a proxy URL may carry credentials.
fn system_settings_snapshot() -> String {
    format!("{:?}", hyper_util::client::proxy::matcher::Matcher::from_system())
}

/// Build a fresh egress-proxy cell from the currently-effective proxy. Held in
/// `AppState`; a clone backs the forward connector.
pub fn new_cell() -> EgressProxyCell {
    Arc::new(RwLock::new(resolve_current()))
}

/// Re-resolve the effective egress proxy and swap it into `cell` in place — the
/// hot-reload path (`/proxy/reload`), no restart.
pub fn reload_cell(cell: &EgressProxyCell) {
    *cell.write().unwrap() = resolve_current();
}

/// The forward hop's current route: the proxy Sprott was given, parsed; else
/// this computer's proxy settings. `None` = direct (a given proxy that is not
/// an HTTP proxy, which the CONNECT hop can't use).
fn resolve_current() -> Option<Upstream> {
    let Some(url) = crate::cli::egress_proxy::effective() else {
        return Some(Upstream::System(Arc::new(
            hyper_util::client::proxy::matcher::Matcher::from_system(),
        )));
    };
    match parse_proxy(&url) {
        Some(cfg) => {
            tracing::info!(
                proxy_host = %cfg.host,
                proxy_port = cfg.port,
                "resident proxy forward hop routes through the egress proxy"
            );
            Some(Upstream::Given(Arc::new(cfg)))
        }
        None => {
            tracing::warn!(
                "egress proxy '{}' is not an HTTP proxy URL — the resident \
                 proxy's forward hop dials upstream directly",
                url
            );
            None
        }
    }
}

/// Build the resident proxy's forward connector: hyper-rustls (same rustls
/// config hudsucker's `with_rustls_connector` uses — aws-lc-rs provider, webpki
/// roots, TLS1.2+1.3, HTTP/1 only, matching hudsucker's non-default `http2`)
/// wrapping our egress-proxy-aware `TunnelConnector`. `cell` is the live proxy
/// (shared with `AppState`) the connector reads per-connection.
pub fn forward_connector(cell: EgressProxyCell) -> HttpsConnector<TunnelConnector> {
    let provider = aws_lc_rs::default_provider();
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the safe default protocol versions")
        .with_webpki_roots()
        .with_no_client_auth();

    HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(TunnelConnector::new(cell))
}

/// A base connector (`Service<Uri>`) that dials the target directly or through
/// the configured HTTP egress proxy via `CONNECT`. Wrapped by hyper-rustls,
/// which then layers TLS to the original host over whichever stream this
/// returns. Reads the proxy from a shared live cell, so a runtime `sprott config set proxy`
/// re-points the forward hop on the NEXT connection — no restart.
#[derive(Clone)]
pub struct TunnelConnector {
    proxy: EgressProxyCell,
    /// Hosts that always dial direct (loopback + `NO_PROXY`), lowercased. Static
    /// for the daemon's life (the pinned custodian + loopback don't change).
    no_proxy: Arc<Vec<String>>,
}

/// A parsed HTTP egress proxy the forward hop tunnels through.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyCfg {
    host: String,
    port: u16,
    /// `Basic <base64(user:pass)>` value when the proxy URL carries userinfo.
    auth: Option<String>,
}

impl TunnelConnector {
    fn new(proxy: EgressProxyCell) -> Self {
        Self {
            proxy,
            no_proxy: Arc::new(resolve_no_proxy_env()),
        }
    }

    /// The proxy to tunnel through for `host` (`https` = the forward target's
    /// scheme), or `None` to dial direct.
    fn use_proxy_for(&self, host: &str, https: bool) -> Option<Arc<ProxyCfg>> {
        let route = self.proxy.read().unwrap().clone()?;
        let h = host.to_ascii_lowercase();
        if self.no_proxy.iter().any(|e| no_proxy_matches(e, &h)) {
            return None;
        }
        match route {
            Upstream::Given(p) => Some(p),
            Upstream::System(m) => system_proxy_for(&m, &h, https),
        }
    }
}

impl Service<Uri> for TunnelConnector {
    type Response = TokioIo<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let host = dst
                .host()
                .ok_or_else(|| -> BoxError { "forward target has no host".into() })?
                .to_string();
            let port = dst.port_u16().unwrap_or(match dst.scheme_str() {
                Some("http") => 80,
                _ => 443, // https + the hudsucker MITM default
            });

            let connect = async {
                match this.use_proxy_for(&host, dst.scheme_str() != Some("http")) {
                    Some(p) => connect_via_proxy(&p, &host, port).await,
                    None => dial(tcp_dialer(GaiResolver::new()), &host, port).await,
                }
            };
            let stream = connect_within(CONNECT_TIMEOUT, &host, port, connect).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

/// Bound a forward-hop connect to `host:port` by `limit`. However time runs out
/// (this bound, or the dialer's own connect timeout), the error reads
/// `forward connect to host:port timed out`.
async fn connect_within(
    limit: Duration,
    host: &str,
    port: u16,
    connect: impl Future<Output = Result<TcpStream, BoxError>>,
) -> Result<TcpStream, BoxError> {
    match tokio::time::timeout(limit, connect).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) if !is_timeout(&*e) => Err(e),
        _ => Err(format!("forward connect to {}:{} timed out", host, port).into()),
    }
}

/// Did time run out? The dialer reports its connect timeout as an
/// `io::ErrorKind::TimedOut` somewhere in the error's source chain.
fn is_timeout(err: &(dyn std::error::Error + 'static)) -> bool {
    std::iter::successors(Some(err), |e| e.source()).any(|e| {
        e.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
    })
}

/// The TCP dialer for both forward-hop legs (straight to the upstream, or to the
/// egress proxy): hyper-util's `HttpConnector`, the connector reqwest is built
/// on, so the broker reaches a host the way a standard HTTP client does. When a
/// name resolves to both IPv6 and IPv4 addresses it races the two families
/// (Happy Eyeballs, RFC 8305: the second family starts after hyper-util's
/// default 300 ms) instead of trying the addresses one after another, so a
/// black-holed IPv6 route costs that delay, not the whole `CONNECT_TIMEOUT`.
/// Its connect timeout is `CONNECT_TIMEOUT`, split across each family's
/// addresses as reqwest's is, so one dead address doesn't use up the budget.
/// `resolver` is the system resolver in production; tests pass a fixed one.
fn tcp_dialer<R>(resolver: R) -> HttpConnector<R> {
    let mut dialer = HttpConnector::new_with_resolver(resolver);
    dialer.set_nodelay(true);
    dialer.set_connect_timeout(Some(CONNECT_TIMEOUT));
    dialer
}

/// `host:port` as a URI authority. An IPv6 literal is the only host with a
/// colon (RFC 3986): one from a `Uri` keeps its brackets, an egress proxy given
/// as `http://::1:7890` (or with a zone, `fe80::1%eth0`) arrives without them,
/// so they are added here. The connector strips them again before resolving.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Open a TCP connection to `host:port` with `dialer` (see [`tcp_dialer`]).
async fn dial<C>(mut dialer: C, host: &str, port: u16) -> Result<TcpStream, BoxError>
where
    C: Service<Uri, Response = TokioIo<TcpStream>>,
    C::Error: Into<BoxError>,
{
    // The `http` scheme only satisfies the connector, which dials TCP and nothing
    // more; hyper-rustls layers TLS on top.
    let uri: Uri = format!("http://{}", authority(host, port)).parse()?;
    std::future::poll_fn(|cx| dialer.poll_ready(cx))
        .await
        .map_err(Into::into)?;
    let io = dialer.call(uri).await.map_err(Into::into)?;
    Ok(io.into_inner())
}

/// Open a CONNECT tunnel to `host:port` through the HTTP proxy `p` and return
/// the tunneled TCP stream (TLS is layered on top by the caller).
async fn connect_via_proxy(p: &ProxyCfg, host: &str, port: u16) -> Result<TcpStream, BoxError> {
    let mut stream = dial(tcp_dialer(GaiResolver::new()), &p.host, p.port).await?;

    let mut req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n",
        host = host,
        port = port
    );
    if let Some(auth) = &p.auth {
        req.push_str("Proxy-Authorization: ");
        req.push_str(auth);
        req.push_str("\r\n");
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read only the response head. The proxy sends nothing after the CONNECT
    // reply until we write (the TLS ClientHello), and the upstream hasn't been
    // spoken to yet, so a byte-at-a-time read to the `\r\n\r\n` terminator can
    // never swallow tunnel payload — no framed buffer to hand off is needed.
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(
                format!("proxy closed the connection during CONNECT to {host}:{port}").into(),
            );
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 8 * 1024 {
            return Err("proxy CONNECT response head too large".into());
        }
    }

    let status_line = head
        .split(|&b| b == b'\n')
        .next()
        .map(|l| String::from_utf8_lossy(l).trim().to_string())
        .unwrap_or_default();
    // `HTTP/1.1 200 Connection established` — accept any 2xx.
    let ok = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .map(|c| (200..300).contains(&c))
        .unwrap_or(false);
    if !ok {
        return Err(format!(
            "egress proxy refused CONNECT to {host}:{port}: {}",
            if status_line.is_empty() {
                "<no status line>"
            } else {
                &status_line
            }
        )
        .into());
    }
    Ok(stream)
}

/// The proxy this computer's settings name for `host`, as a tunnel target.
/// `None` = direct: the settings name none for it, or name a non-HTTP proxy
/// the CONNECT hop can't use (logged).
fn system_proxy_for(
    m: &hyper_util::client::proxy::matcher::Matcher,
    host: &str,
    https: bool,
) -> Option<Arc<ProxyCfg>> {
    let scheme = if https { "https" } else { "http" };
    let dst: Uri = format!("{scheme}://{host}/").parse().ok()?;
    let intercept = m.intercept(&dst)?;
    let uri = intercept.uri();
    if uri.scheme_str() != Some("http") {
        tracing::warn!(
            "this computer's proxy for {} is not an HTTP proxy; the forward hop dials direct",
            host
        );
        return None;
    }
    // Same host form `parse_proxy` yields (an IPv6 host keeps its brackets).
    let proxy_host = uri.host()?.to_string();
    let auth = intercept
        .basic_auth()
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    Some(Arc::new(ProxyCfg {
        host: proxy_host,
        port: uri.port_u16().unwrap_or(80),
        auth,
    }))
}

/// Parse an `http://[user:pass@]host[:port]` proxy URL. Returns `None` for a
/// non-HTTP scheme (https/socks) — unsupported for the CONNECT forward hop.
fn parse_proxy(url: &str) -> Option<ProxyCfg> {
    // Scheme: require explicit `http://`, or accept a bare `host:port` as HTTP
    // (the shape some shells export). Reject https/socks explicitly.
    let rest = match url.split_once("://") {
        Some(("http", r)) => r,
        Some((other, _)) => {
            let _ = other; // https, socks5, socks5h, … — unsupported here
            return None;
        }
        None => url, // bare host[:port]
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((u, hp)) => (Some(u), hp),
        None => (None, authority),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (host_port, 80),
    };
    if host.is_empty() {
        return None;
    }
    let auth = userinfo.filter(|u| !u.is_empty()).map(|u| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(u.as_bytes())
        )
    });
    Some(ProxyCfg {
        host: host.to_string(),
        port,
        auth,
    })
}

/// Loopback (always) plus every `NO_PROXY` / `no_proxy` entry, lowercased.
fn resolve_no_proxy_env() -> Vec<String> {
    let mut out: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    for key in ["NO_PROXY", "no_proxy"] {
        for e in std::env::var(key).unwrap_or_default().split(',') {
            let e = e.trim().to_ascii_lowercase();
            if !e.is_empty() && !out.contains(&e) {
                out.push(e);
            }
        }
    }
    out
}

/// Does `NO_PROXY` entry `entry` cover `host`? Matches the common conventions:
/// `*` (all), exact host, and domain-suffix (`example.com` / `.example.com`
/// both cover `api.example.com`).
fn no_proxy_matches(entry: &str, host: &str) -> bool {
    if entry == "*" {
        return true;
    }
    let e = entry.trim_start_matches('.');
    host == e || host.ends_with(&format!(".{}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A live cell holding `p` — the shape `AppState`/`forward_connector` share.
    fn cell(p: Option<ProxyCfg>) -> EgressProxyCell {
        Arc::new(RwLock::new(p.map(|p| Upstream::Given(Arc::new(p)))))
    }

    #[test]
    fn parse_http_proxy_forms() {
        assert_eq!(
            parse_proxy("http://127.0.0.1:7778"),
            Some(ProxyCfg {
                host: "127.0.0.1".into(),
                port: 7778,
                auth: None
            })
        );
        // bare host:port is treated as HTTP
        assert_eq!(
            parse_proxy("proxy.corp:3128"),
            Some(ProxyCfg {
                host: "proxy.corp".into(),
                port: 3128,
                auth: None
            })
        );
        // default port 80 when omitted
        assert_eq!(parse_proxy("http://proxy.corp").unwrap().port, 80);
        // trailing path is ignored
        assert_eq!(parse_proxy("http://p:8080/pac").unwrap().port, 8080);
    }

    #[test]
    fn parse_proxy_userinfo_becomes_basic_auth() {
        let cfg = parse_proxy("http://alice:s3cr3t@proxy.corp:8080").unwrap();
        assert_eq!(cfg.host, "proxy.corp");
        assert_eq!(cfg.port, 8080);
        let want = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(b"alice:s3cr3t")
        );
        assert_eq!(cfg.auth.as_deref(), Some(want.as_str()));
    }

    #[test]
    fn non_http_proxy_is_rejected() {
        // https/socks proxies aren't supported for the CONNECT forward hop.
        assert_eq!(parse_proxy("https://proxy.corp:8080"), None);
        assert_eq!(parse_proxy("socks5://127.0.0.1:1080"), None);
        assert_eq!(parse_proxy("socks5h://127.0.0.1:1080"), None);
    }

    #[test]
    fn no_proxy_matching() {
        assert!(no_proxy_matches("*", "anything.example.com"));
        assert!(no_proxy_matches("example.com", "example.com"));
        assert!(no_proxy_matches("example.com", "api.example.com"));
        assert!(no_proxy_matches(".example.com", "api.example.com"));
        assert!(!no_proxy_matches("example.com", "notexample.com"));
        assert!(!no_proxy_matches("api.example.com", "example.com"));
    }

    #[test]
    fn use_proxy_honours_no_proxy_and_loopback() {
        let c = TunnelConnector {
            proxy: cell(Some(ProxyCfg {
                host: "127.0.0.1".into(),
                port: 7778,
                auth: None,
            })),
            no_proxy: Arc::new(vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "internal.corp".into(),
            ]),
        };
        // external host → through the proxy
        assert!(c.use_proxy_for("gmail.googleapis.com", true).is_some());
        // loopback + NO_PROXY host → direct
        assert!(c.use_proxy_for("localhost", true).is_none());
        assert!(c.use_proxy_for("internal.corp", true).is_none());
        assert!(c.use_proxy_for("db.internal.corp", true).is_none());
    }

    #[test]
    fn no_configured_proxy_never_uses_one() {
        let c = TunnelConnector {
            proxy: cell(None),
            no_proxy: Arc::new(vec![]),
        };
        assert!(c.use_proxy_for("gmail.googleapis.com", true).is_none());
    }

    #[test]
    fn swapping_the_shared_cell_repoints_a_live_connector() {
        // The hot-reload contract: an ALREADY-built connector reads the shared
        // cell per-connection, so `/proxy/reload` swapping it in place re-points
        // the forward hop with no rebuild/restart.
        let shared = cell(None);
        let c = TunnelConnector {
            proxy: shared.clone(),
            no_proxy: Arc::new(vec!["localhost".into(), "127.0.0.1".into()]),
        };
        // Starts direct.
        assert!(c.use_proxy_for("gmail.googleapis.com", true).is_none());
        // A `sprott config set proxy` reload swaps the cell…
        *shared.write().unwrap() = Some(Upstream::Given(Arc::new(ProxyCfg {
            host: "127.0.0.1".into(),
            port: 7778,
            auth: None,
        })));
        // …and the same connector now tunnels — without being rebuilt.
        let p = c
            .use_proxy_for("gmail.googleapis.com", true)
            .expect("now proxied");
        assert_eq!((p.host.as_str(), p.port), ("127.0.0.1", 7778));
        // …and a `sprott config unset proxy` reload swaps it back to direct.
        *shared.write().unwrap() = None;
        assert!(c.use_proxy_for("gmail.googleapis.com", true).is_none());
    }

    // ── live socket e2e: the actual thing that was broken ────────────────────
    // A fake backend that greets whoever reaches it, and a fake HTTP proxy that
    // honours CONNECT and tunnels to that backend. Drives the real connector to
    // prove the forward hop travels THROUGH the proxy (the Gmail failure), and
    // that with no proxy it dials the target directly. (AsyncReadExt/AsyncWriteExt
    // come in via `use super::*`.)
    use tokio::net::{TcpListener, TcpStream as TokioTcp};

    const BANNER: &[u8] = b"UPSTREAM-OK";

    /// Bind a backend that writes `BANNER` to every accepted connection.
    async fn spawn_backend() -> u16 {
        let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let _ = s.write_all(BANNER).await;
                let _ = s.flush().await;
            }
        });
        port
    }

    /// Bind an HTTP proxy that accepts one CONNECT, records its target, replies
    /// 200, and tunnels to `backend_port`. Returns `(proxy_port, seen_target)`.
    async fn spawn_proxy(backend_port: u16) -> (u16, Arc<std::sync::Mutex<Option<String>>>) {
        let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(None));
        let seen_w = seen.clone();
        tokio::spawn(async move {
            if let Ok((mut client, _)) = l.accept().await {
                // Read the CONNECT head.
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while client.read(&mut b).await.unwrap_or(0) == 1 {
                    head.push(b[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&head);
                let target = line
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .map(String::from);
                *seen_w.lock().unwrap() = target;
                client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                client.flush().await.unwrap();
                // Tunnel to the real backend (loopback, ignoring the CONNECT host).
                if let Ok(mut backend) = TokioTcp::connect(("127.0.0.1", backend_port)).await {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
                }
            }
        });
        (port, seen)
    }

    #[tokio::test]
    async fn forward_hop_travels_through_the_egress_proxy() {
        let backend_port = spawn_backend().await;
        let (proxy_port, seen) = spawn_proxy(backend_port).await;

        let mut conn = TunnelConnector {
            proxy: cell(Some(ProxyCfg {
                host: "127.0.0.1".into(),
                port: proxy_port,
                auth: None,
            })),
            no_proxy: Arc::new(vec![]), // a non-loopback target so the proxy is used
        };
        // Target host is NOT loopback (else NO_PROXY defaults would force direct);
        // the port carries the backend so the fake proxy tunnels there.
        let uri: Uri = format!("https://api.example.test:{}", backend_port)
            .parse()
            .unwrap();
        let io = conn.call(uri).await.expect("connect via proxy");

        let mut stream = io.into_inner();
        let mut buf = vec![0u8; BANNER.len()];
        stream
            .read_exact(&mut buf)
            .await
            .expect("read banner through tunnel");
        assert_eq!(buf, BANNER, "bytes must arrive through the proxy tunnel");

        // And the proxy must have been asked to reach the real target.
        let target = seen.lock().unwrap().clone().unwrap_or_default();
        assert_eq!(target, format!("api.example.test:{}", backend_port));
    }

    #[tokio::test]
    async fn forward_hop_dials_direct_when_no_proxy() {
        let backend_port = spawn_backend().await;
        let mut conn = TunnelConnector {
            proxy: cell(None),
            no_proxy: Arc::new(vec![]),
        };
        // No proxy configured → connect straight to the backend on loopback.
        let uri: Uri = format!("https://127.0.0.1:{}", backend_port)
            .parse()
            .unwrap();
        let io = conn.call(uri).await.expect("direct connect");
        let mut stream = io.into_inner();
        let mut buf = vec![0u8; BANNER.len()];
        stream
            .read_exact(&mut buf)
            .await
            .expect("read banner direct");
        assert_eq!(buf, BANNER);
    }

    // ── Happy Eyeballs: a hanging first address must not stall the dial ──────
    // The api.cloudflare.com failure: the name resolves IPv6-first, the IPv6
    // route black-holes (connects hang, they are not refused), IPv4 works.
    use hyper_util::client::legacy::connect::dns::Name;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::net::TcpSocket;

    /// Answers every name with a fixed address list, in order.
    #[derive(Clone)]
    struct FixedResolver(Vec<SocketAddr>);

    impl Service<Name> for FixedResolver {
        type Response = std::vec::IntoIter<SocketAddr>;
        type Error = std::io::Error;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _name: Name) -> Self::Future {
            std::future::ready(Ok(self.0.clone().into_iter()))
        }
    }

    /// Fill the accept queue of `listener`, which never accepts, so any further
    /// connect to it hangs: the kernel drops the SYN instead of refusing it, the
    /// way a black-holed route behaves. The returned connections must stay alive.
    async fn fill_accept_queue(listener: &TcpListener) -> Vec<TokioTcp> {
        let addr = listener.local_addr().unwrap();
        let mut queued = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(200), TokioTcp::connect(addr)).await {
                Ok(Ok(s)) => queued.push(s),
                Ok(Err(e)) => panic!("filling the accept queue of {addr}: {e}"),
                Err(_) => return queued, // full: this connect hung
            }
            assert!(queued.len() < 64, "accept queue of {addr} never filled");
        }
    }

    #[test]
    fn authority_brackets_a_bare_ipv6_host() {
        assert_eq!(authority("::1", 7890), "[::1]:7890");
        assert_eq!(authority("[::1]", 7890), "[::1]:7890");
        assert_eq!(authority("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(authority("fe80::1%eth0", 7890), "[fe80::1%eth0]:7890");
        assert_eq!(authority("10.0.0.1", 80), "10.0.0.1:80");
        assert_eq!(authority("api.example.com", 443), "api.example.com:443");
        for (h, p) in [
            ("::1", 7890u16),
            ("[::1]", 7890),
            ("fe80::1%eth0", 7890),
            ("10.0.0.1", 80),
            ("api.example.com", 443),
        ] {
            let uri: Uri = format!("http://{}", authority(h, p))
                .parse()
                .expect("valid authority");
            assert_eq!(uri.port_u16(), Some(p));
        }
    }

    #[tokio::test]
    async fn dial_falls_back_to_ipv4_when_ipv6_hangs() {
        // The connector applies the URI's port to every resolved address, so the
        // working IPv4 listener and the hanging IPv6 one share a port.
        let mut pair = None;
        for _ in 0..20 {
            let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = v4.local_addr().unwrap().port();
            let v6 = match TcpSocket::new_v6() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("skipped: no IPv6 sockets on this machine ({e})");
                    return;
                }
            };
            match v6.bind((Ipv6Addr::LOCALHOST, port).into()) {
                Ok(()) => {
                    pair = Some((v4, v6.listen(1).unwrap(), port));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(e) => {
                    eprintln!("skipped: no IPv6 loopback on this machine ({e})");
                    return;
                }
            }
        }
        let (v4, v6, port) = pair.expect("a port free on both 127.0.0.1 and ::1");
        let ok_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let hang_addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
        tokio::spawn(async move {
            while let Ok((mut s, _)) = v4.accept().await {
                let _ = s.write_all(BANNER).await;
                let _ = s.flush().await;
            }
        });
        let _queued = fill_accept_queue(&v6).await;

        let addrs = vec![hang_addr, ok_addr];
        let bound = CONNECT_TIMEOUT / 4;

        let started = std::time::Instant::now();
        let dialer = tcp_dialer(FixedResolver(addrs.clone()));
        let mut stream = connect_within(
            CONNECT_TIMEOUT,
            "upstream.test",
            port,
            dial(dialer, "upstream.test", port),
        )
        .await
        .expect("dial");
        let took = started.elapsed();
        assert!(took < bound, "dial took {took:?}");
        assert_eq!(stream.peer_addr().unwrap(), ok_addr);
        let mut buf = vec![0u8; BANNER.len()];
        stream.read_exact(&mut buf).await.expect("read banner");
        assert_eq!(buf, BANNER);

        // Control: the IPv6 address really hangs rather than failing fast, so
        // the old one-address-after-another dial is still stuck on it after
        // longer than the dial above took in total.
        assert!(
            tokio::time::timeout(bound, TokioTcp::connect(&addrs[..]))
                .await
                .is_err(),
            "a sequential dial must still be waiting on {hang_addr}"
        );
    }

    #[tokio::test]
    async fn timed_out_dial_reads_forward_connect_timed_out() {
        // A dial whose only address hangs, cut short either by the dialer's own
        // connect timeout or by the outer bound: the agent sees the same text.
        let sock = TcpSocket::new_v4().unwrap();
        sock.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let hang = sock.listen(1).unwrap();
        let _queued = fill_accept_queue(&hang).await;
        let hang_addr = hang.local_addr().unwrap();
        let port = hang_addr.port();
        let want = format!("forward connect to upstream.test:{port} timed out");

        let short = Duration::from_millis(300);
        for (dialer_timeout, outer) in [(short, CONNECT_TIMEOUT), (CONNECT_TIMEOUT, short)] {
            let mut dialer = tcp_dialer(FixedResolver(vec![hang_addr]));
            dialer.set_connect_timeout(Some(dialer_timeout));
            let started = std::time::Instant::now();
            let err = connect_within(
                outer,
                "upstream.test",
                port,
                dial(dialer, "upstream.test", port),
            )
            .await
            .expect_err("a hanging address cannot connect");
            assert_eq!(err.to_string(), want);
            assert!(started.elapsed() < CONNECT_TIMEOUT / 4);
        }
    }
}
