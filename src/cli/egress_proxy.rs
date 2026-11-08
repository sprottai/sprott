//! Device-level EGRESS proxy: the ONE upstream HTTP proxy that BOTH the daemon
//! and this CLI use to reach every remote host — the Sprott backend (pairing,
//! `sc agent`, sync), third-party OAuth code/refresh exchanges, the resident MITM
//! proxy's forward hop, and `sc upgrade`'s GitHub fetch. Only loopback is exempt
//! (pinned into `NO_PROXY` by `proxy_env::pin_localhost_no_proxy`); every other
//! destination follows the proxy, exactly the way curl/git/Docker behave.
//!
//! WHY this exists separate from the child-facing proxy (`proxy_env`): the
//! macOS launchd agent (and the systemd unit) do NOT inherit the operator's
//! shell `HTTPS_PROXY`, and both unit generators whitelist only `SPROTT_*`, so
//! a `$HTTPS_PROXY` set in a terminal never reaches the long-running daemon.
//! Agents behind a corporate/on-demand proxy (and users in regions that can only
//! reach the Sprott backend through a proxy) therefore need a persisted,
//! device-level value the daemon — and every short-lived `sc` command — can read
//! on its own, without depending on the current shell.
//!
//! Model (deliberately the standard one — Docker/systemd/git all do this): the
//! proxy is CONFIGURED at the device level, persisted in a file, and applied to
//! the process env at startup BEFORE any HTTP client is built (reqwest honours
//! `*_PROXY` natively, so one env shaping covers every client). `sprott config set proxy`
//! writes it + bounces the daemon; changing it is a service-config change, not a
//! per-request knob. An explicit shell `HTTPS_PROXY` still WINS (env > config),
//! so this only fills the gap, never overrides an operator who set it directly.
//! Hosts that must stay direct (e.g. a narrow proxy that can't reach us) go in
//! the operator's own `NO_PROXY` — we never silently carve the backend out.
//!
//! LIVE FOLLOW (so a proxied agent just works without `sprott config set proxy`): every
//! `sc run` reports its shell proxy to the daemon's in-memory ambient slot (see
//! [`ambient`] / [`set_ambient`] and `POST /proxy/ambient`). The daemon then
//! follows the operator's CURRENT shell proxy, nothing is persisted, and a shell
//! with no proxy simply falls back to the file. `sprott config set proxy` stays the
//! explicit override and the only option for a headless/remote daemon that no
//! `sc run` ever reports to. Ambient and file are ONE resolver ([`effective`]),
//! not two mechanisms — ambient is just the env tier kept live instead of frozen.
//!
//! THE COMPUTER'S SETTINGS (the default when neither is set): every client then
//! follows this computer's own proxy settings, the ones its browser uses, read
//! by the community implementation reqwest ships (`system-proxy`, i.e. hyper-util
//! `Matcher::from_system`): the process's `*_PROXY` variables, then macOS System
//! Settings or Windows Internet Settings. The daemon re-reads them while it runs
//! and swaps its clients when they change (`proxy::upstream::spawn_system_proxy_watch`),
//! so turning a proxy app on or off needs no restart and no `sprott config`.
//! Precedence, highest first: the live shell proxy, `sprott config set proxy`,
//! the computer's settings, direct.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};

use crate::config::default_state_dir;

/// The LIVE "ambient" egress proxy: the operator's shell proxy, kept CURRENT.
///
/// In a short-lived `sc` process this is SEEDED once from that process's own
/// shell at startup (`apply_to_env`) and never changes — so `effective()` is
/// still "this shell's proxy, else the file", exactly as before. In the
/// long-running daemon it is seeded from the daemon's OWN startup env (empty
/// under systemd/launchd, which don't inherit a shell) and then REFRESHED by
/// every `sc run`, which reports its shell proxy to `POST /proxy/ambient`. That
/// is what lets the daemon follow the operator's live proxy state with NO
/// persisted `sprott config set proxy`, and with no stale-value risk: it is in-memory only,
/// so a restart clears it and the next `sc run` re-seeds it.
///
/// `Some(url)` = an ambient proxy to use; `None` = none reported, fall through
/// to the file. Starts `None` (unseeded) until `apply_to_env` runs — so a unit
/// test that never calls it sees `effective()` == the file, as before.
static AMBIENT: RwLock<Option<String>> = RwLock::new(None);

/// Set by [`apply_to_env`] in the daemon: only the daemon routes its clients
/// through [`effective`] ([`crate::util::http_builder`]).
static DAEMON: AtomicBool = AtomicBool::new(false);

/// The env keys [`apply_to_env`] filled from the stored proxy in this
/// process: not the operator's shell, so a daemon this process starts must
/// not inherit them ([`injected_env_keys`]).
static INJECTED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

/// The proxy variables, in the order reqwest reads them.
const PROXY_KEYS: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Persisted egress-proxy URL location: `<state_dir>/egress-proxy` (one line, the
/// URL). Absent/empty = no configured egress proxy.
pub fn path() -> std::path::PathBuf {
    default_state_dir().join("egress-proxy")
}

/// The configured egress-proxy URL, or `None` when unset. Trims whitespace and
/// treats an empty file as unset.
pub fn load() -> Option<String> {
    let s = std::fs::read_to_string(path()).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Persist `url` as the device egress proxy (0600 — it may carry proxy
/// userinfo). Overwrites any prior value.
pub fn store(url: &str) -> Result<(), String> {
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
    }
    std::fs::write(&p, format!("{}\n", url.trim()))
        .map_err(|e| format!("write {}: {}", p.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Remove the configured egress proxy (no-op if already absent).
pub fn clear() -> Result<(), String> {
    match std::fs::remove_file(path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {}", path().display(), e)),
    }
}

/// Apply the configured egress proxy to THIS process's environment before any
/// HTTP client is built. No-op when nothing is configured. Called at startup for
/// every `sc` invocation (daemon + CLI) so `serve`'s clients and `sc upgrade`'s
/// GitHub fetch both honour it. An already-set `HTTPS_PROXY` in the real env
/// takes precedence and is left untouched (env > config).
pub fn apply_to_env(daemon: bool) {
    // Seed the ambient proxy from THIS process's REAL shell BEFORE we fill env
    // slots from the file, so `effective()` keeps env > config even after this
    // pollutes the env. Only seed an empty slot: a `/proxy/ambient` push that
    // already set a live value (daemon) must not be clobbered by a later call.
    {
        let mut a = AMBIENT.write().unwrap();
        if a.is_none() {
            *a = shell_proxy_now();
        }
    }
    // The daemon routes every client through `effective()` (via
    // `util::http_builder`), and follows the computer's own proxy settings when
    // nothing is set. Writing the stored value into its env would make a later
    // `sprott config unset proxy` linger there and shadow those settings.
    if daemon {
        DAEMON.store(true, Ordering::SeqCst);
        return;
    }
    // Any other process leaves routing to reqwest, which reads these
    // variables itself (per scheme, with NO_PROXY), then the computer's
    // settings: the stored proxy fills only the slots the shell left empty,
    // so the shell proxy wins, then the stored one, then the computer's.
    let Some(url) = load() else { return };
    let mut injected = INJECTED.lock().unwrap();
    for key in empty_proxy_slots(|k| std::env::var_os(k)) {
        std::env::set_var(key, &url);
        if !injected.contains(&key) {
            injected.push(key);
        }
    }
    // NB: we do NOT pin the Sprott backend into NO_PROXY. A configured proxy
    // applies to every remote host (backend included) — the mainstream
    // convention, and the only behaviour that works for operators who can reach
    // us *only* through a proxy. Loopback stays direct via
    // `proxy_env::pin_localhost_no_proxy`; any other exceptions are the
    // operator's own `NO_PROXY` to make.
}

/// The proxy variables the operator's shell left unset or empty (`get`
/// reads one): the only ones the stored proxy may fill (pure).
fn empty_proxy_slots(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> Vec<&'static str> {
    PROXY_KEYS
        .into_iter()
        .filter(|k| get(k).is_none_or(|v| v.is_empty()))
        .collect()
}

/// Is this process the daemon (its clients route through [`effective`])?
pub fn is_daemon() -> bool {
    DAEMON.load(Ordering::SeqCst)
}

/// The proxy variables [`apply_to_env`] set in this process from the stored
/// proxy. A daemon started from here gets them removed: they are not the
/// operator's shell, and the daemon reads the stored proxy itself (so a later
/// `sprott config unset proxy` applies to it).
pub fn injected_env_keys() -> Vec<&'static str> {
    INJECTED.lock().unwrap().clone()
}

/// The egress proxy the DAEMON's own swappable clients (the shared reqwest
/// client + the resident proxy's forward connector) should use RIGHT NOW,
/// honouring env > config: the live ambient proxy (the shell proxy `sc run`
/// last reported, or this process's own shell) wins; otherwise the stored file,
/// re-read FRESH so a runtime `sprott config set proxy` (which rewrites the file) or an
/// ambient push takes effect via `/proxy/reload` / `/proxy/ambient` with no
/// restart. Falls back to [`load`] when nothing ambient is set.
pub fn effective() -> Option<String> {
    let ambient = AMBIENT.read().unwrap();
    let file = load();
    resolve(ambient.as_deref(), file.as_deref())
}

/// Pure precedence: the ambient (live shell / pushed) proxy wins over the stored
/// file, both over a direct route. Split out so the ordering is unit-testable
/// without touching the process-global `AMBIENT` (a global-mutating test would
/// be flaky under parallel runs).
fn resolve(ambient: Option<&str>, file: Option<&str>) -> Option<String> {
    ambient.or(file).map(str::to_string)
}

/// The live ambient egress proxy this process currently holds, WITHOUT the file
/// fallback. `sc run` reads it to report its shell proxy to the daemon: in a CLI
/// process this is exactly the shell proxy captured at startup (the file is the
/// daemon's own concern, so it must not be folded in here). `None` = this shell
/// has no proxy, which tells the daemon to fall through to its file config.
pub fn ambient() -> Option<String> {
    AMBIENT.read().unwrap().clone()
}

/// Set the live ambient egress proxy — the daemon's `/proxy/ambient` handler
/// calls this when an `sc run` reports its shell proxy. Returns whether the
/// value CHANGED, so the caller can skip a client rebuild when it didn't. Never
/// persists: purely in-memory, so it can never strand the daemon across a
/// restart the way a stale file could.
pub fn set_ambient(proxy: Option<String>) -> bool {
    let mut a = AMBIENT.write().unwrap();
    if *a == proxy {
        return false;
    }
    *a = proxy;
    true
}

/// Apply the egress route to a reqwest client builder: the single place every
/// HTTP client agrees on how it reaches the internet. `Some(url)` = the proxy
/// Sprott was given; setting it also turns off reqwest's own detection, so
/// this fully owns the routing. `None` = follow this computer's proxy settings
/// (see the match arm). Loopback and any operator `NO_PROXY` stay direct; a
/// malformed proxy URL logs and falls back to a direct dial.
pub fn apply(b: reqwest::ClientBuilder, proxy: Option<&str>) -> reqwest::ClientBuilder {
    match proxy {
        Some(url) => match reqwest::Proxy::all(url) {
            Ok(p) => {
                let p = match std::env::var("NO_PROXY")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| reqwest::NoProxy::from_string(&s))
                {
                    Some(np) => p.no_proxy(Some(np)),
                    None => p,
                };
                b.proxy(p)
            }
            Err(e) => {
                tracing::warn!(
                    "egress proxy '{}' is not a valid proxy URL ({}) — dialing directly",
                    url,
                    e
                );
                b.no_proxy()
            }
        },
        // Nothing given to Sprott: follow this computer's proxy settings.
        // reqwest's `system-proxy` (hyper-util `Matcher::from_system`) reads the
        // `*_PROXY` variables of this process, then the OS settings: macOS
        // System Settings, Windows Internet Settings. The daemon puts no proxy
        // of its own into its env (`apply_to_env`), so a value cleared at
        // runtime can't linger there; what it reads is the computer's.
        None => b,
    }
}

/// Apply the currently-[`effective`] egress proxy to a client builder. Because
/// `effective()` re-reads the stored value FRESH, a `sprott config set proxy` that ran
/// after the daemon started (via `/proxy/reload`, no restart) is honoured by the
/// very next client built through here — the whole point of the hot path.
pub fn apply_effective(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    apply(b, effective().as_deref())
}

/// The one constructor for the daemon's per-call cloud clients (sync loops,
/// op-relay): an HTTP client with the effective device egress proxy applied and
/// the given overall timeout. Routing sync/relay through here is what makes
/// `sprott config set proxy` reach them without a daemon restart — see the module header.
pub fn client(timeout: std::time::Duration) -> reqwest::Result<reqwest::Client> {
    crate::util::http_builder()
        .timeout(timeout)
        .default_headers(version_headers())
        .build()
}

/// Every cloud call announces the binary version (team §8.3: the backend's
/// format gate + the /admin version census read it). One constant header —
/// no fingerprinting surface beyond what User-Agent already carries.
fn version_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Ok(v) = reqwest::header::HeaderValue::from_str(env!("CARGO_PKG_VERSION")) {
        h.insert("x-sprott-version", v);
    }
    h
}

/// The constructor for the daemon's STREAMING cloud connection (the SSE sync
/// stream, design/sse-sync.md): same fresh-proxy contract as [`client`]
/// — built per (re)connect, so a runtime `sprott config set proxy` is honoured at the
/// very next dial — but with ONLY a connect budget. A total `.timeout()` here
/// would be a bug: it fires mid-body and would kill a healthy held-open
/// stream at the deadline. Liveness on the open stream is the caller's job
/// (sync_stream's 45s no-bytes watchdog).
pub fn client_streaming(connect: std::time::Duration) -> reqwest::Result<reqwest::Client> {
    crate::util::http_builder()
        .connect_timeout(connect)
        .default_headers(version_headers())
        .build()
}

/// A proxy URL with any `user:password@` removed, for logs, replies and
/// reports. A proxy URL can carry credentials; nothing Sprott prints or logs
/// may include them.
pub fn redact(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
            format!("{scheme}://{host}")
        }
        None => url
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(url)
            .to_string(),
    }
}

/// The first non-empty proxy variable in THIS process's env right now. Read once by
/// `apply_to_env` before it shapes env, so it reflects the operator's shell.
fn shell_proxy_now() -> Option<String> {
    for key in PROXY_KEYS {
        if let Some(v) = std::env::var_os(key) {
            let v = v.to_string_lossy().trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {

    #[test]
    fn redact_drops_userinfo_keeps_host_port() {
        assert_eq!(redact("http://u:p@box:9999"), "http://box:9999");
        assert_eq!(redact("http://proxy.local:3128"), "http://proxy.local:3128");
        assert_eq!(redact("box:9999"), "box:9999");
        assert_eq!(redact("u:p@box:9999"), "box:9999");
    }
    use super::*;

    #[test]
    fn resolve_prefers_ambient_then_file_then_direct() {
        // Ambient (live shell / pushed) wins over the file...
        assert_eq!(
            resolve(Some("http://a"), Some("http://b")).as_deref(),
            Some("http://a")
        );
        // ...file is the fallback when nothing ambient is set...
        assert_eq!(resolve(None, Some("http://b")).as_deref(), Some("http://b"));
        // ...ambient alone still routes...
        assert_eq!(resolve(Some("http://a"), None).as_deref(), Some("http://a"));
        // ...and neither = direct.
        assert_eq!(resolve(None, None), None);
    }

    /// The stored proxy fills only the variables the shell left unset or
    /// empty (the shell proxy wins), and those are the ones a daemon started
    /// from this process must not inherit.
    #[test]
    fn the_stored_proxy_fills_only_empty_slots() {
        let shell = |k: &str| match k {
            "HTTPS_PROXY" => Some(std::ffi::OsString::from("http://shell:1")),
            "http_proxy" => Some(std::ffi::OsString::new()),
            _ => None,
        };
        assert_eq!(
            empty_proxy_slots(shell),
            vec!["https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
        );
        assert_eq!(empty_proxy_slots(|_| None).len(), PROXY_KEYS.len());
    }

    /// Only the daemon routes through `effective()`; a process that never
    /// declared itself the daemon (any CLI command, a unit test) leaves the
    /// route to reqwest's own reading of its env and the computer's settings.
    #[test]
    fn only_the_daemon_routes_through_the_effective_proxy() {
        assert!(!is_daemon());
    }
}
