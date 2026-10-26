//! `sc config set/get/unset/ls` — persistent preferences.
//!
//! - `cb-port`: `~/.sprott/config.toml` `[settings]`, the fallback for
//!   `--cb-port`. Resolution chain: flag > `SPROTT_CB_PORT` > this > default.
//! - `proxy`: the device's upstream EGRESS proxy, stored in its own file
//!   ([`egress_proxy`]) because the daemon reads it too. The daemon runs under
//!   launchd/systemd and does NOT inherit the operator's shell `HTTPS_PROXY`, so
//!   behind a corporate or on-demand proxy its own egress (OAuth code/refresh
//!   exchange, the resident proxy's forward hop, `sc upgrade`) would hit the
//!   internet directly and time out. Setting or clearing it HOT-reloads the
//!   running daemon (`POST /proxy/reload`), which rebuilds its egress clients
//!   in place: instant, with NO restart and NO vault re-unlock.
//!
//! Keys are kebab-case on the CLI (matches the flag names),
//! snake_case in the TOML file (Rust convention).

use crate::cli::active::{load, save};
use crate::cli::{active, egress_proxy, service};
use crate::config::ConfigSubcommand;

pub async fn run(sub: ConfigSubcommand) -> Result<(), String> {
    match sub {
        ConfigSubcommand::Set { key, value } => run_set(&key, &value).await,
        ConfigSubcommand::Get { key } => run_get(&key),
        ConfigSubcommand::Unset { key } => run_unset(&key).await,
        ConfigSubcommand::Ls => run_ls(),
    }
}

async fn run_set(key: &str, value: &str) -> Result<(), String> {
    let mut cfg = load().unwrap_or_default();
    match canonical_key(key)? {
        Key::CbPort => {
            let n: u16 = value
                .parse()
                .map_err(|_| format!("cb-port must be a 1..=65535 integer, got {:?}", value))?;
            cfg.settings.cb_port = Some(n);
        }
        Key::Proxy => return set_proxy(value).await,
    }
    let path = save(&cfg)?;
    println!("set {} = {}  ({})", key, value, path.display());
    Ok(())
}

fn run_get(key: &str) -> Result<(), String> {
    let cfg = load().unwrap_or_default();
    match canonical_key(key)? {
        Key::CbPort => match cfg.settings.cb_port {
            Some(n) => {
                println!("{}", n);
                Ok(())
            }
            None => Err(format!("{} is not set", key)),
        },
        Key::Proxy => match egress_proxy::load() {
            Some(url) => {
                println!("{url}");
                // A real shell HTTPS_PROXY overrides the stored value (env >
                // config). Note it so the effective route is never a surprise.
                if let Some(shell) = std::env::var_os("HTTPS_PROXY").filter(|v| !v.is_empty()) {
                    let shell = shell.to_string_lossy();
                    if shell != url {
                        eprintln!(
                            "note: your shell HTTPS_PROXY ({shell}) overrides this for `sprott` \
                             itself; the daemon uses the value above."
                        );
                    }
                }
                Ok(())
            }
            None => Err(format!("{} is not set", key)),
        },
    }
}

async fn run_unset(key: &str) -> Result<(), String> {
    let mut cfg = load().unwrap_or_default();
    let was = match canonical_key(key)? {
        Key::CbPort => cfg.settings.cb_port.take().map(|v| v.to_string()),
        Key::Proxy => return unset_proxy(key).await,
    };
    save(&cfg)?;
    match was {
        Some(prev) => println!("unset {} (was {})", key, prev),
        None => println!("{} was already unset", key),
    }
    Ok(())
}

fn run_ls() -> Result<(), String> {
    let cfg = load().unwrap_or_default();
    let mut any = false;
    if let Some(n) = cfg.settings.cb_port {
        println!("cb-port = {}", n);
        any = true;
    }
    if let Some(url) = egress_proxy::load() {
        println!("proxy = {}", url);
        any = true;
    }
    if !any {
        println!("(no settings yet; try `sprott config set cb-port 23394`)");
    }
    Ok(())
}

enum Key {
    CbPort,
    Proxy,
}

fn canonical_key(key: &str) -> Result<Key, String> {
    match key.replace('_', "-").to_ascii_lowercase().as_str() {
        "cb-port" => Ok(Key::CbPort),
        "proxy" => Ok(Key::Proxy),
        other => Err(format!(
            "unknown setting: {:?}. Known keys: cb-port, proxy",
            other
        )),
    }
}

/// Accept a bare `host:port` as `http://host:port`; leave a full URL as-is.
fn normalize_proxy(url: &str) -> String {
    let u = url.trim();
    if u.contains("://") {
        u.to_string()
    } else {
        format!("http://{}", u)
    }
}

async fn set_proxy(value: &str) -> Result<(), String> {
    let url = normalize_proxy(value);
    if egress_proxy::load().as_deref() == Some(url.as_str()) {
        println!("proxy is already {url}");
        return Ok(());
    }
    egress_proxy::store(&url)?;
    println!("set proxy = {}  ({})", url, egress_proxy::path().display());
    apply_proxy_live().await
}

async fn unset_proxy(key: &str) -> Result<(), String> {
    let Some(prev) = egress_proxy::load() else {
        println!("{} was already unset", key);
        return Ok(());
    };
    egress_proxy::clear()?;
    println!(
        "unset {} (was {}); the daemon reaches the internet directly",
        key, prev
    );
    apply_proxy_live().await
}

/// Hot-reload the running daemon's egress clients (`POST /proxy/reload`) so the
/// new proxy applies immediately — no restart, no vault re-unlock. When no
/// daemon is installed/reachable yet, the stored value is picked up by the first
/// `sc up`. A reload failure is never fatal (the value is already persisted);
/// we just tell the user how it'll take effect.
async fn apply_proxy_live() -> Result<(), String> {
    if !service::unit_installed() {
        eprintln!("  (no daemon installed yet; it'll take effect on `sprott up`.)");
        return Ok(());
    }
    let cfg = active::load().unwrap_or_default();
    let url = format!(
        "{}/proxy/reload",
        active::control_root(&cfg).trim_end_matches('/')
    );
    let client = match crate::util::http_builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Err(format!("http client: {}", e)),
    };
    match client.post(&url).send().await {
        Ok(r) if r.status().is_success() => {
            eprintln!("  Applied to the running daemon (no restart).");
            Ok(())
        }
        Ok(r) => {
            eprintln!(
                "  (daemon returned HTTP {}; restart to apply: `sprott restart`)",
                r.status()
            );
            Ok(())
        }
        Err(_) => {
            eprintln!("  (daemon not reachable; it'll take effect on next `sprott up`.)");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_is_a_config_key() {
        assert!(matches!(canonical_key("proxy"), Ok(Key::Proxy)));
        assert!(matches!(canonical_key("PROXY"), Ok(Key::Proxy)));
        assert!(matches!(canonical_key("cb_port"), Ok(Key::CbPort)));
        let err = canonical_key("nope").err().unwrap();
        assert!(err.contains("cb-port, proxy"), "{err}");
        assert_eq!(normalize_proxy("127.0.0.1:7778"), "http://127.0.0.1:7778");
        assert_eq!(normalize_proxy(" https://p:1 "), "https://p:1");
    }
}
