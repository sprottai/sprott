//! `sprott set <KEY> <VALUE>` / `sprott get <KEY>` / `sprott rm <KEY>`
//!
//! Every verb drives ONE op through the shared approval path
//! (`cli::approve::approve_op`): paired → the cloud `/grant/{op_id}` link,
//! self-host → the local on-box ceremony. For `set`, the VALUE is deposited
//! with the local daemon first (`deposit_values`) and the op carries only its
//! salted digest — plaintext never rides the op (which travels to the cloud
//! grant page), and one passkey approval covers the whole write.

use std::collections::BTreeMap;
use std::io::IsTerminal;

use serde_json::json;

use crate::cli::active::resolve_active;
use crate::cli::approve::{act_result, approve_op, deposit_values, ApproveOpts};
use crate::cli::conn::{valid_conn_id, valid_role, validate_raw_host};
use crate::cli::webauthn::*;
use crate::config::{GetArgs, RmArgs, SetArgs};

/// What `sc set` does with the item's broker binding.
enum BrokerIntent {
    /// Blank Enter at the prompt: write the VALUE only and leave any existing
    /// host binding exactly as it is (a new key simply has none yet). This is
    /// the rotation fast-path — never touches the trust surface.
    Unspecified,
    /// Explicit `none` / `--no-broker`: store with NO host, REMOVING any prior
    /// anchor — human-only, invisible to the agent.
    NoBroker,
    /// Create a raw connection anchored to these exact FQDNs.
    Host(Vec<String>),
}

pub async fn run_set(args: SetArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    // §1: secret KEYs are ALWAYS uppercase. Force-uppercase on input (a lowercase
    // key is auto-converted, never stored lowercase) so there is one canonical
    // form. Reject anything that isn't a valid env KEY even after uppercasing.
    let key = args.key.trim().to_ascii_uppercase();
    if !valid_role(&key) {
        return Err(format!(
            "'{}' is not a valid secret key. Use UPPERCASE letters, digits and '_' (e.g. STRIPE_KEY)",
            args.key.trim()
        ));
    }

    // Value: explicit arg, `-` = stdin, else hidden TTY prompt, else (non-TTY)
    // an error.
    let value = match args.value.as_deref() {
        Some("-") => read_value_arg(&key)?,
        Some(v) => v.to_string(),
        None => prompt_secret_value(&key)?,
    };

    // Broker intent: --no-broker | --host <h..> | (TTY) prompt | (non-TTY) error.
    // Rewriting a key that already exists is a value change: its bindings stay
    // as they are, so the host question is skipped. Unknown (locked vault, old
    // daemon) still asks.
    let exists = args.host.is_empty()
        && !args.no_broker
        && key_exists(&custodian, &vault, &key).await == Some(true);
    let intent = if exists {
        BrokerIntent::Unspecified
    } else {
        resolve_broker_intent(&key, &args.host, args.no_broker)?
    };

    // The single-secret sugar: the connection id is the lowercased key — a plain
    // handle (safe now that `secrets` is stored explicitly, no reverse-index
    // coupling — §9). Validate the id + anchor hosts BEFORE spending a passkey
    // gesture — an invalid --host must not cost the user an unlock touch.
    let conn = key.to_ascii_lowercase();
    if let BrokerIntent::Host(hosts) = &intent {
        if !valid_conn_id(&conn) {
            return Err(format!(
                "can't derive a connection id from '{}'; use `sprott connection add <name> --host {} --from-literal {}=<value>` instead",
                key,
                hosts.first().map(String::as_str).unwrap_or("<domain>"),
                key
            ));
        }
        for h in hosts {
            validate_raw_host(h)?;
        }
    }

    // Fast-path: while the vault is UNLOCKED the daemon writes the secret
    // directly under its resident K — no op, no passkey. Only a LOCKED vault
    // needs the grant ceremony below (which unlocks + writes). The value rides
    // the local control plane only, never the cloud.
    let (hosts_arg, no_broker_arg) = match &intent {
        BrokerIntent::Unspecified => (Vec::new(), false), // value only, binding untouched
        BrokerIntent::NoBroker => (Vec::new(), true),
        BrokerIntent::Host(h) => (h.clone(), false),
    };
    if let Some(body) = crate::cli::approve::set_secret_unlocked(
        &custodian,
        &vault,
        &key,
        &value,
        &hosts_arg,
        no_broker_arg,
    )
    .await?
    {
        print_set_result(&key, &conn, &intent, &body);
        return Ok(());
    }

    // Locked → deposit the value with the LOCAL daemon; only its salted digest
    // rides the op (the op JSON travels to the cloud grant page — value must not).
    let mut values = BTreeMap::new();
    values.insert(key.clone(), value);
    let digest = deposit_values(&custodian, &vault, &values).await?;

    let mut scope = json!({ "values_digest": digest });
    match &intent {
        // Unspecified: neither flag — the daemon writes the value and leaves
        // any existing binding exactly as it is.
        BrokerIntent::Unspecified => {}
        BrokerIntent::NoBroker => scope["no_broker"] = json!(true),
        BrokerIntent::Host(hosts) => scope["hosts"] = json!(hosts),
    }
    let op = json!({
        "act": { "type": { "custom": "secret-set" }, "target": key, "scope": scope },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
        return_after_remote_link: false,
    };
    let body = approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Store secret {}", key),
        &opts,
    )
    .await?;

    let result = act_result(&body);
    print_set_result(&key, &conn, &intent, &result);
    Ok(())
}

/// Print the `sc set` outcome as one line. `result` is the unlocked fast-path
/// response or the ceremony's `act_result(body)`; both carry `existed`,
/// `used_by`, `hosts` and `removed_prior_anchor` (an older daemon omits the
/// first two, so the line then says only what is known).
fn print_set_result(key: &str, conn: &str, intent: &BrokerIntent, result: &serde_json::Value) {
    let strs = |field: &str| -> Vec<String> {
        result
            .get(field)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let existed = result.get("existed").and_then(|v| v.as_bool());
    let verb = if existed == Some(true) { "updated" } else { "saved" };
    let detail = match intent {
        BrokerIntent::Unspecified => {
            let used_by = strs("used_by");
            let hosts = strs("hosts");
            if !used_by.is_empty() {
                Some(format!("used by {}", used_by.join(", ")))
            } else if !hosts.is_empty() {
                Some(format!("for {}", hosts.join(", ")))
            } else if result.get("used_by").is_some() {
                Some("no host, the agent can't use it yet".to_string())
            } else {
                None
            }
        }
        BrokerIntent::NoBroker => {
            let removed = result
                .get("removed_prior_anchor")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Some(if removed {
                "host removed, humans only".to_string()
            } else {
                "humans only, the agent can't use it".to_string()
            })
        }
        BrokerIntent::Host(hosts) => Some(format!(
            "for {} · phantom {}",
            hosts.join(", "),
            crate::core::host::short_phantom(conn)
        )),
    };
    match detail {
        Some(d) => eprintln!("{} {} · {}", key, verb, d),
        None => eprintln!("{} {}", key, verb),
    }
}

/// Whether `key` is already a native secret in `vault`. `None` when the daemon
/// can't say (locked vault, unreachable, older daemon): the caller then asks.
async fn key_exists(custodian: &str, vault: &str, key: &str) -> Option<bool> {
    let url = format!(
        "{}/v/{}/secret-keys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let client = crate::util::http_builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let names = body.get("native_keys")?.as_array()?;
    Some(names.iter().any(|n| n.as_str() == Some(key)))
}

/// Decide the broker binding for `sc set`. Host is a REQUIRED answer (spec §11):
/// `--no-broker` / `--host none` opt out explicitly; otherwise `--host` anchors;
/// missing on a TTY → prompt; missing off a TTY → a clear error naming both
/// fixes (never hang, never silently store an unusable item).
fn resolve_broker_intent(
    key: &str,
    host: &[String],
    no_broker: bool,
) -> Result<BrokerIntent, String> {
    if no_broker {
        return Ok(BrokerIntent::NoBroker);
    }
    // `--host none` is the explicit opt-out sentinel.
    if host.len() == 1 && host[0].eq_ignore_ascii_case("none") {
        return Ok(BrokerIntent::NoBroker);
    }
    if !host.is_empty() {
        return Ok(BrokerIntent::Host(host.to_vec()));
    }
    if std::io::stdin().is_terminal() {
        let entered = prompt_host(key)?;
        // Blank Enter = "skip this question": write the value, leave any
        // existing binding untouched (a rotation must never silently drop the
        // anchor). Removing a binding stays EXPLICIT: `none` / `--no-broker`.
        if entered.is_empty() {
            return Ok(BrokerIntent::Unspecified);
        }
        if entered.eq_ignore_ascii_case("none") {
            return Ok(BrokerIntent::NoBroker);
        }
        Ok(BrokerIntent::Host(vec![entered]))
    } else {
        Err(format!(
            "'{}' needs a host so the agent can use it. Pass `--host <domain>` (the API's domain, e.g. api.stripe.com), or `--no-broker` to store it for humans only",
            key
        ))
    }
}

/// Largest secret value read from stdin (matches the daemon's write cap).
const MAX_STDIN_VALUE_BYTES: u64 = 64 * 1024;

/// The value `-` (`sprott set KEY -`, `--from-literal SLOT=-`): read it from
/// stdin, the way that keeps it out of `ps` and shell history off a terminal.
/// On a terminal there is nothing piped, so it is the hidden prompt instead.
/// Drops one trailing newline (`echo` adds it). One stdin per command, so a
/// caller with several values allows `-` once.
pub(crate) fn read_value_arg(label: &str) -> Result<String, String> {
    use std::io::Read as _;
    if std::io::stdin().is_terminal() {
        return prompt_secret_value(label);
    }
    let mut buf = Vec::new();
    std::io::stdin()
        .take(MAX_STDIN_VALUE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {} from stdin: {}", label, e))?;
    stdin_value(buf, label)
}

/// The bytes read from stdin as the value: at most the cap, UTF-8, one
/// trailing newline (`\n` or `\r\n`) dropped, not empty.
fn stdin_value(buf: Vec<u8>, label: &str) -> Result<String, String> {
    if buf.len() as u64 > MAX_STDIN_VALUE_BYTES {
        return Err(format!(
            "{} on stdin is over {} bytes",
            label, MAX_STDIN_VALUE_BYTES
        ));
    }
    let mut v = String::from_utf8(buf).map_err(|_| format!("{} on stdin is not UTF-8", label))?;
    if v.ends_with('\n') {
        v.pop();
        if v.ends_with('\r') {
            v.pop();
        }
    }
    if v.is_empty() {
        return Err(format!("no value for {} on stdin", label));
    }
    Ok(v)
}

/// Hidden value prompt (TTY only — keeps the secret out of shell history / `ps`).
fn prompt_secret_value(key: &str) -> Result<String, String> {
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "no value given for '{}'. Pass it as an argument, or `-` to read it from stdin",
            key
        ));
    }
    let v = rpassword::prompt_password(format!("Value for {} (hidden): ", key))
        .map_err(|e| format!("read value: {}", e))?;
    if v.is_empty() {
        return Err("value cannot be empty".into());
    }
    Ok(v)
}

/// Host prompt (new keys only). Blank is a first-class answer (value only,
/// existing binding untouched), so pressing Enter never errors. `none` still
/// opts out explicitly; `--help` documents it, the prompt stays one line.
fn prompt_host(key: &str) -> Result<String, String> {
    use std::io::Write as _;
    eprint!("API host for {} (e.g. api.stripe.com; Enter to skip): ", key);
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read host: {}", e))?;
    Ok(line.trim().to_string())
}

pub async fn run_rm(args: RmArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    // §1: secret KEYs are canonical uppercase — normalize on input so `sc rm
    // github_token` finds the stored `GITHUB_TOKEN`.
    let key = args.key.trim().to_ascii_uppercase();
    if key.is_empty() {
        return Err("key required".into());
    }
    // Anti-fat-finger confirm BEFORE the gesture (the grant page also names the
    // op). The referenced-by detail is reported AFTER — the daemon computes it
    // while it holds the open vault. The KEY name rides the op (public); the
    // value never leaves the vault.
    if !args.yes && std::io::stdin().is_terminal() {
        let ans = crate::cli::connect::prompt_line(&format!("Remove key '{}'? [y/N]: ", key))?;
        if !matches!(ans.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("aborted");
            return Ok(());
        }
    }
    let op = json!({
        "act": { "type": { "custom": "secret-rm" }, "target": key, "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
        return_after_remote_link: false,
    };
    let body = approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Remove key {}", key),
        &opts,
    )
    .await?;

    let refs: Vec<String> = act_result(&body)
        .get("referenced_by")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !refs.is_empty() {
        eprintln!(
            "note: {} is referenced by connection(s): {}. They turn unconfigured until the key is re-added",
            key,
            refs.join(", ")
        );
    }
    println!("key '{}' removed", key);
    Ok(())
}

pub async fn run_get(args: GetArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    // Case-SENSITIVE exact match — the mainstream convention for env vars and
    // secret managers (GCP/AWS/Vault). `get` reads across ALL stores: native
    // keys are canonical UPPERCASE, but external stores (GCP Secret Manager)
    // preserve their own casing, so a lowercase name like `xh-gcp-test` is only
    // reachable verbatim. We do NOT uppercase here (that would make external
    // lowercase secrets unreadable); `sc get github_token` must be typed as the
    // stored `GITHUB_TOKEN`.
    let key = args.key.trim().to_string();
    if key.is_empty() {
        return Err("key cannot be empty".into());
    }

    let op = json!({
        "act": { "type": "export", "target": key, "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
        return_after_remote_link: false,
    };
    let body = approve_op(&custodian, &vault, &op, &format!("Reveal {}", key), &opts).await?;
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("no value in response. Op may have been consumed")?;
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    out.write_all(value.as_bytes())
        .map_err(|e| format!("stdout: {}", e))?;
    out.write_all(b"\n").ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_value_drops_one_trailing_newline() {
        assert_eq!(stdin_value(b"sk-1\n".to_vec(), "K").unwrap(), "sk-1");
        assert_eq!(stdin_value(b"sk-1\r\n".to_vec(), "K").unwrap(), "sk-1");
        assert_eq!(stdin_value(b"sk-1".to_vec(), "K").unwrap(), "sk-1");
        // Only one: a value that really ends in a newline keeps the rest.
        assert_eq!(stdin_value(b"a\n\n".to_vec(), "K").unwrap(), "a\n");
    }

    #[test]
    fn stdin_value_rejects_empty_oversize_and_non_utf8() {
        assert!(stdin_value(Vec::new(), "K").is_err());
        assert!(stdin_value(b"\n".to_vec(), "K").is_err());
        assert!(stdin_value(vec![b'x'; 64 * 1024 + 1], "K").is_err());
        assert!(stdin_value(vec![0xff, 0xfe], "K").is_err());
        assert!(stdin_value(vec![b'x'; 64 * 1024], "K").is_ok());
    }
}
