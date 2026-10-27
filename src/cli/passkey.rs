//! `sprott passkey ...` — manage the active vault's enrolled passkeys.
//!
//! `ls` lists; `add`, `rm` and `rename` print the console page where that is
//! done (in the browser, where the identity key lives). `rm` / `rename` first
//! resolve their PASSKEY argument against the vault's list, so a typo or an
//! ambiguous name fails here instead of on the page.

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::resolve_active;
use crate::config::PasskeySubcommand;

/// The console page where passkeys are added, renamed and removed.
const PASSKEYS_PAGE: &str = "/account/passkeys";

pub async fn run(sub: PasskeySubcommand, json: bool) -> Result<(), String> {
    match sub {
        PasskeySubcommand::Ls(_a) => run_ls(json).await,
        PasskeySubcommand::Add(_) => {
            let url = crate::cli::vault::console_page(PASSKEYS_PAGE)?;
            eprintln!("Add a passkey in the Sprott console:");
            eprintln!("  {}", url);
            Ok(())
        }
        PasskeySubcommand::Rm(a) => {
            let name = resolve_listed(&a.passkey).await?;
            let url = crate::cli::vault::console_page(PASSKEYS_PAGE)?;
            eprintln!("Remove the passkey {} in the Sprott console:", name);
            eprintln!("  {}", url);
            Ok(())
        }
        PasskeySubcommand::Rename(a) => {
            let name = resolve_listed(&a.passkey).await?;
            let url = crate::cli::vault::console_page(PASSKEYS_PAGE)?;
            eprintln!(
                "Rename the passkey {} to \"{}\" in the Sprott console:",
                name, a.new_name
            );
            eprintln!("  {}", url);
            Ok(())
        }
    }
}

/// Resolve a PASSKEY argument against the active vault's passkeys and
/// render the match for a message: `"name" (credential id)`.
async fn resolve_listed(token: &str) -> Result<String, String> {
    let (custodian, vault) = resolve_active(None)?;
    let body = fetch(&custodian, &vault).await?;
    let p = resolve_passkey(token, &body.passkeys)?;
    Ok(match p.device_name.as_deref() {
        Some(n) => format!("\"{}\" ({})", n, p.credential_id),
        None => p.credential_id.clone(),
    })
}

/// Resolve a PASSKEY argument the way the vault resolver does, first match
/// wins: an exact credential id, an exact name (case-insensitive), or a
/// unique credential id prefix of 4+ chars. Ambiguity is an error listing the
/// candidates, never a guess.
fn resolve_passkey<'a>(token: &str, keys: &'a [PasskeyMeta]) -> Result<&'a PasskeyMeta, String> {
    let token = token.trim();
    if let Some(p) = keys.iter().find(|p| p.credential_id == token) {
        return Ok(p);
    }
    let by_name: Vec<&PasskeyMeta> = keys
        .iter()
        .filter(|p| {
            p.device_name
                .as_deref()
                .is_some_and(|n| n.trim().eq_ignore_ascii_case(token))
        })
        .collect();
    match by_name.as_slice() {
        [p] => return Ok(*p),
        [] => {}
        many => return Err(ambiguous_passkey_err(token, "name", many)),
    }
    if token.len() >= 4 {
        let by_prefix: Vec<&PasskeyMeta> = keys
            .iter()
            .filter(|p| p.credential_id.starts_with(token))
            .collect();
        match by_prefix.as_slice() {
            [p] => return Ok(*p),
            [] => {}
            many => return Err(ambiguous_passkey_err(token, "id prefix", many)),
        }
    }
    Err(format!(
        "no passkey matches '{}'. Run `sprott passkey ls` and pass its exact name, its credential id, or a unique id prefix",
        token
    ))
}

fn ambiguous_passkey_err(token: &str, by: &str, cands: &[&PasskeyMeta]) -> String {
    let list = cands
        .iter()
        .map(|p| {
            let short = p.credential_id.get(..12).unwrap_or(&p.credential_id);
            match p.device_name.as_deref() {
                Some(n) => format!("  {} ({})", n, short),
                None => format!("  {}", p.credential_id),
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "'{}' matches {} passkeys by {}. Be specific (use the credential id or a unique prefix):\n{}",
        token,
        cands.len(),
        by,
        list
    )
}

#[derive(Debug, Deserialize)]
struct PasskeysBody {
    #[serde(default)]
    vault_exists: bool,
    #[serde(default)]
    passkeys: Vec<PasskeyMeta>,
}

#[derive(Debug, Deserialize)]
struct PasskeyMeta {
    credential_id: String,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    transports: Vec<String>,
    #[serde(default)]
    last_used_at: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

async fn fetch(custodian: &str, vault: &str) -> Result<PasskeysBody, String> {
    let url = format!(
        "{}/v/{}/passkeys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let client = crate::util::http_builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach custodian: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "custodian returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    resp.json().await.map_err(|e| format!("parse: {}", e))
}

async fn run_ls(json: bool) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let body = fetch(&custodian, &vault).await?;
    if json {
        // Machine-readable mirror of the human table: one object per enrolled
        // passkey (public metadata only). A not-yet-enrolled or empty vault
        // emits an empty array.
        let arr: Vec<serde_json::Value> = body
            .passkeys
            .iter()
            .map(|p| {
                serde_json::json!({
                    "credential_id": p.credential_id,
                    "device_name": p.device_name,
                    "transports": p.transports,
                    "last_used_at": p.last_used_at,
                    "created_at": p.created_at,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if !body.vault_exists {
        println!(
            "(vault {} is not yet enrolled; run `sprott setup`)",
            vault
        );
        return Ok(());
    }
    if body.passkeys.is_empty() {
        println!(
            "(vault {} has no passkeys; re-enroll via `sprott setup`)",
            vault
        );
        return Ok(());
    }
    let id_w = body
        .passkeys
        .iter()
        .map(|p| p.credential_id.len())
        .max()
        .unwrap_or(0)
        .min(32)
        .max(8);
    println!(
        "  {:<iw$}  {:<24}  {}",
        "CREDENTIAL_ID",
        "DEVICE",
        "LAST USED",
        iw = id_w
    );
    for p in &body.passkeys {
        let id_display = if p.credential_id.len() > id_w {
            format!("{}…", &p.credential_id[..id_w.saturating_sub(1)])
        } else {
            p.credential_id.clone()
        };
        let device = p.device_name.as_deref().unwrap_or("(unnamed)");
        let last_used = p
            .last_used_at
            .as_deref()
            .or(p.created_at.as_deref())
            .unwrap_or("?");
        println!(
            "  {:<iw$}  {:<24}  {}{}",
            id_display,
            device,
            last_used,
            if !p.transports.is_empty() {
                format!("  [{}]", p.transports.join(","))
            } else {
                String::new()
            },
            iw = id_w
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(id: &str, name: Option<&str>) -> PasskeyMeta {
        PasskeyMeta {
            credential_id: id.into(),
            device_name: name.map(str::to_string),
            transports: Vec::new(),
            last_used_at: None,
            created_at: None,
        }
    }

    /// Exact credential id, then exact name (case-insensitive), then a
    /// unique id prefix of 4+ chars; ambiguity lists the candidates.
    #[test]
    fn passkey_token_id_name_prefix() {
        let keys = [
            pk("AbCd1234-xyz", Some("MacBook")),
            pk("AbCd9876_uvw", Some("iPhone")),
            pk("Zz00", Some("AbCd1234-xyz")),
            pk("Yy11", None),
        ];
        let id = |t: &str| resolve_passkey(t, &keys).map(|p| p.credential_id.clone());
        assert_eq!(
            id("AbCd1234-xyz").unwrap(),
            "AbCd1234-xyz",
            "id beats a name"
        );
        assert_eq!(id("macbook").unwrap(), "AbCd1234-xyz");
        assert_eq!(id("IPHONE").unwrap(), "AbCd9876_uvw");
        assert_eq!(id("AbCd98").unwrap(), "AbCd9876_uvw");
        assert_eq!(id("Yy11").unwrap(), "Yy11");
        let amb = id("AbCd").unwrap_err();
        assert!(amb.contains("MacBook") && amb.contains("iPhone"), "{amb}");
        assert!(id("abcd98").is_err(), "an id prefix is case-sensitive");
        assert!(id("Yy1").is_err(), "a prefix needs 4+ chars");
        assert!(id("nope").is_err());

        let twins = [pk("Aaaa1", Some("Laptop")), pk("Bbbb2", Some("laptop"))];
        let err = resolve_passkey("Laptop", &twins).unwrap_err();
        assert!(err.contains("2 passkeys by name"), "{err}");
    }
}
