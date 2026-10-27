//! `sprott vault ...` — vault lifecycle ops.

use serde_json::json;
use std::io::{self, IsTerminal as _, Write as _};

use crate::cli::active::{
    forget as forget_vault, join_vault_url, known_vaults, load as load_config, put_active,
    resolve_active, resolve_vault_token, KnownVault,
};
use crate::cli::status::{fetch_status, print_status, VaultState};
use crate::cli::webauthn::*;
use crate::config::{
    ApprovalArgs, VaultCreateArgs, VaultDeleteArgs, VaultForgetArgs, VaultSubcommand, VaultUseArgs,
};

/// True if the custodian URL points at this machine. Used to specialize
/// "daemon down" hints — a remote daemon being unreachable is a network
/// problem; a local one almost always means the daemon isn't running (`sprott up`).
fn is_localhost(custodian: &str) -> bool {
    let after_scheme = custodian
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = after_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub async fn run(sub: VaultSubcommand, approval: &ApprovalArgs, json: bool) -> Result<(), String> {
    match sub {
        VaultSubcommand::Status(_a) => crate::cli::status::run(json).await,
        VaultSubcommand::Ls(_a) => run_ls(json).await,
        VaultSubcommand::Use(a) => run_use(a).await,
        VaultSubcommand::Forget(a) => run_forget(a).await,
        VaultSubcommand::Create(a) => run_create(a).await,
        VaultSubcommand::Rm(a) => run_rm(a, approval).await,
    }
}

async fn run_ls(json: bool) -> Result<(), String> {
    let cfg = load_config()?;
    let known = known_vaults();
    let active = (cfg.daemon.as_deref(), cfg.vault.as_deref());
    if json {
        let rows: Vec<serde_json::Value> = known
            .iter()
            .map(|kv| {
                json!({
                    "url": join_vault_url(&kv.daemon, &kv.vault),
                    "daemon": kv.daemon,
                    "vault": kv.vault,
                    "label": kv.label,
                    "kind": kv.kind,
                    "default": active == (Some(kv.daemon.as_str()), Some(kv.vault.as_str())),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_default()
        );
        return Ok(());
    }
    if known.is_empty() {
        println!("(no vaults yet; `sprott vault create` or `sprott vault use`)");
        return Ok(());
    }
    for (i, kv) in known.iter().enumerate() {
        let marker = if active == (Some(&kv.daemon), Some(&kv.vault)) {
            "*"
        } else {
            " "
        };
        println!("  {} {}", marker, ls_row(i, kv));
    }
    Ok(())
}

/// One `sprott vault ls` row after its default marker: `N) name (kind)  id`.
/// Leads with the human name + kind so an agent told "the team vault" can pick
/// the right one; the id trails as the canonical, copyable handle. `N` is the
/// number the vault resolver accepts.
fn ls_row(i: usize, kv: &KnownVault) -> String {
    let name = kv.label.as_deref().unwrap_or("(unnamed)");
    let kind = kv.kind.as_deref().unwrap_or("?");
    format!("{}) {} ({})  {}", i + 1, name, kind, kv.vault)
}

/// `<VAULT>` of `vault use` / `vault forget`, through the one resolver
/// `--vault` uses; absent, an interactive pick. `None` = the pick was cancelled.
fn resolve_target(target: Option<String>) -> Result<Option<(String, String)>, String> {
    let cfg = load_config().unwrap_or_default();
    let token = match target {
        Some(t) => t,
        None => match interactive_pick()? {
            Some(t) => t,
            None => return Ok(None),
        },
    };
    resolve_vault_token(&token, &cfg).map(Some)
}

async fn run_use(args: VaultUseArgs) -> Result<(), String> {
    let Some((custodian, vault)) = resolve_target(args.target)? else {
        eprintln!("cancelled");
        return Ok(());
    };

    // Probe before saving. If the vault doesn't exist on the custodian,
    // refuse — bad active state would silently confuse later commands.
    // (Daemon unreachable is OK — accept and warn; user might be offline.)
    let s = fetch_status(&custodian, &vault).await;
    match s.state {
        VaultState::NotFound => {
            return Err(format!(
                "vault not found on custodian: {}\n  run `sprott vault create` to make a new one, or pick a different vault",
                join_vault_url(&custodian, &vault)
            ));
        }
        VaultState::Unreachable => {
            if is_localhost(&custodian) {
                eprintln!(
                    "warning: no local daemon at {}. Start one with `sprott up`",
                    custodian
                );
                eprintln!(
                    "  (saving anyway; `sprott status` will recheck once the daemon is up)"
                );
            } else {
                eprintln!("warning: couldn't reach custodian; saving anyway");
            }
        }
        _ => {}
    }
    put_active(&custodian, &vault).map_err(|e| format!("save config: {}", e))?;
    print_status(&s);
    // Pin-aware (design/vault-addressing.md): a shell that carries a launch pin
    // keeps targeting it — say so here, at the moment of the switch, instead of
    // letting the very next `sc ls` contradict the header above.
    if let Ok(pin) = std::env::var("SPROTT_VAULT_ID") {
        if !pin.is_empty() && pin != vault {
            eprintln!(
                "note: this shell is pinned to {} via $SPROTT_VAULT_ID, so `sprott` here still targets it;",
                pin
            );
            eprintln!(
                "      the new default applies everywhere else; `unset SPROTT_VAULT_ID` to follow it here"
            );
        }
    }
    Ok(())
}

async fn run_forget(args: VaultForgetArgs) -> Result<(), String> {
    let Some((custodian, vault)) = resolve_target(args.target)? else {
        eprintln!("cancelled");
        return Ok(());
    };
    let removed = forget_vault(&custodian, &vault)?;
    if !removed {
        return Err(format!(
            "vault not in known list: {}",
            join_vault_url(&custodian, &vault)
        ));
    }
    println!("forgot: {}", join_vault_url(&custodian, &vault));
    Ok(())
}

/// List the known vaults as `sprott vault ls` does and read one answer: a
/// token for the vault resolver, or `None` when Enter cancels.
fn interactive_pick() -> Result<Option<String>, String> {
    if !io::stdin().is_terminal() {
        return Err("pass the vault (see `sprott vault ls`)".into());
    }
    let cfg = load_config().unwrap_or_default();
    let known = known_vaults();
    if known.is_empty() {
        return Err("no vaults on this machine yet (`sprott vault create`)".into());
    }
    let active = (cfg.daemon.as_deref(), cfg.vault.as_deref());
    for (i, kv) in known.iter().enumerate() {
        let marker = if active == (Some(&kv.daemon), Some(&kv.vault)) {
            "*"
        } else {
            " "
        };
        eprintln!("  {} {}", marker, ls_row(i, kv));
    }
    eprint!("Vault (number, name or id; Enter to cancel): ");
    io::stderr().flush().ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
    let trimmed = buf.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
}

/// `sc vault create`: vaults are created in the Sprott console, where the
/// identity key lives (it never reaches this daemon). Print the link; the new
/// vault syncs to this machine on its own once created.
async fn run_create(_args: VaultCreateArgs) -> Result<(), String> {
    let url = console_page("/vaults?new=vault")?;
    eprintln!("Create the vault in the Sprott console:");
    eprintln!("  {}", url);
    eprintln!("This machine picks it up automatically once it exists.");
    Ok(())
}

/// An absolute console page link (`{console origin}{path}`) for this machine's
/// pairing. Vault creation and passkey enrollment happen there.
pub(crate) fn console_page(path: &str) -> Result<String, String> {
    let origin = crate::cli::active::console_origin()
        .ok_or("this machine isn't paired to Sprott yet: run `sprott login` first")?;
    Ok(format!("{}{}", origin.trim_end_matches('/'), path))
}

async fn run_rm(args: VaultDeleteArgs, approval: &ApprovalArgs) -> Result<(), String> {
    if !args.yes {
        return Err("destructive; pass -y/--yes to confirm vault deletion".into());
    }
    if args.target.trim().is_empty() {
        return Err("vault cannot be empty".into());
    }
    let (custodian, vault) = resolve_active(Some(args.target.as_str()))?;
    // Name the vault the token resolved to, so `vault rm 2` shows which one.
    let shown = match known_vaults()
        .into_iter()
        .find(|kv| kv.vault == vault)
        .and_then(|kv| kv.label)
        .filter(|l| !l.trim().is_empty())
    {
        Some(name) => format!("\"{}\" ({})", name, vault),
        None => vault.clone(),
    };

    if atty_isatty_stdin() {
        eprint!(
            "Permanently delete vault {}? Type its id to confirm: ",
            shown
        );
        io::stderr().flush().ok();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
        if buf.trim() != vault {
            return Err("confirmation mismatch. Aborted".into());
        }
    }

    // Delete is approval-only (the daemon wipes the vault from the grant's
    // W_c) — same shape as unlock/lock, so it goes through the ONE shared
    // approval path: cloud /grant link when paired, local ceremony for
    // self-host. No bespoke gesture here.
    let op = json!({
        "act": { "type": { "custom": "vault-delete" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = crate::cli::approve::ApproveOpts::from_flags(approval);
    crate::cli::approve::approve_op(
        &custodian,
        &vault,
        &op,
        "Delete vault (irreversible)",
        &opts,
    )
    .await?;
    eprintln!("sprott vault rm: ok (vault {} wiped)", shown);
    Ok(())
}

fn atty_isatty_stdin() -> bool {
    unsafe { libc_isatty(0) != 0 }
}

#[link(name = "c")]
extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}
