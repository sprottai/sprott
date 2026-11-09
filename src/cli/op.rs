//! `sc op wait` — block until a pending approval op resolves, then exit.
//!
//! The waiter half of the captive-portal contract (CREDENTIAL_BROKER.md §14):
//! a brokered request that needs a passkey fails with an `op_id` + approve
//! link. The agent surfaces the link, backgrounds `sc op wait <op_id>`, and
//! treats the process exit as its wake-up — then re-runs the original
//! command (the approval is cached; the retry consumes it). Polling `/op/{id}`
//! never consumes anything, so waiting and retrying can't race each other.
//! A change the daemon makes itself on approval (a set, a connection, a
//! service, a removal) is already applied when the wait ends, so nothing is
//! re-run ([`rerun_after_approval`]).
//!
//! Exit codes are the contract: 0 approved, 5 not approved (a person said no,
//! or a stated cause), 6 ended without a decision (withdrawn by the requester
//! or superseded by a newer request), 3 expired/unknown, 4 timed out waiting,
//! 1 local failure. 2 is clap's usage-error code — a malformed invocation must
//! stay distinguishable from a human rejection.
//! Progress and the outcome are one line each on stderr; `--json` puts the final
//! poll body on stdout.

use std::time::{Duration, Instant};

use reqwest::header::RETRY_AFTER;
use serde_json::Value;

use crate::cli::active::{control_root, load};
use crate::config::{ApprovalArgs, OpWaitArgs};

/// Give up after this many CONSECUTIVE transport failures (~30s dark with the
/// 2s cadence + 15s client timeout) — a dead daemon must not strand a
/// background waiter forever; the op survives, so a fresh wait can re-attach.
const ERROR_STREAK_LIMIT: u32 = 10;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Default `--timeout` for `op wait`: past the 30-minute approval window, so
/// the op's own expiry normally ends the wait first.
const WAIT_TIMEOUT_SECS: u64 = 1900;

enum Verdict {
    Approved,
    Rejected,
    Pending,
}

/// How an op that ended as `rejected` ended, from its `reason`: a person's
/// no, a withdrawal by the requester, a newer request replacing it, or
/// another stated cause (e.g. approved, but applying it failed).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NotApproved<'a> {
    Rejected,
    Withdrawn,
    Superseded,
    Other(&'a str),
}

pub(crate) fn not_approved(reason: &str) -> NotApproved<'_> {
    use crate::server::handlers::op::{ABANDONED_REASON, WITHDRAWN_REASON};
    match reason {
        // "user denied" = the same human no from an older daemon.
        "" | "user rejected" | "user denied" => NotApproved::Rejected,
        r if r == WITHDRAWN_REASON || r == ABANDONED_REASON => NotApproved::Withdrawn,
        r if r.contains("superseded") => NotApproved::Superseded,
        r => NotApproved::Other(r),
    }
}

/// Wire-status → outcome. `consumed` counts as approved: the gesture landed
/// and something already took the value — for the re-run ceremony that's
/// success, same as `cli::approve` treats it.
fn verdict(status: &str) -> Verdict {
    match status {
        "ok" | "consumed" => Verdict::Approved,
        "rejected" => Verdict::Rejected,
        _ => Verdict::Pending,
    }
}

/// Whether an approved op (`act` = the poll's act discriminator, `op` = the
/// poll's op JSON) still needs the original command run again. The daemon
/// applies a requested change on approval, so re-running it would ask for a
/// second approval. A brokered request (`use`) retries to spend its approval;
/// an unlock or lock re-run reports the state it reached. A `widen-host` the
/// proxy minted (its scope carries `etld1`) answered a request that was refused
/// and never sent, so that request runs again.
fn rerun_after_approval(act: &str, op: &Value) -> bool {
    match act.strip_prefix("custom:") {
        None | Some("vault-unlock" | "vault-lock") => true,
        Some("widen-host") => op.pointer("/act/scope/etld1").is_some(),
        Some(_) => false,
    }
}

fn not_answering(root: &str, op_id: &str) -> String {
    format!(
        "daemon not answering at {}. The approval survives; once it is back, re-run: sprott op wait {}",
        root, op_id
    )
}

/// Poll cadence: honor the server's `Retry-After` hint when it's sane,
/// else the fixed default (matches `cli::approve`'s remote arm).
fn next_delay(retry_after: Option<&str>) -> Duration {
    retry_after
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|s| (1..=30).contains(s))
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL)
}

pub async fn run_wait(args: OpWaitArgs, approval: &ApprovalArgs, json: bool) -> Result<(), String> {
    let timeout = approval.timeout.unwrap_or(WAIT_TIMEOUT_SECS);
    // Corrupt config degrades to defaults, NOT a hardcoded localhost that
    // would ignore an agent's $SPROTT_BROKER_URL (same rule as custodian.rs).
    let root = control_root(&load().unwrap_or_default());
    let poll_url = format!(
        "{}/op/{}",
        root.trim_end_matches('/'),
        urlencoding::encode(&args.op_id)
    );

    // The command that minted the op already printed its link.
    eprintln!("Waiting for approval in the browser.");

    let client = crate::util::http_builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;

    // Clamp to a year — a u64::MAX timeout would overflow Instant + Duration.
    let deadline = Instant::now() + Duration::from_secs(timeout.min(31_536_000));
    let mut error_streak: u32 = 0;
    let mut delay = DEFAULT_POLL_INTERVAL;

    // Poll first, sleep after — the tap may already have landed before the
    // waiter started, and the first answer should be instant.
    loop {
        match client.get(&poll_url).send().await {
            Err(_) => {
                error_streak += 1;
                if error_streak >= ERROR_STREAK_LIMIT {
                    return Err(not_answering(&root, &args.op_id));
                }
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                eprintln!("Expired or unknown. Re-run the original command for a new approval.");
                std::process::exit(3);
            }
            Ok(resp) => {
                let http_ok = resp.status().is_success();
                let retry_after = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                delay = next_delay(retry_after.as_deref());
                match resp.json::<Value>().await {
                    Ok(body) if http_ok => {
                        error_streak = 0;
                        let status = body.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        match verdict(status) {
                            Verdict::Approved => {
                                if json {
                                    println!("{}", body);
                                }
                                let act = body.get("act").and_then(|s| s.as_str()).unwrap_or("");
                                let op = body.get("op").cloned().unwrap_or(Value::Null);
                                if rerun_after_approval(act, &op) {
                                    eprintln!("Approved. Re-run the original command.");
                                } else {
                                    eprintln!("Approved and applied.");
                                    crate::cli::approve::say_not_served(
                                        &crate::cli::approve::act_result(&body),
                                    );
                                }
                                std::process::exit(0);
                            }
                            Verdict::Rejected => {
                                if json {
                                    println!("{}", body);
                                }
                                let reason =
                                    body.get("reason").and_then(|s| s.as_str()).unwrap_or("");
                                match not_approved(reason) {
                                    NotApproved::Superseded => {
                                        eprintln!(
                                            "Superseded by a newer approval request. \
                                             Re-run the original command."
                                        );
                                        std::process::exit(6);
                                    }
                                    NotApproved::Withdrawn => {
                                        eprintln!(
                                            "Withdrawn by the requester, not rejected. \
                                             Re-run the original command to ask again."
                                        );
                                        std::process::exit(6);
                                    }
                                    // Not a person saying no (e.g. "approved, but
                                    // applying it failed: …"): retrying after the
                                    // cause is fixed is legitimate.
                                    NotApproved::Other(r) => {
                                        eprintln!(
                                            "Not approved: {}. Fix the cause, then re-run.",
                                            r.trim_end_matches('.')
                                        );
                                    }
                                    NotApproved::Rejected => {
                                        eprintln!("Rejected by the approver. Do not retry.");
                                    }
                                }
                                std::process::exit(5);
                            }
                            Verdict::Pending => {}
                        }
                    }
                    // 5xx / auth walls / non-JSON: a server that isn't
                    // answering the contract counts toward the bail streak —
                    // never spin silently to the deadline.
                    _ => {
                        error_streak += 1;
                        if error_streak >= ERROR_STREAK_LIMIT {
                            return Err(not_answering(&root, &args.op_id));
                        }
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            eprintln!(
                "Timed out after {}s. If it is still pending, re-attach with: sprott op wait {}",
                timeout, args.op_id
            );
            std::process::exit(4);
        }
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_withdrawal_or_a_newer_request_is_not_a_rejection() {
        use crate::server::handlers::op::{ABANDONED_REASON, WITHDRAWN_REASON};
        assert_eq!(not_approved(""), NotApproved::Rejected);
        assert_eq!(not_approved("user rejected"), NotApproved::Rejected);
        assert_eq!(not_approved("user denied"), NotApproved::Rejected);
        assert_eq!(not_approved(WITHDRAWN_REASON), NotApproved::Withdrawn);
        assert_eq!(not_approved(ABANDONED_REASON), NotApproved::Withdrawn);
        assert_eq!(not_approved("superseded by a newer request"), NotApproved::Superseded);
        assert_eq!(
            not_approved("approved, but applying it failed: x"),
            NotApproved::Other("approved, but applying it failed: x")
        );
    }

    #[test]
    fn verdict_maps_wire_statuses() {
        assert!(matches!(verdict("ok"), Verdict::Approved));
        assert!(matches!(verdict("consumed"), Verdict::Approved));
        assert!(matches!(verdict("rejected"), Verdict::Rejected));
        assert!(matches!(verdict("pending"), Verdict::Pending));
        assert!(matches!(verdict(""), Verdict::Pending));
    }

    #[test]
    fn only_a_retry_or_a_lifecycle_op_is_re_run() {
        let none = Value::Null;
        assert!(rerun_after_approval("use", &none));
        assert!(rerun_after_approval("export", &none));
        assert!(rerun_after_approval("custom:vault-unlock", &none));
        assert!(rerun_after_approval("custom:vault-lock", &none));
        // A consumed tombstone carries no act.
        assert!(rerun_after_approval("", &none));
        // The proxy's widen-host answers a refused request: run it again.
        let proxy_widen = serde_json::json!({
            "act": { "type": { "custom": "widen-host" }, "target": "",
                     "scope": { "connection_id": "github", "host": "uploads.github.com", "etld1": "github.com" } }
        });
        assert!(rerun_after_approval("custom:widen-host", &proxy_widen));
        // `sprott connection add-host` mints the same act without etld1: applied.
        let cli_widen = serde_json::json!({
            "act": { "type": { "custom": "widen-host" }, "target": "",
                     "scope": { "connection_id": "github", "host": "uploads.github.com" } }
        });
        assert!(!rerun_after_approval("custom:widen-host", &cli_widen));
        for applied in [
            "custom:secret-set",
            "custom:secret-rm",
            "custom:connection-add",
            "custom:connection-rm",
            "custom:widen-host",
            "custom:narrow-host",
            "custom:service-add",
            "custom:service-rm",
            "custom:vault-delete",
        ] {
            assert!(!rerun_after_approval(applied, &none), "{applied}");
        }
    }

    #[test]
    fn next_delay_honors_sane_hints_only() {
        assert_eq!(next_delay(Some("3")), Duration::from_secs(3));
        assert_eq!(next_delay(Some(" 5 ")), Duration::from_secs(5));
        // Absent, unparseable, zero, or absurd hints fall back to the default.
        assert_eq!(next_delay(None), DEFAULT_POLL_INTERVAL);
        assert_eq!(next_delay(Some("soon")), DEFAULT_POLL_INTERVAL);
        assert_eq!(next_delay(Some("0")), DEFAULT_POLL_INTERVAL);
        assert_eq!(next_delay(Some("3600")), DEFAULT_POLL_INTERVAL);
    }
}
