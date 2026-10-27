//! Broker flow helpers that outlive the retired `/use`+`/stream` ingress.
//!
//! The resident phantom-only proxy (S2) calls into these from its request
//! pipeline: register a pending approval op, answer a pending client, scrub
//! hop-by-hop headers, and mint an oauth2 access token. Keeping them in one
//! surviving module is what lets the v3 `broker.rs` template engine and the
//! `/use`+`/stream` handlers be deleted without stranding the reusable core.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::audit;
use crate::error::{AppError, Result};
use crate::protocol::Operation;
use crate::state::{AppState, ApprovalEvent};

/// The daemon's shared outbound HTTP client accessor (redirect policy = none;
/// egress proxy hot-swappable). Re-exported here so the proxy pipeline has one
/// obvious home for it.
pub use crate::core::forward::http_client;

/// `sha256(bytes)` as lowercase hex — the oauth mint-cache key (§5). Hashing the
/// refresh token keeps the map keys fixed-size and not raw secrets.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// A hop-by-hop header (RFC 7230 §6.1) that must never be forwarded verbatim.
pub fn is_hop_by_hop(name_lc: &str) -> bool {
    matches!(
        name_lc,
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Shared tail of the Use pending-op flow: issue the challenge `r`, create the
/// `ApprovalRecord` (stamped with the policy context the approve handler reads
/// for its cache write), persist the `pending` audit row, register with the
/// cloud op-relay, and emit the `pending` SSE event. Returns
/// `(op_id, r, expires_at)`. Ingress-agnostic by design — the proxy compiles an
/// `authorize_only` Use `Operation` and funnels it through here.
pub fn register_pending_use(
    state: &Arc<AppState>,
    vault_id: &str,
    mut op: Operation,
    policy_context: Option<crate::approval::PolicyContext>,
    ip: IpAddr,
    agent_prefix: Option<String>,
) -> Result<(String, String, u64)> {
    // The consequence tier rides the signed op like every other mint (a
    // time-window use is "warn", a one-shot one "neutral").
    crate::protocol::consent::stamp_tone(&mut op);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let r = {
        let mut store = state.challenges.lock().unwrap();
        store.issue(ip).ok_or(AppError::TooManyRequests)?
    };

    let (op_id, expires_at, supersedes) = {
        let mut store = state.approvals.lock().unwrap();
        // Op-agent binding (team §C1): the triggering agent's prefix lands on
        // the record so every consumption surface can enforce "only the agent
        // this was approved FOR can use it". A `use` op also joins its intent
        // chain here (design/approvals-inbox.md D1): live byte-identical
        // retries are marked superseded by this one — display only, they stay
        // approvable — in the same store mutation as the create.
        let c = store.create_chained(
            vault_id.to_string(),
            op.clone(),
            r.clone(),
            policy_context,
            agent_prefix.clone(),
        );
        (c.id, c.expires_at_unix, c.supersedes)
    };

    if let Ok(audit_store) = state.audit_for_vault(vault_id) {
        let mut row = audit::row_from_op(&op_id, &op, now as i64, expires_at as i64);
        row.agent_prefix = agent_prefix.clone();
        if let Err(e) = audit_store.insert(&row) {
            tracing::warn!(vault = %vault_id, op = %op_id, "audit insert pending (use) failed: {}", e);
        }
    }

    crate::relay::client::spawn_register_and_poll(
        state.clone(),
        vault_id.to_string(),
        op_id.clone(),
        serde_json::to_value(&op).unwrap_or(Value::Null),
        r.clone(),
        expires_at,
        agent_prefix,
        supersedes,
    );

    state.emit_event(ApprovalEvent {
        vault_id: vault_id.to_string(),
        approval_id: op_id.clone(),
        kind: "pending".into(),
        op_summary: Some(serde_json::to_value(&op).unwrap_or(Value::Null)),
        response_preview: None,
        reason: None,
    });

    Ok((op_id, r, expires_at))
}

/// Mint the credential a minted connection's access phantom injects. The
/// `raw` bytes are the mint's INPUT (oauth2 refresh token / snaplii api key),
/// not the wire token the upstream wants: exchange them at the mechanism's
/// token endpoint (or reuse a still-valid cached token) and return the fresh
/// token. `auth` is the mechanism of the definition the request was decided
/// on (its snapshot's, custom-first), so the mint never disagrees with the
/// pipeline about which config backs the connection. The token cache lives
/// on the Unlocked state's `oauth_access`, keyed by the input (never
/// persisted). On an invalid input credential the connection is flagged
/// needs-reauth and an `Unauthorized` propagates.
pub async fn resolve_auth_value(
    state: &Arc<crate::state::AppState>,
    vault_id: &str,
    conn_id: &str,
    service_id: &str,
    auth: &crate::service::AuthDef,
    raw: &[u8],
) -> Result<Vec<u8>> {

    // The connection's CURRENT refresh token: whatever path produced `raw`
    // (the session cache, or a ceremony's fresh decrypt from the store, which
    // may still hold a replaced value), it is followed through every rotation
    // made since (stored or still pending), because the provider honors only
    // the newest. This is the one place every mint input passes through.
    let current = state.current_refresh_token(vault_id, conn_id, raw);
    let mut input: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(
        current
            .as_ref()
            .map(|t| t.as_bytes().to_vec())
            .unwrap_or_else(|| raw.to_vec()),
    );

    // §5: mint cache keyed by sha256(mint input). The input is read LOCALLY
    // only to compute the key; on a hit nothing is minted and the input never
    // leaves the daemon.
    let mut refresh_hash = sha256_hex(&input);
    if let Some(cached) = state.oauth_access_lookup(vault_id, &refresh_hash) {
        return Ok(cached);
    }

    // Single-flight per vault: a rotating provider (OpenAI) mints a NEW
    // refresh_token on every refresh and invalidates the old, so two concurrent
    // cache-miss requests would race — the second's now-stale token gets
    // invalid_grant and the connection false-flags needs-reauth. Serialize the
    // refresh + rotation write-back under the SAME per-vault write lock the
    // connect path uses, then re-check the cache (the winner may have filled it).
    let _guard = state
        .vault_write_guard(vault_id)
        .await
        .map_err(|error| error.app_error())?;
    // Single-flight per connection: a refresh that won the lock while we
    // waited rotated the token we read, and cached its access token under the
    // rotated one. Follow it: reuse that access token, and never send the
    // replaced refresh token (a rotating provider refuses it, and some revoke
    // the whole token family on such a reuse).
    if let Some(now_current) = state.current_refresh_token(vault_id, conn_id, raw) {
        if now_current.as_bytes() != input.as_slice() {
            input = zeroize::Zeroizing::new(now_current.as_bytes().to_vec());
            refresh_hash = sha256_hex(&input);
        }
    }
    if let Some(cached) = state.oauth_access_lookup(vault_id, &refresh_hash) {
        return Ok(cached);
    }
    let raw: &[u8] = &input;

    let oauth = match auth {
        crate::service::AuthDef::Oauth2(o) => o,
        crate::service::AuthDef::Snaplii(_) => {
            // Snaplii's bespoke key→JWT exchange (auth::snaplii): same cache,
            // same key, no rotation. The connection id doubles as the agent
            // label Snaplii sees (user-chosen; multi-account = distinct ids).
            let api_key = std::str::from_utf8(raw).map_err(|_| {
                AppError::Internal(format!("snaplii api key for '{}' not utf-8", service_id))
            })?;
            let (jwt, expires_at) = crate::auth::snaplii::exchange(api_key, conn_id)
                .await
                .map_err(|e| {
                    tracing::warn!(vault = %vault_id, service = %service_id, "snaplii exchange failed: {}", e);
                    if e.contains("HTTP 401") || e.contains("HTTP 403") {
                        // The stored key itself was refused — reconnect territory.
                        state.oauth_mark_reauth(vault_id, conn_id);
                        AppError::Unauthorized(format!(
                            "snaplii api key rejected. Reconnect {}",
                            service_id
                        ))
                    } else {
                        AppError::Internal(e)
                    }
                })?;
            state.oauth_clear_reauth(vault_id, conn_id);
            let safe_expires_at = expires_at.saturating_sub(60);
            state.oauth_access_insert(
                vault_id,
                &refresh_hash,
                jwt.as_bytes().to_vec(),
                safe_expires_at,
            );
            return Ok(jwt.into_bytes());
        }
    };

    let resolved = state.services.resolve_oauth_config(&oauth);
    let token_url = resolved.token_url.as_deref().ok_or_else(|| {
        AppError::Internal(format!(
            "service '{}' is oauth2 but declares no token_url",
            service_id
        ))
    })?;
    let client_id = resolved.client_id.clone().ok_or_else(|| {
        AppError::Internal(format!(
            "service '{}' is oauth2 but declares no client_id",
            service_id
        ))
    })?;
    let client_secret = resolved.client_secret.clone();

    let refresh_token_str = std::str::from_utf8(raw).map_err(|_| {
        AppError::Internal(format!(
            "oauth2 refresh_token for '{}' not utf-8",
            service_id
        ))
    })?;
    let style = state.services.oauth_style(&oauth);
    let token_auth = state.services.token_auth(&oauth);
    // The def's refresh_params are static (the validator refused
    // placeholders: there is no consent state at refresh time).
    let extra = crate::auth::oauth2::render_extra_params(&oauth.refresh_params, None)
        .map_err(AppError::Internal)?;

    let (access_token, expires_at, rotated_refresh) = crate::auth::oauth2::perform_refresh(
        token_url,
        &client_id,
        client_secret.as_deref(),
        refresh_token_str,
        style,
        token_auth,
        &extra,
    )
    .await
    .map_err(|e| {
        tracing::warn!(vault = %vault_id, service = %service_id, "oauth2 refresh failed: {}", e);
        if e.contains("invalid_grant") {
            state.oauth_mark_reauth(vault_id, conn_id);
            AppError::Unauthorized(format!(
                "oauth2 refresh_token invalid. Reconnect {}",
                service_id
            ))
        } else if let Some(transport) = e.strip_prefix("oauth2 refresh request failed: ") {
            // We never even reached the token endpoint: a network/proxy problem,
            // not a bad credential. Say so (and don't double-wrap "refresh failed:
            // refresh request failed:"), and point at the proxy knob.
            AppError::Internal(format!(
                "couldn't reach {}'s token endpoint to refresh the access token ({}). \
                 If this machine needs a proxy for outbound HTTPS, set one with \
                 `sprott config set proxy <url>`.",
                service_id, transport
            ))
        } else {
            AppError::Internal(format!("oauth2 refresh failed: {}", e))
        }
    })?;

    state.oauth_clear_reauth(vault_id, conn_id);
    let safe_expires_at = expires_at.saturating_sub(60);

    // A rotating provider handed back a NEW refresh_token and killed the one we
    // sent: persist it back to the vault (else the next refresh sends a dead
    // token) and cache the minted access token under the NEW key — the next
    // request reads the rotated token, so keying on the old hash would always
    // miss. We hold the write lock; the persist helper must NOT re-acquire it.
    let cache_key = match rotated_refresh.as_deref() {
        Some(new_rt) if new_rt.as_bytes() != raw => {
            // Every reader of the replaced token follows it from now on.
            state.note_rotated_to(vault_id, raw, new_rt);
            match crate::auth::connect::persist_rotated_refresh_locked(
                state,
                vault_id,
                conn_id,
                &oauth.refresh_token,
                raw,
                new_rt,
                false,
            ) {
                // Landed durably in the store (the session cache now holds
                // it, nothing is pending for the slot): sent to the cloud once
                // this lock drops.
                Ok(_) => crate::auth::connect::spawn_push(state, vault_id),
                // Not stored: the session still uses the new token, which is
                // stored again on its own retry timer, after a sync round and
                // at unlock; the user is told.
                Err(why) => crate::auth::connect::rotation_not_stored(
                    state,
                    vault_id,
                    conn_id,
                    &oauth.refresh_token,
                    raw,
                    new_rt,
                    &why,
                ),
            }
            sha256_hex(new_rt.as_bytes())
        }
        // §5: no rotation → cache under the SAME key the lookup uses, so a
        // subsequent request within the token's lifetime hits without re-minting.
        _ => refresh_hash,
    };
    state.oauth_access_insert(
        vault_id,
        &cache_key,
        access_token.as_bytes().to_vec(),
        safe_expires_at,
    );
    Ok(access_token.into_bytes())
}
