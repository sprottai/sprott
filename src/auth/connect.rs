//! OAuth CONNECT completion on the daemon (CONNECTION_SCHEMA.md §5).
//!
//! The browser drives Google consent with the **public Desktop client + PKCE**
//! and seals `{ service, config, code, verifier }` into `aux.connecting[<id>]`
//! (CONNECTION_SCHEMA.md §2). To stay **cloud-blind**, the code is relayed to the
//! daemon *through the sealed vault* (the cloud only ever stores ciphertext) —
//! never through the backend. This module is the daemon side of that handshake:
//!
//! 1. with the vault **open** (retained `K` from an unlocked session), read every
//!    in-flight connect from `aux.connecting`;
//! 2. for each, resolve the connection's *service* → its provider
//!    (client_id / secret / token_url + the fixed redirect_uri, all from the
//!    public Desktop literal) and exchange the code at `token_url`;
//! 3. WRITE the durable refresh_token at its bound BARE key (§3 `keys` map) and
//!    **MOVE** the entry from `aux.connecting` into `aux.connections`; re-seal the
//!    body under the same `K` and persist `vault.dat`.
//!
//! **No approval op.** This is the completion of a *user-initiated*,
//! passkey-sealed, Google-authenticated connect; the daemon holds `K` while
//! unlocked and re-seals directly. Approval-ops gate *agent* requests, not the
//! daemon's own connect-completion. An agent cannot forge a Google login plus a
//! passkey-sealed code.
//!
//! **Multi-connection.** `connection_id` is independent of `service_id`: each
//! `connecting`/`connections` entry names its `service` explicitly, so two Gmail
//! accounts (`gmail`, `gmail_work`) connect side-by-side. Every secret is stored
//! at a BARE uppercase KEY; the connection record's `keys` map binds each role
//! to its key (identity for the default connection, `<ROLE>_<QUALIFIER>` by
//! default for a named one — see [`secret_key_for`] / [`suggested_secret_key`]).
//!
//! **Best-effort, never fatal.** Anything that goes wrong logs and is skipped; a
//! malformed/unresolvable pending or an exchange failure (e.g. an expired code)
//! leaves the `connecting` entry in place so the user can retry within the code
//! TTL (~10 min). It never panics the daemon and never blocks serving.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{de::DeserializeOwned, Serialize};
use sudp::state::ProtectedState;

use crate::auth::oauth2::{ExchangedTokens, OAuthStyle, TokenAuth};
use crate::state::AppState;
use crate::storage::plaintext::{secret_key_for, suggested_secret_key, Connecting, Connection};
use crate::storage::sealed_vault::{ReconcileBase, ViewBase};

/// The OAuth client/endpoint a pending connect resolves to before exchange, plus
/// the service's secret role (so we know where to write the result).
#[derive(Debug, Clone)]
pub struct ExchangeConfig {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub style: OAuthStyle,
    /// How the client authenticates at the token endpoint (`[auth]
    /// token_auth`): in the body, or an `Authorization: Basic` header.
    pub token_auth: TokenAuth,
    /// The def's extra exchange-body params (`[auth.token_params]`), raw —
    /// the `{state}` placeholder is substituted at exchange time from the
    /// pending connect's consent state.
    pub token_params: std::collections::HashMap<String, String>,
    /// The OAuth client's fixed redirect_uri (provider config), echoed at the
    /// token call so it matches the browser's consent request.
    pub redirect_uri: String,
    /// The service's mainstream secret role, e.g. `GMAIL_REFRESH_TOKEN` — the base
    /// name the refresh_token is written under (namespaced per `conn`).
    pub secret_role: String,
    /// The secret KEY a returned OIDC id_token is stored under, when the service
    /// declares one (`[oauth2].id_token`). `None` = don't store it.
    pub id_token_role: Option<String>,
    /// `exposes` roles derived from the exchange's id_token: `(role, claim
    /// path)`. The role is stored UPPERCASED at its §3 address (env-key
    /// convention; the lowercase phantom segment matches case-insensitively).
    pub exposes: Vec<(String, Vec<String>)>,
}

/// Resolve the exchange config for a connection's **service**. The service def
/// is looked up in the built-in registry first, then this vault's own
/// per-vault custom services (`aux.services`, e.g. a user-authored inline
/// `[oauth2]`) — without the fallback a custom OAuth service's connect could
/// never complete (its def isn't in the global registry). `None` when the
/// service is unknown to BOTH, isn't oauth2, or is missing a token_url /
/// client_id / secret role.
pub fn resolve_exchange_config(
    services: &crate::service::ServiceRegistry,
    custom: &std::collections::HashMap<String, crate::service::ServiceDef>,
    service: &str,
) -> Option<ExchangeConfig> {
    // custom-FIRST (see proxy::handler): a vault-authored def wins over a same-id
    // registry service for connect / token-exchange too.
    let svc = custom.get(service).or_else(|| services.get(service))?;
    let oauth = svc.oauth2()?;
    let resolved = services.resolve_oauth_config(oauth);
    let token_url = resolved.token_url?;
    let client_id = resolved.client_id?;
    let secret_role = oauth.refresh_token.clone();
    let style = services.oauth_style(oauth);
    // Each exposed role's claim path: the explicit `[oauth2].claims` mapping,
    // else the role name itself as a top-level claim.
    let exposes = oauth
        .exposes
        .iter()
        .map(|role| {
            let path = oauth
                .claims
                .get(role)
                .cloned()
                .unwrap_or_else(|| vec![role.clone()]);
            (role.clone(), path)
        })
        .collect();
    Some(ExchangeConfig {
        token_url,
        client_id,
        client_secret: resolved.client_secret,
        style,
        token_auth: services.token_auth(oauth),
        token_params: oauth.token_params.clone(),
        redirect_uri: resolved.redirect_uri,
        secret_role,
        id_token_role: oauth.id_token.clone(),
        exposes,
    })
}

/// The loopback port a `service`'s consent redirect will land on — resolved
/// from its def with the SAME custom-FIRST rule as the exchange (a vault-
/// authored def wins over a same-id registry service), because that resolved
/// redirect_uri is what the console baked into the consent URL. `None` for a
/// non-oauth service or a non-loopback/portless redirect. The caller gates the
/// result on `ServiceRegistry::loopback_allowlist` — resolution says where the
/// redirect will land, the allowlist says whether we may listen there.
fn loopback_port_for(
    services: &crate::service::ServiceRegistry,
    custom: &std::collections::HashMap<String, crate::service::ServiceDef>,
    service: &str,
) -> Option<u16> {
    let svc = custom.get(service).or_else(|| services.get(service))?;
    let oauth = svc.oauth2()?;
    crate::service::loopback_port(&services.resolve_oauth_config(oauth).redirect_uri)
}

/// Read a `connection_id → T` map out of `m.aux[<key>]`. Empty when the key is
/// absent or doesn't parse (forward-compat: a newer schema we can't read yields
/// no entries — never an error).
fn aux_map<T: DeserializeOwned>(m: &ProtectedState, key: &str) -> BTreeMap<String, T> {
    m.aux
        .get(key)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// Write a `connection_id → T` map back into `m.aux[<key>]`, dropping the key
/// entirely when the map is empty (matching the `skip_serializing_if` shape the
/// rest of the aux schema round-trips with). Leaves all other aux fields intact.
fn set_aux_map<T: Serialize>(m: &mut ProtectedState, key: &str, map: BTreeMap<String, T>) {
    if !m.aux.is_object() {
        // A v3 vault's aux is always an object; tolerate a malformed one by
        // starting fresh rather than panicking.
        m.aux = serde_json::json!({});
    }
    let obj = m.aux.as_object_mut().expect("aux normalized to object");
    if map.is_empty() {
        obj.remove(key);
    } else if let Ok(v) = serde_json::to_value(&map) {
        obj.insert(key.to_string(), v);
    }
}

/// Apply one successful exchange to the open `ProtectedState`: write the durable
/// refresh_token at its bound BARE key (overwriting any prior one — a re-connect
/// supersedes), store the id_token / its derived `exposes` claims when the
/// service declares them, and **MOVE** the entry from `aux.connecting` into
/// `aux.connections` (no partial/duplicate record). `hosts` carries any exact
/// FQDNs pinned at connect for a wildcard service; `keys` carries the creator's
/// explicit role→KEY bindings — absent, a NAMED connection gets the
/// [`suggested_secret_key`] defaults derived here (the default connection binds
/// identity, so it stores no map). Pure state transition (no I/O) so it's
/// unit-testable against a mocked `ProtectedState`.
pub fn apply_exchange_result(
    m: &mut ProtectedState,
    conn: &str,
    service: &str,
    hosts: Option<Vec<String>>,
    keys: Option<BTreeMap<String, String>>,
    cfg: &ExchangeConfig,
    tokens: &ExchangedTokens,
) {
    // The record's role→KEY bindings. Every role this exchange stores must be
    // bound BEFORE the writes below so writer and future readers use one map.
    let keys: Option<BTreeMap<String, String>> = keys.or_else(|| {
        if conn == service {
            return None; // identity binding — no map stored
        }
        let mut map = BTreeMap::new();
        let mut bind = |role: &str| {
            let r = role.to_ascii_uppercase();
            let k = suggested_secret_key(conn, service, &r);
            map.insert(r, k);
        };
        bind(&cfg.secret_role);
        if let Some(idt_role) = &cfg.id_token_role {
            bind(idt_role);
        }
        for (role, _) in &cfg.exposes {
            bind(role);
        }
        Some(map)
    });
    let mut rec = Connection {
        name: None, // set below from the connecting entry
        service: Some(service.to_string()),
        hosts,
        secrets: None,
        keys,
        written: None, // set below: every KEY this exchange stores
    };
    let mut written: Vec<String> = Vec::new();
    let mut put = |m: &mut ProtectedState, key: String, value: Vec<u8>| {
        if !written.contains(&key) {
            written.push(key.clone());
        }
        m.put_secret(key, value);
    };
    if let Some(rt) = &tokens.refresh_token {
        put(
            m,
            secret_key_for(Some(&rec), &cfg.secret_role),
            rt.as_bytes().to_vec(),
        );
    }
    if let Some(idt) = &tokens.id_token {
        // Store the raw id_token only when the service names a slot for it.
        if let Some(idt_role) = &cfg.id_token_role {
            put(
                m,
                secret_key_for(Some(&rec), idt_role),
                idt.as_bytes().to_vec(),
            );
        }
        // Derive each exposed role from its id_token claim. Stored UPPERCASED
        // (env-key convention for vault items); the lowercase phantom segment
        // resolves case-insensitively. A missing claim is logged, not fatal —
        // the phantom then answers with the precise "not derived" refusal.
        for (role, path) in &cfg.exposes {
            match crate::auth::oauth2::id_token_claim(idt, path) {
                Some(v) => {
                    let key = role.to_ascii_uppercase();
                    put(m, secret_key_for(Some(&rec), &key), v.into_bytes());
                }
                None => tracing::warn!(
                    conn = %conn,
                    role = %role,
                    "oauth connect: id_token carries no claim at the exposes path"
                ),
            }
        }
    } else if !cfg.exposes.is_empty() {
        tracing::warn!(
            conn = %conn,
            "oauth connect: service exposes derived roles but the exchange returned no id_token"
        );
    }
    written.sort();
    rec.written = Some(written);
    // MOVE: drop from `connecting`, add to `connections` (name carried over).
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    let name = connecting.remove(conn).and_then(|c| c.name);
    set_aux_map(m, "connecting", connecting);

    let mut connections = aux_map::<Connection>(m, "connections");
    // Service-backed: secrets derive from the service def, never stored here;
    // `keys` is the role→KEY binding fixed above.
    connections.insert(conn.to_string(), Connection { name, ..rec });
    set_aux_map(m, "connections", connections);
}

/// Collect the in-flight connects worth exchanging from `aux.connecting`. Pure
/// (no network) for testability.
///
/// A connect that already carries a terminal `error` (its code was
/// `invalid_grant` — expired/used) is DONE, not pending: it stays in
/// `connecting` only so the console can render "reconnect". Re-exchanging it is
/// futile AND harmful — the re-mark re-pushes the entry, which the cloud-sync
/// watcher sees as a change and re-processes, forming a self-perpetuating retry
/// storm against the token endpoint. So skip error'd entries; only a fresh
/// connect (no `error`) or a transient failure (never stamped one) is retried.
fn collect_pending(m: &ProtectedState) -> Vec<(String, Connecting)> {
    aux_map::<Connecting>(m, "connecting")
        .into_iter()
        // Skip an entry still AWAITING its code (empty `code`): an auto-catch
        // connect seals `{code_verifier, state}` BEFORE consent and only gets a
        // code once the 8765 listener catches the redirect (or the user pastes).
        // Exchanging an empty code would earn a bogus invalid_grant and clobber
        // the flow. `error.is_none()` still excludes terminally-failed entries.
        .filter(|(_, c)| c.oauth2.error.is_none() && !c.oauth2.code.is_empty())
        .collect()
}

/// Merge codes the 8765 loopback listener caught into their matching pending
/// entries (keyed by connection id), so [`collect_pending`] picks them up for
/// exchange this cycle. Only fills an EMPTY code — never overwrites one already
/// present (a racing paste wins whichever landed first). Pure state edit.
fn inject_codes(m: &mut ProtectedState, codes: &std::collections::BTreeMap<String, String>) {
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    let mut changed = false;
    for (conn, code) in codes {
        if let Some(entry) = connecting.get_mut(conn) {
            if entry.oauth2.code.is_empty() && !code.is_empty() {
                entry.oauth2.code = code.clone();
                changed = true;
            }
        }
    }
    if changed {
        set_aux_map(m, "connecting", connecting);
    }
}

/// Per-run outcome of the connect state machine, so callers (and ultimately
/// `sc sync`) can SURFACE what happened instead of failing silently. Three
/// disjoint buckets:
/// - `completed`: got a refresh_token, MOVEd to `connections`.
/// - `failed`: TERMINALLY rejected (`invalid_grant` / other 4xx) — an `error` was
///   stamped so the console renders "reconnect"; carries the provider's reason.
/// - `unreached`: a TRANSIENT failure (couldn't reach the provider — network /
///   proxy / 5xx): left pending, NO error stamped, retried on its own timer
///   ([`crate::auth::retry`]); carries the provider host so the user can tell "my egress is broken" from "the code died".
#[derive(Debug, Default, Clone)]
pub struct ConnectReport {
    pub completed: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub unreached: Vec<(String, String)>,
    /// The `completed` connects are stored but this device does not serve
    /// them yet ([`crate::error::STORED_NOT_SERVED_MSG`]).
    pub not_served: bool,
}

impl ConnectReport {
    /// Did anything MUTATE the sealed state (⇒ the caller must persist + push)?
    /// A transient `unreached` stamps nothing, so it does not count.
    pub fn changed(&self) -> bool {
        !self.completed.is_empty() || !self.failed.is_empty()
    }
}

/// The bare host of a token endpoint (`https://oauth2.googleapis.com/token` →
/// `oauth2.googleapis.com`), for the human-readable "couldn't reach X" signal.
fn provider_host(token_url: &str) -> String {
    let after = token_url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(token_url);
    after
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(token_url)
        .to_string()
}

/// Sentinel the exchange closure returns for a code THIS daemon has already
/// redeemed (see [`crate::state::AppState::was_code_redeemed`]). `run_pending`
/// treats it as neither success nor failure: skip silently, leave the entry,
/// stamp NO error — a re-`invalid_grant` on an already-consumed code must never
/// clobber the live connection.
const ALREADY_REDEEMED: &str = "__sc_already_redeemed__";

/// Sentinel the exchange closure returns when a code still fails transiently
/// past [`CODE_EXCHANGE_WINDOW`]: `run_pending` marks the connection failed.
const CODE_EXPIRED: &str = "__sc_code_expired__";

/// How long a transiently failing code exchange is retried: RFC 6749 §4.1.2
/// recommends a maximum authorization code lifetime of 10 minutes, so past
/// that the code is presumed dead and only a fresh consent recovers.
pub(crate) const CODE_EXCHANGE_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// Has a code first tried at `first_tried` outlived its exchange window (pure)?
pub(crate) fn code_exchange_expired(first_tried: std::time::Instant, now: std::time::Instant) -> bool {
    now.saturating_duration_since(first_tried) > CODE_EXCHANGE_WINDOW
}

/// Drive the connecting→refresh→move state machine over an open `ProtectedState`,
/// given an async `exchange` closure (injected so tests can avoid real network
/// calls). Mutates `m` in place; returns a [`ConnectReport`] of what happened. On
/// a per-connect failure it logs and **leaves the `connecting` entry in place**
/// (the user retries within the code TTL) — it never aborts the whole batch.
///
/// The caller persists + pushes whenever [`ConnectReport::changed`] is true.
///
/// `exchange(conn, cfg, connecting)` performs the code→token call and returns the
/// tokens (or an error string to log + skip).
pub async fn run_pending<F, Fut>(
    services: &crate::service::ServiceRegistry,
    custom: &std::collections::HashMap<String, crate::service::ServiceDef>,
    m: &mut ProtectedState,
    mut exchange: F,
) -> ConnectReport
where
    F: FnMut(String, ExchangeConfig, Connecting) -> Fut,
    Fut: std::future::Future<Output = Result<ExchangedTokens, String>>,
{
    let pending = collect_pending(m);
    let mut report = ConnectReport::default();
    for (conn, p) in pending {
        let Some(cfg) = resolve_exchange_config(services, custom, &p.service) else {
            tracing::warn!(
                conn = %conn,
                service = %p.service,
                "oauth connect: no oauth2 exchange config for the connection's service \
                 (unknown/non-oauth2 service or missing provider creds); leaving connecting"
            );
            continue;
        };
        // Capture what the post-exchange MOVE needs before `p` is consumed.
        let service = p.service.clone();
        let hosts = p.hosts.clone();
        let keys = p.keys.clone();
        let cfg_apply = cfg.clone();
        let host = provider_host(&cfg_apply.token_url);
        match exchange(conn.clone(), cfg, p).await {
            Ok(tokens) => {
                if tokens.refresh_token.is_none() {
                    // No durable credential came back (consent without offline
                    // access). Leave connecting so the user can redo consent.
                    tracing::warn!(
                        conn = %conn,
                        "oauth connect: exchange returned no refresh_token; leaving connecting"
                    );
                    continue;
                }
                apply_exchange_result(m, &conn, &service, hosts, keys, &cfg_apply, &tokens);
                report.completed.push(conn.clone());
                tracing::info!(
                    conn = %conn,
                    "oauth connect: refresh_token persisted; moved to connections"
                );
            }
            Err(e) => {
                if e == ALREADY_REDEEMED {
                    // Idempotency: this daemon already redeemed this code, and a
                    // stale write (a buggy web Save, a cross-device echo, or a
                    // pull that resurrected the pending entry before our success
                    // push landed) put it back in `connecting`. Re-sending it
                    // would earn a no-win `invalid_grant`; treat it as neither
                    // success nor failure — leave the entry, stamp nothing, let
                    // sync convergence settle it.
                    tracing::info!(
                        conn = %conn,
                        "oauth connect: code already redeemed by this daemon — skipping stale re-introduction (not a failure)"
                    );
                    continue;
                }
                if e == CODE_EXPIRED {
                    let reason = "the authorization code expired before the provider could be reached; reconnect".to_string();
                    mark_connecting_failed(m, &conn, &reason);
                    report.failed.push((conn.clone(), reason));
                    tracing::warn!(conn = %conn, "oauth connect: exchange still failing past the code's lifetime; marked failed");
                    continue;
                }
                if let Some(reason) = terminal_exchange_reason(&e) {
                    // Terminal: retrying the SAME code/config can never succeed.
                    // Stamp the connecting entry so the console shows
                    // "failed — reconnect" (with the provider's reason) instead
                    // of a perpetual "connecting" retry-storming the token
                    // endpoint. Only a fresh consent (new code, possibly a fixed
                    // def) recovers — it overwrites this entry, clearing the
                    // error.
                    mark_connecting_failed(m, &conn, &reason);
                    report.failed.push((conn.clone(), reason));
                    tracing::warn!(conn = %conn, "oauth connect: terminal exchange rejection — marked failed: {}", e);
                } else {
                    // Transient (network / provider 5xx / rate limit) — leave
                    // connecting; its retry timer tries again (backoff). Report it so `sc sync`
                    // can say "couldn't reach <host>" instead of a silent spin.
                    report.unreached.push((conn.clone(), host));
                    tracing::warn!(conn = %conn, "oauth connect: exchange failed (transient), will retry: {}", e);
                }
            }
        }
    }
    report
}

/// Classify an exchange failure: `Some(reason)` when re-sending the SAME
/// request can never succeed (the provider REJECTED it — expired code, missing
/// client_secret, bad client, wrong redirect …), `None` when it's worth
/// retrying (network error, provider 5xx, rate limit). Blindly retrying a
/// rejection forms a retry storm against the token endpoint: the sync watcher
/// re-processes the pending entry every cycle, forever.
///
/// The error is a formatted string (`exchange_code` returns
/// `"… returned HTTP <status>: <body>"`), so classification is textual: any
/// 4xx is a rejection except 408 (timeout) and 429 (rate limit). The reason
/// surfaces the provider's `error_description`/`error` when the body is the
/// standard RFC 6749 §5.2 JSON.
fn terminal_exchange_reason(e: &str) -> Option<String> {
    if e.contains("invalid_grant") {
        return Some("authorization expired or already used".to_string());
    }
    let rejected = e.contains("returned HTTP 4")
        && !e.contains("returned HTTP 408")
        && !e.contains("returned HTTP 429");
    if !rejected {
        return None;
    }
    let detail = e
        .split_once(": ")
        .and_then(|(_, body)| serde_json::from_str::<serde_json::Value>(body.trim()).ok())
        .and_then(|v| {
            v.get("error_description")
                .or_else(|| v.get("error"))
                .and_then(|d| d.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "provider rejected the exchange".to_string());
    Some(format!("provider rejected the exchange: {}", detail))
}

/// Stamp a terminal `error` on one `connecting` entry (leaving code/code_verifier
/// so the console still knows which connection it is). No-op if the entry is gone.
fn mark_connecting_failed(m: &mut ProtectedState, conn: &str, reason: &str) {
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    if let Some(entry) = connecting.get_mut(conn) {
        entry.oauth2.error = Some(reason.to_string());
    }
    set_aux_map(m, "connecting", connecting);
}

/// Process all in-flight connects (`aux.connecting`) for one vault: open the body
/// with the retained `K`, exchange each pending code, write the refresh_tokens,
/// MOVE each entry to `aux.connections`, re-seal under the same `K`, and persist
/// `vault.dat`.
///
/// Best-effort end-to-end:
/// - Locked vault (no retained `K`) → skip (the next unlock re-runs this).
/// - No pending connects → no-op (no disk write).
/// - A retained `K` that can't open the body (rotated `K`) → log + skip.
/// - Per-connect failures are handled by [`run_pending`] (leave + retry).
///
/// Holds the per-vault write lock for the open→mutate→re-seal→write cycle so it
/// serializes against approve.rs's writes and the cloud-sync pull (same lock).
/// Never panics; any error logs and returns.
pub async fn process_vault_connects(
    state: &Arc<AppState>,
    vault_id: &str,
    injected: Option<std::collections::BTreeMap<String, String>>,
) -> ConnectReport {
    // Apply any pending connects (open → exchange → re-seal → persist). On a
    // completion, fan the re-sealed blob out to OTHER devices via the cloud.
    // `injected` (conn → code) carries any codes the 8765 loopback listener just
    // caught; `None` on the ordinary sync path (nothing to inject).
    let report = apply_pending_connects(state, vault_id, injected).await;
    if report.changed() {
        // A fresh connect landed → clear any stale needs-reauth flag for this
        // vault (a still-dead token re-marks on the next /use).
        state.oauth_clear_reauth_vault(vault_id);
        // Propagate to OTHER devices: push the re-sealed blob back to the cloud.
        // A Google authorization code is single-use, so only THIS daemon could
        // redeem the pending connect — every other device's daemon must PULL the
        // resulting refresh_token rather than re-exchange (which fails
        // `invalid_grant`). Cloud-blind preserved: the pushed blob is ciphertext.
        // Detached + best-effort, after the write lock drops (push only reads
        // vault.dat + HTTP).
        let state = state.clone();
        let vid = vault_id.to_string();
        tokio::spawn(async move {
            // Keyset lifecycle rides the whole-blob push (the `/blob` marker) AND
            // the per-cred wrap material rides `/keys`; content (the new
            // refresh-token secret + connection MOVE) rides the per-item push.
            crate::sync::push_blob_best_effort(&state, &vid).await;
            crate::sync::push_keys_best_effort(&state, &vid).await;
            crate::sync::push_items_best_effort(&state, &vid).await;
        });
    }
    report
}

/// Apply pending connects WITHOUT the cloud push-back. Returns a [`ConnectReport`]
/// of what happened (empty when locked / nothing pending). The push fan-out lives
/// in the public `process_vault_connects` wrapper, NOT here — that split is
/// load-bearing: the cloud-sync CAS-conflict recovery
/// (`sync::recover_after_conflict`) calls this inner fn to re-apply its mutation
/// on a freshly-pulled blob; routing it through the push-spawning wrapper would
/// form an async-recursion cycle (push → recover → process → push) the compiler
/// can't prove `Send`. Keeping the push out of the recursive edge breaks it.
pub(crate) async fn apply_pending_connects(
    state: &Arc<AppState>,
    vault_id: &str,
    injected: Option<std::collections::BTreeMap<String, String>>,
) -> ConnectReport {
    let report = apply_pending_connects_inner(state, vault_id, injected).await;
    // A transient exchange failure writes nothing, so no event or sync would
    // bring it back: it owns a retry timer with backoff until a run leaves
    // none (every pending entry is tried each run, so this run's report is the
    // whole answer; a locked or unreadable vault is retried at unlock).
    if report.unreached.is_empty() {
        crate::auth::retry::settle(state, vault_id, crate::auth::retry::Job::CodeExchange);
    } else {
        crate::auth::retry::schedule(state, vault_id, crate::auth::retry::Job::CodeExchange);
    }
    report
}

async fn apply_pending_connects_inner(
    state: &Arc<AppState>,
    vault_id: &str,
    injected: Option<std::collections::BTreeMap<String, String>>,
) -> ConnectReport {
    let Some(k) = state.cloned_state_key(vault_id) else {
        return ConnectReport::default(); // Locked — no retained K; next unlock retries.
    };

    let Ok(_guard) = state.vault_write_guard(vault_id).await else {
        return ConnectReport::default();
    };

    // Rotated refresh tokens not stored yet: stored again now.
    retry_pending_rotations_locked(state, vault_id);

    let vault_dat = match crate::storage::sealed_vault::read(&vault_dat_path(state, vault_id)) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth connect: read vault.dat failed: {}", e);
            None
        }
    };
    // `M` + the base it was read from (per-item store first: see
    // `open_m_for_write`). Not openable → skip; a re-unlock heals a rotated K.
    // Trace it: this return also silently skips loopback-listener arming, so
    // without a line here a skipped scan is indistinguishable from "no pending
    // connect".
    let (mut m, base) = match open_m_for_write(state, vault_id, &k, vault_dat.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            if e.contains("undecryptable with retained K") {
                state.mark_vault_key_changed(vault_id);
            }
            tracing::debug!(vault = %vault_id, "oauth connect: skipping scan: {}", e);
            return ConnectReport::default();
        }
    };

    // Register every loopback connect still AWAITING its redirect (carries a
    // `state`, no code yet) so the on-demand listener can match an incoming
    // `?code&state` to this (vault, connection). The listen PORT comes from the
    // connect's service def (custom-FIRST, same resolution the exchange uses)
    // and must sit in the allowlist parsed from LOCALLY-INSTALLED defs — vault
    // content picks among shipped targets (8765 canonical, 1455 openai_codex),
    // it can never open a new port. Off-allowlist redirect ⇒ paste-only.
    // Runs each ordinary sync tick, keeping the in-memory index fresh
    // (self-reaps at the 2h ceiling). Skipped on the injected path (the
    // completion call for an entry we already took out of the index) so a
    // just-completed connect isn't re-registered stale.
    if injected.is_none() {
        let custom = state.custom_services_snapshot(vault_id);
        let allowed = state.services.loopback_allowlist();
        for (conn_id, c) in aux_map::<Connecting>(&m, "connecting") {
            if c.oauth2.code.is_empty() {
                if let Some(st) = &c.oauth2.state {
                    match loopback_port_for(&state.services, &custom, &c.service) {
                        Some(port) if allowed.contains(&port) => {
                            state.note_loopback_pending(st, vault_id, &conn_id, port);
                        }
                        Some(port) => tracing::debug!(
                            conn = %conn_id, port,
                            "oauth connect: redirect port not in the local-def allowlist; paste-only"
                        ),
                        None => tracing::debug!(
                            conn = %conn_id,
                            "oauth connect: no loopback redirect target; paste-only"
                        ),
                    }
                }
            }
        }
        // Open each pending port's listener ON DEMAND — only while some connect
        // is awaiting its redirect there. Idempotent + single-instance per port:
        // N concurrent connects (across all vaults) share ONE listener per port
        // (`ensure_running` no-ops if already up, so the daemon never races
        // itself into a port conflict); each self-closes when its last pending
        // clears. No pending ⇒ nothing opens.
        for port in state.pending_loopback_ports() {
            crate::auth::loopback::ensure_running(state.clone(), port);
        }
    }

    // Fill in any codes the 8765 listener caught this round, so the matching
    // entries become exchangeable in the pre-check + run below.
    if let Some(injected) = &injected {
        inject_codes(&mut m, injected);
    }

    // Cheap pre-check: nothing to do if there are no in-flight connects.
    if collect_pending(&m).is_empty() {
        return ConnectReport::default();
    }

    let services = &state.services;
    // Per-vault custom services (`aux.services`) so a user-authored inline
    // [oauth2] service's connect can resolve — the bootstrap that populates
    // this cache always runs before us (sync/watch/unlock+write all refresh
    // the cache, THEN process connects), so it's fresh here.
    let custom = state.custom_services_snapshot(vault_id);
    let st = state.clone();
    let report = run_pending(services, &custom, &mut m, move |_conn, cfg, p| {
        let state = st.clone();
        async move {
            // Idempotency key = the authorization code. A single-use code this
            // daemon already redeemed must never be re-exchanged (a stale write
            // can resurrect its `connecting` entry); re-sending earns a no-win
            // `invalid_grant` that would clobber the live connection. The ledger
            // is daemon-local + never synced, so no stale write can revert it.
            if state.was_code_redeemed(&p.oauth2.code) {
                return Err(ALREADY_REDEEMED.to_string());
            }
            // The def's token_params, the `{state}` placeholder filled from
            // THIS pending connect's consent state. A def that asks for it
            // when the entry has none fails here, with why.
            let extra = crate::auth::oauth2::render_extra_params(
                &cfg.token_params,
                p.oauth2.state.as_deref(),
            )?;
            let out = crate::auth::oauth2::exchange_code(
                &cfg.token_url,
                &cfg.client_id,
                cfg.client_secret.as_deref(),
                &p.oauth2.code,
                &p.oauth2.code_verifier,
                &cfg.redirect_uri,
                cfg.style,
                cfg.token_auth,
                &extra,
            )
            .await;
            match &out {
                Ok(_) => state.note_code_redeemed(&p.oauth2.code),
                // Retried transient failures stop once the code can no longer
                // be valid: the connection is marked failed ("reconnect")
                // instead of staying "connecting" for good.
                Err(e) if terminal_exchange_reason(e).is_none()
                    && code_exchange_expired(state.code_first_tried(&p.oauth2.code), std::time::Instant::now()) =>
                {
                    return Err(CODE_EXPIRED.to_string());
                }
                Err(_) => {}
            }
            out
        }
    })
    .await;

    // A terminal connect (completed or failed) no longer awaits a redirect —
    // drop its pending-loopback index entry so the on-demand 8765 listener can
    // close promptly (the auto-catch path already took it; this covers a
    // paste-fallback completion whose pre-seal entry no redirect consumed).
    for c in &report.completed {
        state.clear_loopback_for_conn(vault_id, c);
    }
    for (c, _) in &report.failed {
        state.clear_loopback_for_conn(vault_id, c);
    }

    if !report.changed() {
        // Nothing MUTATED (all left pending / transient) — don't rewrite or push.
        // Still return the report so a transient `unreached` surfaces to `sc sync`.
        return report;
    }
    // A terminal failure (invalid_grant) with no completion still MUTATED the
    // state (stamped `error` on the connecting entry) — fall through so it's
    // persisted + pushed, surfacing "reconnect" in the console.

    // Post-connect view: the new refresh_token secret + connecting→connections
    // MOVE, folded from the mutated M.
    let view = match crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth connect: view rebuild failed: {}", e);
            return ConnectReport::default();
        }
    };

    // Persist (see `write_view`): the per-item store, then the vault.dat
    // mirror, then the cache from what landed, so /use sees the new
    // refresh_token without a manual lock/unlock. A connect the store did not
    // take is reported failed, never served from memory; one it took that
    // this device does not serve yet is reported so.
    let mut report = report;
    let not_applied = match write_view(
        state,
        vault_id,
        vault_dat,
        &m,
        &view,
        WriteKey::Held(&k),
        &base,
    ) {
        Ok((n, installed)) => {
            report.not_served = !installed.served();
            n
        }
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth connect: not stored: {}", e);
            let why = format!("the connection could not be stored: {}", e);
            let completed = std::mem::take(&mut report.completed);
            report
                .failed
                .extend(completed.into_iter().map(|c| (c, why.clone())));
            return report;
        }
    };
    if !not_applied.is_empty() {
        let keys = crate::storage::item::VaultKeys::from_material(&k);
        fail_refused_connects(&mut report, &not_applied, keys.id_seed);
    }
    tracing::info!(
        vault = %vault_id,
        connects = report.completed.len(),
        failed = report.failed.len(),
        "oauth connect: processed"
    );
    report
}

/// A completed connect whose `connection:<id>` row the store refused or set
/// aside (`not_applied`: `(item id, why)`) did not complete: moved to
/// `failed`, with why. `id_seed` derives the row ids.
fn fail_refused_connects(
    report: &mut ConnectReport,
    not_applied: &[(String, String)],
    id_seed: &[u8],
) {
    let completed = std::mem::take(&mut report.completed);
    for conn in completed {
        let wire = crate::storage::item::wire_id_for::<sudp::primitives::StdPrimitives>(
            id_seed,
            crate::storage::item::ItemNs::Connection,
            &conn,
        );
        match not_applied
            .iter()
            .find(|(id, _)| wire.as_ref().is_ok_and(|w| w == id))
        {
            Some((_, why)) => report.failed.push((conn, why.clone())),
            None => report.completed.push(conn),
        }
    }
}

/// What a rotation store did (all three leave nothing pending for the slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotationStored {
    /// The vault's store now holds the new token.
    Written,
    /// It already did.
    AlreadyStored,
    /// The slot no longer holds the value the rotation replaced (a newer
    /// value was stored since, or the secret is gone): the pending token is
    /// stale and dropped.
    Superseded,
}

/// Persist a ROTATED refresh_token back into the sealed vault at its bound BARE
/// key (`secret_key_for` over the established connection record — the SAME slot
/// the connect exchange wrote). A rotating provider (OpenAI) hands back a fresh
/// refresh_token on every refresh and invalidates the one we sent (RFC 9700
/// §4.14.2), so the broker calls this right after the mint: the new token is
/// made durable on receipt, in the vault's one store, before it is used again.
///
/// One sealed row, written durably ([`PerItemVault::write_rotated_secret`] +
/// an fsynced atomic replace): no fold of the rest of the store and no merge,
/// so nothing about OTHER rows can make it fail. What is left: the vault
/// locked meanwhile, a store that cannot be read or written, or the slot's
/// row unreadable with this session's key (a keyset not caught up with; it is
/// never written over). A vault with no per-item store (legacy whole-blob)
/// keeps the full rewrite.
///
/// `old` is the value the rotation replaced. With `if_current`, the token is
/// written only while the slot still holds `old` (a delayed retry must never
/// put an older token over a newer one). On success the session cache points
/// at `new` and nothing stays pending for the slot.
///
/// The caller ALREADY HOLDS the per-vault write lock
/// ([`AppState::vault_write_lock`]); this does NOT take it. `Err` (why) when
/// the token was not stored; the caller keeps it in use and pending
/// ([`rotation_not_stored`]), never a corrupt write.
pub(crate) fn persist_rotated_refresh_locked(
    state: &Arc<AppState>,
    vault_id: &str,
    conn_id: &str,
    role: &str,
    old: &[u8],
    new_refresh_token: &str,
    if_current: bool,
) -> Result<RotationStored, String> {
    type S = sudp::primitives::StdPrimitives;
    let Some(k) = state.cloned_state_key(vault_id) else {
        return Err("the vault is locked".into());
    };
    let store = state
        .vaults
        .per_item_path(vault_id)
        .ok()
        .map(|path| (crate::storage::sealed_vault::read_per_item(&path), path));
    let stored = match store {
        Some((Ok(Some(mut pv)), path)) => {
            // The slot the refresh token was read from: the session's record
            // of the connection (identity key for a default connection).
            let rec = state.connection_snapshot(vault_id, conn_id);
            let key = secret_key_for(rec.as_ref(), role);
            let keys = crate::storage::item::VaultKeys::from_material(&k);
            let replaces = if_current
                .then(|| std::str::from_utf8(old).ok())
                .flatten();
            if if_current && replaces.is_none() {
                return Ok(RotationStored::Superseded);
            }
            match pv
                .write_rotated_secret::<S>(keys, vault_id, &key, new_refresh_token, replaces)
                .map_err(|e| e.to_string())?
            {
                crate::storage::sealed_vault::RotatedWrite::Written(id) => {
                    crate::storage::sealed_vault::write_per_item_atomic(&path, &pv)
                        .map_err(|e| format!("the vault's store could not be written: {}", e))?;
                    state.clear_sync_conflict(vault_id, &id);
                    RotationStored::Written
                }
                crate::storage::sealed_vault::RotatedWrite::AlreadyStored => {
                    RotationStored::AlreadyStored
                }
                crate::storage::sealed_vault::RotatedWrite::Superseded => {
                    RotationStored::Superseded
                }
            }
        }
        Some((Err(e), _)) => return Err(format!("the vault's store cannot be read: {}", e)),
        _ => {
            persist_rotated_refresh_whole_blob(state, vault_id, conn_id, role, new_refresh_token, &k)?;
            RotationStored::Written
        }
    };
    match stored {
        RotationStored::Written | RotationStored::AlreadyStored => {
            state.cache_replace_value(vault_id, conn_id, old, new_refresh_token.as_bytes());
            tracing::info!(vault = %vault_id, conn = %conn_id, "oauth refresh: rotated refresh_token persisted");
        }
        RotationStored::Superseded => {
            tracing::info!(vault = %vault_id, conn = %conn_id, "oauth refresh: a newer refresh_token was stored since; the pending one is dropped");
        }
    }
    state.drop_pending_rotation(vault_id, conn_id, role);
    Ok(stored)
}

/// [`persist_rotated_refresh_locked`] for a vault with no per-item store: the
/// whole body is rewritten (and re-sealed into `vault.dat`).
fn persist_rotated_refresh_whole_blob(
    state: &Arc<AppState>,
    vault_id: &str,
    conn_id: &str,
    role: &str,
    new_refresh_token: &str,
    k: &[u8],
) -> Result<(), String> {
    let vault_dat = match crate::storage::sealed_vault::read(&vault_dat_path(state, vault_id)) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth rotate: read vault.dat failed: {}", e);
            None
        }
    };
    let (mut m, base) = open_m_for_write(state, vault_id, k, vault_dat.as_ref())?;
    let rec = aux_map::<Connection>(&m, "connections").remove(conn_id);
    m.put_secret(
        secret_key_for(rec.as_ref(), role),
        new_refresh_token.as_bytes().to_vec(),
    );
    let view = crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m)
        .map_err(|e| format!("view rebuild failed: {}", e))?;
    let (not_applied, _) = write_view(
        state,
        vault_id,
        vault_dat,
        &m,
        &view,
        WriteKey::Held(k),
        &base,
    )?;
    if !not_applied.is_empty() {
        return Err(sentences(&not_applied));
    }
    Ok(())
}

/// A rotated refresh token this device could not store (`why`): the provider
/// now honors only the new one, so the session uses it (`old` → `new` in the
/// cache, and in every cache rebuilt from the store until it is stored), the
/// store is retried on its own timer with backoff ([`crate::auth::retry`]),
/// after every sync round and at unlock, and the user is told.
pub(crate) fn rotation_not_stored(
    state: &Arc<AppState>,
    vault_id: &str,
    conn_id: &str,
    role: &str,
    old: &[u8],
    new: &str,
    why: &str,
) {
    tracing::warn!(vault = %vault_id, conn = %conn_id, "oauth rotate: not stored: {}", why);
    state.cache_replace_value(vault_id, conn_id, old, new.as_bytes());
    state.note_rotation_pending(vault_id, conn_id, role, old, new, why);
    crate::auth::retry::schedule(state, vault_id, crate::auth::retry::Job::RotationStore);
}

/// Store again the rotated refresh tokens not stored yet. The caller holds
/// the vault write lock. Each is written only while its slot still holds the
/// value it replaced (an older token never goes over a newer one). One that
/// lands is pushed; one that does not stays pending, still reported, and
/// keeps its retry timer. A locked vault is not attempted: it cannot be
/// sealed until unlock, which runs this again.
pub(crate) fn retry_pending_rotations_locked(state: &Arc<AppState>, vault_id: &str) {
    if state.cloned_state_key(vault_id).is_none() {
        crate::auth::retry::settle(state, vault_id, crate::auth::retry::Job::RotationStore);
        return;
    }
    let mut left = false;
    for ((conn_id, role), p) in state.take_pending_rotations(vault_id) {
        match persist_rotated_refresh_locked(state, vault_id, &conn_id, &role, &p.old, &p.new, true) {
            Ok(RotationStored::Written) => spawn_push(state, vault_id),
            Ok(_) => {}
            Err(why) => {
                left = true;
                state.note_rotation_pending(vault_id, &conn_id, &role, &p.old, &p.new, &why);
            }
        }
    }
    if left {
        crate::auth::retry::schedule(state, vault_id, crate::auth::retry::Job::RotationStore);
    } else {
        crate::auth::retry::settle(state, vault_id, crate::auth::retry::Job::RotationStore);
    }
}

/// The rotation retry timer's job: take the vault write lock and store again.
pub(crate) async fn retry_pending_rotations(state: &Arc<AppState>, vault_id: &str) {
    let Ok(_guard) = state.vault_write_guard(vault_id).await else {
        return;
    };
    retry_pending_rotations_locked(state, vault_id);
}

/// Before a vault locks (the caller holds its write lock, K still in hand):
/// one attempt to store every rotated refresh token still pending, since
/// sealing needs K and the lock evicts it. A token that still cannot be
/// stored stays in memory in plaintext (on the vault runtime, which the lock
/// keeps): it is the ONLY valid copy, so dropping it would force a
/// reconnect. It is stored at the next unlock, or lost if the daemon exits
/// first, which is logged.
pub(crate) fn store_pending_rotations_before_lock(state: &Arc<AppState>, vault_id: &str) {
    if !state.has_pending_rotations(vault_id) {
        return;
    }
    retry_pending_rotations_locked(state, vault_id);
    if state.has_pending_rotations(vault_id) {
        tracing::warn!(
            vault = %vault_id,
            "vault locking with a rotated refresh token not stored yet: kept in memory until the next unlock stores it (lost if the daemon exits first)"
        );
    }
}

/// Push this vault's keys and items in the background: the push takes the
/// vault write lock itself, so it runs once the caller's guard drops. No
/// runtime (a plain test): nothing.
pub(crate) fn spawn_push(state: &Arc<AppState>, vault_id: &str) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let state = state.clone();
    let vid = vault_id.to_string();
    tokio::spawn(async move {
        crate::sync::push_keys_best_effort(&state, &vid).await;
        crate::sync::push_items_best_effort(&state, &vid).await;
    });
}

/// Open the vault body `M` a daemon-side write mutates, plus the
/// [`ViewBase`] it was read from. The per-item store is the LIVE content
/// (pulls land there only), so it wins whenever it exists, exactly as
/// `open_view_for_grant_keep_key` / `open_view_with_state_key` read; `vault.dat`
/// is the fallback for a vault without one (and otherwise only a write-through
/// mirror the caller re-seals). Reading a lagging vault.dat first made a
/// connect/refresh write its stale values back over newer pulled ones. An
/// unreadable store is an error, never a silent fall back to vault.dat.
fn open_m_for_write(
    state: &Arc<AppState>,
    vault_id: &str,
    k: &[u8],
    vault_dat: Option<&crate::storage::SealedVault>,
) -> Result<(ProtectedState, ViewBase), String> {
    let pv = match state.vaults.per_item_path(vault_id) {
        Ok(p) => crate::storage::sealed_vault::read_per_item(&p)
            .map_err(|e| format!("per-item store unreadable: {}", e))?,
        Err(_) => None,
    };
    let (m, view) = if let Some(pv) = pv {
        let view = crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(
            k, &pv, vault_id,
        )
        .map_err(|e| format!("per-item view undecryptable with retained K: {}", e))?;
        (build_m_from_view(&view)?, view)
    } else {
        let vault = vault_dat.ok_or("neither a per-item store nor vault.dat")?;
        let m = crate::server::handlers::metadata::open_protected_state_with_key(k, vault)
            .map_err(|e| format!("vault.dat undecryptable with retained K: {}", e))?;
        let view = crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m)
            .map_err(|e| format!("view rebuild failed: {}", e))?;
        (m, view)
    };
    let base = ViewBase::of(&view).map_err(|e| format!("view base: {}", e))?;
    Ok((m, base))
}

/// Rebuild a [`ProtectedState`] `M` from a folded per-item view — the inverse of
/// [`VaultPlaintextView::from_protected_state`]. Lets the connect state machine
/// (which reads/writes `M`'s aux + secrets) run against a web-enrolled per-item
/// vault that has no whole-blob `vault.dat`.
fn build_m_from_view(
    view: &crate::storage::plaintext::VaultPlaintextView,
) -> Result<ProtectedState, String> {
    let mut m = ProtectedState::new();
    m.aux = serde_json::to_value(&view.aux).map_err(|e| format!("aux to json: {}", e))?;
    for (name, bytes) in &view.native_secrets {
        m.put_secret(name.clone(), bytes.clone());
    }
    Ok(m)
}

/// Daemon-side persist of an already-mutated view — the grant-approved
/// equivalent of the CLI's `seal_and_submit_write` for an aux edit (e.g.
/// `sc service rm` / `sc service add`). Writes the per-item store (diff +
/// version bump, contract §4) and the whole-blob `vault.dat` mirror when one
/// backs this vault, and refreshes the in-memory cache from what landed
/// ([`write_view`]). Does NOT push — the caller spawns the sync fan-out AFTER
/// its write guard drops (the push path re-takes the per-vault write lock,
/// which is not reentrant). `base` is [`ViewBase::of`] the view as opened,
/// captured BEFORE the caller mutated it: only what the caller changed or
/// removed relative to it is written, so a row a concurrent pull changed or
/// adopted (pull does not take the write lock) is neither reverted nor
/// dropped. `key` is the key material recovered from the grant (via
/// `open_view_for_grant_keep_key`, [`WriteKey::Grant`]), so the CLI never
/// touches the PRF-derived user key — a `sc service` write works over SSH
/// through the plain grant link — or the key the unlocked vault holds
/// ([`WriteKey::Held`]).
///
/// `Err` unless the whole change landed: a store that cannot be written or a
/// reconcile that fails (`Internal`), or a part of the change refused or set
/// aside (`Conflict`, saying each; the parts that did land are kept, served
/// and pushed). `Ok` says whether this device serves the change now
/// ([`crate::state::Installed`]): a stored change it does not serve yet is
/// reported as such ([`crate::error::STORED_NOT_SERVED_MSG`]), never as an
/// error.
pub(crate) fn persist_mutated_view(
    state: &Arc<AppState>,
    vault_id: &str,
    base: &ViewBase,
    view: &crate::storage::plaintext::VaultPlaintextView,
    key: WriteKey<'_>,
) -> crate::error::Result<crate::state::Installed> {
    use crate::error::AppError;
    let m = build_m_from_view(view).map_err(AppError::Internal)?;
    let vault_dat = crate::storage::sealed_vault::read(&vault_dat_path(state, vault_id))
        .ok()
        .flatten();
    let (not_applied, installed) =
        write_view(state, vault_id, vault_dat, &m, view, key, base).map_err(AppError::Internal)?;
    if not_applied.is_empty() {
        Ok(installed)
    } else {
        // The caller returns this error before its own push: the parts that
        // did land go out now.
        spawn_push(state, vault_id);
        Err(AppError::Conflict(sentences(&not_applied)))
    }
}

/// The sentences of parts of a change not applied, joined.
fn sentences(not_applied: &[(String, String)]) -> String {
    not_applied
        .iter()
        .map(|(_, why)| why.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// `vaults/<vault_id>/vault.dat`.
fn vault_dat_path(state: &AppState, vault_id: &str) -> std::path::PathBuf {
    state
        .config
        .state_dir
        .join("vaults")
        .join(vault_id)
        .join("vault.dat")
}

/// The key material a daemon-side write seals under, and whose key its
/// install serves under ([`crate::state::InstallKey`]).
#[derive(Clone, Copy)]
pub(crate) enum WriteKey<'a> {
    /// The key an approved op's grant delivered: the install serves under it
    /// and, once served, the vault holds it.
    Grant(&'a [u8]),
    /// The key the vault held while unlocked (a write without an approval):
    /// the install serves under the key the vault holds then.
    Held(&'a [u8]),
}

impl<'a> WriteKey<'a> {
    fn material(self) -> &'a [u8] {
        match self {
            WriteKey::Grant(k) | WriteKey::Held(k) => k,
        }
    }

    fn install(self) -> crate::state::InstallKey {
        match self {
            WriteKey::Grant(k) => {
                crate::state::InstallKey::Grant(zeroize::Zeroizing::new(k.to_vec()))
            }
            WriteKey::Held(_) => crate::state::InstallKey::Held,
        }
    }
}

/// Write a mutated `view` (`m`: the same content as a body) under the key
/// material in `key`, relative to `base`, and serve what landed:
///   1. the per-item store, the content every read serves
///      ([`reconcile_per_item_after_connect`]); a store that cannot take the
///      change is an `Err`, and nothing below runs;
///   2. the whole-blob `vault.dat` mirror, when one backs this vault and `k`
///      is the single key it is sealed under (a keyset's key bundle never
///      sealed it: it is left as it is);
///   3. the cache, installed from the store as it now is
///      ([`AppState::install`], under `key`'s rules): served only while the
///      vault is Unlocked and the fold reads every row the served cache read.
///
/// Returns the parts of the change the store refused or set aside, each
/// `(item id, sentence)` (also noted for `sc sync` / `sc status`), and what
/// the install did. `Err` when neither store took the change: the cache is
/// left as it was.
fn write_view(
    state: &Arc<AppState>,
    vault_id: &str,
    vault_dat: Option<crate::storage::SealedVault>,
    m: &ProtectedState,
    view: &crate::storage::plaintext::VaultPlaintextView,
    key: WriteKey<'_>,
    base: &ViewBase,
) -> Result<(Vec<(String, String)>, crate::state::Installed), String> {
    let k = key.material();
    let written = reconcile_per_item_after_connect(
        state,
        vault_id,
        vault_dat.as_ref(),
        view,
        k,
        ReconcileBase::Since(base),
    )?;
    match vault_dat {
        Some(mut vault) if k.len() == crate::storage::item::SINGLE_KEY_LEN => {
            let mirrored =
                crate::server::handlers::metadata::reseal_body_with_key(k, &mut vault, m)
                    .map_err(|e| format!("reseal vault.dat: {}", e))
                    .and_then(|()| {
                        crate::storage::sealed_vault::write_atomic(
                            &vault_dat_path(state, vault_id),
                            &vault,
                        )
                        .map_err(|e| format!("write vault.dat: {}", e))
                    });
            if let Err(e) = mirrored {
                if written.is_none() {
                    return Err(e);
                }
                // The store holds the change; the mirror lags until its next write.
                tracing::warn!(vault = %vault_id, "vault.dat mirror not updated: {}", e);
            }
        }
        Some(_) if written.is_none() => {
            return Err("vault.dat is not sealed under this vault's current key, and no per-item store backs the vault; nothing was written".into());
        }
        Some(_) => {}
        None if written.is_none() => {
            return Err(
                "this vault has neither a per-item store nor vault.dat; nothing was written".into(),
            );
        }
        None => {}
    }
    let not_applied = written.map(|w| w.not_applied).unwrap_or_default();
    Ok((not_applied, state.install(vault_id, key.install())))
}

/// What a per-item store write did ([`reconcile_per_item_after_connect`]).
struct StoreWrite {
    /// The caller's changes the store refused or set aside, each `(item id,
    /// sentence)`.
    not_applied: Vec<(String, String)>,
}

/// Apply the caller's change (`view`, relative to `base`) to the local
/// per-item store as version-bumped item upserts/tombstones, under the key
/// material `k` read the way every other store access reads it
/// ([`crate::storage::item::VaultKeys::from_material`]), then persist it.
///
/// `Ok(None)`: no per-item store backs this vault (no store and no vault.dat
/// to bootstrap one from). `Err`: the change did not land (the store cannot be
/// read, the reconcile failed, or its write failed); the caller reports it and
/// never serves its own view.
fn reconcile_per_item_after_connect(
    state: &Arc<AppState>,
    vault_id: &str,
    vault: Option<&crate::storage::SealedVault>,
    view: &crate::storage::plaintext::VaultPlaintextView,
    k: &[u8],
    base: ReconcileBase<'_>,
) -> Result<Option<StoreWrite>, String> {
    use crate::storage::sealed_vault::{Keyset, PerItemVault};
    type S = sudp::primitives::StdPrimitives;
    let Ok(path) = state.vaults.per_item_path(vault_id) else {
        return Ok(None);
    };
    // Reuse the existing per-item store if present (so versions/cursors are
    // preserved); otherwise bootstrap one from the whole-blob keyset. A
    // web-enrolled per-item vault ALWAYS has a store, so `vault` is `None` there
    // and the bootstrap branch is only reached on the vault.dat path.
    let mut pv = match crate::storage::sealed_vault::read_per_item(&path) {
        Ok(Some(pv)) => pv,
        // An unreadable store may be a v2 (UIK) one: never overwrite it with a
        // bootstrapped v1 keyset (that would downgrade it to integrity-only NoUik).
        Err(e) => return Err(format!("the vault's store cannot be read: {}", e)),
        Ok(None) => {
            let Some(vault) = vault else { return Ok(None) };
            PerItemVault {
                keyset: Keyset {
                    version: vault.version,
                    registry: vault.registry.clone(),
                    credentials: vault.credentials.clone(),
                    keyset_version: 0,
                    // Bootstrapped from a v1 whole-blob vault → v1 keyset.
                    uik: None,
                },
                items: std::collections::BTreeMap::new(),
                items_seq: 0,
                keyset_seq: 0,
                held: Default::default(),
                row_kinds: Default::default(),
            }
        }
    };
    let keys = crate::storage::item::VaultKeys::from_material(k);
    let reconciled = pv
        .reconcile_from_view::<S>(keys, vault_id, view, base)
        .map_err(|e| {
            format!(
                "the change could not be applied to the vault's store: {}",
                e
            )
        })?;
    // Fold before writing: a store this key cannot fold is never written.
    pv.fold_view::<S>(keys, vault_id)
        .map_err(|e| format!("the vault's store cannot be read after the change: {}", e))?;
    if !reconciled.changed.is_empty() {
        crate::storage::sealed_vault::write_per_item_atomic(&path, &pv)
            .map_err(|e| format!("the vault's store could not be written: {}", e))?;
        tracing::info!(
            vault = %vault_id,
            changed = reconciled.changed.len(),
            "per-item store updated"
        );
    }
    // A row written settles an earlier note on it.
    for item in &reconciled.changed {
        state.clear_sync_conflict(vault_id, item);
    }
    let mut not_applied = Vec::new();
    // Owner-config the caller changed while it also changed elsewhere:
    // set aside, never written over; `sc sync` tells the user to re-run.
    for (item, record) in &reconciled.set_aside {
        tracing::warn!(vault = %vault_id, item = %item, record = %record, "changed elsewhere meanwhile; ours set aside, theirs kept");
        not_applied.push((
            item.clone(),
            format!(
                "{} changed elsewhere meanwhile; your change to it was not applied: re-run it",
                record
            ),
        ));
        state.note_sync(
            vault_id,
            item,
            crate::state::SyncNote::ChangedElsewhere(record.clone()),
        );
    }
    // A change refused (a row it would write over cannot be read, or
    // no conflict copy may be written): reported, never applied.
    for (item, why) in &reconciled.refused {
        tracing::warn!(vault = %vault_id, item = %item, "change refused: {}", why);
        not_applied.push((item.clone(), why.clone()));
        state.note_sync(vault_id, item, crate::state::SyncNote::Refused(why.clone()));
    }
    Ok(Some(StoreWrite { not_applied }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ProtectedState` whose `aux.connecting` carries one in-flight connect.
    /// The rest of the aux is a minimal valid v3 shell (only `connecting` matters
    /// to these functions).
    fn with_connecting(conn: &str, service: &str, code: &str) -> ProtectedState {
        let mut m = ProtectedState::new();
        m.aux = serde_json::json!({
            "version": 3,
            "stores": {},
            "store_order": [],
            "connecting": {
                conn: { "service": service, "oauth2": { "code": code, "code_verifier": "verif-xyz" } }
            }
        });
        m
    }

    fn tokens(rt: Option<&str>) -> ExchangedTokens {
        ExchangedTokens {
            refresh_token: rt.map(|s| s.to_string()),
            access_token: "at-123".to_string(),
            expires_at: 9_999_999_999,
            id_token: None,
        }
    }

    /// A minimal ExchangeConfig for apply_exchange_result tests — only the
    /// write-side fields matter (endpoints/client are exchange-side).
    fn cfg(role: &str) -> ExchangeConfig {
        ExchangeConfig {
            token_url: "https://example.test/token".into(),
            client_id: "client".into(),
            client_secret: None,
            style: OAuthStyle::Form,
            token_auth: TokenAuth::Post,
            token_params: Default::default(),
            redirect_uri: "http://127.0.0.1:8765/cb".into(),
            secret_role: role.to_string(),
            id_token_role: None,
            exposes: vec![],
        }
    }

    /// The compiled-in defaults include the gmail service + the google provider
    /// literal, so resolve_exchange_config finds a real config.
    fn gmail_registry() -> crate::service::ServiceRegistry {
        crate::service::ServiceRegistry::load()
    }

    /// No per-vault custom services — most tests exercise the built-in path.
    fn no_custom() -> std::collections::HashMap<String, crate::service::ServiceDef> {
        std::collections::HashMap::new()
    }

    #[test]
    fn collect_pending_reads_aux_connecting() {
        let m = with_connecting("gmail", "gmail", "code-AUX");
        let got = collect_pending(&m);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "gmail");
        assert_eq!(got[0].1.service, "gmail");
        assert_eq!(got[0].1.oauth2.code, "code-AUX");
    }

    #[test]
    fn collect_pending_empty_when_none() {
        let mut m = ProtectedState::new();
        m.aux = serde_json::json!({ "version": 3, "stores": {}, "store_order": [] });
        assert!(collect_pending(&m).is_empty());
    }

    #[test]
    fn collect_pending_skips_terminally_failed() {
        // A connect whose code was invalid_grant carries a terminal `error`.
        // It must NOT be re-collected (else we re-exchange a dead code every
        // sync tick + re-push it, forming a retry storm). It stays in the aux so
        // the console can show "reconnect" — just isn't retried.
        let mut m = with_connecting("gmail", "gmail", "code-DEAD");
        m.aux["connecting"]["gmail"]["oauth2"]["error"] =
            serde_json::json!("authorization expired or already used");
        assert!(
            collect_pending(&m).is_empty(),
            "an error-stamped connect must not be treated as pending"
        );
    }

    #[test]
    fn collect_pending_skips_entry_awaiting_its_code() {
        // An auto-catch connect seals { code_verifier, state } with NO code yet.
        // collect_pending must skip it (exchanging an empty code earns a bogus
        // invalid_grant) — until the 8765 listener injects the caught code.
        let mut m = with_connecting("gmail", "gmail", ""); // empty code
        m.aux["connecting"]["gmail"]["oauth2"]["state"] = serde_json::json!("st-123");
        assert!(
            collect_pending(&m).is_empty(),
            "an entry awaiting its redirect code must not be treated as pending"
        );
        // Inject the caught code → it becomes collectable for exchange.
        let mut codes = std::collections::BTreeMap::new();
        codes.insert("gmail".to_string(), "code-CAUGHT".to_string());
        inject_codes(&mut m, &codes);
        let got = collect_pending(&m);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1.oauth2.code, "code-CAUGHT");
    }

    #[test]
    fn inject_codes_fills_empty_only() {
        // A racing manual paste may have already put a code on the entry — the
        // caught code must NOT overwrite it (whichever landed first wins).
        let mut m = with_connecting("gmail", "gmail", "already-there");
        let mut codes = std::collections::BTreeMap::new();
        codes.insert("gmail".to_string(), "new-code".to_string());
        inject_codes(&mut m, &codes);
        assert_eq!(
            aux_map::<Connecting>(&m, "connecting")["gmail"].oauth2.code,
            "already-there",
        );
    }

    #[test]
    fn apply_exchange_default_writes_bare_and_moves() {
        // Default connection: conn == service → bare refresh_token name, no map.
        let mut m = with_connecting("gmail", "gmail", "code-AUX");
        apply_exchange_result(
            &mut m,
            "gmail",
            "gmail",
            None,
            None,
            &cfg("GMAIL_REFRESH_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("GMAIL_REFRESH_TOKEN").unwrap(), b"rt-NEW");
        assert!(
            aux_map::<Connecting>(&m, "connecting").is_empty(),
            "connecting entry must be dropped after exchange"
        );
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(
            conns.get("gmail").and_then(|c| c.service.as_deref()),
            Some("gmail")
        );
        assert!(
            conns.get("gmail").and_then(|c| c.keys.as_ref()).is_none(),
            "default conn stores no keys map"
        );
        assert_eq!(
            conns.get("gmail").and_then(|c| c.written.clone()),
            Some(vec!["GMAIL_REFRESH_TOKEN".to_string()]),
            "the exchange records the key it wrote, so removal may delete it"
        );
    }

    #[test]
    fn apply_exchange_named_writes_suggested_bare_key_and_records_binding() {
        // Named connection: conn != service → suggested `<ROLE>_<QUALIFIER>`
        // BARE key, recorded in the connection's `keys` map.
        let mut m = with_connecting("gmail_work", "gmail", "code-AUX");
        apply_exchange_result(
            &mut m,
            "gmail_work",
            "gmail",
            None,
            None,
            &cfg("GMAIL_REFRESH_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("GMAIL_REFRESH_TOKEN_WORK").unwrap(), b"rt-NEW");
        assert!(
            m.secrets.get("GMAIL_REFRESH_TOKEN").is_none(),
            "named conn must not clobber the default's key"
        );
        let conns = aux_map::<Connection>(&m, "connections");
        let rec = conns.get("gmail_work").expect("record moved");
        assert_eq!(rec.service.as_deref(), Some("gmail"));
        assert_eq!(
            rec.keys
                .as_ref()
                .and_then(|k| k.get("GMAIL_REFRESH_TOKEN"))
                .map(String::as_str),
            Some("GMAIL_REFRESH_TOKEN_WORK"),
        );
    }

    #[test]
    fn apply_exchange_named_honors_creator_chosen_keys() {
        // A creator-supplied binding (e.g. "reuse my existing key") wins over
        // the suggestion, for both the write and the recorded map.
        let mut m = with_connecting("gmail_work", "gmail", "code-AUX");
        let mut keys = BTreeMap::new();
        keys.insert(
            "GMAIL_REFRESH_TOKEN".to_string(),
            "MY_WORK_GMAIL_RT".to_string(),
        );
        apply_exchange_result(
            &mut m,
            "gmail_work",
            "gmail",
            None,
            Some(keys),
            &cfg("GMAIL_REFRESH_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("MY_WORK_GMAIL_RT").unwrap(), b"rt-NEW");
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(
            conns
                .get("gmail_work")
                .and_then(|c| c.keys.as_ref())
                .and_then(|k| k.get("GMAIL_REFRESH_TOKEN"))
                .map(String::as_str),
            Some("MY_WORK_GMAIL_RT"),
        );
    }

    #[test]
    fn apply_exchange_carries_pinned_hosts_into_connection() {
        let mut m = with_connecting("acme-forge", "acme", "code-AUX");
        apply_exchange_result(
            &mut m,
            "acme-forge",
            "acme",
            Some(vec!["tenant.acme.dev".to_string()]),
            None,
            &cfg("ACME_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(
            conns.get("acme-forge").and_then(|c| c.hosts.clone()),
            Some(vec!["tenant.acme.dev".to_string()]),
        );
    }

    #[test]
    fn apply_exchange_derives_exposes_from_id_token() {
        use base64::Engine as _;
        let enc = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        let claims = serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "acct-42" }
        });
        let idt = format!(
            "{}.{}.{}",
            enc(b"{}"),
            enc(claims.to_string().as_bytes()),
            enc(b"s")
        );

        let mut m = with_connecting("openai_codex", "openai_codex", "code-AUX");
        let mut c = cfg("OPENAI_CODEX_REFRESH_TOKEN");
        c.exposes = vec![(
            "account_id".to_string(),
            vec![
                "https://api.openai.com/auth".to_string(),
                "chatgpt_account_id".to_string(),
            ],
        )];
        let mut t = tokens(Some("rt-NEW"));
        t.id_token = Some(idt);
        apply_exchange_result(&mut m, "openai_codex", "openai_codex", None, None, &c, &t);
        assert_eq!(m.secret("OPENAI_CODEX_REFRESH_TOKEN").unwrap(), b"rt-NEW");
        // Derived role stored UPPERCASED at the bare (default-conn) address.
        assert_eq!(m.secret("ACCOUNT_ID").unwrap(), b"acct-42");
    }

    #[test]
    fn apply_exchange_overwrites_existing_refresh_token() {
        let mut m = with_connecting("gmail", "gmail", "code-A");
        m.put_secret("GMAIL_REFRESH_TOKEN", b"rt-OLD".to_vec());
        apply_exchange_result(
            &mut m,
            "gmail",
            "gmail",
            None,
            None,
            &cfg("GMAIL_REFRESH_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("GMAIL_REFRESH_TOKEN").unwrap(), b"rt-NEW");
    }

    #[tokio::test]
    async fn run_pending_success_moves_and_writes() {
        let services = gmail_registry();
        let role = services
            .service_env_key("gmail")
            .expect("gmail has a secret role");
        let mut m = with_connecting("gmail", "gmail", "code-AUX");

        let mut seen = None;
        let report = run_pending(&services, &no_custom(), &mut m, |conn, cfg, p| {
            seen = Some((
                conn.clone(),
                cfg.token_url.clone(),
                cfg.redirect_uri.clone(),
                p.oauth2.code.clone(),
            ));
            async move { Ok(tokens(Some("rt-NEW"))) }
        })
        .await;

        assert_eq!(report.completed, vec!["gmail".to_string()]);
        assert!(
            aux_map::<Connecting>(&m, "connecting").is_empty(),
            "connecting cleared"
        );
        assert_eq!(
            aux_map::<Connection>(&m, "connections")
                .get("gmail")
                .and_then(|c| c.service.clone()),
            Some("gmail".to_string()),
        );
        assert_eq!(m.secret(&role).unwrap(), b"rt-NEW");
        let (conn, token_url, redirect_uri, code) = seen.expect("exchange called");
        assert_eq!(conn, "gmail");
        assert_eq!(code, "code-AUX");
        assert!(
            token_url.starts_with("https://oauth2.googleapis.com/token"),
            "token_url must come from the google provider literal, got {token_url}"
        );
        assert!(
            redirect_uri.starts_with("http://127.0.0.1"),
            "redirect_uri must come from the provider/loopback default, got {redirect_uri}"
        );
    }

    #[tokio::test]
    async fn run_pending_failure_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-EXPIRED");

        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            |_conn, _cfg, _p| async move {
                Err("oauth2 code-exchange returned HTTP 400: invalid_grant".to_string())
            },
        )
        .await;

        assert!(
            report.completed.is_empty(),
            "a failed exchange completes nothing"
        );
        assert_eq!(
            report.failed.len(),
            1,
            "invalid_grant is a terminal failure"
        );
        assert!(
            aux_map::<Connecting>(&m, "connecting").contains_key("gmail"),
            "connecting must survive a failed exchange (user retries within TTL)"
        );
        assert!(aux_map::<Connection>(&m, "connections").is_empty());
    }

    #[test]
    fn terminal_exchange_reason_classifies_rejections_vs_transients() {
        // 4xx rejections are terminal, with the provider's detail surfaced.
        let missing_secret = terminal_exchange_reason(
            "oauth2 code-exchange returned HTTP 400 Bad Request: {\"error\":\"invalid_request\",\"error_description\":\"client_secret is missing.\"}",
        );
        assert_eq!(
            missing_secret.as_deref(),
            Some("provider rejected the exchange: client_secret is missing.")
        );
        assert!(terminal_exchange_reason("… invalid_grant …").is_some());
        assert!(
            terminal_exchange_reason("oauth2 code-exchange returned HTTP 401: nope").is_some()
        );
        // Network errors, 5xx, timeouts, and rate limits stay retryable.
        assert!(
            terminal_exchange_reason("oauth2 code-exchange request failed: connection reset")
                .is_none()
        );
        assert!(
            terminal_exchange_reason("oauth2 code-exchange returned HTTP 500: oops").is_none()
        );
        assert!(
            terminal_exchange_reason("oauth2 code-exchange returned HTTP 429: slow down")
                .is_none()
        );
        assert!(
            terminal_exchange_reason("oauth2 code-exchange returned HTTP 408: timeout").is_none()
        );
    }

    #[tokio::test]
    async fn run_pending_rejection_marks_failed_transient_does_not() {
        let services = gmail_registry();

        // A 400 rejection (not invalid_grant) stamps a terminal error.
        let mut m = with_connecting("gmail", "gmail", "code-A");
        let report = run_pending(&services, &no_custom(), &mut m, |_conn, _cfg, _p| async move {
            Err("oauth2 code-exchange returned HTTP 400 Bad Request: {\"error\":\"invalid_request\",\"error_description\":\"client_secret is missing.\"}".to_string())
        })
        .await;
        assert_eq!((report.completed.len(), report.failed.len()), (0, 1));
        let entry = &aux_map::<Connecting>(&m, "connecting")["gmail"];
        assert!(
            entry
                .oauth2
                .error
                .as_deref()
                .unwrap_or("")
                .contains("client_secret is missing."),
            "the provider's reason must surface on the entry: {:?}",
            entry.oauth2.error
        );

        // A 5xx stays pending with NO error (retried on its own timer), but IS surfaced
        // as `unreached` so `sc sync` can say "couldn't reach the provider".
        let mut m = with_connecting("gmail", "gmail", "code-B");
        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            |_conn, _cfg, _p| async move {
                Err("oauth2 code-exchange returned HTTP 500: oops".to_string())
            },
        )
        .await;
        assert_eq!((report.completed.len(), report.failed.len()), (0, 0));
        assert_eq!(
            report.unreached.len(),
            1,
            "a transient failure is reported as unreached"
        );
        assert!(aux_map::<Connecting>(&m, "connecting")["gmail"]
            .oauth2
            .error
            .is_none());
    }

    #[tokio::test]
    async fn run_pending_already_redeemed_skips_without_failing() {
        // A code THIS daemon already redeemed can be resurrected in `connecting`
        // by a stale write (buggy web Save, cross-device echo, or a pull that
        // re-introduces the entry before our success push lands). Re-exchanging
        // it would earn `invalid_grant`; the exchange closure returns the
        // ALREADY_REDEEMED sentinel instead. The machine must SKIP it: nothing
        // reported, and the entry LEFT UNTOUCHED (no error — a redeemed code is
        // not a failure, so it must never clobber the live connection).
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-USED");
        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            |_conn, _cfg, _p| async move { Err(ALREADY_REDEEMED.to_string()) },
        )
        .await;
        assert_eq!(
            (
                report.completed.len(),
                report.failed.len(),
                report.unreached.len()
            ),
            (0, 0, 0),
            "a redeemed-code skip must report nothing"
        );
        assert!(
            !report.changed(),
            "nothing mutated ⇒ caller must not persist/push"
        );
        let entry = &aux_map::<Connecting>(&m, "connecting")["gmail"];
        assert!(
            entry.oauth2.error.is_none(),
            "a redeemed code must NOT be stamped failed: {:?}",
            entry.oauth2.error
        );
        assert_eq!(entry.oauth2.code, "code-USED", "the entry is left intact");
    }

    #[tokio::test]
    async fn run_pending_no_refresh_token_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-A");

        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            |_conn, _cfg, _p| async move {
                Ok(tokens(None)) // consent without offline access → no refresh_token
            },
        )
        .await;

        assert!(report.completed.is_empty());
        assert!(
            aux_map::<Connecting>(&m, "connecting").contains_key("gmail"),
            "no durable token ⇒ leave connecting"
        );
    }

    #[tokio::test]
    async fn run_pending_unknown_service_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("whatever", "nosuchservice", "code-A");

        let mut called = false;
        let report = run_pending(&services, &no_custom(), &mut m, |_conn, _cfg, _p| {
            called = true;
            async move { Ok(tokens(Some("rt"))) }
        })
        .await;

        assert!(report.completed.is_empty());
        assert!(!called, "exchange must not run when no config resolves");
        assert!(aux_map::<Connecting>(&m, "connecting").contains_key("whatever"));
    }

    #[test]
    fn resolve_exchange_config_for_gmail_uses_public_desktop_client() {
        let services = gmail_registry();
        let cfg = resolve_exchange_config(&services, &no_custom(), "gmail")
            .expect("gmail resolves to an oauth2 exchange config");
        assert!(cfg
            .token_url
            .starts_with("https://oauth2.googleapis.com/token"));
        assert!(
            cfg.client_id.ends_with(".apps.googleusercontent.com"),
            "client_id must be the google provider literal"
        );
        // The public Desktop client ships a (non-confidential) secret.
        assert!(cfg.client_secret.is_some());
        assert!(matches!(cfg.style, OAuthStyle::Form));
        assert!(cfg.redirect_uri.starts_with("http://127.0.0.1"));
        assert!(
            !cfg.secret_role.is_empty(),
            "gmail service declares a secret role"
        );
    }

    #[test]
    fn resolve_exchange_config_none_for_unknown() {
        let services = gmail_registry();
        assert!(resolve_exchange_config(&services, &no_custom(), "nosuchservice").is_none());
    }

    #[test]
    fn resolve_exchange_config_finds_a_per_vault_custom_service() {
        // A user-authored inline [oauth2] service lives ONLY in aux.services,
        // never the built-in registry — the finisher must resolve it via the
        // `custom` map (regression: without it a custom OAuth connect could
        // never complete and retried forever).
        let services = gmail_registry();
        let toml_src = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["REFRESH_TOKEN"]

[auth]
type = "oauth2"
authorization_url = "https://auth.acme.dev/authorize"
token_url = "https://auth.acme.dev/token"
client_id = "acme-public"
refresh_token = "REFRESH_TOKEN"
"#;
        let def: crate::service::ServiceDef =
            crate::service::gate::admit_toml(toml_src).expect("valid custom oauth2 def");
        let mut custom = std::collections::HashMap::new();
        custom.insert("acme".to_string(), def);

        // Unknown to the built-in registry alone…
        assert!(resolve_exchange_config(&services, &no_custom(), "acme").is_none());
        // …resolvable once the vault's own custom def is supplied.
        let cfg = resolve_exchange_config(&services, &custom, "acme")
            .expect("custom inline oauth2 service resolves");
        assert_eq!(cfg.token_url, "https://auth.acme.dev/token");
        assert_eq!(cfg.client_id, "acme-public");
        assert_eq!(cfg.secret_role, "REFRESH_TOKEN");
    }

    #[test]
    fn resolve_exchange_config_custom_shadows_same_id_registry() {
        // custom-FIRST precedence: when a vault-authored def and a registry
        // service share an id, the USER's def wins — so shipping a first-party
        // service never silently repoints an existing custom connection (a user's
        // `gmail` that is really something else keeps its own wiring). The
        // registry defines `gmail`; a same-id custom def with a distinct token
        // endpoint must shadow it.
        let services = gmail_registry();
        // Sanity: the registry really defines `gmail` (else this proves nothing).
        assert!(
            resolve_exchange_config(&services, &no_custom(), "gmail").is_some(),
            "registry must define gmail for the shadow test to be meaningful"
        );
        let toml_src = r#"
[service]
id = "gmail"
name = "Custom shadow of gmail"
hosts = ["api.example.test"]
secrets = ["REFRESH_TOKEN"]

[auth]
type = "oauth2"
authorization_url = "https://shadow.test/authorize"
token_url = "https://shadow.test/token"
client_id = "shadow-client"
refresh_token = "REFRESH_TOKEN"
"#;
        let def: crate::service::ServiceDef =
            crate::service::gate::admit_toml(toml_src).expect("valid custom oauth2 def");
        let mut custom = std::collections::HashMap::new();
        custom.insert("gmail".to_string(), def);

        let cfg = resolve_exchange_config(&services, &custom, "gmail")
            .expect("resolves with a same-id custom def present");
        // The CUSTOM endpoint + client win, not the registry's Google ones.
        assert_eq!(cfg.token_url, "https://shadow.test/token");
        assert_eq!(cfg.client_id, "shadow-client");
    }

    /// A connect / token refresh never writes a stale value back over one a
    /// pull landed in the per-item store: `M` is read from the store (not the
    /// lagging vault.dat), and only the caller's change vs that base is written,
    /// even when another pull lands between the read and the reconcile (a
    /// connect awaits a token exchange in between).
    #[test]
    fn connect_write_never_reverts_a_pulled_value() {
        use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
        use crate::storage::sealed_vault::PerItemVault;
        type S = sudp::primitives::StdPrimitives;
        let cfg = crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/sprott-test-connect-prec-{}",
                std::process::id()
            )),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            relying_party: crate::passkey::webauthn::RelyingParty::exact(
                "http://localhost",
                "localhost",
            ),
            body_cap: crate::config::DEFAULT_BODY_CAP,
        };
        let state = Arc::new(AppState::new(cfg));
        let vid = "conn-prec";
        let k = [0x42u8; 32];
        let keys = VaultKeys::single(&k);
        let _ = std::fs::remove_dir_all(state.vaults.dir_for(vid).unwrap());

        // vault.dat: the stale mirror, OPENAI_API_KEY = "old".
        let mut m_old = ProtectedState::new();
        m_old.aux = serde_json::json!({
            "version": crate::storage::plaintext::PLAINTEXT_VERSION,
            "stores": {},
            "store_order": []
        });
        m_old.put_secret("OPENAI_API_KEY", b"old".to_vec());
        let mut vault = crate::storage::sealed_vault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
            vec![],
        )
        .unwrap();
        crate::server::handlers::metadata::reseal_body_with_key(&k, &mut vault, &m_old).unwrap();
        crate::storage::sealed_vault::write_atomic(&state.vaults.vault_path(vid).unwrap(), &vault)
            .unwrap();

        // Per-item store: seeded from the old state, then a pull landed "new" at v2.
        let pi_path = state.vaults.per_item_path(vid).unwrap();
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        let old_view =
            crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m_old).unwrap();
        pv.seed_items_from_view::<S>(keys, vid, &old_view).unwrap();
        let pull = |pv: &mut PerItemVault, v: u64, value: &str| {
            let id = pv
                .seal_and_upsert::<S>(
                    keys,
                    vid,
                    ItemNs::Secret,
                    "OPENAI_API_KEY",
                    v,
                    &ItemPayload::secret_live("OPENAI_API_KEY", value),
                )
                .unwrap();
            pv.items.get_mut(&id).unwrap().synced_version = v;
        };
        for s in pv.items.values_mut() {
            s.synced_version = s.version;
        }
        pull(&mut pv, 2, "new");
        crate::storage::sealed_vault::write_per_item_atomic(&pi_path, &pv).unwrap();

        // Read: the store wins over vault.dat.
        let (mut m, base) = open_m_for_write(&state, vid, &k, Some(&vault)).unwrap();
        assert_eq!(m.secret("OPENAI_API_KEY").unwrap(), b"new");

        // Another pull lands while the "exchange" runs: "newer" at v3.
        let mut pv = crate::storage::sealed_vault::read_per_item(&pi_path)
            .unwrap()
            .unwrap();
        pull(&mut pv, 3, "newer");
        crate::storage::sealed_vault::write_per_item_atomic(&pi_path, &pv).unwrap();

        // The refresh writes only its own secret.
        m.put_secret("GMAIL_REFRESH_TOKEN", b"rt".to_vec());
        let view = crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m).unwrap();
        reconcile_per_item_after_connect(
            &state,
            vid,
            Some(&vault),
            &view,
            &k,
            ReconcileBase::Since(&base),
        )
        .unwrap()
        .expect("a per-item store backs the vault");
        // What an install serves: the store's fold.
        let served = || {
            crate::server::handlers::metadata::fold_store_with_key(&state, vid, &k)
                .unwrap()
                .0
        };

        let pv = crate::storage::sealed_vault::read_per_item(&pi_path)
            .unwrap()
            .unwrap();
        let folded = pv.fold_view::<S>(keys, vid).unwrap();
        assert_eq!(folded.native_secrets["OPENAI_API_KEY"], b"newer");
        assert_eq!(folded.native_secrets["GMAIL_REFRESH_TOKEN"], b"rt");
        assert_eq!(served().native_secrets, folded.native_secrets);

        // Keep-both: the caller (base still "new") now edits OPENAI_API_KEY too.
        // The cache must serve THEIRS at the canonical name, ours as the copy.
        m.put_secret("OPENAI_API_KEY", b"mine".to_vec());
        let view = crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m).unwrap();
        reconcile_per_item_after_connect(
            &state,
            vid,
            Some(&vault),
            &view,
            &k,
            ReconcileBase::Since(&base),
        )
        .unwrap()
        .unwrap();
        let served = served();
        assert_eq!(served.native_secrets["OPENAI_API_KEY"], b"newer");
        assert_eq!(
            served.native_secrets[&crate::storage::item::conflict_copy_name("OPENAI_API_KEY")],
            b"mine"
        );
        let _ = std::fs::remove_dir_all(state.vaults.dir_for(vid).unwrap());
    }

    /// A state on a fresh temp dir.
    fn temp_state() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config {
            state_dir: dir.path().to_path_buf(),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            relying_party: crate::passkey::webauthn::RelyingParty::exact(
                "http://localhost",
                "localhost",
            ),
            body_cap: crate::config::DEFAULT_BODY_CAP,
        };
        let mut state = AppState::new(cfg);
        state.vaults = crate::storage::vault_dir::VaultDir::new(dir.path());
        (dir, Arc::new(state))
    }

    /// A daemon write on a re-keyed vault (the retained key material is the
    /// key bundle `id_seed ‖ content`) lands in the store, read and written
    /// the way every other access reads the material. A store that cannot take
    /// the change (here: its re-key proof no longer verifies) is an error the
    /// caller sees: nothing is written and nothing is served from memory.
    #[test]
    fn a_write_on_a_rekeyed_vault_lands_or_is_an_error() {
        use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
        use crate::storage::sealed_vault::{read_per_item, write_per_item_atomic};
        type S = sudp::primitives::StdPrimitives;
        let fx = crate::storage::sealed_vault::tests::rekeyed_fixture();
        let vid = fx.vault;
        let material = fx.material();
        let keys = VaultKeys::from_material(&material);
        let (_dir, state) = temp_state();
        state.open_ledger_for_tests(&[]);
        let mut pv = fx.pv.clone();
        let a = pv
            .seal_and_upsert::<S>(
                keys,
                vid,
                ItemNs::Secret,
                "A",
                1,
                &ItemPayload::secret_live("A", "a"),
            )
            .unwrap();
        pv.items.get_mut(&a).unwrap().synced_version = 1;
        let path = state.vaults.per_item_path(vid).unwrap();
        write_per_item_atomic(&path, &pv).unwrap();

        // `sc secret set B` on the unlocked vault: the change lands in the
        // store and is served.
        assert!(state
            .install(
                vid,
                crate::state::InstallKey::Unlock(zeroize::Zeroizing::new(material.to_vec())),
            )
            .served());
        let view =
            crate::server::handlers::metadata::open_view_with_state_key(&state, vid, &material)
                .unwrap();
        let base = ViewBase::of(&view).unwrap();
        let mut changed =
            crate::server::handlers::metadata::open_view_with_state_key(&state, vid, &material)
                .unwrap();
        changed.native_secrets.insert("B".into(), b"b".to_vec());
        assert!(
            persist_mutated_view(&state, vid, &base, &changed, WriteKey::Held(&material))
                .unwrap()
                .served()
        );
        let folded = read_per_item(&path)
            .unwrap()
            .unwrap()
            .fold_view::<S>(keys, vid)
            .unwrap();
        assert_eq!(folded.native_secrets["A"], b"a");
        assert_eq!(folded.native_secrets["B"], b"b");
        assert!(
            !state.is_vault_locked(vid),
            "the session serves the store's fold"
        );

        // A row this key cannot open is never written over: the change to it
        // is refused and said in the error (a conflict, not an internal
        // failure); the rest of the change lands.
        let other = VaultKeys {
            id_seed: &fx.id_seed,
            content: &[0x99u8; 32],
            prev: &[],
        };
        let mut pv = read_per_item(&path).unwrap().unwrap();
        let x = pv
            .plant::<S>(
                other,
                vid,
                ItemNs::Secret,
                "X",
                1,
                &ItemPayload::secret_live("X", "x"),
            )
            .unwrap();
        pv.items.get_mut(&x).unwrap().synced_version = 1;
        write_per_item_atomic(&path, &pv).unwrap();
        let open = || {
            crate::server::handlers::metadata::open_view_with_state_key(&state, vid, &material)
                .unwrap()
        };
        let base2 = ViewBase::of(&open()).unwrap();
        let mut mine = open();
        mine.native_secrets.insert("X".into(), b"mine".to_vec());
        mine.native_secrets.insert("D".into(), b"d".to_vec());
        match persist_mutated_view(&state, vid, &base2, &mine, WriteKey::Held(&material)) {
            Err(crate::error::AppError::Conflict(m)) => {
                assert!(m.starts_with("secret X: this item was changed with a vault key this device does not have"), "{}", m)
            }
            other => panic!("a conflict, not {:?}", other.err()),
        }
        let pv = read_per_item(&path).unwrap().unwrap();
        assert_eq!(pv.items[&x].version, 1, "not written over");
        assert_eq!(
            pv.fold_view::<S>(keys, vid).unwrap().native_secrets["D"],
            b"d"
        );

        // A store whose re-key proof no longer verifies: the write is refused,
        // the store is left byte for byte, and a locked session stays locked.
        state.lock_vault(vid);
        let mut bad = read_per_item(&path).unwrap().unwrap();
        bad.keyset
            .uik
            .as_mut()
            .unwrap()
            .rekey_proof
            .as_mut()
            .unwrap()
            .sig[0] ^= 1;
        write_per_item_atomic(&path, &bad).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut again = changed;
        again.native_secrets.insert("C".into(), b"c".to_vec());
        let err = persist_mutated_view(&state, vid, &base, &again, WriteKey::Held(&material))
            .unwrap_err()
            .to_string();
        assert!(err.contains("could not be applied"), "{}", err);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(state.is_vault_locked(vid), "nothing served from memory");
    }

    /// A code exchange that still fails transiently past the code's
    /// lifetime marks the connection failed ("reconnect") instead of leaving
    /// it "connecting" for good; inside the window it stays pending.
    #[tokio::test]
    async fn a_code_still_failing_past_its_lifetime_is_marked_failed() {
        let t0 = std::time::Instant::now();
        assert!(!code_exchange_expired(t0, t0 + std::time::Duration::from_secs(599)));
        assert!(code_exchange_expired(t0, t0 + std::time::Duration::from_secs(601)));

        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-late");
        let report = run_pending(&services, &no_custom(), &mut m, |_conn, _cfg, _p| async move {
            Err(CODE_EXPIRED.to_string())
        })
        .await;
        assert_eq!((report.failed.len(), report.unreached.len()), (1, 0));
        assert!(report.changed(), "the failure is written so the console shows it");
        let entry = &aux_map::<Connecting>(&m, "connecting")["gmail"];
        assert!(entry
            .oauth2
            .error
            .as_deref()
            .unwrap_or("")
            .contains("expired before the provider could be reached"));
    }

    /// The first transient failure of a code starts its window, and later
    /// asks return the same instant.
    #[test]
    fn a_code_window_counts_from_its_first_try() {
        let (_dir, state) = temp_state();
        let first = state.code_first_tried("code-1");
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(state.code_first_tried("code-1"), first);
        assert!(state.code_first_tried("code-2") > first);
    }

    /// A store on the re-keyed fixture whose `refresh_token` slot holds
    /// `value`, the vault unlocked with a cache that holds it too.
    fn rotation_fixture(
        value: &str,
    ) -> (
        tempfile::TempDir,
        Arc<AppState>,
        &'static str,
        Vec<u8>,
        std::path::PathBuf,
        String,
    ) {
        rotation_fixture_at("refresh_token", value, cache_holding(value))
    }

    /// [`rotation_fixture`] with the slot `slot` and the session `cache`.
    fn rotation_fixture_at(
        slot: &str,
        value: &str,
        cache: crate::state::SecretsCache,
    ) -> (
        tempfile::TempDir,
        Arc<AppState>,
        &'static str,
        Vec<u8>,
        std::path::PathBuf,
        String,
    ) {
        use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
        use crate::storage::sealed_vault::write_per_item_atomic;
        type S = sudp::primitives::StdPrimitives;
        let fx = crate::storage::sealed_vault::tests::rekeyed_fixture();
        let vid = fx.vault;
        let material = fx.material();
        let keys = VaultKeys::from_material(&material);
        let (dir, state) = temp_state();
        state.open_ledger_for_tests(&[]);
        let mut pv = fx.pv.clone();
        let id = pv
            .seal_and_upsert::<S>(
                keys,
                vid,
                ItemNs::Secret,
                slot,
                1,
                &ItemPayload::secret_live(slot, value),
            )
            .unwrap();
        pv.items.get_mut(&id).unwrap().synced_version = 1;
        let path = state.vaults.per_item_path(vid).unwrap();
        write_per_item_atomic(&path, &pv).unwrap();
        state.unlock_vault(vid.into(), cache, zeroize::Zeroizing::new(material.clone()));
        (dir, state, vid, material, path, id)
    }

    /// A session cache whose `codex` connection holds `value`.
    fn cache_holding(value: &str) -> crate::state::SecretsCache {
        let mut cache = crate::state::SecretsCache::default();
        cache.entries.insert(
            "codex".into(),
            crate::state::CacheEntry {
                value: value.as_bytes().to_vec(),
                expires_at: None,
                from_bootstrap: true,
                agent_prefix: None,
            },
        );
        cache
    }

    fn stored_refresh_token(path: &std::path::Path, material: &[u8], vid: &str) -> Vec<u8> {
        type S = sudp::primitives::StdPrimitives;
        crate::storage::sealed_vault::read_per_item(path)
            .unwrap()
            .unwrap()
            .fold_view::<S>(crate::storage::item::VaultKeys::from_material(material), vid)
            .unwrap()
            .native_secrets["refresh_token"]
            .clone()
    }

    /// A rotated refresh token lands as ONE durable row of the vault's store,
    /// at the slot the connection reads it from; the session cache follows,
    /// and whatever was pending for that slot is dropped.
    #[test]
    fn a_rotated_refresh_token_is_one_row_and_settles_the_slot() {
        let (_dir, state, vid, material, path, id) = rotation_fixture("rt-1");
        // An earlier rotation of the same slot was left pending.
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-1", "rt-2", "earlier");
        let stored =
            persist_rotated_refresh_locked(&state, vid, "codex", "refresh_token", b"rt-1", "rt-3", false)
                .unwrap();
        assert_eq!(stored, RotationStored::Written);
        assert_eq!(stored_refresh_token(&path, &material, vid), b"rt-3");
        let pv = crate::storage::sealed_vault::read_per_item(&path).unwrap().unwrap();
        assert_eq!(pv.items[&id].version, 2);
        assert_eq!(state.cache_lookup(vid, "codex").unwrap(), b"rt-3");
        assert!(state.take_pending_rotations(vid).is_empty(), "the slot settled");
        assert!(state.sync_note_lines(vid).is_empty());
    }

    /// A delayed retry never puts an older token over a newer one: the store
    /// holds rt-3 now, the pending rt-2 (which replaced rt-1) is dropped.
    #[test]
    fn a_stale_pending_rotation_is_dropped_not_written() {
        let (_dir, state, vid, material, path, _) = rotation_fixture("rt-3");
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-1", "rt-2", "earlier");
        retry_pending_rotations_locked(&state, vid);
        assert_eq!(stored_refresh_token(&path, &material, vid), b"rt-3");
        assert!(state.take_pending_rotations(vid).is_empty());
        assert!(state.sync_note_lines(vid).is_empty());
        assert_eq!(state.cache_lookup(vid, "codex").unwrap(), b"rt-3");
    }

    /// While a rotation is pending, every cache rebuilt from the store (a
    /// pull, an unlock) serves the rotated token, not the dead one; the retry
    /// that stores it leaves the cache on it.
    #[test]
    fn a_rebuilt_cache_keeps_serving_the_pending_rotation() {
        let (_dir, state, vid, material, path, _) = rotation_fixture("rt-1");
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-1", "rt-2", "disk");
        // A rebuild from the store, which still holds rt-1.
        state.unlock_vault(vid.into(), cache_holding("rt-1"), zeroize::Zeroizing::new(material.clone()));
        assert_eq!(state.cache_lookup(vid, "codex").unwrap(), b"rt-2");
        retry_pending_rotations_locked(&state, vid);
        assert_eq!(stored_refresh_token(&path, &material, vid), b"rt-2");
        assert_eq!(state.cache_lookup(vid, "codex").unwrap(), b"rt-2");
        assert!(state.take_pending_rotations(vid).is_empty());
    }

    /// Two rotations failing in a row chain: the store still holds the first
    /// replaced value, so the pending entry keeps it, and the retry stores
    /// the newest token instead of finding the slot "changed" and dropping it.
    #[test]
    fn chained_failed_rotations_keep_the_first_replaced_value() {
        let (_dir, state, vid, material, path, _) = rotation_fixture("rt-0");
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-0", "rt-1", "disk");
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-1", "rt-2", "disk");
        assert_eq!(state.pending_rotation_of(vid, "codex", b"rt-0").unwrap().as_str(), "rt-2");
        retry_pending_rotations_locked(&state, vid);
        assert_eq!(stored_refresh_token(&path, &material, vid), b"rt-2");
        assert!(!state.has_pending_rotations(vid));
        // An unrelated value for the slot replaces the entry as before.
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-2", "rt-3", "disk");
        state.note_rotation_pending(vid, "codex", "refresh_token", b"other", "rt-9", "disk");
        assert!(state.pending_rotation_of(vid, "codex", b"rt-2").is_none());
        assert_eq!(state.pending_rotation_of(vid, "codex", b"other").unwrap().as_str(), "rt-9");
    }

    /// Every mint input passes through the pending rotations: a ceremony that
    /// fresh-decrypted the replaced token from the store mints with (here:
    /// finds the access token cached under) the rotated one, never the dead
    /// one.
    #[tokio::test]
    async fn a_mint_from_the_replaced_token_uses_the_pending_rotation() {
        use sha2::{Digest, Sha256};
        let (_dir, state, vid, _material, _path, _) = rotation_fixture("rt-0");
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-0", "rt-1", "disk");
        let hash: String = Sha256::digest(b"rt-1").iter().map(|b| format!("{:02x}", b)).collect();
        state.oauth_access_insert(vid, &hash, b"at-1".to_vec(), u64::MAX);
        let minted = crate::server::broker_flow::resolve_auth_value(&state, vid, "codex", "gmail", b"rt-0")
            .await
            .unwrap();
        assert_eq!(minted, b"at-1");
    }

    /// Two mints that read the same refresh token at once, on a provider that
    /// rotates it: exactly one refresh reaches the token endpoint (the other
    /// would send a token the provider already replaced), and both get the
    /// same access token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_mints_on_a_rotating_provider_refresh_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        // A rotating token endpoint: rt-0 → rt-1 (+ at-1); a replaced token
        // is refused, as a provider with reuse detection would.
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move |body: String| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    // Hold the response so the second mint is waiting meanwhile.
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    if body.contains("refresh_token=rt-0") {
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(serde_json::json!({
                                "access_token": "at-1", "expires_in": 3600, "refresh_token": "rt-1"
                            })),
                        )
                    } else {
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({ "error": "invalid_grant" })),
                        )
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mut def = crate::service::gate::admit_toml(
            r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_REFRESH_TOKEN"]
[auth]
type = "oauth2"
authorization_url = "https://auth.acme.dev/authorize"
token_url = "https://auth.acme.dev/token"
client_id = "acme-public"
refresh_token = "ACME_REFRESH_TOKEN"
"#,
        )
        .unwrap();
        match def.auth.as_mut() {
            Some(crate::service::AuthDef::Oauth2(o)) => {
                o.token_url = Some(format!("http://{}/token", addr));
            }
            _ => panic!("an oauth2 def"),
        }
        let mut cache = cache_holding("rt-0");
        cache.custom_services.insert("acme".into(), def);
        let (_dir, state, vid, material, path, _) =
            rotation_fixture_at("ACME_REFRESH_TOKEN", "rt-0", cache);

        let (a, b) = tokio::join!(
            crate::server::broker_flow::resolve_auth_value(&state, vid, "codex", "acme", b"rt-0"),
            crate::server::broker_flow::resolve_auth_value(&state, vid, "codex", "acme", b"rt-0"),
        );
        assert_eq!(a.unwrap(), b"at-1");
        assert_eq!(b.unwrap(), b"at-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one refresh");
        // The rotation was stored, and a later mint reading the replaced
        // token (a stale fresh decrypt) still needs no refresh.
        type S = sudp::primitives::StdPrimitives;
        let stored = crate::storage::sealed_vault::read_per_item(&path)
            .unwrap()
            .unwrap()
            .fold_view::<S>(crate::storage::item::VaultKeys::from_material(&material), vid)
            .unwrap();
        assert_eq!(stored.native_secrets["ACME_REFRESH_TOKEN"], b"rt-1");
        let again = crate::server::broker_flow::resolve_auth_value(&state, vid, "codex", "acme", b"rt-0")
            .await
            .unwrap();
        assert_eq!(again, b"at-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A slot row this session's key cannot open is never written over: the
    /// store refuses (the token stays pending, retried after the keyset pull
    /// or at unlock), nothing is written.
    #[test]
    fn a_slot_row_the_key_cannot_read_is_an_error_not_a_copy() {
        use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
        type S = sudp::primitives::StdPrimitives;
        let (_dir, state, vid, material, path, id) = rotation_fixture("rt-1");
        let mut pv = crate::storage::sealed_vault::read_per_item(&path).unwrap().unwrap();
        let other = VaultKeys {
            id_seed: VaultKeys::from_material(&material).id_seed,
            content: &[0x99u8; 32],
            prev: &[],
        };
        pv.plant::<S>(other, vid, ItemNs::Secret, "refresh_token", 7, &ItemPayload::secret_live("refresh_token", "theirs"))
            .unwrap();
        crate::storage::sealed_vault::write_per_item_atomic(&path, &pv).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err =
            persist_rotated_refresh_locked(&state, vid, "codex", "refresh_token", b"rt-1", "rt-2", false)
                .unwrap_err();
        assert!(err.contains("vault key this device does not have"), "{}", err);
        assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");
        let pv = crate::storage::sealed_vault::read_per_item(&path).unwrap().unwrap();
        assert_eq!(pv.items[&id].version, 7);
    }

    /// Locking: one attempt to store what is pending while K is in hand; a
    /// token that still cannot be stored stays in memory (the only copy) and
    /// is stored by the retry after the next unlock. A locked vault arms no
    /// timer.
    #[tokio::test]
    async fn pending_rotations_are_stored_before_the_lock_or_kept_for_unlock() {
        let (_dir, state, vid, material, path, _) = rotation_fixture("rt-1");
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-1", "rt-2", "disk");
        store_pending_rotations_before_lock(&state, vid);
        state.lock_vault(vid);
        assert_eq!(stored_refresh_token(&path, &material, vid), b"rt-2");
        assert!(state.take_pending_rotations(vid).is_empty());

        // The store cannot be written at lock time: kept in memory.
        let (_dir, state, vid, material, path, _) = rotation_fixture("rt-1");
        let good = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-1", "rt-2", "disk");
        store_pending_rotations_before_lock(&state, vid);
        state.lock_vault(vid);
        assert!(state.has_pending_rotations(vid), "kept: the only copy");
        retry_pending_rotations_locked(&state, vid);
        assert!(state.has_pending_rotations(vid), "locked: not attempted");
        assert!(!state
            .runtime_if_present(vid)
            .unwrap()
            .retries
            .lock()
            .unwrap()
            .armed(crate::auth::retry::Job::RotationStore));
        // The store is back and the vault unlocks: the retry stores it.
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, good).unwrap();
        state.unlock_vault(vid.into(), cache_holding("rt-1"), zeroize::Zeroizing::new(material.clone()));
        retry_pending_rotations_locked(&state, vid);
        assert_eq!(stored_refresh_token(&path, &material, vid), b"rt-2");
        assert!(!state.has_pending_rotations(vid));
    }

    /// A store that cannot be written keeps the token pending in the session
    /// and arms its own retry timer (no sync involved).
    #[tokio::test]
    async fn a_store_that_cannot_be_written_arms_the_rotation_retry() {
        let (_dir, state, vid, _material, path, _) = rotation_fixture("rt-1");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-1", "rt-2", "first try");
        retry_pending_rotations_locked(&state, vid);
        assert_eq!(state.take_pending_rotations(vid).len(), 1, "still pending");
        let runtime = state.runtime_if_present(vid).unwrap();
        assert!(runtime
            .retries
            .lock()
            .unwrap()
            .armed(crate::auth::retry::Job::RotationStore));
    }

    /// A rotated refresh token whose store failed stays in use: the session
    /// holds the new token in place of the old, it is kept to store again on
    /// its own retry timer, and the user is told; once stored, the note
    /// settles.
    #[test]
    fn a_rotated_token_not_stored_stays_in_use_and_pending() {
        let (_dir, state) = temp_state();
        state.open_ledger_for_tests(&[]);
        let vid = "v-rotate";
        let mut cache = crate::state::SecretsCache::default();
        cache.entries.insert(
            "codex".into(),
            crate::state::CacheEntry {
                value: b"old-rt".to_vec(),
                expires_at: None,
                from_bootstrap: true,
                agent_prefix: None,
            },
        );
        cache.allow_secrets.insert(
            "codex".into(),
            [("REFRESH_TOKEN".to_string(), b"old-rt".to_vec())].into(),
        );
        state.unlock_vault(vid.into(), cache, zeroize::Zeroizing::new(vec![0u8; 32]));
        rotation_not_stored(
            &state,
            vid,
            "codex",
            "refresh_token",
            b"old-rt",
            "new-rt",
            "the store failed",
        );
        assert_eq!(state.cache_lookup(vid, "codex").unwrap(), b"new-rt");
        assert_eq!(
            state.cache_lookup_secrets(vid, "codex").unwrap()["REFRESH_TOKEN"],
            b"new-rt"
        );
        assert!(state.sync_note_lines(vid).iter().any(|l| l.starts_with(
            "connection codex: the provider's new refresh token could not be stored"
        )));
        let pending = state.take_pending_rotations(vid);
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].0,
            ("codex".to_string(), "refresh_token".to_string())
        );
        assert_eq!(pending[0].1.new.as_str(), "new-rt");
        assert_eq!(pending[0].1.old.as_slice(), b"old-rt");
        state.clear_rotation_note(vid, "codex");
        assert!(state.sync_note_lines(vid).is_empty());
    }

    /// A completed connect whose connection row the store refused is
    /// reported failed with why; one whose row landed stays completed.
    #[test]
    fn a_connect_whose_connection_row_was_refused_is_reported_failed() {
        type S = sudp::primitives::StdPrimitives;
        let k = [0x42u8; 32];
        let refused = crate::storage::item::wire_id_for::<S>(
            &k,
            crate::storage::item::ItemNs::Connection,
            "gmail",
        )
        .unwrap();
        let mut report = ConnectReport {
            completed: vec!["gmail".into(), "github".into()],
            ..Default::default()
        };
        fail_refused_connects(
            &mut report,
            &[(refused, "connection gmail: not applied".into())],
            &k,
        );
        assert_eq!(report.completed, vec!["github".to_string()]);
        assert_eq!(
            report.failed,
            vec![(
                "gmail".to_string(),
                "connection gmail: not applied".to_string()
            )]
        );
    }
}
