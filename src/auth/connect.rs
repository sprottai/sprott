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
/// present (a racing paste wins whichever landed first). A caught code is
/// this device's (`me`) to redeem: only it holds the code, so the entry names
/// it as `redeemer`, and a write that stores the code stores the claim with
/// it. Pure state edit.
fn inject_codes(
    m: &mut ProtectedState,
    codes: &std::collections::BTreeMap<String, String>,
    me: Option<&str>,
) -> Vec<String> {
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    let mut filled = Vec::new();
    for (conn, code) in codes {
        if let Some(entry) = connecting.get_mut(conn) {
            if entry.oauth2.code.is_empty() && !code.is_empty() {
                entry.oauth2.code = code.clone();
                entry.oauth2.redeemer = me.map(str::to_string);
                filled.push(conn.clone());
            }
        }
    }
    if !filled.is_empty() {
        set_aux_map(m, "connecting", connecting);
    }
    filled
}

/// Per-run outcome of the connect state machine, so callers (and ultimately
/// `sc sync`) can SURFACE what happened instead of failing silently. Three
/// disjoint buckets:
/// - `completed`: got a refresh_token, MOVEd to `connections`.
/// - `failed`: TERMINALLY rejected (`invalid_grant` / other 4xx) — an `error` was
///   stamped so the console renders "reconnect"; carries the provider's reason.
/// - `unreached`: a TRANSIENT failure with no HTTP answer (network / proxy /
///   TLS): left pending, NO error stamped, retried on its own timer
///   ([`crate::auth::retry`]); carries the provider host so the user can tell "my egress is broken" from "the code died".
/// - `provider_error`: the provider answered with an error worth retrying
///   (5xx, 408, 429, an unusable answer): left pending and retried the same way.
#[derive(Debug, Default, Clone)]
pub struct ConnectReport {
    pub completed: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// `(connection, provider host, transport detail)`.
    pub unreached: Vec<(String, String, String)>,
    /// The `unreached` connects whose request was never sent (the connection
    /// to the provider failed first): the code did not reach it, so any
    /// device may redeem it.
    pub not_sent: Vec<String>,
    /// `(connection, provider host, the provider's answer)`.
    pub provider_error: Vec<(String, String, String)>,
    /// Connects whose claim got no answer from the cloud (see
    /// [`claim_code`]): not exchanged this run, retried on the timer.
    pub claim_unanswered: Vec<String>,
    /// Connects whose code this device gave up for another device to redeem
    /// (its request was never sent): a claim released, or a caught code
    /// stored unclaimed.
    pub handed_off: Vec<String>,
    /// Connects whose code this device gave up and may not claim again yet
    /// ([`CodeHistory::cooling`]): retried on the timer.
    pub cooling: Vec<String>,
    /// Left pending without an error stamp for a reason other than the
    /// network (no exchange config, no refresh_token returned):
    /// `(connection, reason)`. Nothing is written for these.
    pub left_pending: Vec<(String, String)>,
    /// Codes the loopback listener caught for connects this run is retrying,
    /// now in their pending entries in the vault's store (as a paste would
    /// be). Listed only once the store holds them.
    pub code_stored: Vec<String>,
    /// The `completed` connects are stored but this device does not serve
    /// them yet ([`crate::error::STORED_NOT_SERVED_MSG`]).
    pub not_served: bool,
}

impl ConnectReport {
    /// Did anything MUTATE the sealed state (⇒ the caller must persist + push)?
    /// A transient `unreached` stamps nothing, so it does not count.
    pub fn changed(&self) -> bool {
        !self.completed.is_empty() || !self.failed.is_empty() || !self.code_stored.is_empty()
    }

    /// Did a connect reach an end (completed or failed for good)?
    pub fn settled(&self) -> bool {
        !self.completed.is_empty() || !self.failed.is_empty()
    }

    /// Is a connect left for the retry timer: an exchange that failed
    /// transiently, or a claim the cloud did not answer?
    pub fn retrying(&self) -> bool {
        !self.unreached.is_empty()
            || !self.provider_error.is_empty()
            || !self.claim_unanswered.is_empty()
            || !self.cooling.is_empty()
    }

    /// Is connect `conn`'s exchange being retried?
    fn exchange_retrying(&self, conn: &str) -> bool {
        self.unreached.iter().any(|(c, _, _)| c == conn)
            || self.provider_error.iter().any(|(c, _, _)| c == conn)
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

/// Sentinel prefix the exchange closure returns when a code still fails
/// transiently past [`CODE_EXCHANGE_WINDOW`], followed by the last error:
/// `run_pending` marks the connection failed, saying how it last failed.
const CODE_EXPIRED: &str = "__sc_code_expired__";

/// How a code exchange failed, read from its error text: what the stamp, the
/// result page and `sprott sync` say, and whether the code may go to another
/// device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExchangeFailure {
    /// The connection to the provider failed before the request was sent
    /// (DNS, TCP connect, TLS handshake, proxy CONNECT, connect timeout): the
    /// code never reached it. The transport detail.
    NotSent(String),
    /// Sent, and no HTTP answer came back (a timeout or a reset after
    /// connecting): the code may have reached the provider. The detail.
    NoAnswer(String),
    /// The provider answered with an error worth retrying (5xx, 408, 429, an
    /// answer without tokens or that doesn't parse). Its answer.
    Answered(String),
    /// Re-sending the same request can never succeed (the provider rejected
    /// it, or it can't be built). The reason.
    Terminal(String),
}

pub(crate) fn classify_exchange_error(e: &str) -> ExchangeFailure {
    use crate::auth::oauth2::{
        CODE_EXCHANGE_NOT_BUILT, CODE_EXCHANGE_NOT_SENT, CODE_EXCHANGE_REQUEST_FAILED,
    };
    if let Some(d) = e.strip_prefix(CODE_EXCHANGE_NOT_SENT) {
        return ExchangeFailure::NotSent(d.to_string());
    }
    if let Some(d) = e.strip_prefix(CODE_EXCHANGE_REQUEST_FAILED) {
        return ExchangeFailure::NoAnswer(d.to_string());
    }
    if let Some(d) = e.strip_prefix(CODE_EXCHANGE_NOT_BUILT) {
        return ExchangeFailure::Terminal(d.to_string());
    }
    if let Some(reason) = terminal_exchange_reason(e) {
        return ExchangeFailure::Terminal(reason);
    }
    ExchangeFailure::Answered(e.strip_prefix("oauth2 code-exchange ").unwrap_or(e).to_string())
}

/// How long a transiently failing code exchange is retried: RFC 6749 §4.1.2
/// recommends a maximum authorization code lifetime of 10 minutes, so past
/// that the code is presumed dead and only a fresh consent recovers.
pub(crate) const CODE_EXCHANGE_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// Has a code first tried at `first_tried` outlived its exchange window (pure)?
pub(crate) fn code_exchange_expired(first_tried: std::time::Instant, now: std::time::Instant) -> bool {
    now.saturating_duration_since(first_tried) > CODE_EXCHANGE_WINDOW
}

/// What this device does with an in-flight connect's code, given the claim
/// on its row (`redeemer`), whether the cloud holds the row as this device
/// does (`confirmed`: no local change unpushed), and this device (`me`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimStep {
    /// The cloud's row names this device: it exchanges the code.
    Redeem,
    /// Unclaimed, or claimed here but not on the cloud yet: it writes its
    /// claim first ([`claim_code`]).
    Claim,
    /// Another device's: never exchanged, stamped or written here.
    Leave,
}

pub(crate) fn claim_step(redeemer: Option<&str>, confirmed: bool, me: &str) -> ClaimStep {
    match redeemer {
        Some(r) if r != me => ClaimStep::Leave,
        Some(_) if confirmed => ClaimStep::Redeem,
        _ => ClaimStep::Claim,
    }
}

/// What [`claim_code`] found or did.
#[derive(Debug)]
pub(crate) enum Claimed {
    /// This device may exchange the code now: the entry, claimed by it.
    Mine(Connecting),
    /// Not this run: another device's claim, or the cloud did not take ours.
    No,
    /// The cloud did not answer the claim: not this run, retried on the timer.
    Unanswered,
    /// This device gave the code up and may not claim it again yet
    /// ([`CodeHistory::cooling`]): retried on the timer.
    Cooling,
}

/// The pending connect `conn` (`entry`, as this run read it) as this device
/// (`me`) may exchange it now.
///
/// An authorization code is used at most once, and every device of the
/// account is the same client (RFC 6749 §4.1.2). So a device exchanges a code
/// it read from the vault only once the cloud's row names it as `redeemer`:
/// an unclaimed row is claimed first, with compare-and-swap at the version the
/// cloud is known to hold (the standard optimistic-concurrency claim, as the
/// console's install requests are claimed). Any other outcome (another writer
/// changed the row first, a refusal, a changed vault key, no answer) writes
/// nothing here and leaves the code this run; it is never reconciled over
/// theirs. With no cloud configured the claim stays local: no other device
/// sees the vault. A vault with no per-item store has no row to claim:
/// `entry` is claimed in memory.
///
/// The caller holds the vault write lock.
async fn claim_code<P: crate::sync::ItemPush>(
    state: &Arc<AppState>,
    vault_id: &str,
    k: &[u8],
    conn: &str,
    entry: &Connecting,
    me: &str,
    push: &P,
) -> Claimed {
    let claimed = |mut e: Connecting| {
        e.oauth2.redeemer = Some(me.to_string());
        e
    };
    let row = match read_connect_row(state, vault_id, k, conn) {
        Ok(Some(row)) => row,
        Ok(None) => return Claimed::No,
        Err(NoStore) => {
            return match claim_step(entry.oauth2.redeemer.as_deref(), true, me) {
                ClaimStep::Leave => Claimed::No,
                _ => Claimed::Mine(claimed(entry.clone())),
            };
        }
    };
    let confirmed = row.version == row.synced;
    match claim_step(row.entry.oauth2.redeemer.as_deref(), confirmed, me) {
        ClaimStep::Leave => return Claimed::No,
        ClaimStep::Redeem => return Claimed::Mine(row.entry),
        ClaimStep::Claim => {}
    }
    let code = row.entry.oauth2.code.clone();
    if state
        .code_history(&code)
        .is_some_and(|h| h.cooling(std::time::Instant::now()))
    {
        return Claimed::Cooling;
    }
    // Claimed from an unclaimed row: this process sees every attempt from
    // here on (a code is unclaimed only while no attempt may have reached
    // the provider).
    let from_unclaimed = row.entry.oauth2.redeemer.is_none();
    let mine = claimed(row.entry.clone());
    match cas_write_connect(state, vault_id, k, conn, row, &mine, push).await {
        Cas::Written => {
            if from_unclaimed {
                state.code_history_start(&code);
            }
            Claimed::Mine(mine)
        }
        Cas::NotTaken => Claimed::No,
        Cas::NoAnswer => Claimed::Unanswered,
    }
}

/// Release this device's (`me`) claim on connect `conn`'s code: its row with
/// no `redeemer`, written with compare-and-swap like the claim. For a code
/// whose request failed before it was sent: it never reached the provider, so
/// another device may redeem it. `true` when the cloud took it (or no cloud
/// is configured); otherwise the claim stays, and nothing is written here.
/// The caller holds the vault write lock.
async fn release_claim<P: crate::sync::ItemPush>(
    state: &Arc<AppState>,
    vault_id: &str,
    k: &[u8],
    conn: &str,
    me: &str,
    push: &P,
) -> bool {
    let Ok(Some(row)) = read_connect_row(state, vault_id, k, conn) else {
        return false;
    };
    if row.entry.oauth2.redeemer.as_deref() != Some(me) {
        return false;
    }
    let mut released = row.entry.clone();
    released.oauth2.redeemer = None;
    matches!(
        cas_write_connect(state, vault_id, k, conn, row, &released, push).await,
        Cas::Written
    )
}

/// The vault has no per-item store: no row to claim.
struct NoStore;

/// A pending connect's row as the store holds it, with a code to exchange.
struct ConnectRow {
    pv: crate::storage::sealed_vault::PerItemVault,
    path: std::path::PathBuf,
    id: String,
    version: u64,
    /// The version last known to be on the cloud.
    synced: u64,
    entry: Connecting,
}

/// Connect `conn`'s row, when it is live with a code and no error stamp
/// (`None` otherwise, or when the store can't be read).
fn read_connect_row(
    state: &Arc<AppState>,
    vault_id: &str,
    k: &[u8],
    conn: &str,
) -> Result<Option<ConnectRow>, NoStore> {
    use crate::storage::item::{wire_id_for, ItemNs, VaultKeys};
    type S = sudp::primitives::StdPrimitives;
    let Ok(path) = state.vaults.per_item_path(vault_id) else {
        return Err(NoStore);
    };
    let pv = match crate::storage::sealed_vault::read_per_item(&path) {
        Ok(Some(pv)) => pv,
        Ok(None) => return Err(NoStore),
        Err(e) => {
            tracing::warn!(vault = %vault_id, conn = %conn, "oauth connect: store unreadable: {}", e);
            return Ok(None);
        }
    };
    let keys = VaultKeys::from_material(k);
    let Ok(id) = wire_id_for::<S>(keys.id_seed, ItemNs::Connecting, conn) else {
        return Ok(None);
    };
    let Some((version, synced)) = pv.items.get(&id).map(|r| (r.version, r.synced_version)) else {
        return Ok(None);
    };
    let entry: Connecting = match pv.open_item::<S>(keys, vault_id, ItemNs::Connecting, conn) {
        Ok(Some(p)) if !p.is_tombstone() => match serde_json::from_value(p.body) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        },
        _ => return Ok(None),
    };
    if entry.oauth2.code.is_empty() || entry.oauth2.error.is_some() {
        return Ok(None);
    }
    Ok(Some(ConnectRow {
        pv,
        path,
        id,
        version,
        synced,
        entry,
    }))
}

/// How a compare-and-swap write of a pending connect's row ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cas {
    /// The cloud took it (or no cloud is configured), and the store holds it.
    Written,
    /// The cloud did not take it: another writer changed the row first, a
    /// refusal, a changed vault key, no `/items` route. Nothing written here.
    NotTaken,
    /// No answer from the cloud (unreachable, a timeout, a 5xx, an answer
    /// that doesn't parse). Nothing written here.
    NoAnswer,
}

/// Write `entry` as `row`'s connect, over the row the store holds, with
/// compare-and-swap at the version the cloud is known to hold; the store is
/// written only when the cloud took it (or no cloud is configured).
async fn cas_write_connect<P: crate::sync::ItemPush>(
    state: &Arc<AppState>,
    vault_id: &str,
    k: &[u8],
    conn: &str,
    row: ConnectRow,
    entry: &Connecting,
    push: &P,
) -> Cas {
    use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
    use crate::sync::PushOutcome;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    type S = sudp::primitives::StdPrimitives;
    let ConnectRow {
        mut pv,
        path,
        id,
        version,
        synced,
        ..
    } = row;
    let Ok(body) = serde_json::to_value(entry) else {
        return Cas::NotTaken;
    };
    if pv
        .seal_and_upsert::<S>(
            VaultKeys::from_material(k),
            vault_id,
            ItemNs::Connecting,
            conn,
            version + 1,
            &ItemPayload::live(ItemNs::Connecting, conn, body),
        )
        .is_err()
    {
        return Cas::NotTaken;
    }
    let Some(sealed) = pv.items.get(&id).cloned() else {
        return Cas::NotTaken;
    };
    let base = (synced > 0).then_some(synced);
    let ct = URL_SAFE_NO_PAD.encode(&sealed.ct);
    match push
        .push(vault_id, &id, base, sealed.version, &ct, sealed.generation)
        .await
    {
        None => {}
        Some(Ok(PushOutcome::Ok { .. })) => {
            if let Some(r) = pv.items.get_mut(&id) {
                r.synced_version = r.version;
                r.base = None;
            }
        }
        Some(Ok(PushOutcome::Revoked(membership))) => {
            crate::sync::schedule_revoke_vault_access(state, vault_id, membership);
            return Cas::NotTaken;
        }
        Some(Ok(PushOutcome::Conflict { .. })) => {
            tracing::info!(vault = %vault_id, conn = %conn, "oauth connect: the code's row changed first; not written");
            return Cas::NotTaken;
        }
        Some(Ok(_)) => {
            tracing::warn!(vault = %vault_id, conn = %conn, "oauth connect: the cloud did not take the code's row");
            return Cas::NotTaken;
        }
        Some(Err(e)) => {
            tracing::warn!(vault = %vault_id, conn = %conn, "oauth connect: no answer to the code's row write: {}", e);
            return Cas::NoAnswer;
        }
    }
    if let Err(e) = crate::storage::sealed_vault::write_per_item_atomic(&path, &pv) {
        tracing::warn!(vault = %vault_id, conn = %conn, "oauth connect: the code's row was not stored: {}", e);
        return Cas::NotTaken;
    }
    Cas::Written
}

/// Drive the connecting→refresh→move state machine over an open `ProtectedState`,
/// given an async `exchange` closure (injected so tests can avoid real network
/// calls). Mutates `m` in place; returns a [`ConnectReport`] of what happened. On
/// a per-connect failure it logs and **leaves the `connecting` entry in place**
/// (the user retries within the code TTL) — it never aborts the whole batch.
///
/// The caller persists + pushes whenever [`ConnectReport::changed`] is true.
///
/// `skip`: connects this device does not redeem this run (another device's
/// claim, or a claim of its own that did not land, see [`claim_code`]): not
/// exchanged, stamped or reported.
///
/// `exchange(conn, cfg, connecting)` performs the code→token call and returns the
/// tokens (or an error string to log + skip).
pub async fn run_pending<F, Fut>(
    services: &crate::service::ServiceRegistry,
    custom: &std::collections::HashMap<String, crate::service::ServiceDef>,
    m: &mut ProtectedState,
    skip: &std::collections::BTreeSet<String>,
    mut exchange: F,
) -> ConnectReport
where
    F: FnMut(String, ExchangeConfig, Connecting) -> Fut,
    Fut: std::future::Future<Output = Result<ExchangedTokens, String>>,
{
    let pending = collect_pending(m);
    let mut report = ConnectReport::default();
    for (conn, p) in pending.into_iter().filter(|(c, _)| !skip.contains(c)) {
        let Some(cfg) = resolve_exchange_config(services, custom, &p.service) else {
            tracing::warn!(
                conn = %conn,
                service = %p.service,
                "oauth connect: no oauth2 exchange config for the connection's service \
                 (unknown/non-oauth2 service or missing provider creds); leaving connecting"
            );
            report.left_pending.push((
                conn.clone(),
                format!("no OAuth exchange settings for service `{}` on this computer", p.service),
            ));
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
                    report.left_pending.push((
                        conn.clone(),
                        "the provider returned no refresh token".to_string(),
                    ));
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
                if let Some(last) = e.strip_prefix(CODE_EXPIRED) {
                    let reason = code_expired_reason(&host, &classify_exchange_error(last));
                    mark_connecting_failed(m, &conn, &reason);
                    report.failed.push((conn.clone(), reason));
                    tracing::warn!(conn = %conn, "oauth connect: exchange still failing past the code's lifetime; marked failed");
                    continue;
                }
                match classify_exchange_error(&e) {
                    ExchangeFailure::Terminal(reason) => {
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
                    }
                    // Transient: leave connecting; its retry timer tries again
                    // (backoff). Reported so `sc sync` and the result page say
                    // what happened instead of a silent spin.
                    ExchangeFailure::NotSent(detail) => {
                        report.not_sent.push(conn.clone());
                        report.unreached.push((conn.clone(), host, detail));
                        tracing::warn!(conn = %conn, "oauth connect: exchange not sent (connection failed), will retry: {}", e);
                    }
                    ExchangeFailure::NoAnswer(detail) => {
                        report.unreached.push((conn.clone(), host, detail));
                        tracing::warn!(conn = %conn, "oauth connect: exchange got no answer, will retry: {}", e);
                    }
                    ExchangeFailure::Answered(detail) => {
                        report.provider_error.push((conn.clone(), host, detail));
                        tracing::warn!(conn = %conn, "oauth connect: provider answered with an error, will retry: {}", e);
                    }
                }
            }
        }
    }
    report
}

/// This process's history of one authorization code, kept in memory by its
/// hash from the moment this process caught the code or claimed it from an
/// unclaimed row (so it saw every attempt since anyone could send it).
#[derive(Debug, Clone, Copy)]
pub struct CodeHistory {
    /// An attempt may have reached the provider: it was sent, or it is not
    /// known that it wasn't.
    pub maybe_sent: bool,
    /// Times this device gave up its claim on the code (released it, or
    /// stored a caught code unclaimed).
    pub releases: u32,
    /// When it last did.
    pub released_at: Option<std::time::Instant>,
    /// When the history started (it expires with the code).
    pub started: std::time::Instant,
}

impl CodeHistory {
    pub fn new(now: std::time::Instant) -> Self {
        Self {
            maybe_sent: false,
            releases: 0,
            released_at: None,
            started: now,
        }
    }

    /// Is this device still kept from claiming the code again after giving it
    /// up (a visibility timeout, as SQS's)? The wait after the n-th release
    /// is the retry backoff's n-th step, so claim and release writes stay
    /// bounded however fast the connection fails.
    pub fn cooling(&self, now: std::time::Instant) -> bool {
        self.released_at.is_some_and(|t| {
            now.saturating_duration_since(t)
                < crate::auth::retry::backoff(self.releases.saturating_sub(1))
        })
    }
}

/// May a code whose request just failed before it was sent go to another
/// device? Only when this process knows the code's whole history and no
/// attempt may have reached the provider: once a request may have been
/// delivered it is never handed off (RFC 6749 §4.1.2). An unknown history
/// (`None`, e.g. after a restart) keeps the claim (pure).
pub(crate) fn may_hand_off(history: Option<&CodeHistory>) -> bool {
    history.is_some_and(|h| !h.maybe_sent)
}

/// The stamped reason for a code whose exchange kept failing transiently past
/// its lifetime, by how it last failed: the host this computer could not
/// reach (with the one setting that usually fixes it, as a suggestion), or
/// the host's answer.
fn code_expired_reason(host: &str, last: &ExchangeFailure) -> String {
    let with = |d: &str| if d.is_empty() { String::new() } else { format!(": {d}") };
    match last {
        ExchangeFailure::NotSent(d) => format!(
            "couldn't reach {host} from this computer; stopped retrying after 10 minutes{}. \
             Connect again. Suggestion: check this computer's network or proxy \
             (`sprott config set proxy <url>`)",
            with(d)
        ),
        ExchangeFailure::NoAnswer(d) => format!(
            "got no answer from {host}; stopped retrying after 10 minutes{}. Connect again",
            with(d)
        ),
        ExchangeFailure::Answered(d) | ExchangeFailure::Terminal(d) => format!(
            "{host} answered with an error; stopped retrying after 10 minutes{}. Connect again",
            with(d)
        ),
    }
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
    if report.settled() {
        // A fresh connect landed → clear any stale needs-reauth flag for this
        // vault (a still-dead token re-marks on the next /use).
        state.oauth_clear_reauth_vault(vault_id);
    }
    if report.changed() {
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
    // A transient exchange failure, or a claim the cloud did not answer,
    // writes nothing, so no event or sync would bring it back: it owns a
    // retry timer with backoff until a run leaves none (every pending entry is
    // tried each run, so this run's report is the whole answer; a locked or
    // unreadable vault is retried at unlock).
    if !report.retrying() {
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
    let Ok(_guard) = state.vault_write_guard(vault_id).await else {
        return ConnectReport::default();
    };

    // Read under the write lock (lock runs under it too), so a lock that won
    // the race leaves nothing to seal with an evicted K.
    let Some(k) = state.cloned_state_key(vault_id) else {
        return ConnectReport::default(); // Locked — no retained K; next unlock retries.
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

    // This device, as a code's `redeemer` names it.
    let me = crate::device_auth::device_signer().map(|s| s.device_id().to_string());

    // Fill in the codes the loopback listener caught this round. A caught code
    // is then handled exactly like a pasted one: if this run does not finish
    // the connect (a transient failure), the code is sealed into its pending
    // entry, with this device as its redeemer, and pushed, so the same retry,
    // expiry and status path owns it.
    let before_catch = aux_map::<Connecting>(&m, "connecting");
    let caught: Vec<String> = match &injected {
        Some(injected) => inject_codes(&mut m, injected, me.as_deref()),
        None => Vec::new(),
    };
    // Only this process holds a caught code: it sees every attempt.
    for conn in &caught {
        if let Some(code) = injected.as_ref().and_then(|i| i.get(conn)) {
            state.code_history_start(code);
        }
    }

    // Cheap pre-check: nothing to do if there are no in-flight connects.
    if collect_pending(&m).is_empty() {
        return ConnectReport::default();
    }

    let services = &state.services;
    // Per-vault custom services (`aux.services`) so a user-authored inline
    // [oauth2] service's connect can resolve — the install that builds the
    // snapshot always runs before us (sync/watch/unlock+write all install,
    // THEN process connects), so it's fresh here.
    let custom = state.custom_services_snapshot(vault_id);

    // A code read from the vault is exchanged only by the device whose claim
    // the cloud holds ([`claim_code`]); a caught one is exchanged from memory
    // first. Nothing is claimed that this run would not exchange: a code this
    // daemon already redeemed, or one whose service it cannot exchange.
    let mut skip = std::collections::BTreeSet::new();
    let mut claim_unanswered = Vec::new();
    let mut cooling = Vec::new();
    for (conn, p) in collect_pending(&m) {
        if caught.contains(&conn)
            || state.was_code_redeemed(&p.oauth2.code)
            || resolve_exchange_config(services, &custom, &p.service).is_none()
        {
            continue;
        }
        let claimed = match me.as_deref() {
            Some(me) => claim_code(state, vault_id, &k, &conn, &p, me, &crate::sync::Cloud).await,
            None => Claimed::No,
        };
        match claimed {
            Claimed::Mine(entry) => set_connecting(&mut m, &conn, entry),
            Claimed::No => {
                tracing::debug!(vault = %vault_id, conn = %conn, "oauth connect: code not claimed by this device; left to its redeemer");
                skip.insert(conn);
            }
            Claimed::Unanswered => {
                claim_unanswered.push(conn.clone());
                skip.insert(conn);
            }
            Claimed::Cooling => {
                cooling.push(conn.clone());
                skip.insert(conn);
            }
        }
    }

    let st = state.clone();
    let report = run_pending(services, &custom, &mut m, &skip, move |_conn, cfg, p| {
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
            )
            .map_err(|e| format!("{}{e}", crate::auth::oauth2::CODE_EXCHANGE_NOT_BUILT))?;
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
            // Whether this attempt may have reached the provider: all but a
            // request that failed before it was sent, or was never built.
            let maybe_sent = match &out {
                Ok(_) => true,
                Err(e) => {
                    !e.starts_with(crate::auth::oauth2::CODE_EXCHANGE_NOT_BUILT)
                        && !matches!(classify_exchange_error(e), ExchangeFailure::NotSent(_))
                }
            };
            state.code_history_attempt(&p.oauth2.code, maybe_sent);
            match &out {
                Ok(_) => state.note_code_redeemed(&p.oauth2.code),
                // Retried transient failures stop once the code can no longer
                // be valid: the connection is marked failed ("reconnect")
                // instead of staying "connecting" for good.
                Err(e) if !matches!(classify_exchange_error(e), ExchangeFailure::Terminal(_))
                    && code_exchange_expired(state.code_first_tried(&p.oauth2.code), std::time::Instant::now()) =>
                {
                    return Err(format!("{CODE_EXPIRED}{e}"));
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
    let mut report = report;
    report.claim_unanswered = claim_unanswered;
    report.cooling = cooling;

    // A request that failed before it was sent never reached the provider, so
    // its code may go to any device: a non-idempotent request is handed on
    // only then (as Envoy's `retry_on: connect-failure` and gRPC's transparent
    // retries do). A caught code is stored unclaimed, and a claim held here is
    // released with compare-and-swap. Any other failure keeps the claim: the
    // code may have reached the provider.
    // Only when this process saw every attempt and none may have reached the
    // provider ([`may_hand_off`]); after a release this device waits before
    // claiming the code again ([`CodeHistory::cooling`]).
    for conn in report.not_sent.clone() {
        let Some(mut entry) = aux_map::<Connecting>(&m, "connecting").remove(&conn) else {
            continue;
        };
        if !may_hand_off(state.code_history(&entry.oauth2.code).as_ref()) {
            continue;
        }
        let release = match (caught.contains(&conn), me.as_deref()) {
            (true, _) => true,
            (false, Some(me)) => {
                release_claim(state, vault_id, &k, &conn, me, &crate::sync::Cloud).await
            }
            (false, None) => false,
        };
        if release {
            state.code_history_released(&entry.oauth2.code);
            entry.oauth2.redeemer = None;
            set_connecting(&mut m, &conn, entry);
            report.handed_off.push(conn);
        }
    }

    // A caught code is stored like a paste only while its exchange is being
    // retried, and only claimed by this device or handed off. One this run
    // left otherwise (no exchange settings, no refresh token, already
    // redeemed here, or, on a device with no identity to claim it with, an
    // attempt that may have reached the provider) is not stored: its entry
    // stays as it was.
    let (stored, unsettled) = caught_codes_to_store(&caught, &report, me.is_some());
    for conn in unsettled {
        if let Some(entry) = before_catch.get(&conn) {
            set_connecting(&mut m, &conn, entry.clone());
        }
    }
    report.code_stored = stored;

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
    // mirror, then the snapshot from what landed, so a request sees the new
    // refresh_token without a manual lock/unlock. A connect the store did not
    // take is reported failed, never served from memory; one it took that
    // this device does not serve yet is reported so.
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
            report.code_stored.clear();
            return report;
        }
    };
    // A caught code counts as stored only when the store holds it now (the
    // store may have refused or left its row).
    if !report.code_stored.is_empty() {
        let held = held_codes(state, vault_id, &k);
        let caught_code = |c: &str| injected.as_ref().and_then(|i| i.get(c));
        report
            .code_stored
            .retain(|c| caught_code(c).is_some_and(|code| held.get(c) == Some(code)));
    }
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

/// Put `entry` as connect `conn` in `m`.
fn set_connecting(m: &mut ProtectedState, conn: &str, entry: Connecting) {
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    connecting.insert(conn.to_string(), entry);
    set_aux_map(m, "connecting", connecting);
}

/// Of the codes the loopback listener `caught` this run: those to store (the
/// exchange is being retried, and the code is claimed by this device, which
/// `can_claim` with its identity, or handed off), and those left neither
/// stored nor settled, whose entry goes back to what it was before the catch
/// (pure).
fn caught_codes_to_store(
    caught: &[String],
    report: &ConnectReport,
    can_claim: bool,
) -> (Vec<String>, Vec<String>) {
    let settled = |c: &str| {
        report.completed.iter().any(|x| x == c) || report.failed.iter().any(|(f, _)| f == c)
    };
    let mut stored = Vec::new();
    let mut unsettled = Vec::new();
    for c in caught {
        if report.exchange_retrying(c) && (can_claim || report.handed_off.contains(c)) {
            stored.push(c.clone());
        } else if !settled(c) {
            unsettled.push(c.clone());
        }
    }
    (stored, unsettled)
}

/// The code each pending connect holds in the vault's store now (its
/// per-item store, else vault.dat): empty when neither can be read.
fn held_codes(state: &Arc<AppState>, vault_id: &str, k: &[u8]) -> BTreeMap<String, String> {
    let vault_dat = crate::storage::sealed_vault::read(&vault_dat_path(state, vault_id))
        .ok()
        .flatten();
    match open_m_for_write(state, vault_id, k, vault_dat.as_ref()) {
        Ok((m, _)) => aux_map::<Connecting>(&m, "connecting")
            .into_iter()
            .map(|(c, e)| (c, e.oauth2.code))
            .collect(),
        Err(_) => BTreeMap::new(),
    }
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
/// keeps the full rewrite, without an install.
///
/// `old` is the value the rotation replaced. With `if_current`, the token is
/// written only while the slot still holds `old` (a delayed retry must never
/// put an older token over a newer one).
///
/// Under the vault's build mutex: the store write, then (only while Unlocked)
/// the served snapshot is patched to hold the stored token at its slot
/// ([`AppState::patch_rotated_locked`]: no fold, no permit touched), then the
/// slot's pending entry is dropped. An install that read the store before the
/// write swaps first, and the patch lands on its snapshot.
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
    let Some(runtime) = state.runtime_if_present(vault_id) else {
        return Err("the vault is locked".into());
    };
    runtime.with_build_lock(|| {
        let (stored, key) = write_rotated_refresh(
            state,
            vault_id,
            conn_id,
            role,
            old,
            new_refresh_token,
            if_current,
        )?;
        match stored {
            RotationStored::Written | RotationStored::AlreadyStored => {
                state.patch_rotated_locked(&runtime, vault_id, &key, new_refresh_token.as_bytes());
                tracing::info!(vault = %vault_id, conn = %conn_id, "oauth refresh: rotated refresh_token persisted");
            }
            RotationStored::Superseded => {
                tracing::info!(vault = %vault_id, conn = %conn_id, "oauth refresh: a newer refresh_token was stored since; the pending one is dropped");
            }
        }
        state.drop_pending_rotation(vault_id, conn_id, role);
        Ok(stored)
    })
}

/// The store write of [`persist_rotated_refresh_locked`] (its caller holds the
/// build mutex), and the slot it wrote.
fn write_rotated_refresh(
    state: &Arc<AppState>,
    vault_id: &str,
    conn_id: &str,
    role: &str,
    old: &[u8],
    new_refresh_token: &str,
    if_current: bool,
) -> Result<(RotationStored, String), String> {
    type S = sudp::primitives::StdPrimitives;
    let Some(k) = state.cloned_state_key(vault_id) else {
        return Err("the vault is locked".into());
    };
    let store = state
        .vaults
        .per_item_path(vault_id)
        .ok()
        .map(|path| (crate::storage::sealed_vault::read_per_item(&path), path));
    // The slot the refresh token was read from: the session's record of the
    // connection (identity key for a default connection).
    let rec = state.connection_snapshot(vault_id, conn_id);
    let key = secret_key_for(rec.as_ref(), role);
    let stored = match store {
        Some((Ok(Some(mut pv)), path)) => {
            let keys = crate::storage::item::VaultKeys::from_material(&k);
            let replaces = if_current
                .then(|| std::str::from_utf8(old).ok())
                .flatten();
            if if_current && replaces.is_none() {
                return Ok((RotationStored::Superseded, key));
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
            let key = persist_rotated_refresh_whole_blob(
                state,
                vault_id,
                conn_id,
                role,
                new_refresh_token,
                &k,
            )?;
            return Ok((RotationStored::Written, key));
        }
    };
    Ok((stored, key))
}

/// [`persist_rotated_refresh_locked`] for a vault with no per-item store: the
/// whole body is rewritten (and re-sealed into `vault.dat`), without an
/// install (the caller patches the snapshot). Returns the slot written.
fn persist_rotated_refresh_whole_blob(
    state: &Arc<AppState>,
    vault_id: &str,
    conn_id: &str,
    role: &str,
    new_refresh_token: &str,
    k: &[u8],
) -> Result<String, String> {
    let vault_dat = match crate::storage::sealed_vault::read(&vault_dat_path(state, vault_id)) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth rotate: read vault.dat failed: {}", e);
            None
        }
    };
    let (mut m, base) = open_m_for_write(state, vault_id, k, vault_dat.as_ref())?;
    let rec = aux_map::<Connection>(&m, "connections").remove(conn_id);
    let key = secret_key_for(rec.as_ref(), role);
    m.put_secret(key.clone(), new_refresh_token.as_bytes().to_vec());
    let view = crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m)
        .map_err(|e| format!("view rebuild failed: {}", e))?;
    let not_applied = write_store(state, vault_id, vault_dat, &m, &view, k, &base)?;
    if !not_applied.is_empty() {
        return Err(sentences(&not_applied));
    }
    Ok(key)
}

/// A rotated refresh token this device could not store (`why`): the provider
/// now honors only the new one, so the session uses it (every mint input is
/// followed through the pending entry, [`AppState::current_refresh_token`],
/// while the snapshot still holds `old` as the store does), the store is
/// retried on its own timer with backoff ([`crate::auth::retry`]), after every
/// sync round and at unlock, and the user is told.
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
///   3. the snapshot, installed from the store as it now is
///      ([`AppState::install`], under `key`'s rules): served only while the
///      vault is Unlocked and the fold reads every row the served snapshot
///      read.
///
/// Returns the parts of the change the store refused or set aside, each
/// `(item id, sentence)` (also noted for `sc sync` / `sc status`), and what
/// the install did. `Err` when neither store took the change: the snapshot
/// is left as it was.
fn write_view(
    state: &Arc<AppState>,
    vault_id: &str,
    vault_dat: Option<crate::storage::SealedVault>,
    m: &ProtectedState,
    view: &crate::storage::plaintext::VaultPlaintextView,
    key: WriteKey<'_>,
    base: &ViewBase,
) -> Result<(Vec<(String, String)>, crate::state::Installed), String> {
    let not_applied = write_store(state, vault_id, vault_dat, m, view, key.material(), base)?;
    Ok((not_applied, state.install(vault_id, key.install())))
}

/// Steps 1 and 2 of [`write_view`] (the stores), without the install: the
/// parts of the change the store refused or set aside.
fn write_store(
    state: &Arc<AppState>,
    vault_id: &str,
    vault_dat: Option<crate::storage::SealedVault>,
    m: &ProtectedState,
    view: &crate::storage::plaintext::VaultPlaintextView,
    k: &[u8],
    base: &ViewBase,
) -> Result<Vec<(String, String)>, String> {
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
    Ok(written.map(|w| w.not_applied).unwrap_or_default())
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
        inject_codes(&mut m, &codes, None);
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
        inject_codes(&mut m, &codes, Some("dev_me"));
        let entry = &aux_map::<Connecting>(&m, "connecting")["gmail"];
        assert_eq!(entry.oauth2.code, "already-there");
        assert_eq!(entry.oauth2.redeemer, None, "not caught here, not claimed");
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
        let report = run_pending(&services, &no_custom(), &mut m, &Default::default(), |conn, cfg, p| {
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
            &Default::default(),
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

    /// The expiry stamp says how the exchange last failed: no answer names
    /// the host it couldn't reach and the proxy setting, as a suggestion; an
    /// answer from the host says so, with no proxy suggestion.
    #[test]
    fn code_expired_reason_says_how_it_last_failed() {
        let host = "oauth2.googleapis.com";
        let r = code_expired_reason(host, &ExchangeFailure::NotSent("connection refused".into()));
        assert!(r.starts_with("couldn't reach oauth2.googleapis.com"), "{r}");
        assert!(r.contains("Suggestion: check this computer's network or proxy (`sprott config set proxy <url>`)"));
        let r = code_expired_reason(host, &ExchangeFailure::NoAnswer("operation timed out".into()));
        assert_eq!(
            r,
            "got no answer from oauth2.googleapis.com; stopped retrying after 10 minutes: operation timed out. Connect again"
        );
        let r = code_expired_reason(host, &ExchangeFailure::Answered("returned HTTP 503: busy".into()));
        assert_eq!(
            r,
            "oauth2.googleapis.com answered with an error; stopped retrying after 10 minutes: returned HTTP 503: busy. Connect again"
        );
        assert!(!code_expired_reason(host, &ExchangeFailure::Answered(String::new())).contains(": "));
    }

    /// An exchange error is read as: not sent (the connection failed first),
    /// sent with no answer, a retryable answer, or terminal.
    #[test]
    fn exchange_errors_are_classified_by_what_happened() {
        use crate::auth::oauth2::{CODE_EXCHANGE_NOT_SENT, CODE_EXCHANGE_REQUEST_FAILED};
        assert_eq!(
            classify_exchange_error(&format!("{CODE_EXCHANGE_NOT_SENT}dns error")),
            ExchangeFailure::NotSent("dns error".into())
        );
        assert_eq!(
            classify_exchange_error(&format!("{CODE_EXCHANGE_REQUEST_FAILED}operation timed out")),
            ExchangeFailure::NoAnswer("operation timed out".into())
        );
        for answered in [
            "oauth2 code-exchange returned HTTP 503 Service Unavailable: busy",
            "oauth2 code-exchange returned HTTP 429 Too Many Requests: slow down",
            "oauth2 code-exchange returned HTTP 408 Request Timeout: ",
            "oauth2 code-exchange parse failed: expected value",
            "oauth2 code-exchange response missing access_token",
        ] {
            let ExchangeFailure::Answered(d) = classify_exchange_error(answered) else {
                panic!("{answered}: the provider answered");
            };
            assert!(!d.starts_with("oauth2 code-exchange"), "{d}");
        }
        assert!(matches!(
            classify_exchange_error("oauth2 code-exchange returned HTTP 400 Bad Request: {\"error\":\"invalid_grant\"}"),
            ExchangeFailure::Terminal(_)
        ));
        assert_eq!(
            classify_exchange_error(&format!(
                "{}needs the consent state",
                crate::auth::oauth2::CODE_EXCHANGE_NOT_BUILT
            )),
            ExchangeFailure::Terminal("needs the consent state".into())
        );
    }

    /// A transient failure is reported by kind, and a request that was never
    /// sent is listed so its code can go to another device; a code still
    /// failing past its window is stamped with how it last failed.
    #[tokio::test]
    async fn run_pending_reports_transient_failures_by_kind() {
        use crate::auth::oauth2::CODE_EXCHANGE_NOT_SENT;
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-A");
        let report = run_pending(&services, &no_custom(), &mut m, &Default::default(), |_c, _cfg, _p| async move {
            Err(format!("{CODE_EXCHANGE_NOT_SENT}tcp connect error: Connection refused"))
        })
        .await;
        assert_eq!(report.not_sent, vec!["gmail".to_string()]);
        assert_eq!(report.unreached[0].2, "tcp connect error: Connection refused");
        assert!(report.retrying() && !report.changed());

        let mut m = with_connecting("gmail", "gmail", "code-B");
        let report = run_pending(&services, &no_custom(), &mut m, &Default::default(), |_c, _cfg, _p| async move {
            Err("oauth2 code-exchange returned HTTP 503 Service Unavailable: busy".to_string())
        })
        .await;
        assert!(report.unreached.is_empty() && report.not_sent.is_empty());
        assert_eq!(report.provider_error[0].1, "oauth2.googleapis.com");
        assert!(report.provider_error[0].2.contains("HTTP 503"));
        assert!(report.retrying());

        let mut m = with_connecting("gmail", "gmail", "code-C");
        let report = run_pending(&services, &no_custom(), &mut m, &Default::default(), |_c, _cfg, _p| async move {
            Err(format!("{CODE_EXPIRED}oauth2 code-exchange returned HTTP 503 Service Unavailable: busy"))
        })
        .await;
        assert!(report.failed[0].1.starts_with("oauth2.googleapis.com answered with an error"));
    }

    /// A caught code is stored only while its exchange is retried; one left
    /// for another reason goes back to its entry before the catch.
    #[test]
    fn a_caught_code_is_stored_only_while_retried() {
        let caught: Vec<String> = ["a", "b", "c", "d", "e"].iter().map(|s| s.to_string()).collect();
        let report = ConnectReport {
            completed: vec!["a".into()],
            failed: vec![("b".into(), "rejected".into())],
            unreached: vec![("c".into(), "h".into(), "timed out".into())],
            provider_error: vec![("d".into(), "h".into(), "HTTP 503".into())],
            left_pending: vec![("e".into(), "the provider returned no refresh token".into())],
            ..Default::default()
        };
        let (stored, unsettled) = caught_codes_to_store(&caught, &report, true);
        assert_eq!(stored, vec!["c".to_string(), "d".to_string()]);
        assert_eq!(unsettled, vec!["e".to_string()]);

        // A device with no identity can't claim: only a handed-off code (never
        // sent) is stored; one that may have reached the provider is not.
        let report = ConnectReport {
            unreached: vec![
                ("c".into(), "h".into(), "timed out".into()),
                ("d".into(), "h".into(), "connection refused".into()),
            ],
            not_sent: vec!["d".into()],
            handed_off: vec!["d".into()],
            ..Default::default()
        };
        let (stored, unsettled) = caught_codes_to_store(&["c".into(), "d".into()], &report, false);
        assert_eq!(stored, vec!["d".to_string()]);
        assert_eq!(unsettled, vec!["c".to_string()]);
    }

    /// A code goes to another device only when this process saw its whole
    /// history and no attempt may have reached the provider; an unknown
    /// history (e.g. after a restart) keeps the claim.
    #[test]
    fn a_code_is_handed_off_only_if_never_sent() {
        let now = std::time::Instant::now();
        assert!(!may_hand_off(None), "unknown history");
        let fresh = CodeHistory::new(now);
        assert!(may_hand_off(Some(&fresh)));
        let sent = CodeHistory {
            maybe_sent: true,
            ..fresh
        };
        assert!(!may_hand_off(Some(&sent)));

        let (_dir, state) = temp_state();
        state.code_history_attempt("code-x", false);
        assert!(state.code_history("code-x").is_none(), "an attempt starts no history");
        state.code_history_start("code-x");
        state.code_history_attempt("code-x", false);
        assert!(may_hand_off(state.code_history("code-x").as_ref()));
        // NoAnswer, then NotSent: an earlier attempt may have arrived.
        state.code_history_attempt("code-x", true);
        state.code_history_attempt("code-x", false);
        assert!(!may_hand_off(state.code_history("code-x").as_ref()));
        // Starting again keeps the history.
        state.code_history_start("code-x");
        assert!(state.code_history("code-x").unwrap().maybe_sent);
    }

    /// After giving a code up, this device waits the retry backoff's next
    /// step before claiming it again, so however fast the connection fails,
    /// claim and release writes stay bounded over the code's lifetime.
    #[test]
    fn claim_and_release_writes_are_bounded_by_the_cooldown() {
        let t0 = std::time::Instant::now();
        let mut h = CodeHistory::new(t0);
        assert!(!h.cooling(t0), "never released");
        let mut writes = 0;
        for s in 0..CODE_EXCHANGE_WINDOW.as_secs() {
            let now = t0 + std::time::Duration::from_secs(s);
            if !h.cooling(now) {
                // Claim, the request fails before it is sent, release.
                writes += 2;
                h.releases += 1;
                h.released_at = Some(now);
            }
        }
        assert_eq!(writes, 12, "releases at 0, 5, 20, 65, 185 and 485 s");
        let last = h.released_at.unwrap();
        assert!(h.cooling(last + std::time::Duration::from_secs(299)));
        assert!(!h.cooling(last + std::time::Duration::from_secs(300)));
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
        let report = run_pending(&services, &no_custom(), &mut m, &Default::default(), |_conn, _cfg, _p| async move {
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

        // A 5xx stays pending with NO error (retried on its own timer). The
        // provider answered, so it is surfaced as `provider_error`, not as
        // `unreached` ("couldn't reach" is only for a request with no answer).
        let mut m = with_connecting("gmail", "gmail", "code-B");
        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            &Default::default(),
            |_conn, _cfg, _p| async move {
                Err("oauth2 code-exchange returned HTTP 500: oops".to_string())
            },
        )
        .await;
        assert_eq!((report.completed.len(), report.failed.len()), (0, 0));
        assert_eq!(
            (report.unreached.len(), report.provider_error.len()),
            (0, 1),
            "a provider's retryable error is reported as provider_error"
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
            &Default::default(),
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
            &Default::default(),
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
        let report = run_pending(&services, &no_custom(), &mut m, &Default::default(), |_conn, _cfg, _p| {
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
        let report = run_pending(&services, &no_custom(), &mut m, &Default::default(), |_conn, _cfg, _p| async move {
            Err(format!(
                "{CODE_EXPIRED}{}operation timed out",
                crate::auth::oauth2::CODE_EXCHANGE_REQUEST_FAILED
            ))
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
            .contains("stopped retrying after 10 minutes"));
    }

    /// A caught code fills only an empty pending entry (a pasted code already
    /// in the vault wins), and the filled ones are reported so a run that does
    /// not finish them stores them like a paste, claimed by this device in the
    /// same write.
    #[test]
    fn a_caught_code_fills_an_empty_entry_and_is_reported() {
        let caught: std::collections::BTreeMap<String, String> =
            [("ga4".to_string(), "code-1".to_string())].into();
        let mut m = with_connecting("ga4", "ga4", "");
        assert_eq!(
            inject_codes(&mut m, &caught, Some("dev_me")),
            vec!["ga4".to_string()]
        );
        let entry = &aux_map::<Connecting>(&m, "connecting")["ga4"];
        assert_eq!(entry.oauth2.code, "code-1");
        assert_eq!(entry.oauth2.redeemer.as_deref(), Some("dev_me"));

        let mut pasted = with_connecting("ga4", "ga4", "pasted");
        assert!(inject_codes(&mut pasted, &caught, Some("dev_me")).is_empty());
        assert_eq!(aux_map::<Connecting>(&pasted, "connecting")["ga4"].oauth2.code, "pasted");
    }

    #[test]
    fn a_stored_code_is_a_change_but_not_a_settled_connect() {
        let r = ConnectReport { code_stored: vec!["ga4".into()], ..Default::default() };
        assert!(r.changed(), "persisted and pushed like a paste");
        assert!(!r.settled());
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
    /// `value`, bound by the raw connection `codex` (so the snapshot serves
    /// the slot), unlocked.
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
        rotation_fixture_at("refresh_token", value)
    }

    /// [`rotation_fixture`] with the slot `slot`.
    fn rotation_fixture_at(
        slot: &str,
        value: &str,
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
        let conn = pv
            .seal_and_upsert::<S>(
                keys,
                vid,
                ItemNs::Connection,
                "codex",
                1,
                &ItemPayload::live(
                    ItemNs::Connection,
                    "codex",
                    serde_json::json!({ "hosts": ["api.codex.dev"], "secrets": [slot] }),
                ),
            )
            .unwrap();
        pv.items.get_mut(&conn).unwrap().synced_version = 1;
        let path = state.vaults.per_item_path(vid).unwrap();
        write_per_item_atomic(&path, &pv).unwrap();
        unlock_fixture(&state, vid, &material);
        (dir, state, vid, material, path, id)
    }

    fn unlock_fixture(state: &AppState, vid: &str, material: &[u8]) {
        let key = crate::state::InstallKey::Unlock(zeroize::Zeroizing::new(material.to_vec()));
        assert!(state.install(vid, key).served());
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
    /// at the slot the connection reads it from; the served snapshot is
    /// patched to it, and whatever was pending for that slot is dropped.
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
        assert_eq!(state.served_native(vid, "refresh_token").unwrap(), b"rt-3");
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
        assert_eq!(state.served_native(vid, "refresh_token").unwrap(), b"rt-3");
    }

    /// While a rotation is pending, a snapshot rebuilt from the store (a
    /// pull, an unlock) holds what the store holds, and every mint input is
    /// followed to the rotated token, never the dead one; the retry that
    /// stores it patches the snapshot to it.
    #[test]
    fn a_rebuilt_snapshot_mints_with_the_pending_rotation() {
        let (_dir, state, vid, material, path, _) = rotation_fixture("rt-1");
        state.note_rotation_pending(vid, "codex", "refresh_token", b"rt-1", "rt-2", "disk");
        // A rebuild from the store, which still holds rt-1.
        unlock_fixture(&state, vid, &material);
        assert_eq!(state.served_native(vid, "refresh_token").unwrap(), b"rt-1");
        assert_eq!(
            state.current_refresh_token(vid, "codex", b"rt-1").unwrap().as_str(),
            "rt-2"
        );
        retry_pending_rotations_locked(&state, vid);
        assert_eq!(stored_refresh_token(&path, &material, vid), b"rt-2");
        assert_eq!(state.served_native(vid, "refresh_token").unwrap(), b"rt-2");
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
        let auth = state.services.get("gmail").unwrap().auth.clone().unwrap();
        let minted =
            crate::server::broker_flow::resolve_auth_value(&state, vid, "codex", "gmail", &auth, b"rt-0")
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
        let auth = def.auth.clone().unwrap();
        let (_dir, state, vid, material, path, _) = rotation_fixture_at("ACME_REFRESH_TOKEN", "rt-0");

        let (a, b) = tokio::join!(
            crate::server::broker_flow::resolve_auth_value(&state, vid, "codex", "acme", &auth, b"rt-0"),
            crate::server::broker_flow::resolve_auth_value(&state, vid, "codex", "acme", &auth, b"rt-0"),
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
        let again =
            crate::server::broker_flow::resolve_auth_value(&state, vid, "codex", "acme", &auth, b"rt-0")
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
        unlock_fixture(&state, vid, &material);
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

    /// A rotated refresh token whose store failed stays in use: the snapshot
    /// keeps what the store holds, every mint input is followed to the new
    /// token, it is kept to store again on its own retry timer, and the user
    /// is told; once stored, the note settles.
    #[test]
    fn a_rotated_token_not_stored_stays_in_use_and_pending() {
        let (_dir, state) = temp_state();
        state.open_ledger_for_tests(&[]);
        let vid = "v-rotate";
        state.unlock_vault(
            vid.into(),
            crate::snapshot::Snapshot::default(),
            zeroize::Zeroizing::new(vec![0u8; 32]),
        );
        rotation_not_stored(
            &state,
            vid,
            "codex",
            "refresh_token",
            b"old-rt",
            "new-rt",
            "the store failed",
        );
        assert_eq!(
            state.current_refresh_token(vid, "codex", b"old-rt").unwrap().as_str(),
            "new-rt"
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

    /// Who redeems a code: the device the cloud's claim names; an unclaimed
    /// code, or this device's claim not on the cloud yet, is claimed first;
    /// another device's claim is left alone.
    #[test]
    fn claim_step_decides_who_redeems_a_code() {
        assert_eq!(claim_step(None, true, "dev_me"), ClaimStep::Claim);
        assert_eq!(claim_step(None, false, "dev_me"), ClaimStep::Claim);
        assert_eq!(
            claim_step(Some("dev_me"), true, "dev_me"),
            ClaimStep::Redeem
        );
        assert_eq!(
            claim_step(Some("dev_me"), false, "dev_me"),
            ClaimStep::Claim
        );
        assert_eq!(claim_step(Some("dev_b"), true, "dev_me"), ClaimStep::Leave);
        assert_eq!(claim_step(Some("dev_b"), false, "dev_me"), ClaimStep::Leave);
    }

    /// A connect this device does not redeem this run is not exchanged,
    /// stamped or reported.
    #[tokio::test]
    async fn run_pending_never_touches_a_skipped_code() {
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-X");
        let skip: std::collections::BTreeSet<String> = ["gmail".to_string()].into();
        let calls = std::cell::Cell::new(0);
        let report = run_pending(&services, &no_custom(), &mut m, &skip, |_c, _cfg, _p| {
            calls.set(calls.get() + 1);
            async move { Err::<ExchangedTokens, String>("invalid_grant".into()) }
        })
        .await;
        assert_eq!(calls.get(), 0);
        assert!(!report.changed() && report.unreached.is_empty() && report.left_pending.is_empty());
        assert_eq!(
            aux_map::<Connecting>(&m, "connecting")["gmail"]
                .oauth2
                .error,
            None
        );
    }

    /// A cloud for [`claim_code`]: answers every push with `outcome`.
    struct FakePush {
        outcome: fn() -> Option<Result<crate::sync::PushOutcome, String>>,
        calls: std::sync::Mutex<Vec<(Option<u64>, u64)>>,
    }

    impl FakePush {
        fn new(outcome: fn() -> Option<Result<crate::sync::PushOutcome, String>>) -> Self {
            Self {
                outcome,
                calls: Default::default(),
            }
        }

        fn calls(&self) -> Vec<(Option<u64>, u64)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl crate::sync::ItemPush for FakePush {
        async fn push(
            &self,
            _vault: &str,
            _item_id: &str,
            base: Option<u64>,
            version: u64,
            _ct_b64: &str,
            _generation: Option<u64>,
        ) -> Option<Result<crate::sync::PushOutcome, String>> {
            self.calls.lock().unwrap().push((base, version));
            (self.outcome)()
        }
    }

    const CLAIM_KEY: [u8; 32] = [0x42u8; 32];

    /// The body of the in-flight connect `gmail` (code `c`).
    fn connect_body(redeemer: Option<&str>) -> serde_json::Value {
        let mut oauth2 = serde_json::json!({ "code": "c", "code_verifier": "v" });
        if let Some(r) = redeemer {
            oauth2["redeemer"] = r.into();
        }
        serde_json::json!({ "service": "gmail", "oauth2": oauth2 })
    }

    /// A store holding the in-flight connect `gmail` claimed by `redeemer`,
    /// at v2, last confirmed on the cloud at `synced`. Returns the state,
    /// vault, store path and the row's id.
    fn claim_fixture(
        redeemer: Option<&str>,
        synced: u64,
    ) -> (
        tempfile::TempDir,
        Arc<AppState>,
        &'static str,
        std::path::PathBuf,
        String,
    ) {
        use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
        use crate::storage::sealed_vault::PerItemVault;
        type S = sudp::primitives::StdPrimitives;
        let (dir, state) = temp_state();
        let vid = "claim-v";
        let keys = VaultKeys::single(&CLAIM_KEY);
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        let body = connect_body(redeemer);
        let id = pv
            .seal_and_upsert::<S>(
                keys,
                vid,
                ItemNs::Connecting,
                "gmail",
                2,
                &ItemPayload::live(ItemNs::Connecting, "gmail", body),
            )
            .unwrap();
        pv.items.get_mut(&id).unwrap().synced_version = synced;
        let path = state.vaults.per_item_path(vid).unwrap();
        crate::storage::sealed_vault::write_per_item_atomic(&path, &pv).unwrap();
        (dir, state, vid, path, id)
    }

    /// The stored row `id`: `(version, synced_version, its connect)`.
    fn stored_connect(
        path: &std::path::Path,
        id: &str,
        vid: &str,
    ) -> (u64, u64, Option<Connecting>) {
        use crate::storage::item::{ItemNs, VaultKeys};
        type S = sudp::primitives::StdPrimitives;
        let pv = crate::storage::sealed_vault::read_per_item(path)
            .unwrap()
            .unwrap();
        let row = &pv.items[id];
        let entry = pv
            .open_item::<S>(
                VaultKeys::single(&CLAIM_KEY),
                vid,
                ItemNs::Connecting,
                "gmail",
            )
            .unwrap()
            .filter(|p| !p.is_tombstone())
            .map(|p| serde_json::from_value(p.body).unwrap());
        (row.version, row.synced_version, entry)
    }

    fn entry(redeemer: Option<&str>) -> Connecting {
        serde_json::from_value(connect_body(redeemer)).unwrap()
    }

    fn mine(c: Claimed) -> Option<Connecting> {
        match c {
            Claimed::Mine(e) => Some(e),
            Claimed::No | Claimed::Unanswered | Claimed::Cooling => None,
        }
    }

    /// A claim held here is released with compare-and-swap (after a request
    /// that was never sent); another device's claim, or a release the cloud
    /// did not take, changes nothing.
    #[tokio::test]
    async fn a_claim_is_released_with_compare_and_swap() {
        use crate::sync::PushOutcome;
        let (_dir, state, vid, path, id) = claim_fixture(Some("dev_me"), 2);
        let cloud = FakePush::new(|| Some(Ok(PushOutcome::Ok { version: 3, seq: 1 })));
        assert!(release_claim(&state, vid, &CLAIM_KEY, "gmail", "dev_me", &cloud).await);
        assert_eq!(cloud.calls(), vec![(Some(2), 3)]);
        let (v, synced, stored) = stored_connect(&path, &id, vid);
        assert_eq!((v, synced), (3, 3));
        let stored = stored.unwrap();
        assert_eq!(stored.oauth2.redeemer, None);
        assert_eq!(stored.oauth2.code, "c", "the code stays for another device");

        let (_dir, state, vid, path, id) = claim_fixture(Some("dev_b"), 2);
        assert!(!release_claim(&state, vid, &CLAIM_KEY, "gmail", "dev_me", &cloud).await);
        assert_eq!(stored_connect(&path, &id, vid).0, 2);

        let (_dir, state, vid, path, id) = claim_fixture(Some("dev_me"), 2);
        let busy = FakePush::new(|| Some(Ok(PushOutcome::Conflict { current_version: 3 })));
        assert!(!release_claim(&state, vid, &CLAIM_KEY, "gmail", "dev_me", &busy).await);
        let (v, _, stored) = stored_connect(&path, &id, vid);
        assert_eq!(v, 2);
        assert_eq!(stored.unwrap().oauth2.redeemer.as_deref(), Some("dev_me"));
    }

    /// A code this device gave up is not claimed again while it cools down:
    /// nothing is written (a wake-driven run respects it; the retry timer
    /// claims once it has passed).
    #[tokio::test]
    async fn a_code_given_up_is_not_claimed_while_cooling() {
        use crate::sync::PushOutcome;
        let (_dir, state, vid, path, id) = claim_fixture(None, 2);
        state.code_history_start("c");
        state.code_history_released("c");
        let cloud = FakePush::new(|| Some(Ok(PushOutcome::Ok { version: 3, seq: 1 })));
        let got = claim_code(&state, vid, &CLAIM_KEY, "gmail", &entry(None), "dev_me", &cloud).await;
        assert!(matches!(got, Claimed::Cooling));
        assert!(cloud.calls().is_empty());
        assert_eq!(stored_connect(&path, &id, vid).0, 2);
    }

    /// An unclaimed code is claimed with compare-and-swap at the version the
    /// cloud holds before it is exchanged; once the cloud holds the claim the
    /// device redeems it without another write.
    #[tokio::test]
    async fn a_code_is_claimed_with_compare_and_swap_before_it_is_exchanged() {
        use crate::sync::PushOutcome;
        let (_dir, state, vid, path, id) = claim_fixture(None, 2);
        let cloud = FakePush::new(|| Some(Ok(PushOutcome::Ok { version: 3, seq: 1 })));
        let got = mine(
            claim_code(
                &state,
                vid,
                &CLAIM_KEY,
                "gmail",
                &entry(None),
                "dev_me",
                &cloud,
            )
            .await,
        )
        .expect("claimed");
        assert_eq!(got.oauth2.redeemer.as_deref(), Some("dev_me"));
        assert_eq!(cloud.calls(), vec![(Some(2), 3)]);
        let (v, synced, stored) = stored_connect(&path, &id, vid);
        assert_eq!((v, synced), (3, 3), "the claim is on the cloud");
        assert_eq!(stored.unwrap().oauth2.redeemer.as_deref(), Some("dev_me"));

        let none = FakePush::new(|| None);
        let again = claim_code(&state, vid, &CLAIM_KEY, "gmail", &got, "dev_me", &none).await;
        assert_eq!(mine(again).unwrap().oauth2.redeemer.as_deref(), Some("dev_me"));
        assert!(none.calls().is_empty(), "redeemed with no write");
    }

    /// A claim the cloud did not take (another writer changed the row first,
    /// a refusal, no answer) writes nothing and redeems nothing this run; no
    /// answer is retried on the timer.
    #[tokio::test]
    async fn a_claim_the_cloud_did_not_take_writes_nothing() {
        use crate::sync::PushOutcome;
        let outcomes: [fn() -> Option<Result<PushOutcome, String>>; 5] = [
            || Some(Ok(PushOutcome::Conflict { current_version: 3 })),
            || {
                Some(Ok(PushOutcome::Rejected {
                    status: 403,
                    error: "x".into(),
                }))
            },
            || Some(Ok(PushOutcome::KeysetChanged)),
            || Some(Err("reach cloud: timed out".into())),
            || Some(Err("item PUT HTTP 503".into())),
        ];
        for outcome in outcomes {
            let (_dir, state, vid, path, id) = claim_fixture(None, 2);
            let cloud = FakePush::new(outcome);
            let got = claim_code(
                &state,
                vid,
                &CLAIM_KEY,
                "gmail",
                &entry(None),
                "dev_me",
                &cloud,
            )
            .await;
            let unanswered = (outcome)().is_some_and(|r| r.is_err());
            assert_eq!(matches!(got, Claimed::Unanswered), unanswered);
            assert!(mine(got).is_none());
            assert_eq!(cloud.calls().len(), 1);
            let (v, synced, stored) = stored_connect(&path, &id, vid);
            assert_eq!((v, synced), (2, 2));
            assert_eq!(stored.unwrap().oauth2.redeemer, None);
        }
    }

    /// Another device's claim is never exchanged or written over; this
    /// device's claim not on the cloud yet (e.g. a caught code stored but not
    /// pushed) is claimed again with compare-and-swap; with no cloud
    /// configured the claim stays local.
    #[tokio::test]
    async fn only_a_claim_the_cloud_holds_is_redeemed() {
        use crate::sync::PushOutcome;
        let (_dir, state, vid, path, id) = claim_fixture(Some("dev_b"), 2);
        let cloud = FakePush::new(|| Some(Ok(PushOutcome::Ok { version: 3, seq: 1 })));
        assert!(mine(
            claim_code(
                &state,
                vid,
                &CLAIM_KEY,
                "gmail",
                &entry(Some("dev_b")),
                "dev_me",
                &cloud
            )
            .await
        )
        .is_none());
        assert!(cloud.calls().is_empty());
        assert_eq!(stored_connect(&path, &id, vid).0, 2);

        let (_dir, state, vid, path, id) = claim_fixture(Some("dev_me"), 1);
        let got = claim_code(
            &state,
            vid,
            &CLAIM_KEY,
            "gmail",
            &entry(Some("dev_me")),
            "dev_me",
            &cloud,
        )
        .await;
        assert!(mine(got).is_some());
        assert_eq!(cloud.calls(), vec![(Some(1), 3)]);
        assert_eq!(stored_connect(&path, &id, vid).1, 3);

        let (_dir, state, vid, path, id) = claim_fixture(None, 2);
        let local = FakePush::new(|| None);
        let got = claim_code(
            &state,
            vid,
            &CLAIM_KEY,
            "gmail",
            &entry(None),
            "dev_me",
            &local,
        )
        .await;
        assert_eq!(mine(got).unwrap().oauth2.redeemer.as_deref(), Some("dev_me"));
        let (v, synced, stored) = stored_connect(&path, &id, vid);
        assert_eq!((v, synced), (3, 2), "stored, unpushed");
        assert_eq!(stored.unwrap().oauth2.redeemer.as_deref(), Some("dev_me"));
    }

    /// A failure stamp never brings back a connect completed elsewhere while
    /// the exchange ran (its tombstone landed in the store), and lands when
    /// the connect is still the one it read.
    #[test]
    fn a_failure_stamp_never_brings_back_a_completed_connect() {
        use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
        type S = sudp::primitives::StdPrimitives;
        for completed_elsewhere in [true, false] {
            let (_dir, state, vid, path, id) = claim_fixture(Some("dev_me"), 2);
            let (mut m, base) = open_m_for_write(&state, vid, &CLAIM_KEY, None).unwrap();
            if completed_elsewhere {
                let mut pv = crate::storage::sealed_vault::read_per_item(&path)
                    .unwrap()
                    .unwrap();
                pv.seal_and_upsert::<S>(
                    VaultKeys::single(&CLAIM_KEY),
                    vid,
                    ItemNs::Connecting,
                    "gmail",
                    3,
                    &ItemPayload::tombstone(ItemNs::Connecting, "gmail"),
                )
                .unwrap();
                pv.items.get_mut(&id).unwrap().synced_version = 3;
                crate::storage::sealed_vault::write_per_item_atomic(&path, &pv).unwrap();
            }
            mark_connecting_failed(&mut m, "gmail", "authorization expired or already used");
            let view =
                crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m).unwrap();
            reconcile_per_item_after_connect(
                &state,
                vid,
                None,
                &view,
                &CLAIM_KEY,
                ReconcileBase::Since(&base),
            )
            .unwrap()
            .expect("a per-item store backs the vault");
            let (v, _, stored) = stored_connect(&path, &id, vid);
            if completed_elsewhere {
                assert_eq!(v, 3);
                assert!(stored.is_none(), "still completed");
            } else {
                assert_eq!(v, 3);
                let stamped = stored.unwrap();
                assert_eq!(stamped.oauth2.redeemer.as_deref(), Some("dev_me"));
                assert!(stamped.oauth2.error.is_some());
            }
        }
    }
}
