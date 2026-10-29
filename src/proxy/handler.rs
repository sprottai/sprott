//! The resident proxy's request handler: the whole brokered pipeline.
//!
//! One `BrokerHandler` is cloned per TCP connection. On a CONNECT it captures
//! the vault id from `Proxy-Authorization` and decides MITM-vs-blind-tunnel by
//! whether the destination host is anchored by any known vault's connection
//! (unlocked live, or a locked vault's last-known anchors — so a phantom sent
//! while locked gets an explicit `vault_locked` instead of a blind tunnel).
//! For each intercepted inner request it: finds phantoms, resolves them to ONE
//! connection, enforces the host anchor, evaluates policy, substitutes the real
//! credential at egress, strips the agent's own/proxy auth, and forwards. A
//! request with no phantom is forwarded untouched — the phantom is the only
//! injection trigger.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use http_body_util::BodyExt;
use hudsucker::hyper::{header, HeaderMap, Method, Request, Response, StatusCode, Uri};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use serde_json::json;

use crate::error::ScCode;
use crate::proxy::resolver::{self, Phantom};
use crate::state::AppState;

/// The last-resort `ask`-once window when neither the matched rule nor any
/// floor (`default.ttl`) pins one — the "Ask once" grant lasts this long after
/// approval. Kept in sync with the console's shown default (15 min).
pub(crate) const DEFAULT_ASK_TTL: u64 = 900;

/// What `handle_response` needs to write the terminal audit row after the
/// upstream answers a forwarded (allow) request.
#[derive(Clone)]
pub struct AuditPending {
    pub vault_id: String,
    pub service: String,
    pub method: String,
    pub path: String,
    /// Agent attribution for the audit row: prefix of the CONNECT-authenticated
    /// agent api-key (see `audit::agent_key_prefix`). Never the full key.
    pub agent_prefix: Option<String>,
}

#[derive(Clone)]
pub struct BrokerHandler {
    pub state: Arc<AppState>,
    /// Vault id captured from the CONNECT's `Proxy-Authorization` username,
    /// inherited by every inner-request clone of this handler.
    pub vid: Option<String>,
    /// Agent api-key captured from the CONNECT's `Proxy-Authorization` PASSWORD
    /// (§8) — the agent's identity, verified in `pipeline` before any phantom
    /// substitution. Inherited by inner-request clones alongside `vid`.
    pub key: Option<String>,
    /// The `ag_…` id of a CRYPTO-VERIFIED agent PoP token (hop-A), resolved at
    /// CONNECT time in `should_intercept` (that's where the CONNECT authority the
    /// token binds is available) and inherited by inner-request clones. `Some`
    /// only when the `Proxy-Authorization` password was a valid, fresh `scpop1…`
    /// token for this vault+target; `None` for the legacy Basic api-key path. The
    /// authorization check (this `ag_` ∈ the vault's authorized-agents table) is
    /// still done in `pipeline` — this field is only "who proved possession".
    pub agent_id: Option<String>,
    /// Set on the allow/forward path; consumed by `handle_response`.
    pub pending: Option<AuditPending>,
}

impl BrokerHandler {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            vid: None,
            key: None,
            agent_id: None,
            pending: None,
        }
    }
}

impl HttpHandler for BrokerHandler {
    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        // The agent's (vid, api-key) ride the CONNECT's Proxy-Authorization
        // userinfo (`base64("<vid>:<key>")`); capture both so inner-request clones
        // inherit them (read-only). The key is VERIFIED later in `pipeline`,
        // before any substitution — here we only need vid PRESENCE.
        let (vid, key) = creds_from_proxy_auth(req);
        self.vid = vid;
        self.key = key;
        // hop-A: if the Proxy-Auth password is an agent PoP token (`scpop1…`),
        // crypto-verify it HERE — the CONNECT authority it binds (`host:port`) is
        // only available at CONNECT time (the inner-request pipeline sees a bare
        // host). A valid, fresh token for THIS vault + target resolves the `ag_`
        // id; the authorization check (`ag_` ∈ the vault's authorized-agents
        // table) happens in `pipeline`. Dual-auth: a non-PoP password (a legacy
        // Basic api-key) leaves `agent_id` None and takes the hash-set path, so
        // nothing bricks. Only the crypto (signature + freshness) is checked here.
        self.agent_id = match (
            self.vid.as_deref(),
            self.key.as_deref(),
            req.uri().authority(),
        ) {
            (Some(vid), Some(key), Some(authority)) => crate::agent_pop::verify_agent_proxy_pop(
                key,
                vid,
                authority.as_str(),
                crate::util::now_unix(),
                crate::agent_pop::DEFAULT_MAX_SKEW_SECS,
            ),
            _ => None,
        };
        // Absent Proxy-Auth (no vid) → non-participating traffic: blind-tunnel it
        // (§8; a stray phantom then reaches upstream literally → clean 401, never
        // a leak). A creds-less CONNECT to a host we DO anchor was already met
        // with a 407 in handle_request (RFC 7235 challenge), so anything absent
        // reaching here targets a host no known vault anchors. Only a request
        // that NAMES a vault and targets an anchored host is a MITM candidate —
        // the precise per-vault anchor + the key check happen in `pipeline`.
        if self.vid.is_none() {
            return false;
        }
        match req.uri().host() {
            Some(h) => self.state.host_in_any_known_union(h),
            None => false,
        }
    }

    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        // A CONNECT normally passes straight through to process_connect, which
        // returns `200 Connection established` and then lets should_intercept
        // read the CONNECT's Proxy-Authorization to decide MITM-vs-tunnel.
        //
        // But not every client sends proxy credentials preemptively. The RFC 7235
        // convention is to send an unauthenticated request first and only repeat
        // it WITH credentials after a `407 Proxy Authentication Required`
        // challenge. Debian/Ubuntu git (libcurl-gnutls) does exactly this — the
        // whole system-git population; curl, wget and python were measured
        // sending creds preemptively, so they were never affected. A challenge-
        // first client's creds-less CONNECT has no vid, so today it gets
        // blind-tunneled — the phantom is never substituted and reaches the
        // upstream literally (a clean 401, but the credential path silently never
        // engages). Answer it with a 407 so it re-sends authenticated. Scope the
        // challenge to a host some known vault anchors: unrelated traffic still
        // tunnels untouched, preserving "only routed traffic is touched".
        if req.method() == Method::CONNECT {
            let (vid, _) = creds_from_proxy_auth(&req);
            if vid.is_none() {
                if let Some(h) = req.uri().host() {
                    if self.state.host_in_any_known_union(h) {
                        return proxy_auth_challenge().into();
                    }
                }
            }
            return req.into();
        }

        // API face (CREDENTIAL_BROKER.md §14): an origin-form request (or an absolute-form
        // one looped back at our own authority) is discovery / op-poll / health /
        // ca — self-answered read-only here, never forwarded upstream. This is the
        // agent's ONE port: the same listener serves the proxy face (below) and
        // this read API.
        if crate::proxy::api_face::is_api_face(&req, self.state.config.proxy_port) {
            return crate::proxy::api_face::respond(&self.state, &req)
                .await
                .into();
        }

        self.pipeline(ctx.client_addr.ip(), req).await
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        if let Some(p) = self.pending.take() {
            write_forward_audit(&self.state, &p, res.status().as_u16(), None, None);
        }
        res
    }

    /// A forward-hop to the upstream failed (couldn't connect, egress proxy
    /// refused/dropped the CONNECT, TLS to the origin failed, …). hudsucker's
    /// DEFAULT for this is an EMPTY `502` — which is the worst possible signal
    /// for the audience here: an AI agent making a brokered call gets a blank
    /// body and can't tell a NETWORK/PROXY problem from a dead credential or a
    /// provider outage, so it typically misreports "the token is broken." The
    /// precise cause our `TunnelConnector` already computed (host:port + whether
    /// it was a direct dial or a proxy CONNECT) otherwise reaches only the daemon
    /// log. Surface it on the wire instead, tagged `egress_unreachable`, and — for
    /// a reachability failure — say how to point us at a proxy.
    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        egress_error_response(err)
    }
}

impl BrokerHandler {
    /// Stable attribution id for the current agent — used for audit rows, the
    /// mask lookup, and the grant cache key: the resolved, admitted `ag_` (the
    /// only agent credential since §15 W3). One helper so all surfaces agree.
    fn agent_attribution(&self) -> Option<String> {
        self.agent_id.clone()
    }

    async fn pipeline(&mut self, ip: IpAddr, req: Request<Body>) -> RequestOrResponse {
        let is_https = req.uri().scheme_str() == Some("https");
        let dest_host = match req.uri().host() {
            Some(h) => h.to_ascii_lowercase(),
            None => return req.into(), // origin-form / no authority: not ours
        };

        let (mut parts, body) = req.into_parts();
        // `orig_body` is the un-scanned streaming body; `body_bytes` is the
        // buffered copy when we scan. Exactly one is live past the scan below,
        // so both consumers `take()` from the Option.
        let mut orig_body = Some(body);
        // The method is normalized ONCE, here: policy, the reuse classes, the
        // grant keys and the upstream all see the same uppercase method, so a
        // rule written for `DELETE` also decides a `delete`.
        parts.method = normalize_method(&parts.method);
        let method = parts.method.as_str().to_string();
        // The path is normalized ONCE, here, as Envoy does for path-based
        // access control (core/path.rs): everything below decides on this form
        // and a brokered request is forwarded in it, so the upstream runs the
        // path that was checked. One it can't normalize is refused below if the
        // request is brokered.
        let raw_path = parts.uri.path().to_string();
        let norm_path = crate::core::path::normalize(&raw_path);
        let path = norm_path.clone().unwrap_or_else(|_| raw_path.clone());
        let pq = match parts.uri.query() {
            Some(q) => format!("{path}?{q}"),
            None => path.clone(),
        };

        // ── gather phantom-bearing scan sites ────────────────────────────────
        let mut phantoms: Vec<Phantom> = Vec::new();
        merge_phantoms(&mut phantoms, resolver::collect_phantoms(&pq));
        for value in parts.headers.values() {
            if let Ok(s) = value.to_str() {
                merge_phantoms(&mut phantoms, resolver::collect_phantoms(s));
            }
        }
        // Authorization: Basic <b64> — decode before matching.
        let basic = basic_auth_decoded(&parts.headers);
        if let Some(decoded) = &basic {
            merge_phantoms(&mut phantoms, resolver::collect_phantoms(decoded));
        }

        // A phantom from before 2.0 (`__sc__…__`) is no phantom any more: left (rename:keep)
        // alone it would leave unauthenticated and come back as a bare 401.
        // Refuse it and name its replacement. Scanned on the original URL,
        // headers and decoded Basic auth, outside every 2.0 phantom (2.0.x
        // only; delete in 2.1).
        let old = std::iter::once(pq.as_str())
            .chain(parts.headers.values().filter_map(|v| v.to_str().ok()))
            .chain(basic.as_deref())
            .find_map(resolver::old_phantom);
        if let Some((old, new)) = old {
            return err_response(
                ScCode::PhantomRenamed,
                &format!("{old} is the phantom name from before Sprott 2.0; use {new}"),
            )
            .into();
        }

        // ── unified body boundary (P1) ───────────────────────────────────────
        // Policy judgment and phantom resolution consume ONE buffered view of
        // the body, produced right here — never two boundaries. A request that
        // names a phantom in its URL/headers is brokered, so its body MUST fit
        // the cap for policy to see it: over-cap is a hard, explained refusal
        // (413) — never a policy-blind forward with a live credential, and
        // never an approval prompt over content the user can't read (P2).
        // Content-Type takes no part in this decision (it's caller-controlled);
        // for phantom-less requests it stays a cheap heuristic for whether a
        // body-only phantom is worth looking for — an unscanned body-only
        // phantom just reaches upstream literally (a clean 401, the documented
        // semantic).
        let cap = self.state.config.body_cap;
        let header_phantoms = !phantoms.is_empty();
        if header_phantoms {
            // A declared over-cap length is refused before reading a byte.
            if let Some(n) = content_length(&parts.headers) {
                if n > cap {
                    return body_over_cap(n, cap).into();
                }
            }
        }
        // Buffer the body ONLY for a brokered (phantom-bearing) request, whose
        // policy may match `[requests]` shapes against body fields. A body is
        // never an injection site (service/mod.rs: header/query/URL/Basic), so a
        // phantom-less request is no longer buffered to hunt for a body-only
        // phantom — that path is gone.
        let scan_body = header_phantoms;

        let mut body_bytes: Option<Vec<u8>> = None;
        if scan_body {
            let body = orig_body.take().expect("body present before scan");
            match buffer_body(body, cap).await {
                Ok(bytes) => body_bytes = Some(bytes),
                Err(refusal) => return refusal.into(),
            }
        }
        // A compressed body (RFC 9110 content codings) is decoded in memory so
        // policy reads what the server will. It goes upstream decoded only when
        // a `[requests]` shape decided on it (below); otherwise the bytes go
        // untouched, so a body stored compressed (an upload) stays as sent.
        let decoded = body_bytes
            .as_deref()
            .and_then(|b| decode_content(&parts.headers, b, cap));
        let readable: Option<&[u8]> = match &decoded {
            Some(Ok(d)) => Some(d),
            _ => body_bytes.as_deref(),
        };

        // No phantom anywhere → forward untouched (rebuild body if we buffered).
        if phantoms.is_empty() {
            // We only reach here for an intercepted request — the host is anchored
            // by some unlocked connection — that named no phantom. Most often the
            // caller simply forgot it; left untouched the request goes upstream
            // unauthenticated and the puzzling result is a bare 401/403 with no
            // hint that the credential was never in the request. Leave a greppable
            // breadcrumb (`sc log --raw | grep phantom`) for exactly that debug.
            tracing::debug!(
                host = %dest_host,
                "routed to an anchored host but the request carries no phantom — \
                 forwarded unauthenticated; include the connection's phantom \
                 (e.g. __sprott__<conn>__) if brokering was intended"
            );
            let body = body_bytes
                .map(Body::from)
                .unwrap_or_else(|| orig_body.take().unwrap_or_else(Body::empty));
            return Request::from_parts(parts, body).into();
        }

        // A phantom over plain HTTP can't be TLS-substituted — refuse.
        if !is_https {
            return err_response(
                ScCode::PhantomPlainHttp,
                "a phantom requires HTTPS (the proxy only substitutes inside TLS)",
            )
            .into();
        }

        // A brokered request goes upstream on the normalized path it is
        // decided on; one whose path can't be normalized is refused.
        if let Err(e) = norm_path {
            return err_response(ScCode::RequestUnreadable, &e.to_string()).into();
        }
        if path != raw_path {
            let authority = parts
                .uri
                .authority()
                .map(|a| a.as_str().to_string())
                .unwrap_or_else(|| dest_host.clone());
            match format!("https://{}{}", authority, pq).parse::<Uri>() {
                Ok(u) => parts.uri = u,
                Err(_) => {
                    return err_response(ScCode::RequestUnreadable, "the request path is malformed")
                        .into()
                }
            }
        }

        // ── one connection per request ───────────────────────────────────────
        let mut conns: Vec<&str> = phantoms.iter().map(|p| p.conn.as_str()).collect();
        conns.sort_unstable();
        conns.dedup();
        if conns.len() != 1 {
            return err_response(
                ScCode::MultiConnection,
                &format!(
                    "one connection per request: this request names {}",
                    conns.join(", ")
                ),
            )
            .into();
        }
        let conn = conns[0].to_string();

        // ── admit the agent, then bind the vault (§8, §15 W3) ────────────────
        // A phantom-bearing request is brokered only for an agent that proved
        // its AIK (resolved in `should_intercept`), whose `ag_` the account
        // ledger admits (no later revoke), on a vault whose authorized-agents
        // table lists it, and only while this device itself serves. Localhost
        // is not a trust boundary; an api key alone is no agent credential.
        // The vault's snapshot is taken in the same state-lock section as the
        // lock check and the table is read from it: every later read of vault
        // content in this request comes from this one snapshot.
        let snapshot = {
            use crate::principal_ledger::AgentRefusal;
            match crate::principal_ledger::authorize_agent(
                &self.state,
                self.agent_id.as_deref(),
                self.vid.as_deref(),
            )
            .await
            {
                Ok((_, snapshot)) => snapshot,
                Err(AgentRefusal::Device(e)) => {
                    let (code, msg) = e.code();
                    return err_response(code, &msg).into();
                }
                Err(AgentRefusal::Gone(error)) => {
                    let (code, message) = error.code();
                    return err_response(code, &message).into();
                }
                Err(AgentRefusal::NoIdentity) => {
                    return err_response(
                        ScCode::AgentKey,
                        crate::principal_ledger::NO_AGENT_IDENTITY_MSG,
                    )
                    .into();
                }
                Err(AgentRefusal::NotAdmitted) => {
                    return err_response(
                        ScCode::AgentNotAdmitted,
                        crate::error::AGENT_NOT_ADMITTED_MSG,
                    )
                    .into();
                }
                Err(AgentRefusal::Locked) => {
                    return err_response(ScCode::VaultLocked, crate::error::VAULT_LOCKED_MSG)
                        .into();
                }
                Err(AgentRefusal::NotAuthorized) => {
                    // Deep-link straight to THIS vault's Agent access page so the
                    // agent can relay a one-click fix (path matches the console's
                    // /vault/{id}/{tab} routing).
                    let hint = format!(
                        "this agent is not turned on for this vault. Turn it on in the vault's \
                         Agent access page, then retry: {}/vault/{}/agents",
                        crate::passkey::webauthn::console_link_origin(&self.state.config.origin),
                        self.vid.as_deref().unwrap_or_default(),
                    );
                    return err_response(ScCode::AgentNotAuthorized, &hint).into();
                }
            }
        };
        // Unreachable in practice: `should_intercept` requires a vid to MITM,
        // and a phantom over plain HTTP is refused above. Fail closed rather
        // than guess a vault.
        let (Some(vault_id), Some(snapshot)) = (self.vid.clone(), snapshot) else {
            return err_response(
                ScCode::NoVault,
                "no vault bound. Route credential traffic with `sprott run`",
            )
            .into();
        };
        let state = self.state.clone();
        if let Some(error) = state.vault_gone_error(&vault_id) {
            let (code, message) = error.code();
            return err_response(code, &message).into();
        }
        // Daemon too old for this vault's format (cloud returned SC_UPGRADE_REQUIRED
        // for its sync, design 甲) → fail LOUDLY so the agent runs `sc upgrade`,
        // instead of a silent parked-sync mystery the agent works around or calls a bug.
        if state.is_vault_upgrade_required(&vault_id) {
            return err_response(
                ScCode::UpgradeRequired,
                "Sprott needs an update to use this vault. Run `sprott upgrade`",
            )
            .into();
        }

        // ── reach mask (team §8.1) ───────────────────────────────────────────
        // Visible-but-locked semantics: a masked-off connection is announced as
        // `locked` in the registry, and a named use gets THIS explicit,
        // actionable refusal — never a silent 404, never a policy prompt.
        {
            // Mask lookup key = the agent's attribution id (the resolved `ag_`;
            // table and mask are ag_-keyed since §11).
            let mask_agent = self.agent_attribution().unwrap_or_default();
            let allowed = snapshot
                .agents
                .get(&mask_agent)
                .map(|e| e.connections.allows(&conn));
            if allowed == Some(false) {
                return err_response(
                    ScCode::MaskNotEnabled,
                    &format!(
                        "connection '{}' exists in this vault but is not enabled for this agent; \
                         the responsible member can enable it in the console (Agents)",
                        conn
                    ),
                )
                .into();
            }
        }

        // ── team serve gate (shared-vault offline lease, etc.) ───────────────
        // Serve-time team policy is team-EXCLUSIVE (team-edition §9) and lives in
        // the closed `sprott-ee` overlay behind this hook. The open build wires
        // `NoopHooks` → no gate, so a personal vault is never leased. The overlay
        // impl reads `vault_is_shared` + `cloud_contact_age_secs` (both kept as
        // neutral core bookkeeping) to enforce the offline lease.
        if let Some(denial) = state.team.serve_gate(state.as_ref(), &vault_id) {
            return err_response(denial.code, &denial.message).into();
        }

        // ── resolve the connection ───────────────────────────────────────────
        // An explicit aux.connections entry wins; otherwise, if <conn> names a
        // known service (compiled or custom) we synthesize its DEFAULT
        // connection (conn == service, hosts derived from the service) so a
        // default-connection phantom `__sprott__<service>__` resolves. Only a
        // genuinely unknown id fails closed.
        // A service installed from a source loads only while the vault's
        // owner allows installed services: a connection naming one while they
        // are off is refused by name, not as unknown.
        let installed_off = |s: &str| {
            snapshot.installed_service_off(s).then(|| {
                err_response(
                    ScCode::PolicyDenied,
                    &format!(
                        "'{}' is an installed service. {}",
                        s,
                        crate::service::INSTALLED_OFF_MSG
                    ),
                )
            })
        };
        let conn_rec = match snapshot.connections.get(&conn) {
            Some(rec) => rec.clone(),
            None => {
                if let Some(r) = installed_off(&conn) {
                    return r.into();
                }
                let known_service = state.services.get(&conn).is_some()
                    || snapshot.inputs.custom.contains_key(&conn);
                if known_service {
                    crate::storage::plaintext::Connection {
                        service: Some(conn.clone()),
                        ..Default::default()
                    }
                } else {
                    let (code, message) =
                        unknown_connection_refusal(state.is_vault_key_changed(&vault_id), &conn);
                    return err_response(code, &message).into();
                }
            }
        };
        // custom-FIRST precedence (the SSoT for this rule): a vault-authored
        // def (aux.services) shadows a same-id registry service, so shipping a
        // first-party service NEVER silently repoints a user's existing
        // connection (their `gcp` that is really github keeps working). The
        // registry def applies only where no custom def exists — a fresh,
        // opt-in connection, gated by the create-time duplicate-id check.
        let def = conn_rec
            .service
            .as_deref()
            .and_then(|s| snapshot.inputs.def(&state.services, s));
        if def.is_none() {
            if let Some(r) = conn_rec.service.as_deref().and_then(installed_off) {
                return r.into();
            }
        }
        // The service id policy and the mint use; for a raw connection there
        // is none, so the conn id stands in (a same-named built-in's recipe
        // and tags apply, else the global floor).
        let service_id = conn_rec.service.clone().unwrap_or_else(|| conn.clone());
        // The definition whose `[requests]` shapes read this request, from
        // the request's snapshot. `def` above stays the connection's own for
        // roles and minting.
        let shape_def = shape_definition(&snapshot.inputs, &state.services, def, &service_id);
        // Compute hosts from the record we hold — NOT a second lookup, which
        // would miss a synthesized default connection and wrongly empty the
        // anchor (→ spurious widen-deny). For the synthesized default this
        // derives the service's declared hosts.
        let resolved_hosts = crate::core::host::resolved_hosts(&conn_rec, def);
        // The `denied` audit row every refusal below writes: the request as
        // it came, with why (`code`).
        let refused = AuditPending {
            vault_id: vault_id.clone(),
            service: service_id.clone(),
            method: method.clone(),
            path: path.clone(),
            agent_prefix: self.agent_attribution(),
        };
        let deny = |code: ScCode, msg: &str| -> RequestOrResponse {
            write_forward_audit(&state, &refused, 0, None, Some(code));
            err_response(code, msg).into()
        };

        // ── 1. egress floor (private addresses) ──────────────────────────────
        // On every brokered request: the destination as the client's URL
        // parser reads it must be a canonical, public host (`core::egress`),
        // anchored or not.
        if !crate::core::egress::host_egress_allowed(&dest_host) {
            write_forward_audit(
                &state,
                &refused,
                0,
                Some(&dest_host),
                Some(ScCode::HostForbidden),
            );
            return err_response(
                ScCode::HostForbidden,
                &format!(
                    "destination '{}' is not a permitted egress target",
                    dest_host
                ),
            )
            .into();
        }

        // ── 2. phantom check (static) ────────────────────────────────────────
        // Every explicit role must exist on the connection, through the one
        // connection-to-KEY binding (`snapshot::bindings`); a mint input is
        // never injected. Nothing is read from a store yet.
        let Some(roles) = crate::snapshot::bindings(&conn_rec, def) else {
            let s = conn_rec.service.as_deref().unwrap_or_default();
            let why = snapshot
                .custom_skipped
                .get(s)
                .map(String::as_str)
                .unwrap_or("this device has no such service");
            return deny(
                ScCode::ServiceNotLoaded,
                &format!(
                    "connection '{}' uses service '{}', whose definition is not loaded: {}",
                    conn, s, why
                ),
            );
        };
        let mut wants: Vec<(String, crate::snapshot::Want)> = Vec::new();
        for ph in &phantoms {
            match crate::snapshot::check_phantom(ph.role.as_deref(), &roles) {
                Ok(want) => wants.push((ph.raw.clone(), want)),
                Err(crate::snapshot::PhantomRefusal::RefreshForbidden) => {
                    return deny(ScCode::RefreshForbidden, REFRESH_FORBIDDEN_MSG);
                }
                Err(crate::snapshot::PhantomRefusal::UnknownRole(role)) => {
                    let hint = phantom_role_hint(&conn, &conn_rec, def);
                    return deny(
                        ScCode::UnknownRole,
                        &format!(
                            "connection '{}' has no role '{}'. Its phantoms: {}",
                            conn, role, hint
                        ),
                    );
                }
            }
        }

        // ── 3. the request object + policy (request-model design §1) ────────
        // The request as its definition reads it: the `[requests]` shape whose
        // method, path and condition select it gives the body format and what
        // an approval binds (its scope and what its consent reads); every
        // rule's condition reads the same object. A value something reads
        // that can't be read refuses the request here, before any decision,
        // with the status a server would give it. Pure policy, from the
        // snapshot's inputs: no approval is consulted here (step 6 is).
        let agent_prefix = self.agent_attribution().unwrap_or_default();
        // `request.host`: with the port when it isn't https's default.
        let request_host = match parts.uri.port_u16() {
            Some(port) if port != 443 => format!("{dest_host}:{port}"),
            _ => dest_host.clone(),
        };
        // `request.headers`: the set the request is forwarded with.
        let request_headers = forwarded_headers(&parts.headers);
        // A body whose coding can't be undone can't be read: a condition that
        // reads it refuses the request (one a shape selects is refused below
        // whatever reads it).
        let body_error = match &decoded {
            Some(Err(e)) => Some(crate::core::request::Unreadable {
                status: e.code().status(),
                message: e.to_string(),
            }),
            _ => None,
        };
        type Decided = (
            Option<crate::service::RequestScope>,
            crate::core::policy::Decision,
        );
        let refuse = |u: crate::core::request::Unreadable| -> Response<Body> {
            let code = match u.status {
                422 => ScCode::RequestInvalid,
                415 => ScCode::ContentEncodingUnsupported,
                413 => ScCode::BrokerBodyLimit,
                _ => ScCode::RequestUnreadable,
            };
            write_forward_audit(&state, &refused, 0, None, Some(code));
            err_response(code, &u.message)
        };
        let decide = |p: &str| -> Result<Decided, Response<Body>> {
            // A body that isn't valid in its own coding is refused whatever
            // reads it: a decoder that stops early may run what this one can't
            // see, and no client sends one by mistake. One in a coding this
            // proxy can't undo is refused where a shape selects the request.
            if let Some(Err(e)) = &decoded {
                if !matches!(e, DecodeError::Unsupported(_))
                    || shape_def.is_some_and(|d| d.shape_selects(&method, p))
                {
                    write_forward_audit(&state, &refused, 0, None, Some(e.code()));
                    return Err(err_response(e.code(), &e.to_string()));
                }
            }
            let input = crate::core::request::RequestInput {
                method: &method,
                host: &request_host,
                path: p,
                query: parts.uri.query(),
                headers: &request_headers,
                body: readable,
                body_error: body_error.as_ref(),
            };
            let (req_scope, request) =
                crate::service::read_request(shape_def, input).map_err(&refuse)?;
            // The check that a user rule decided only on bound fields went
            // with `when` and `body`: step 3 covers what conditions read.
            let decision = state
                .evaluate_request_decision(&snapshot.inputs, &conn, &service_id, &request)
                .map_err(&refuse)?;
            Ok((req_scope, decision))
        };
        // An encoded slash has two readings, and servers differ on which they
        // take (core/path.rs): decide on both and keep the stricter. The permit
        // keys, the audit row and the upstream all use the path as normalized.
        let decided = match crate::core::path::slash_decoded(&path) {
            Err(e) => {
                write_forward_audit(&state, &refused, 0, None, Some(ScCode::RequestUnreadable));
                Err(err_response(ScCode::RequestUnreadable, &e.to_string()))
            }
            Ok(others) => decide(&path).and_then(|first| {
                // The stricter reading wins; on a tie, the one a shape read
                // (so the approval binds and shows what it can).
                others.iter().try_fold(first, |kept, alt| {
                    let next = decide(alt)?;
                    let (n, k) = (next.1 .0.restrictiveness(), kept.1 .0.restrictiveness());
                    Ok(if n > k || (n == k && kept.0.is_none() && next.0.is_some()) {
                        next
                    } else {
                        kept
                    })
                })
            }),
        };
        let (req_scope, (level, decided_by, ttl)) = match decided {
            Ok(d) => d,
            Err(refusal) => return refusal.into(),
        };
        let scope_digest = req_scope.as_ref().map(|r| r.digest()).unwrap_or_default();

        use crate::core::policy::AccessLevel;
        // Deny refuses before any value is located, let alone read.
        if level == AccessLevel::Deny {
            return deny(ScCode::PolicyDenied, "this request is blocked by policy");
        }

        // ── 4. values: present and located, none opened ─────────────────────
        // Each KEY is walked through the store order once per snapshot (the
        // walk memo says where it was found); a role-less phantom takes the
        // sole present candidate. This establishes presence and location
        // only: no sealed value is opened, so an agent's retries while an
        // approval is pending touch no secret. Missing → a 4xx, never an op.
        let mut keys: BTreeMap<String, crate::snapshot::Location> = BTreeMap::new();
        let mut injects: Vec<(String, Inject)> = Vec::new();
        for (raw, want) in &wants {
            use crate::snapshot::Want;
            let located = match want {
                Want::Role(b) => locate_one(&snapshot, &state, &vault_id, &b.key)
                    .await
                    .map(|at| (b.key.clone(), at, false)),
                Want::Access(b) => locate_one(&snapshot, &state, &vault_id, &b.key)
                    .await
                    .map(|at| (b.key.clone(), at, true)),
                Want::RoleLess => locate_role_less(&snapshot, &state, &vault_id, &roles)
                    .await
                    .map(|(key, at)| (key, at, false)),
            };
            let (key, at, minted) = match located {
                Ok(l) => l,
                Err(Unlocated::NotSet(missing)) => {
                    let (code, msg) = not_set_refusal(
                        &conn,
                        &missing,
                        state.is_vault_key_changed(&vault_id),
                    );
                    return deny(code, &msg);
                }
                Err(Unlocated::Ambiguous) => {
                    let roles = phantom_role_hint(&conn, &conn_rec, def);
                    return deny(
                        ScCode::AmbiguousPhantom,
                        &format!(
                            "'{}' exposes several secrets. Use a role phantom: {}",
                            conn, roles
                        ),
                    );
                }
                Err(Unlocated::Store(store_id)) => {
                    // P2: a configured store's outage is an explicit refusal,
                    // never a portal that would misread it as "needs approval".
                    return deny(ScCode::StoreUnavailable, &store_unavailable_msg(&store_id));
                }
                Err(Unlocated::Vault(e)) => {
                    let (code, msg) = e.code();
                    return deny(code, &msg);
                }
            };
            keys.entry(key.clone()).or_insert(at);
            injects.push((
                raw.clone(),
                if minted {
                    Inject::Minted(key)
                } else {
                    Inject::Value(key)
                },
            ));
        }

        // ── 5. host anchor (exact FQDN) ──────────────────────────────────────
        // An unanchored host mints the widen-host op, only for a request that
        // passed 1-4. While this device's copy of the vault is behind the
        // store (an install was refused, so an approved widen may be stored
        // but not served) it says so instead of minting another.
        if !crate::core::host::host_allowed(&dest_host, &resolved_hosts) {
            let behind = state.is_vault_behind(&vault_id);
            // Refused whether or not the widen request below registers.
            write_forward_audit(
                &state,
                &refused,
                0,
                Some(&dest_host),
                Some(if behind {
                    ScCode::VaultKeyChanged
                } else {
                    ScCode::HostNotAnchored
                }),
            );
            if behind {
                return err_response(
                    ScCode::VaultKeyChanged,
                    &format!(
                        "connection '{}' is not anchored to '{}' on this device, whose copy of \
                         the vault is behind (a change could not be applied here). Run \
                         `sprott unlock`, then retry",
                        conn, dest_host
                    ),
                )
                .into();
            }
            let hold = snapshot.inputs.approval_hold();
            return self.widen_deny(&vault_id, &conn, &dest_host, hold, ip).await;
        }

        // ── 6. permit ────────────────────────────────────────────────────────
        // A request policy allows carries no permit. Anything else needs a
        // live permit of its decided tier under its key: the request line (or
        // the unit) and the credentials it resolved. None → mint an op and
        // open the portal.
        let credentials = crate::state::CredentialSet::new(&service_id, keys.keys().cloned());
        let portal = Portal {
            conn: conn.clone(),
            service_id: service_id.clone(),
            host: dest_host.clone(),
            method: method.clone(),
            path: path.clone(),
            level,
            decided_by: decided_by.clone(),
            ttl,
            credentials: credentials.clone(),
            fingerprint: snapshot.fingerprint,
            hold: snapshot.inputs.approval_hold(),
        };
        let permit = match level {
            AccessLevel::Allow => None,
            _ => match crate::state::PermitKey::of(
                level,
                &decided_by,
                req_scope.is_some(),
                &agent_prefix,
                &conn,
                &method,
                &dest_host,
                &path,
                &scope_digest,
                credentials,
            ) {
                Some(key) => Some(key),
                None => {
                    return self
                        .captive_portal(&vault_id, &portal, req_scope.as_ref(), ip)
                        .await;
                }
            },
        };
        let auth = match state.authorize(&vault_id, snapshot.clone(), keys, permit) {
            Ok(auth) => auth,
            Err(crate::state::Unauthorized::NoPermit) => {
                return self
                    .captive_portal(&vault_id, &portal, req_scope.as_ref(), ip)
                    .await;
            }
            Err(crate::state::Unauthorized::Refused(e)) => {
                let (code, msg) = e.code();
                return err_response(code, &msg).into();
            }
        };

        // ── 7. values, only now ──────────────────────────────────────────────
        let values = match state.materialize(&vault_id, &auth) {
            Ok(values) => values,
            Err(crate::state::Unreadable::NotHeld(key)) => {
                let (code, msg) = not_set_refusal(&conn, &[key], false);
                return deny(code, &msg);
            }
            Err(crate::state::Unreadable::Refused(e)) => {
                let (code, msg) = e.code();
                return err_response(code, &msg).into();
            }
        };
        let mut substitutes = PhantomValues::default();
        for (raw, inject) in &injects {
            let bytes = match inject {
                Inject::Value(key) => values.get(key).map(<[u8]>::to_vec),
                Inject::Minted(key) => {
                    // The ACCESS phantom of a minted mechanism: minted from the
                    // stored input (oauth refresh token / snaplii api key) with
                    // the snapshot's definition, after following any rotation
                    // made since; cached in `oauth_access` for every tier.
                    let (Some(input), Some(auth_def)) =
                        (values.get(key), def.and_then(|d| d.auth.as_ref()))
                    else {
                        return err_response(
                            ScCode::OauthMint,
                            "this connection's mint input could not be read",
                        )
                        .into();
                    };
                    match crate::server::broker_flow::resolve_auth_value(
                        &state, &vault_id, &conn, &service_id, auth_def, input,
                    )
                    .await
                    {
                        Ok(token) => Some(token),
                        Err(crate::error::AppError::Unauthorized(m)) => {
                            return err_response(ScCode::OauthMint, &m).into();
                        }
                        Err(other) => {
                            return err_response(ScCode::OauthMint, &format!("{:?}", other)).into();
                        }
                    }
                }
            };
            let Some(text) = bytes.and_then(|b| String::from_utf8(b).ok()) else {
                return err_response(
                    ScCode::SecretEncoding,
                    "resolved credential is not valid UTF-8",
                )
                .into();
            };
            substitutes.insert(raw.clone(), text);
        }
        drop(values);

        // ── substitute everywhere + strip shadowing auth ─────────────────────
        let mut parts = parts;
        // URL: rebuild the absolute URI with the substituted path+query. The
        // authority (host[:port]) is preserved from the MITM'd request.
        let (new_pq, _) = resolver::substitute(&pq, |ph| substitutes.get(&ph.raw));
        if new_pq != pq {
            let authority = parts
                .uri
                .authority()
                .map(|a| a.as_str().to_string())
                .unwrap_or_else(|| dest_host.clone());
            if let Ok(u) = format!("https://{}{}", authority, new_pq).parse::<Uri>() {
                parts.uri = u;
            }
        }

        // Headers: substitute values, decode/re-encode Basic, strip proxy/agent
        // auth, drop hop-by-hop. The body is never rewritten (not an injection
        // site), so its content-length stays what was set when it was read.
        let new_headers = rewrite_headers(&parts.headers, &substitutes, false);
        parts.headers = new_headers;
        drop(substitutes);
        // A body a shape decided on goes upstream as it was read: decoded.
        let forward_decoded = match decoded {
            Some(Ok(d)) if req_scope.is_some() => {
                parts.headers.remove(header::CONTENT_ENCODING);
                parts.headers.insert(header::CONTENT_LENGTH, d.len().into());
                Some(d)
            }
            _ => None,
        };

        // Egress guard — never emit an unresolved phantom in a credential
        // position. `substitute` leaves a phantom it can't fill verbatim, so
        // re-scan the wire-bound URL + headers (incl. decoded Basic). A survivor
        // means a header/URL phantom the resolver declined; block it rather than
        // let the literal `__sprott__…__` reach upstream (which returns a bare 401 the
        // agent misreads as a dead credential). The body is intentionally NOT
        // scanned: a phantom there is inert placeholder text, never a secret.
        let leaked_phantom = {
            let pq_now = parts.uri.path_and_query().map(|x| x.as_str()).unwrap_or("");
            resolver::contains_phantom(pq_now)
                || parts
                    .headers
                    .values()
                    .any(|v| v.to_str().map(resolver::contains_phantom).unwrap_or(false))
                || basic_auth_decoded(&parts.headers)
                    .as_deref()
                    .map(resolver::contains_phantom)
                    .unwrap_or(false)
        };
        if leaked_phantom {
            return err_response(
                ScCode::PhantomUnresolved,
                "a Sprott phantom in this request could not be resolved, so the request was \
                 blocked before the placeholder could reach upstream. Check the connection/role \
                 name (`sprott registry`), or run `sprott unlock` if the vault is locked",
            )
            .into();
        }

        // ── 8. consume ───────────────────────────────────────────────────────
        // Every request, allow included: the vault must still be Unlocked,
        // and a single-use permit is spent now (failures before this keep it;
        // nothing after restores it). One another request spent first sends
        // this one to the portal.
        match state.consume(&vault_id, auth) {
            Ok(true) => {}
            Ok(false) => {
                return self
                    .captive_portal(&vault_id, &portal, req_scope.as_ref(), ip)
                    .await;
            }
            Err(e) => {
                let (code, msg) = e.code();
                return err_response(code, &msg).into();
            }
        }
        // The snapshot is not held while the request is forwarded.
        drop(snapshot);

        // ── 9. forward ───────────────────────────────────────────────────────
        // Body: forwarded byte-for-byte, or decoded when a shape decided on it
        // (never an injection site). A phantom in the body passes through as
        // inert placeholder text — never substituted
        // (so a real secret can't be written into a persisted/readable field) and
        // never blocked (so discussing the schema in a body stays untouched).
        let out_body = match (forward_decoded, body_bytes) {
            (Some(d), _) => Body::from(d),
            (None, Some(bytes)) => Body::from(bytes),
            (None, None) => orig_body.take().unwrap_or_else(Body::empty),
        };

        self.pending = Some(AuditPending {
            vault_id,
            service: service_id,
            method,
            path,
            agent_prefix: self.agent_attribution(),
        });
        Request::from_parts(parts, out_body).into()
    }
    /// Build + register the captive-portal (ask) op and return the 401 that
    /// surfaces the approve link through a dumb tool's error output.
    #[allow(clippy::too_many_arguments)]
    async fn captive_portal(
        &self,
        vault_id: &str,
        p: &Portal,
        req_scope: Option<&crate::service::RequestScope>,
        ip: IpAddr,
    ) -> RequestOrResponse {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let Portal {
            conn,
            service_id,
            host,
            method,
            path,
            level,
            decided_by,
            ttl,
            credentials,
            fingerprint,
            hold,
        } = p;
        let (level, decided_by) = (*level, decided_by.clone());
        let now = now_secs();
        // Two DIFFERENT windows, deliberately independent:
        //   - grant_ttl: how long the approved `ask`-once grant stays cached so
        //     later matching requests fast-path (rule/floor `ttl`, else 15 min).
        //   - hold_secs: how long THIS pending op waits for the passkey before it
        //     expires (aux.policy.timeout, else 5 min). A long grant window must
        //     not stretch the approval deadline.
        let grant_ttl = ttl.unwrap_or(DEFAULT_ASK_TTL);
        let hold_secs = *hold;

        // The op names the credentials an approval of it permits: the KEYs
        // the request resolved, the same set its permit is keyed by.
        let target = credentials.target();

        let mut scope = json!({
            "connection_id": conn,
            "service": service_id,
            "host": host,
            "method": method,
            "path": path,
            "authorize_only": true,
        });
        // Op-agent binding (team §C1): the requesting agent's key prefix is
        // signed into β via the scope, so the human's approval covers "for
        // THIS agent" — swapping agents invalidates the grant. The grant page
        // can render it as the requester line. Enforcement reads the record's
        // copy (ApprovalRecord.agent_prefix), not this.
        if let Some(prefix) = self.agent_attribution() {
            scope["agent"] = serde_json::Value::String(prefix);
        }
        // Same inputs the lookup and apply use: what decided the request, and
        // whether the path is scoped (a `[requests]` shape matched).
        stamp_signed_level(
            &mut scope,
            level,
            &decided_by,
            req_scope.is_some(),
            method,
            grant_ttl,
        );
        // A window (`exact`, `rule`, `floor`) carries the policy fingerprint
        // it was decided under: approve stores no window when the policy
        // changed since.
        let window = crate::approval::Reuse::of(level, &decided_by, req_scope.is_some(), method)
            .and_then(|r| r.window(grant_ttl))
            .is_some();
        // The bound `[requests]` values and the consent template are what the
        // approver reads: they ride sealed to the vault's current content key
        // (`scope.card`, design §5), never in the clear. The daemon keeps the
        // plaintext in the PolicyContext: its values key the permit an
        // approval stores, and its MAC is what the approver's signature must
        // cover.
        let mut card = None;
        if let Some(rs) = req_scope {
            // Mark this a scoped path (a `[requests]` shape matched), so approve
            // never records a value-blind coarse-window key for it — even when
            // NO field values resolved (an empty-body ask). Without this, one
            // approved blank ask would open a window any later value could ride.
            scope["scoped"] = serde_json::Value::Bool(true);
            let plain = crate::approval::card::Card {
                vars: rs.bound.clone(),
                consent: rs.consent.clone(),
            };
            if !plain.is_empty() {
                match seal_card(&self.state, vault_id, plain) {
                    Ok(sealed) => {
                        scope["card"] = sealed.scope_value();
                        card = Some(sealed);
                    }
                    Err(refusal) => return refusal.into(),
                }
            }
        }
        let op = Operation {
            act: Act {
                kind: ActType::Use,
                target,
                scope,
            },
            bind: Bind {
                redeemer: vault_id.to_string(),
                recipient: None,
            },
            valid: Valid::single_use(now, Some(now + hold_secs)),
        };
        let pc = crate::approval::PolicyContext {
            level,
            decided_by,
            ttl_seconds: grant_ttl,
            host: Some(host.to_string()),
            credentials: Some(credentials.clone()),
            policy_fp: window.then_some(*fingerprint),
            card,
        };

        match crate::server::broker_flow::register_pending_use(
            &self.state,
            vault_id,
            op,
            Some(pc),
            ip,
            self.agent_attribution(),
        ) {
            Ok((op_id, _r, expires_at)) => {
                let approve_url = crate::cli::active::grant_url(&op_id);
                // §9: absolute poll_url. This 401 is emitted mid-proxy (e.g. while
                // brokering a gmail request), so a relative `/op/<id>` would
                // resolve against the UPSTREAM's domain. Loopback is the only
                // address the daemon can assert about itself — correct for the
                // supported local deployment. (A remote-exposed proxy — future,
                // gated — would need an advertised-origin config atom; until
                // then a remote agent just re-runs the command instead of
                // polling, the skill's primary path.)
                let poll_url = format!(
                    "http://127.0.0.1:{}/op/{}",
                    self.state.config.proxy_port, op_id
                );
                let body = format!(
                    "Sprott approval needed to use this credential.\n\
                     Approve with your passkey:\n  {}\n\
                     {}Then re-run the same command.\n\n\
                     {}\n",
                    approve_url,
                    wait_hint(&approve_url, &op_id),
                    json!({
                        "status": "pending",
                        "op_id": op_id,
                        "approve_url": approve_url,
                        "poll_url": poll_url,
                        "expires_at": expires_at,
                    })
                );
                let mut b = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header("x-sprott-error", ScCode::ApprovalNeeded.as_str())
                    .header("x-sprott-approve-url", approve_url.as_str())
                    .header("x-sprott-op-id", op_id.as_str())
                    .header(header::LOCATION, format!("/op/{}", op_id));
                let interval = crate::approval::store::POLL_INTERVAL_HINT_SECS;
                b = b.header(header::RETRY_AFTER, interval.to_string());
                b.body(Body::from(body))
                    .unwrap_or_else(|_| plain(StatusCode::UNAUTHORIZED, "approval required"))
                    .into()
            }
            Err(e) => err_response(
                ScCode::ApprovalRegister,
                &format!("could not register approval: {:?}", e),
            )
            .into(),
        }
    }

    /// Host-anchor miss to a public host → DENY + a one-tap widen op (component
    /// C). The 403 body carries the approve link labeled as a permanent grant.
    async fn widen_deny(
        &self,
        vault_id: &str,
        conn: &str,
        host: &str,
        hold: u64,
        ip: IpAddr,
    ) -> RequestOrResponse {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let now = now_secs();
        let mut scope = json!({
            "connection_id": conn,
            "host": host,
            "etld1": etld1(host),
        });
        // Same signed agent stamp as the credential-use op above.
        if let Some(prefix) = self.agent_attribution() {
            scope["agent"] = serde_json::Value::String(prefix);
        }
        let op = Operation {
            act: Act {
                kind: ActType::Custom("widen-host".into()),
                target: String::new(),
                scope,
            },
            bind: Bind {
                redeemer: vault_id.to_string(),
                recipient: None,
            },
            // Portal pendings inherit the SAME approval window as every
            // other pending op (aux.policy.timeout; SSOT) — was a fixed 15 min.
            valid: Valid::single_use(now, Some(now + hold)),
        };
        let approve_line = match crate::server::broker_flow::register_pending_use(
            &self.state,
            vault_id,
            op,
            None,
            ip,
            self.agent_attribution(),
        ) {
            Ok((op_id, _r, exp)) => {
                let approve_url = crate::cli::active::grant_url(&op_id);
                // Same machine-readable tail as the credential-use 401 above —
                // the waiter contract is op-generic, so the widen op gets it too.
                let poll_url = format!(
                    "http://127.0.0.1:{}/op/{}",
                    self.state.config.proxy_port, op_id
                );
                let body = format!(
                    "Sprott: connection '{}' is not anchored to '{}'.\n\
                     Approve adding this host as a PERMANENT grant (passkey):\n  {}\n\
                     {}Then re-run the same command.\n\n\
                     {}\n",
                    conn,
                    host,
                    approve_url,
                    wait_hint(&approve_url, &op_id),
                    json!({
                        "status": "pending",
                        "op_id": op_id,
                        "approve_url": approve_url,
                        "poll_url": poll_url,
                        "expires_at": exp,
                    })
                );
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header("x-sprott-approve-url", approve_url.as_str())
                    .header("x-sprott-op-id", op_id.as_str())
                    .header("x-sprott-error", ScCode::HostNotAnchored.as_str())
                    .body(Body::from(body))
                    .unwrap_or_else(|_| plain(StatusCode::FORBIDDEN, "host not anchored"))
                    .into();
            }
            Err(e) => format!("(could not open a widen request: {:?})", e),
        };
        err_response(
            ScCode::HostNotAnchored,
            &format!(
                "connection '{}' is not anchored to '{}' {}",
                conn, host, approve_line
            ),
        )
        .into()
    }
}

fn unknown_connection_refusal(key_changed: bool, conn: &str) -> (ScCode, String) {
    if key_changed {
        (
            ScCode::VaultKeyChanged,
            crate::error::VAULT_KEY_CHANGED_MSG.to_string(),
        )
    } else {
        (
            ScCode::UnknownConnection,
            format!("unknown connection '{}'", conn),
        )
    }
}

/// Stamp what approving a Use op grants into its (signed) scope, so what the
/// approver reads is what apply does (design/approvals-inbox.md D1): `level`,
/// then the reuse fields and `window_s` from [`crate::approval::Reuse`] (the
/// SAME classifier apply and the approve-time assertion use). `scoped` = the
/// path has a `[requests]` shape.
pub(crate) fn stamp_signed_level(
    scope: &mut serde_json::Value,
    level: crate::core::policy::AccessLevel,
    decided_by: &crate::core::policy::DecidedBy,
    scoped: bool,
    method: &str,
    grant_ttl: u64,
) {
    scope["level"] = serde_json::Value::String(level.to_string());
    if let Some(reuse) = crate::approval::Reuse::of(level, decided_by, scoped, method) {
        reuse.stamp(scope, grant_ttl);
    }
}

/// Seal an approval card to the vault's current-generation content key
/// (design §5). Refused with the unlock text when the vault is locked, or when
/// the key this session holds is not the current generation's (another member
/// re-keyed since this machine unlocked): a card sealed to an old key is one a
/// removed member could open.
fn seal_card(
    state: &crate::state::AppState,
    vault_id: &str,
    card: crate::approval::card::Card,
) -> std::result::Result<crate::approval::card::SealedCard, Response<Body>> {
    let locked = || err_response(ScCode::VaultLocked, crate::error::VAULT_LOCKED_MSG);
    let material = state.cloned_state_key(vault_id).ok_or_else(locked)?;
    let keys = crate::storage::item::VaultKeys::from_material(&material);
    let pv = state
        .vaults
        .per_item_path(vault_id)
        .ok()
        .and_then(|p| crate::storage::sealed_vault::read_per_item(&p).ok().flatten());
    let gen = match pv {
        Some(pv) => pv.seal_generation(keys).ok_or_else(locked)?,
        None => 0,
    };
    crate::approval::card::seal(card, keys.content, vault_id, gen)
        .map_err(|e| err_response(ScCode::ApprovalRegister, &e.to_string()))
}

/// The waiter line for pending-approval bodies — only when the approve link
/// is absolute (cloud-paired). An unpaired daemon has no reachable approval
/// surface, and a hinted wait there would just block until the op expires.
fn wait_hint(approve_url: &str, op_id: &str) -> String {
    if approve_url.starts_with("http") {
        format!("{}\n", crate::cli::human_action::wait_command(op_id))
    } else {
        String::new()
    }
}

/// What a captive-portal op is minted for: the request as policy decided it
/// (step 3) and the credentials it resolved (step 4).
struct Portal {
    conn: String,
    service_id: String,
    host: String,
    method: String,
    path: String,
    level: crate::core::policy::AccessLevel,
    decided_by: crate::core::policy::DecidedBy,
    ttl: Option<u64>,
    credentials: crate::state::CredentialSet,
    /// The policy fingerprint of the snapshot it was decided on.
    fingerprint: [u8; 32],
    /// How long the op waits for its approval, under that snapshot's policy.
    hold: u64,
}

/// What a phantom injects: a KEY's value, or the token minted from a minted
/// connection's input KEY.
enum Inject {
    Value(String),
    Minted(String),
}

/// The value each phantom (by its raw token) is replaced with: plaintext that
/// lives only for this request and is zeroized when dropped. Never printed.
#[derive(Default)]
struct PhantomValues(HashMap<String, zeroize::Zeroizing<String>>);

impl PhantomValues {
    fn insert(&mut self, raw: String, value: String) {
        self.0.insert(raw, zeroize::Zeroizing::new(value));
    }

    fn get(&self, raw: &str) -> Option<String> {
        self.0.get(raw).map(|v| v.as_str().to_string())
    }
}

impl std::fmt::Debug for PhantomValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.keys().map(|k| format!("{}: <redacted>", k)))
            .finish()
    }
}

/// Why step 4 refused a request.
enum Unlocated {
    /// Absent from every store: this KEY, or every candidate of a role-less
    /// phantom none of whose candidates is present.
    NotSet(Vec<String>),
    /// A role-less phantom with more than one candidate present.
    Ambiguous,
    /// A configured store ahead of the KEY failed, or can't be read here.
    Store(String),
    /// The vault locked or went away meanwhile.
    Vault(crate::error::AppError),
}

impl From<crate::snapshot::WalkError> for Unlocated {
    fn from(e: crate::snapshot::WalkError) -> Unlocated {
        match e {
            crate::snapshot::WalkError::StoreUnavailable(id) => Unlocated::Store(id),
            crate::snapshot::WalkError::Vault(e) => Unlocated::Vault(e),
        }
    }
}

/// Where an explicit role's KEY is. A recorded "absent" is not taken: the
/// KEY is walked again, so one added to an external store later is found.
async fn locate_one(
    snapshot: &crate::snapshot::Snapshot,
    state: &AppState,
    vault_id: &str,
    key: &str,
) -> Result<crate::snapshot::Location, Unlocated> {
    match snapshot.locate(state, vault_id, key, false).await? {
        Some(at) => Ok(at),
        None => Err(Unlocated::NotSet(vec![key.to_string()])),
    }
}

/// A role-less phantom on a static connection: its sole present candidate.
/// With several candidates, a recorded "absent" picks among them (no network
/// for a KEY a walk found nowhere) as long as one is present; with none
/// present, each is walked again. More than one present is ambiguous.
async fn locate_role_less(
    snapshot: &crate::snapshot::Snapshot,
    state: &AppState,
    vault_id: &str,
    roles: &[crate::snapshot::Bound],
) -> Result<(String, crate::snapshot::Location), Unlocated> {
    let candidates = crate::snapshot::role_less_candidates(roles);
    if let [only] = candidates.as_slice() {
        return locate_one(snapshot, state, vault_id, &only.key)
            .await
            .map(|at| (only.key.clone(), at));
    }
    // Pass 1 takes a recorded "absent" as is; with no candidate present,
    // pass 2 walks again only the ones pass 1 answered from that record (it
    // walked the others just now).
    let from_record: Vec<bool> = candidates
        .iter()
        .map(|c| snapshot.recorded_absent(&c.key))
        .collect();
    for pass in [1, 2] {
        let mut present = Vec::new();
        for (c, recorded) in candidates.iter().zip(&from_record) {
            if pass == 2 && !recorded {
                continue;
            }
            if let Some(at) = snapshot.locate(state, vault_id, &c.key, pass == 1).await? {
                if !present.is_empty() {
                    return Err(Unlocated::Ambiguous);
                }
                present.push((c.key.clone(), at));
            }
        }
        if let Some(found) = present.pop() {
            return Ok(found);
        }
    }
    Err(Unlocated::NotSet(
        candidates.iter().map(|c| c.key.clone()).collect(),
    ))
}

/// The refusal for KEYs absent from every store: `secret_not_set`. On a vault
/// whose key changed it is `vault_key_changed`, saying the KEY may sit in a
/// row this device can't read (a permanently unreadable row is one `sprott
/// unlock` does not fix).
fn not_set_refusal(conn: &str, keys: &[String], key_changed: bool) -> (ScCode, String) {
    let msg = match (keys, key_changed) {
        ([], _) => format!("connection '{}' binds no secret", conn),
        ([one], false) => format!("connection '{}': secret {} is not set in this vault", conn, one),
        (many, false) => format!(
            "connection '{}': none of its secrets ({}) is set in this vault",
            conn,
            many.join(", ")
        ),
        ([one], true) => format!(
            "connection '{}': secret {} is unset, or in a row this device can't read",
            conn, one
        ),
        (many, true) => format!(
            "connection '{}': secrets {} are unset, or in rows this device can't read",
            conn,
            many.join(", ")
        ),
    };
    let code = if key_changed && !keys.is_empty() {
        ScCode::VaultKeyChanged
    } else {
        ScCode::SecretNotSet
    };
    (code, msg)
}

fn store_unavailable_msg(store_id: &str) -> String {
    format!(
        "external store '{}' is unavailable, so a secret this request needs could not be read. \
         Check the store's credentials and permissions (daemon logs have the full error)",
        store_id
    )
}

const REFRESH_FORBIDDEN_MSG: &str = "a refresh token never leaves the vault. This connection \
     injects a minted access token; use its default phantom. To reveal the stored secret, run \
     `sprott secret get` (needs a passkey)";

// ── free helpers ─────────────────────────────────────────────────────────────

/// The request method in uppercase: the form every policy and grant surface
/// compares, and the one forwarded upstream.
pub(crate) fn normalize_method(m: &Method) -> Method {
    let s = m.as_str();
    if !s.bytes().any(|b| b.is_ascii_lowercase()) {
        return m.clone();
    }
    // Uppercasing keeps a valid token valid, so this cannot fail; fall back to
    // the original only to stay total.
    Method::from_bytes(s.to_ascii_uppercase().as_bytes()).unwrap_or_else(|_| m.clone())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Merge `more` into `acc`, de-duplicating on `raw` in O(1) per element and
/// capped at [`resolver::MAX_PHANTOMS_PER_SITE`]. Each scan site
/// (`collect_phantoms`) is already capped and O(N); this keeps the cross-site
/// union bounded too, so no attacker-chosen body can drive quadratic work here.
fn merge_phantoms(acc: &mut Vec<Phantom>, more: Vec<Phantom>) {
    let mut seen: std::collections::HashSet<String> = acc.iter().map(|p| p.raw.clone()).collect();
    for p in more {
        if acc.len() >= resolver::MAX_PHANTOMS_PER_SITE {
            break;
        }
        if seen.insert(p.raw.clone()) {
            acc.push(p);
        }
    }
}

/// Read `(vid, api-key)` from a CONNECT's `Proxy-Authorization: Basic
/// base64("<vid>:<key>")`. The vid (username) routes the request to a vault; the
/// key (password) is the agent's identity (§8). Each is `None` when
/// absent/empty. A `None` vid means no Proxy-Auth at all ⇒ non-participating
/// traffic (`should_intercept` blind-tunnels it). The key is NOT trimmed (it's
/// an opaque token hashed for the membership check); the vid is.
fn creds_from_proxy_auth(req: &Request<Body>) -> (Option<String>, Option<String>) {
    let Some(text) = req
        .headers()
        .get(header::PROXY_AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Basic ")
                .or_else(|| s.strip_prefix("basic "))
        })
        .and_then(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .ok()
        })
        .and_then(|d| String::from_utf8(d).ok())
    else {
        return (None, None);
    };
    let (vid, key) = match text.split_once(':') {
        Some((v, k)) => (v.trim(), k),
        None => (text.trim(), ""),
    };
    let vid = (!vid.is_empty()).then(|| vid.to_string());
    let key = (!key.is_empty()).then(|| key.to_string());
    (vid, key)
}

/// Decode `Authorization: Basic <b64>` to `user:pass`, if present.
fn basic_auth_decoded(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = v
        .strip_prefix("Basic ")
        .or_else(|| v.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The header names a request's `Connection` header lists (RFC 9110 §7.6.1):
/// hop-by-hop for this connection, so never forwarded.
fn connection_named(headers: &HeaderMap) -> std::collections::HashSet<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Whether an `Authorization` value is forwarded ([`rewrite_headers`]): only
/// one that carries a phantom (in Basic, inside the decoded pair); the
/// agent's own is stripped.
fn authorization_forwarded(value: &str) -> bool {
    match value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    {
        Some(b64) => base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
            .is_some_and(|text| resolver::contains_phantom(&text)),
        None => resolver::contains_phantom(value),
    }
}

/// The headers a brokered request is forwarded with, as `request.headers`
/// reads them: lowercase names, in order, phantoms intact; without the
/// hop-by-hop headers, those `Connection` names, `Proxy-Authorization`, and
/// an `Authorization` that carries no phantom ([`rewrite_headers`] drops the
/// same set).
fn forwarded_headers(headers: &HeaderMap) -> Vec<(String, Vec<u8>)> {
    let named = connection_named(headers);
    headers
        .iter()
        .filter_map(|(name, value)| {
            let lname = name.as_str().to_ascii_lowercase();
            if lname == "proxy-authorization"
                || crate::server::broker_flow::is_hop_by_hop(&lname)
                || named.contains(&lname)
            {
                return None;
            }
            if lname == "authorization" && !value.to_str().is_ok_and(authorization_forwarded) {
                return None;
            }
            Some((lname, value.as_bytes().to_vec()))
        })
        .collect()
}

/// Rebuild the header map: substitute phantom values, decode/re-encode Basic,
/// strip Proxy-Authorization + any agent Authorization the injected cred
/// replaces, drop hop-by-hop and the headers `Connection` names, and drop
/// content-length when the body was rewritten.
fn rewrite_headers(
    headers: &HeaderMap,
    values: &PhantomValues,
    body_rewritten: bool,
) -> HeaderMap {
    let mut out = HeaderMap::new();
    let named = connection_named(headers);
    for (name, value) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if lname == "proxy-authorization"
            || crate::server::broker_flow::is_hop_by_hop(&lname)
            || named.contains(&lname)
        {
            continue;
        }
        if body_rewritten && lname == "content-length" {
            continue;
        }
        let Ok(vs) = value.to_str() else {
            out.insert(name.clone(), value.clone());
            continue;
        };
        if lname == "authorization" {
            // Basic → decode, substitute, re-encode; else substitute raw. If no
            // phantom was in it, the agent's own auth is stripped (the injected
            // credential elsewhere is the real one; agents can't shadow it).
            if let Some(rest) = vs
                .strip_prefix("Basic ")
                .or_else(|| vs.strip_prefix("basic "))
            {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(rest.trim()) {
                    if let Ok(text) = String::from_utf8(decoded) {
                        let (new_text, any) =
                            resolver::substitute(&text, |ph| values.get(&ph.raw));
                        if any {
                            let enc = base64::engine::general_purpose::STANDARD
                                .encode(new_text.as_bytes());
                            if let Ok(hv) = header::HeaderValue::from_str(&format!("Basic {}", enc))
                            {
                                out.insert(header::AUTHORIZATION, hv);
                            }
                            continue;
                        }
                    }
                }
                // Basic with no phantom → strip.
                continue;
            }
            let (new_v, any) = resolver::substitute(vs, |ph| values.get(&ph.raw));
            if any {
                if let Ok(hv) = header::HeaderValue::from_str(&new_v) {
                    out.insert(header::AUTHORIZATION, hv);
                }
            }
            // No phantom in Authorization → strip (don't forward the agent's own).
            continue;
        }
        // Any other header: substitute in place (no-op if it has no phantom).
        // `append` preserves legitimately repeated headers (e.g. Cookie).
        let (new_v, _) = resolver::substitute(vs, |ph| values.get(&ph.raw));
        match header::HeaderValue::from_str(&new_v) {
            Ok(hv) => {
                out.append(name.clone(), hv);
            }
            Err(_) => {
                out.append(name.clone(), value.clone());
            }
        }
    }
    out
}

/// A human hint listing a connection's role phantoms (for the ambiguous case).
fn phantom_role_hint(
    conn: &str,
    rec: &crate::storage::plaintext::Connection,
    def: Option<&crate::service::ServiceDef>,
) -> String {
    let map = match def {
        Some(d) => crate::core::host::phantoms_for(conn, d),
        // Raw connection: the injectable keys are the record's explicit
        // `secrets` list — the same source `sc connection ls` prints. (This
        // used to fall back to the bare phantom, i.e. the exact form the
        // Ambiguous error had just rejected.)
        None => crate::core::host::phantoms_for_raw(conn, rec.secrets.as_deref().unwrap_or(&[])),
    };
    if map.is_empty() {
        crate::core::host::short_phantom(conn)
    } else {
        map.into_values().collect::<Vec<_>>().join(", ")
    }
}

/// Naive eTLD+1 (display only): the last two dot-labels of `host`.
fn etld1(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

fn plain(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .expect("static response builds")
}

/// The unified-boundary refusal (P1/P2): a phantom-bearing request whose body
/// exceeds the broker cap gets a 413 that says exactly what was over and how
/// to raise the knob — never a policy-blind forward with a live credential,
/// and never an approval prompt over content the user can't read.
/// `declared = 0` means the length was unknown (chunked) and the cap was hit
/// while buffering.
/// The definition whose `[requests]` shapes read a request: the one whose
/// rules decide it. Policy resolves built-in rules by `service_id`, which for
/// a raw connection is the connection id, so a raw connection named like a
/// service gets that service's rules; its shapes (and so the body format its
/// rules' conditions read) must come from the same place. Custom first, as
/// everywhere.
fn shape_definition<'a>(
    inputs: &'a crate::snapshot::PolicyInputs,
    services: &'a crate::service::ServiceRegistry,
    def: Option<&'a crate::service::ServiceDef>,
    service_id: &str,
) -> Option<&'a crate::service::ServiceDef> {
    def.or_else(|| inputs.def(services, service_id))
}

/// Buffer a brokered request's body for policy, at most `cap` bytes.
async fn buffer_body(body: Body, cap: u64) -> Result<Vec<u8>, Response<Body>> {
    // `Limited` enforces the cap even without a Content-Length (chunked
    // transfer); the declared-length check before it is only the cheap early exit.
    match http_body_util::Limited::new(body, cap as usize).collect().await {
        Ok(collected) => Ok(collected.to_bytes().to_vec()),
        Err(e) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => {
            Err(body_over_cap(0, cap))
        }
        Err(e) => {
            tracing::warn!("proxy: body collect failed: {}", e);
            Err(err_response(ScCode::UpstreamBody, "failed to read request body"))
        }
    }
}

/// Why a compressed body could not be read.
#[derive(Debug, Clone, PartialEq)]
enum DecodeError {
    Unsupported(String),
    Corrupt(String),
    OverCap(u64),
}

impl DecodeError {
    fn code(&self) -> ScCode {
        match self {
            DecodeError::Unsupported(_) => ScCode::ContentEncodingUnsupported,
            DecodeError::Corrupt(_) => ScCode::RequestUnreadable,
            DecodeError::OverCap(_) => ScCode::BrokerBodyLimit,
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Unsupported(c) => write!(
                f,
                "the request body's Content-Encoding {c} is not one of gzip, deflate, br, zstd"
            ),
            DecodeError::Corrupt(c) => write!(f, "the request body is not valid {c}"),
            DecodeError::OverCap(cap) => write!(
                f,
                "the request body decodes to more than the broker's inspectable cap ({cap} bytes)"
            ),
        }
    }
}

/// The largest zstd window the decoder allots (2^24 = 16 MiB; every default
/// compression level fits), so a tiny frame can't claim 128 MiB.
const ZSTD_WINDOW_LOG_MAX: u32 = 24;

/// The body with its content codings (RFC 9110 §8.4) undone, last applied
/// first, by flate2 / brotli / zstd; `None` when it has none. Coding names
/// are case-insensitive; a gzip body may hold several members.
fn decode_content(
    headers: &HeaderMap,
    raw: &[u8],
    cap: u64,
) -> Option<Result<Vec<u8>, DecodeError>> {
    use std::io::Read;
    let codings: Vec<String> = headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .flat_map(|v| v.to_str().unwrap_or("?").split(','))
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty() && c != "identity")
        .collect();
    if codings.is_empty() || raw.is_empty() {
        return None;
    }
    let mut data = raw.to_vec();
    for coding in codings.iter().rev() {
        let mut out = Vec::new();
        let read = {
            let input = &data[..];
            let reader: Box<dyn Read + '_> = match coding.as_str() {
                "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(input)),
                "deflate" => Box::new(flate2::read::ZlibDecoder::new(input)),
                "br" => Box::new(brotli::Decompressor::new(input, 4096)),
                "zstd" => match zstd::stream::read::Decoder::new(input)
                    .and_then(|mut d| d.window_log_max(ZSTD_WINDOW_LOG_MAX).map(|_| d))
                {
                    Ok(d) => Box::new(d),
                    Err(_) => return Some(Err(DecodeError::Corrupt(coding.clone()))),
                },
                other => return Some(Err(DecodeError::Unsupported(other.to_string()))),
            };
            reader.take(cap + 1).read_to_end(&mut out)
        };
        if read.is_err() {
            return Some(Err(DecodeError::Corrupt(coding.clone())));
        }
        if out.len() as u64 > cap {
            return Some(Err(DecodeError::OverCap(cap)));
        }
        data = out;
    }
    Some(Ok(data))
}

fn body_over_cap(declared: u64, cap: u64) -> Response<Body> {
    let what = if declared > 0 {
        format!("declared Content-Length ({} bytes)", declared)
    } else {
        "streamed body".to_string()
    };
    err_response(
        ScCode::BrokerBodyLimit,
        &format!(
            "this request names a phantom but its {} exceeds the broker's inspectable \
             cap ({} bytes). The proxy will not forward a credential alongside a body \
             policy cannot see. If the request is legitimate, raise the daemon's \
             --body-cap / SPROTT_BODY_CAP.",
            what, cap
        ),
    )
}

/// Build the agent-facing body for a failed forward-hop (see `handle_error`).
/// A connect-phase failure is a reachability/egress problem, so it names the
/// cause and how to configure a proxy; anything else is reported plainly without
/// a proxy hint that would misdirect. Either way we lead with "not a credential
/// problem" so the agent doesn't blame the token, and tag it `egress_unreachable`
/// / `upstream_error` so tooling can branch on the header.
fn egress_error_response(err: hudsucker::hyper_util::client::legacy::Error) -> Response<Body> {
    let is_connect = err.is_connect();
    let cause = error_chain(&err);
    // Preserve the observability the default handler gave (it logged the raw err).
    tracing::error!(cause = %cause, is_connect, "forward-hop to upstream failed");
    let (code, msg) = egress_error_parts(
        is_connect,
        &cause,
        crate::cli::egress_proxy::effective().is_some(),
    );
    err_response(code, &msg)
}

/// The `(x-sprott-error code, body)` for a forward-hop failure. Pure so the
/// branching (connect vs not, proxy configured vs not) is testable without a
/// `hyper_util` error, which has no public constructor. Never echoes the proxy
/// URL — it can carry userinfo — pointing at `sprott config get proxy` instead.
fn egress_error_parts(is_connect: bool, cause: &str, has_proxy: bool) -> (ScCode, String) {
    if !is_connect {
        return (
            ScCode::UpstreamError,
            format!(
                "could not complete the upstream request (not a credential problem): {}",
                cause
            ),
        );
    }
    let hint = if has_proxy {
        "Egress goes through your configured proxy. Make sure it's up and can reach \
         that host (`sprott config get proxy`), or change it with \
         `sprott config set proxy <url>` / `sprott config unset proxy`."
    } else {
        "No egress proxy is set. If this machine reaches the internet only through a \
         proxy, run `sprott config set proxy <url>`."
    };
    (
        ScCode::EgressUnreachable,
        format!(
            "egress failed (not a credential problem): {}. {}",
            cause, hint
        ),
    )
}

/// Flatten an error's `source()` chain into one line, dropping empty/duplicate
/// frames. For a forward-hop failure the deepest frame is our `TunnelConnector`
/// message (e.g. `forward connect to gmail.googleapis.com:443 timed out`), which
/// already names host:port and direct-vs-proxy.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cur: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = cur {
        let s = e.to_string();
        if !s.is_empty() && !parts.iter().any(|p| p == &s) {
            parts.push(s);
        }
        cur = e.source();
    }
    parts.join(": ")
}

/// A plain-text 4xx/5xx for the MITM plane. Status comes from the registry
/// (`ScCode::row`, the same row every surface uses); the machine token rides
/// `x-sprott-error` AND leads the body (`Sprott: <code>: <msg>`), so the
/// error is attributable even when a tool surfaces only one of the two.
/// text/plain is deliberate — a Sprott refusal must never parse as the
/// upstream service's payload.
fn err_response(code: ScCode, msg: &str) -> Response<Body> {
    let status = StatusCode::from_u16(code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-sprott-error", code.as_str())
        .body(Body::from(format!(
            "Sprott: {}: {}\n",
            code.as_str(),
            msg
        )))
        .unwrap_or_else(|_| plain(status, msg))
}

/// A `407 Proxy Authentication Required` challenge for a CONNECT that arrived
/// without proxy credentials but targets a host we broker. RFC 7235 challenge-
/// first clients (notably Debian/Ubuntu git over libcurl-gnutls) send no
/// `Proxy-Authorization` until they see this, then repeat the CONNECT
/// authenticated. `Basic` is the only scheme we
/// accept — the CONNECT userinfo carries `base64("<vid>:<key>")`; the realm
/// names us. Empty body + explicit zero length so the connection stays alive and
/// the client retries the CONNECT on it.
fn proxy_auth_challenge() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(header::PROXY_AUTHENTICATE, "Basic realm=\"sprott\"")
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap_or_else(|_| {
            plain(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "proxy auth required",
            )
        })
}

/// Best-effort terminal audit row for a forwarded (or denied) request. Denies
/// pass `upstream_status = 0`, `target` (the destination host, for a host
/// refusal) and `code` (why: its ScCode wire name, never free text).
fn write_forward_audit(
    state: &AppState,
    p: &AuditPending,
    upstream_status: u16,
    target: Option<&str>,
    code: Option<ScCode>,
) {
    let Ok(store) = state.audit_for_vault(&p.vault_id) else {
        return;
    };
    let now = now_secs() as i64;
    let status = if upstream_status == 0 {
        crate::audit::STATUS_DENIED
    } else {
        crate::audit::STATUS_ALLOWED
    };
    let row = crate::audit::ApprovalRow {
        id: uuid::Uuid::new_v4().to_string(),
        created_at: now,
        decided_at: Some(now),
        expires_at: now,
        status: status.into(),
        act_kind: "use".into(),
        service: Some(p.service.clone()),
        method: Some(p.method.clone()),
        path: Some(p.path.clone()),
        target: target.map(str::to_string),
        reason: None,
        credential_id: None,
        upstream_status: if upstream_status == 0 {
            None
        } else {
            Some(upstream_status as i64)
        },
        agent_prefix: p.agent_prefix.clone(),
        code: code.map(|c| c.as_str().to_string()),
    };
    if let Err(e) = store.insert(&row) {
        tracing::warn!(vault = %p.vault_id, "proxy audit insert failed: {}", e);
    }
}

#[cfg(test)]
mod permit_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn test_handler() -> BrokerHandler {
        let cfg = crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/sprott-test-h1-{}",
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
        let state = AppState::new(cfg);
        state.open_ledger_for_tests(&[]);
        BrokerHandler::new(Arc::new(state))
    }

    async fn refusal_code(req: Request<Body>) -> Option<String> {
        match test_handler().pipeline(LOOPBACK, req).await {
            RequestOrResponse::Response(r) => r
                .headers()
                .get("x-sprott-error")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            RequestOrResponse::Request(_) => None,
        }
    }

    /// H1: a phantom from before 2.0 in the URL, a header or decoded Basic
    /// auth is refused with its replacement named, never forwarded.
    #[tokio::test]
    async fn an_old_phantom_is_refused_and_named() {
        let b64 = |s: &[u8]| base64::engine::general_purpose::STANDARD.encode(s);
        for req in [
            Request::builder()
                .uri("https://github.com/o/r.git/info/refs")
                .header("authorization", format!("Basic {}", b64(b"x:__sc__github__")))
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("https://api.telegram.org/bot__sc__telegram__/getMe")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("https://api.stripe.com/v1/charges")
                .header("authorization", "Bearer __sc__stripe__")
                .body(Body::empty())
                .unwrap(),
        ] {
            let RequestOrResponse::Response(resp) = test_handler().pipeline(LOOPBACK, req).await
            else {
                panic!("forwarded");
            };
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(resp.headers()["x-sprott-error"], "phantom_renamed");
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let body = String::from_utf8_lossy(&body);
            assert!(
                body.starts_with("Sprott: phantom_renamed: __sc__")
                    && body.contains(" is the phantom name from before Sprott 2.0; use __sprott__"),
                "{body}"
            );
        }
    }

    /// A 2.0 phantom for connection `sc` contains `__sc__token__`; it is a
    /// phantom, not an old one.
    #[tokio::test]
    async fn a_new_phantom_for_connection_sc_is_not_refused_as_old() {
        let req = Request::builder()
            .uri("https://api.example.com/v1")
            .header("authorization", "Bearer __sprott__sc__token__")
            .body(Body::empty())
            .unwrap();
        let code = refusal_code(req).await;
        assert_ne!(code.as_deref(), Some("phantom_renamed"), "{code:?}");
        assert_eq!(code.as_deref(), Some("agent_key"), "it reaches the agent check");
    }

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hudsucker::hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    /// A compressed body is read decoded, in every coding and order; an
    /// unknown coding, a corrupt body and one that inflates past the cap are
    /// told apart.
    #[test]
    fn a_compressed_body_is_read_decoded() {
        use std::io::Write;
        let plain = br#"{"query":"mutation { serviceDelete(id: \"s\") }"}"#;
        let gzip = |b: &[u8]| {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b).unwrap();
            e.finish().unwrap()
        };
        let gz = gzip(plain);
        let decode = |h: &[(&str, &str)], b: &[u8], cap: u64| decode_content(&headers_with(h), b, cap);
        assert_eq!(decode(&[], &gz, 1024), None);
        assert_eq!(decode(&[("content-encoding", "gzip")], b"", 1024), None);
        assert_eq!(decode(&[("content-encoding", "GZIP")], &gz, 1024), Some(Ok(plain.to_vec())));
        // Two gzip members read as one body.
        let two = [gzip(&plain[..10]), gzip(&plain[10..])].concat();
        assert_eq!(decode(&[("content-encoding", "gzip")], &two, 1024), Some(Ok(plain.to_vec())));
        // Codings undone last first: `gzip, br` was gzip then br.
        let mut br = Vec::new();
        brotli::CompressorWriter::new(&mut br, 4096, 5, 22).write_all(&gz).unwrap();
        assert_eq!(
            decode(&[("content-encoding", "gzip, br")], &br, 1024),
            Some(Ok(plain.to_vec()))
        );
        let zs = zstd::stream::encode_all(&plain[..], 3).unwrap();
        assert_eq!(decode(&[("content-encoding", "zstd")], &zs, 1024), Some(Ok(plain.to_vec())));
        assert!(matches!(
            decode(&[("content-encoding", "compress")], &gz, 1024),
            Some(Err(DecodeError::Unsupported(_)))
        ));
        assert!(matches!(
            decode(&[("content-encoding", "gzip")], b"not gzip", 1024),
            Some(Err(DecodeError::Corrupt(_)))
        ));
        assert_eq!(decode(&[("content-encoding", "gzip")], &gz, 16), Some(Err(DecodeError::OverCap(16))));
    }

    /// A raw connection named like a registry service is decided by that
    /// service's rules (policy resolves them by the connection id), so its
    /// requests are read by that service's shapes too: a `serviceDelete` on
    /// a raw `railway` connection asks every time, as on the service's own.
    #[test]
    fn a_raw_connection_named_like_a_service_is_read_by_its_shapes() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let state = test_handler().state;
        let inputs = crate::snapshot::PolicyInputs::default();
        let def = shape_definition(&inputs, &state.services, None, "railway")
            .expect("the registry's railway");
        let rules = state.services.default_policy_rules("railway").unwrap().to_vec();
        let decide = |body: &str| {
            let input = crate::core::request::RequestInput {
                method: "POST",
                path: "/graphql/v2",
                body: Some(body.as_bytes()),
                ..Default::default()
            };
            let (rs, request) = crate::service::read_request(Some(def), input).expect("readable");
            assert!(rs.is_some(), "shape");
            evaluate(&request, Some(&rules), None, &Policy::default(), &["dev".into()]).unwrap()
        };
        assert_eq!(
            decide(r#"{"query":"mutation Del($id: String!) { x: serviceDelete(id: $id) }","variables":{"id":"svc"}}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(decide(r#"{"query":"query { project(id: \"p\") { name } }"}"#), AccessLevel::Allow);
        // A raw connection named like nothing has no shapes and no rules.
        assert!(shape_definition(&inputs, &state.services, None, "my-own-api").is_none());
    }

    /// A brokered request never upgrades to a WebSocket: hop-by-hop headers are
    /// dropped, so frames the proxy can't inspect never ride a credential.
    #[test]
    fn a_brokered_request_cannot_upgrade() {
        let mut h = HeaderMap::new();
        h.insert("upgrade", "websocket".parse().unwrap());
        h.insert("connection", "Upgrade".parse().unwrap());
        h.insert("authorization", "Bearer __sprott__railway__".parse().unwrap());
        let out = rewrite_headers(&h, &PhantomValues::default(), false);
        assert!(!out.contains_key("upgrade") && !out.contains_key("connection"));
    }

    /// `request.headers` is the set the request is forwarded with: a header
    /// `Connection` names is dropped from both (RFC 9110 §7.6.1), and so is
    /// an `Authorization` that carries no phantom.
    #[test]
    fn request_headers_are_the_forwarded_set() {
        let mut h = HeaderMap::new();
        h.insert("connection", "x-trace".parse().unwrap());
        h.insert("x-trace", "1".parse().unwrap());
        h.insert("x-account", "prod".parse().unwrap());
        h.append("x-account", "dev".parse().unwrap());
        h.insert("authorization", "Bearer agent-own".parse().unwrap());
        let names: Vec<String> = forwarded_headers(&h).into_iter().map(|(k, _)| k).collect();
        assert_eq!(names, ["x-account", "x-account"]);
        let out = rewrite_headers(&h, &PhantomValues::default(), false);
        assert!(!out.contains_key("x-trace") && !out.contains_key("authorization"));
        assert_eq!(out.get_all("x-account").iter().count(), 2);
        h.insert("authorization", "Bearer __sprott__railway__".parse().unwrap());
        let kept = forwarded_headers(&h);
        assert!(kept.contains(&("authorization".to_string(), b"Bearer __sprott__railway__".to_vec())));
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("x:__sprott__railway__")
        );
        assert!(authorization_forwarded(&basic));
        assert!(!authorization_forwarded("Basic eDp5"));
    }

    #[test]
    fn an_unknown_connection_names_a_changed_key_only_when_flagged() {
        let (code, message) = unknown_connection_refusal(false, "future");
        assert_eq!(code, ScCode::UnknownConnection);
        assert_eq!(message, "unknown connection 'future'");

        let (code, message) = unknown_connection_refusal(true, "future");
        assert_eq!(code, ScCode::VaultKeyChanged);
        assert_eq!(message, crate::error::VAULT_KEY_CHANGED_MSG);
    }

    fn b64(s: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    /// The unified-boundary refusal contract: 413, machine-readable error
    /// token, and a message naming both the offending size and the knob —
    /// P2 says the caller must learn exactly what was over and how to widen.
    #[test]
    fn body_over_cap_is_explained_413() {
        let resp = body_over_cap(50_000_000, 32 * 1024 * 1024);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.headers().get("x-sprott-error").unwrap(),
            "broker_body_limit"
        );
        // Chunked variant (length unknown while buffering) still explains.
        let resp = body_over_cap(0, 1024);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// The signed Use scope carries the mint-time level, the reuse apply
    /// grants (with its rule id + label or floor class), and `window_s` (an
    /// integer) exactly when that reuse has one.
    #[test]
    fn signed_level_stamp() {
        use crate::core::policy::{AccessLevel, DecidedBy};
        let send = DecidedBy::Rule {
            id: Some("send".into()),
            label: Some("Send email".into()),
        };
        let stamp = |level, by: &DecidedBy, scoped, method: &str, ttl| {
            let mut s = json!({ "method": method });
            stamp_signed_level(&mut s, level, by, scoped, method, ttl);
            s
        };

        let always = stamp(AccessLevel::AskAlways, &send, false, "POST", 900);
        assert_eq!(always["level"], "ask-always");
        assert_eq!(always["reuse"], "none");
        assert!(always.get("window_s").is_none());
        // A scoped path doesn't make ask-always reusable.
        let always_scoped = stamp(AccessLevel::AskAlways, &send, true, "POST", 900);
        assert_eq!(always_scoped["reuse"], "none");
        assert!(always_scoped.get("window_s").is_none());

        let exact = stamp(AccessLevel::Ask, &send, true, "POST", 120);
        assert_eq!(exact["level"], "ask");
        assert_eq!(exact["reuse"], "exact");
        assert_eq!(exact["window_s"], 120);
        assert!(exact["window_s"].is_u64());
        assert!(exact.get("reuse_rule").is_none());

        let rule = stamp(AccessLevel::Ask, &send, false, "POST", 900);
        assert_eq!(rule["reuse"], "rule");
        assert_eq!(rule["reuse_rule"], "send");
        assert_eq!(rule["reuse_label"], "Send email");
        assert_eq!(rule["window_s"], 900);

        let floor = stamp(AccessLevel::Ask, &DecidedBy::Floor, false, "PATCH", 300);
        assert_eq!(floor["reuse"], "floor");
        assert_eq!(floor["reuse_class"], "write");
        assert_eq!(floor["window_s"], 300);

        // An allow-level request mints no op: nothing to reuse.
        let allow = stamp(AccessLevel::Allow, &DecidedBy::Floor, false, "GET", 600);
        assert_eq!(allow["level"], "allow");
        assert!(allow.get("reuse").is_none());
        assert!(allow.get("window_s").is_none());
    }

    /// Ingress normalization: the method every surface compares (and the one
    /// forwarded) is uppercase, so a lowercase `delete` is a DELETE: it hits
    /// a DELETE rule and the write class, and its reuse class follows.
    #[test]
    fn method_is_normalized_at_ingress() {
        use crate::approval::reuse::Class;
        let lower = Method::from_bytes(b"delete").unwrap();
        assert_ne!(
            lower,
            Method::DELETE,
            "hyper keeps an extension-case method"
        );
        let n = normalize_method(&lower);
        assert_eq!(n, Method::DELETE);
        assert_eq!(n.as_str(), "DELETE");
        assert_eq!(
            normalize_method(&Method::from_bytes(b"propPatch").unwrap()).as_str(),
            "PROPPATCH"
        );
        assert_eq!(normalize_method(&Method::GET), Method::GET);
        assert_eq!(Class::of(n.as_str()), Class::Write);
        assert_eq!(Class::of("move"), Class::Write);
        assert_eq!(Class::of("PROPPATCH"), Class::Write);
        assert_eq!(Class::of("head"), Class::Read);
    }

    #[test]
    fn error_chain_flattens_and_dedups() {
        #[derive(Debug)]
        struct E(&'static str, Option<Box<E>>);
        impl std::fmt::Display for E {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for E {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.1.as_deref().map(|e| e as &dyn std::error::Error)
            }
        }
        let e = E(
            "client error (Connect)",
            Some(Box::new(E(
                "forward connect to gmail.googleapis.com:443 timed out",
                None,
            ))),
        );
        assert_eq!(
            error_chain(&e),
            "client error (Connect): forward connect to gmail.googleapis.com:443 timed out"
        );
        // Duplicate frames collapse.
        let dup = E("same", Some(Box::new(E("same", None))));
        assert_eq!(error_chain(&dup), "same");
    }

    #[test]
    fn egress_error_parts_reachability_names_proxy_knob_not_credential() {
        let cause = "forward connect to gmail.googleapis.com:443 timed out";

        // Connect failure, no proxy configured: tell them how to set one, and
        // make clear it is NOT a credential problem (the agent's #1 misread).
        let (code, msg) = egress_error_parts(true, cause, false);
        assert_eq!(code, ScCode::EgressUnreachable);
        assert!(msg.contains(cause));
        assert!(msg.contains("not a credential problem"));
        assert!(msg.contains("sprott config set proxy"));
        assert!(msg.contains("No egress proxy is set"));

        // Connect failure WITH a proxy configured: point at the proxy, never
        // echo its URL (it can carry userinfo), offer get/unset.
        let (code, msg) = egress_error_parts(true, cause, true);
        assert_eq!(code, ScCode::EgressUnreachable);
        assert!(msg.contains("configured proxy"));
        assert!(msg.contains("sprott config get proxy"));
        assert!(msg.contains("sprott config unset proxy"));

        // NOT a connect failure (e.g. upstream sent a bad response): no proxy
        // hint that would misdirect, distinct token.
        let (code, msg) = egress_error_parts(false, "invalid HTTP response", false);
        assert_eq!(code, ScCode::UpstreamError);
        assert!(!msg.contains("sprott config set proxy"));
        assert!(msg.contains("not a credential problem"));
    }

    #[test]
    fn creds_from_proxy_auth_splits_vid_and_key() {
        // vid:key → both captured (the key is the agent's identity, §8).
        let req = Request::builder()
            .uri("api.github.com:443")
            .header(
                header::PROXY_AUTHORIZATION,
                format!("Basic {}", b64(b"vault-abc:sc_agent_k9")),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            creds_from_proxy_auth(&req),
            (
                Some("vault-abc".to_string()),
                Some("sc_agent_k9".to_string())
            )
        );

        // Legacy empty password (`vid:`) → vid present, key None (→ 407 later,
        // it's participating but unauthenticated).
        let no_key = Request::builder()
            .uri("api.github.com:443")
            .header(
                header::PROXY_AUTHORIZATION,
                format!("Basic {}", b64(b"vault-abc:")),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            creds_from_proxy_auth(&no_key),
            (Some("vault-abc".to_string()), None)
        );
    }

    #[test]
    fn creds_absent_or_empty_vid_is_none() {
        // No Proxy-Auth at all → non-participating (blind-tunnel).
        let none = Request::builder()
            .uri("api.github.com:443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(creds_from_proxy_auth(&none), (None, None));
        // Empty vid (`:key`) is not a routing hint → vid None.
        let empty_vid = Request::builder()
            .uri("api.github.com:443")
            .header(
                header::PROXY_AUTHORIZATION,
                format!("Basic {}", b64(b":sc_agent_k9")),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(creds_from_proxy_auth(&empty_vid).0, None);
    }

    #[test]
    fn proxy_auth_challenge_is_407_with_basic_realm() {
        // RFC 7235 challenge-first clients (Debian/Ubuntu git over libcurl-gnutls)
        // only send Proxy-Authorization after this exact response.
        let res = proxy_auth_challenge();
        assert_eq!(res.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(
            res.headers().get(header::PROXY_AUTHENTICATE).unwrap(),
            "Basic realm=\"sprott\"",
        );
    }

    #[test]
    fn basic_auth_decode_roundtrip() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", b64(b"x:secret")).parse().unwrap(),
        );
        assert_eq!(basic_auth_decoded(&h).as_deref(), Some("x:secret"));
    }

    #[test]
    fn etld1_takes_last_two_labels() {
        assert_eq!(etld1("foo.bar.github.com"), "github.com");
        assert_eq!(etld1("api.stripe.com"), "stripe.com");
        assert_eq!(etld1("localhost"), "localhost");
    }

    #[test]
    fn rewrite_headers_strips_proxy_auth_and_injects_basic() {
        let mut values = PhantomValues::default();
        values.insert("__sprott__github__".to_string(), "ghp_REAL".to_string());
        let mut h = HeaderMap::new();
        h.insert(
            header::PROXY_AUTHORIZATION,
            "Basic Zm9vOg==".parse().unwrap(),
        );
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", b64(b"x:__sprott__github__"))
                .parse()
                .unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        assert!(
            out.get(header::PROXY_AUTHORIZATION).is_none(),
            "proxy auth stripped"
        );
        let auth = out.get(header::AUTHORIZATION).unwrap().to_str().unwrap();
        let enc = auth.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(enc)
            .unwrap();
        assert_eq!(decoded, b"x:ghp_REAL", "phantom substituted inside Basic");
    }

    #[test]
    fn rewrite_headers_substitutes_basic_username_position() {
        // git clone https://__sprott__github__@github.com → Basic b64("phantom:") —
        // the phantom rides the USERNAME slot (password empty). Regression pair
        // to the password-position test above.
        let mut values = PhantomValues::default();
        values.insert("__sprott__github__".to_string(), "ghp_REAL".to_string());
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", b64(b"__sprott__github__:"))
                .parse()
                .unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        let auth = out
            .get(header::AUTHORIZATION)
            .expect("auth header survived")
            .to_str()
            .unwrap();
        let enc = auth.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(enc)
            .unwrap();
        assert_eq!(
            decoded, b"ghp_REAL:",
            "phantom substituted in USERNAME position"
        );
    }

    #[test]
    fn rewrite_headers_strips_shadowing_agent_bearer() {
        // The phantom lives elsewhere; the agent's own Authorization must not
        // ride along (it would shadow the injected credential).
        let values = PhantomValues::default();
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Bearer agents-own-token".parse().unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        assert!(out.get(header::AUTHORIZATION).is_none());
    }

    #[test]
    fn rewrite_headers_substitutes_bearer_phantom() {
        let mut values = PhantomValues::default();
        values.insert("__sprott__stripe_key__".to_string(), "sk_live_X".to_string());
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Bearer __sprott__stripe_key__".parse().unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        assert_eq!(
            out.get(header::AUTHORIZATION).unwrap().to_str().unwrap(),
            "Bearer sk_live_X"
        );
    }

    #[test]
    fn rewrite_headers_drops_content_length_when_body_rewritten() {
        let values = PhantomValues::default();
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, "42".parse().unwrap());
        h.insert("x-custom", "keep-me".parse().unwrap());
        let out = rewrite_headers(&h, &values, true);
        assert!(out.get(header::CONTENT_LENGTH).is_none());
        assert_eq!(out.get("x-custom").unwrap(), "keep-me");
    }
}
