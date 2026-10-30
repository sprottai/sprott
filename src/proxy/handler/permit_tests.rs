//! The brokered pipeline end to end with value-less permits: a request is
//! decided, its KEYs located, its permit looked up, and its values read only
//! then. A case approves its op the way `approve_op` does once the grant
//! verified (`approve_use_for_tests`), then replays the request.

use super::*;
use crate::core::policy::{AccessLevel, Levels, Policy, RuleConfig};
use crate::storage::plaintext::{Category, Connection, Store, VaultAux, VaultPlaintextView};
use std::collections::BTreeMap;

const V: &str = "v-permits";
const AG: &str = "ag_permits";
const K: [u8; 32] = [0x51; 32];
const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

fn new_state() -> (tempfile::TempDir, Arc<AppState>) {
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
    let state = AppState::new(cfg);
    state.open_ledger_for_tests(&[AG]);
    (dir, Arc::new(state))
}

/// A vault as a fold reads it, listing the test agent.
#[derive(Clone)]
struct Vault {
    aux: VaultAux,
    secrets: BTreeMap<String, Vec<u8>>,
}

impl Vault {
    fn new() -> Vault {
        let mut aux = VaultAux::initial();
        aux.agents.insert(AG.to_string(), Default::default());
        Vault {
            aux,
            secrets: BTreeMap::new(),
        }
    }

    fn secret(mut self, key: &str, value: &str) -> Vault {
        self.secrets
            .insert(key.to_string(), value.as_bytes().to_vec());
        self
    }

    fn secret_bytes(mut self, key: &str, value: &[u8]) -> Vault {
        self.secrets.insert(key.to_string(), value.to_vec());
        self
    }

    /// A raw connection anchored at `host` with these KEYs.
    fn raw(mut self, id: &str, host: &str, keys: &[&str]) -> Vault {
        self.aux.connections.insert(
            id.to_string(),
            Connection {
                hosts: Some(vec![host.to_string()]),
                secrets: Some(keys.iter().map(|k| k.to_string()).collect()),
                ..Default::default()
            },
        );
        self
    }

    /// A named connection of `service` binding roles to KEYs.
    fn named(mut self, id: &str, service: &str, keys: &[(&str, &str)]) -> Vault {
        self.aux.connections.insert(
            id.to_string(),
            Connection {
                service: Some(service.to_string()),
                keys: Some(
                    keys.iter()
                        .map(|(r, k)| (r.to_string(), k.to_string()))
                        .collect(),
                ),
                ..Default::default()
            },
        );
        self
    }

    fn policy(mut self, f: impl FnOnce(&mut Policy)) -> Vault {
        let mut p = self.aux.policy.take().unwrap_or_default();
        f(&mut p);
        self.aux.policy = Some(p);
        self
    }

    /// A rule the owner adds to a connection, with an optional condition.
    fn rule(self, conn: &str, id: &str, pattern: &str, level: AccessLevel, condition: Option<&str>) -> Vault {
        self.policy(|p| {
            p.connections.entry(conn.to_string()).or_default().rules.push(
                crate::core::policy::UserEntry::Added {
                    id: id.to_string(),
                    rule: RuleConfig {
                        condition: condition.map(crate::core::policy::Condition::lenient),
                        level: Some(level),
                        ttl: Some(600),
                        ..RuleConfig::selecting(pattern)
                    },
                },
            );
        })
    }

    /// A connection's own floor.
    fn floor(self, conn: &str, read: AccessLevel, write: AccessLevel) -> Vault {
        self.policy(|p| {
            p.connections.entry(conn.to_string()).or_default().default = Some(Levels {
                read: Some(read),
                write: Some(write),
                ttl: Some(600),
            });
        })
    }

    fn service(mut self, id: &str, toml: &str) -> Vault {
        self.aux.services.insert(id.to_string(), toml.into());
        self
    }

    /// The external store `name` (in memory), listed before or after native.
    fn store(mut self, name: &str, first: bool) -> Vault {
        let mut extra = serde_json::Map::new();
        extra.insert("name".into(), json!(name));
        self.aux.stores.insert(
            "ext".into(),
            Store {
                kind: crate::store::memory::KIND.into(),
                category: Category::Value,
                items: BTreeMap::new(),
                extra,
            },
        );
        self.aux.store_order.retain(|s| s != "ext");
        if first {
            self.aux.store_order.insert(0, "ext".into());
        } else {
            self.aux.store_order.push("ext".into());
        }
        self
    }

    fn no_store(mut self) -> Vault {
        self.aux.stores.remove("ext");
        self.aux.store_order.retain(|s| s != "ext");
        self
    }

    fn view(&self) -> VaultPlaintextView {
        VaultPlaintextView {
            aux: self.aux.clone(),
            native_secrets: self.secrets.clone(),
            native_secret_notes: BTreeMap::new(),
        }
    }

    /// The vault-unlock op.
    fn unlock(&self, state: &AppState) {
        let k = zeroize::Zeroizing::new(K.to_vec());
        assert!(state.install_view(V, self.view(), k, true).served());
    }

    /// Any other served install (a pull, a write).
    fn install(&self, state: &AppState) {
        let k = zeroize::Zeroizing::new(K.to_vec());
        assert!(state.install_view(V, self.view(), k, false).served());
    }
}

/// What the pipeline did with a request.
enum Out {
    /// Forwarded: the Authorization header and the URL it went with.
    Sent(String, String),
    /// Asked for an approval: the op, and the response body.
    Ask(String, String),
    /// Asked to widen the host: the op.
    Widen(String),
    /// Refused: the code and the message.
    No(String, String),
}

impl Out {
    fn describe(&self) -> String {
        match self {
            Out::Sent(a, u) => format!("sent ({a}) to {u}"),
            Out::Ask(op, body) => format!("ask {op}: {body}"),
            Out::Widen(op) => format!("widen {op}"),
            Out::No(c, m) => format!("refused {c}: {m}"),
        }
    }

    #[track_caller]
    fn sent(&self) -> (String, String) {
        match self {
            Out::Sent(a, u) => (a.clone(), u.clone()),
            other => panic!("not forwarded: {}", other.describe()),
        }
    }

    #[track_caller]
    fn ask(&self) -> String {
        match self {
            Out::Ask(op, _) => op.clone(),
            other => panic!("no approval asked: {}", other.describe()),
        }
    }

    #[track_caller]
    fn refused(&self) -> (String, String) {
        match self {
            Out::No(c, m) => (c.clone(), m.clone()),
            other => panic!("not refused: {}", other.describe()),
        }
    }
}

async fn send(state: &Arc<AppState>, method: &str, url: &str, auth: &str, body: &str) -> Out {
    send_with(state, method, url, auth, &[], body).await
}

/// [`send`] with more headers (a `content-type` among them replaces
/// `application/json`).
async fn send_with(
    state: &Arc<AppState>,
    method: &str,
    url: &str,
    auth: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Out {
    let mut req = Request::builder()
        .method(method)
        .uri(url)
        .header("authorization", auth);
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        req = req.header("content-type", "application/json");
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Body::from(body.to_string())).unwrap();
    let mut handler = BrokerHandler {
        state: state.clone(),
        vid: Some(V.to_string()),
        key: None,
        agent_id: Some(AG.to_string()),
        pending: None,
    };
    match handler.pipeline(LOOPBACK, req).await {
        RequestOrResponse::Request(r) => Out::Sent(
            r.headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
            r.uri().to_string(),
        ),
        RequestOrResponse::Response(r) => {
            let op = r
                .headers()
                .get("x-sprott-op-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let code = r
                .headers()
                .get("x-sprott-error")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            match (op, r.status()) {
                (Some(op), StatusCode::UNAUTHORIZED) => {
                    let body = r.into_body().collect().await.unwrap().to_bytes();
                    Out::Ask(op, String::from_utf8_lossy(&body).into_owned())
                }
                (Some(op), StatusCode::FORBIDDEN) => Out::Widen(op),
                _ => {
                    let body = r.into_body().collect().await.unwrap().to_bytes();
                    Out::No(code, String::from_utf8_lossy(&body).into_owned())
                }
            }
        }
    }
}

fn approve(state: &AppState, op: &str) {
    crate::server::handlers::approve::approve_use_for_tests(state, op).unwrap();
}

fn ops(state: &AppState) -> usize {
    state.approvals.lock().unwrap().len()
}

fn target(state: &AppState, op: &str) -> String {
    state.approvals.lock().unwrap().get_any(op).unwrap().op.act.target.clone()
}

/// The permit identity the proxy computed for an op's request.
fn identity(state: &AppState, op: &str) -> crate::approval::coverage::Identity {
    state
        .approvals
        .lock()
        .unwrap()
        .get_any(op)
        .unwrap()
        .policy_context
        .as_ref()
        .and_then(|pc| pc.identity.clone())
        .expect("an identity")
}

fn bearer(phantom: &str) -> String {
    format!("Bearer {}", phantom)
}

// ── the two cases this fixes ────────────────────────────────────────────────

/// A raw connection `railway` holding RAILWAY_TOKEN, its role phantom, and
/// the built-in ask-always rule `delete-infra` (a raw connection named like
/// a service is decided by its rules and read by its shapes): approve once,
/// the replay is forwarded with the token (the approval used to be spent on
/// a replay that found no value for the role, and asked again).
#[tokio::test]
async fn railway_raw_role_phantom_ask_always_replay_is_forwarded() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("railway", "backboard.railway.com", &["RAILWAY_TOKEN"])
        .secret("RAILWAY_TOKEN", "rw-token")
        .unlock(&state);
    let url = "https://backboard.railway.com/graphql/v2";
    let auth = bearer("__sprott__railway__railway_token__");
    let body = r#"{"query":"mutation { serviceDelete(id: \"s\") }"}"#;
    let op = send(&state, "POST", url, &auth, body).await.ask();
    {
        let approvals = state.approvals.lock().unwrap();
        let rec = approvals.get_any(&op).unwrap();
        assert_eq!(rec.op.act.target, "RAILWAY_TOKEN");
        assert_eq!(rec.op.act.scope["level"], "ask-always");
        assert_eq!(rec.op.act.scope["reuse"], "none");
    }
    approve(&state, &op);
    let (sent, _) = send(&state, "POST", url, &auth, body).await.sent();
    assert_eq!(sent, "Bearer rw-token");
    // One approval, one replay.
    send(&state, "POST", url, &auth, body).await.ask();
    // A query no rule matches is allowed and forwarded.
    let read = r#"{"query":"query { me { name } }"}"#;
    assert_eq!(send(&state, "POST", url, &auth, read).await.sent().0, "Bearer rw-token");
}

/// The built-in Cloudflare connection with two secrets, its ask-always
/// `patch-dns-record` rule, the API token's role phantom: approve once, the
/// replay is forwarded with the token; a replay that also names the account
/// id is another request and asks.
#[tokio::test]
async fn cloudflare_role_phantom_ask_always_replay_is_forwarded() {
    let (_dir, state) = new_state();
    Vault::new()
        .secret("CLOUDFLARE_API_TOKEN", "cf-token")
        .secret("CLOUDFLARE_ACCOUNT_ID", "cf-account")
        .unlock(&state);
    let url = "https://api.cloudflare.com/client/v4/zones/z1/dns_records/r1";
    let auth = bearer("__sprott__cloudflare__cloudflare_api_token__");
    let body = r#"{"content":"1.2.3.4"}"#;
    let op = send(&state, "PATCH", url, &auth, body).await.ask();
    assert_eq!(target(&state, &op), "CLOUDFLARE_API_TOKEN");
    approve(&state, &op);
    let extra = "https://api.cloudflare.com/client/v4/zones/z1/dns_records/r1?a=__sprott__cloudflare__cloudflare_account_id__";
    send(&state, "PATCH", extra, &auth, body).await.ask();
    let (sent, _) = send(&state, "PATCH", url, &auth, body).await.sent();
    assert_eq!(sent, "Bearer cf-token");
    send(&state, "PATCH", url, &auth, body).await.ask();
}

/// A shaped ask carries its card sealed (design §5): the op shows the request
/// line and the decision in the clear, the bound values and the consent only
/// inside `scope.card`, which opens under the vault's content key. The values
/// kept beside the op key the permit, so a replay with another value asks.
#[tokio::test]
async fn a_shaped_ask_carries_its_card_sealed_and_its_values_key_the_permit() {
    let (_dir, state) = new_state();
    Vault::new()
        .secret("CLOUDFLARE_API_TOKEN", "cf-token")
        .secret("CLOUDFLARE_ACCOUNT_ID", "cf-account")
        .unlock(&state);
    let url = "https://api.cloudflare.com/client/v4/zones/z1/dns_records/r1";
    let auth = bearer("__sprott__cloudflare__cloudflare_api_token__");
    let body = r#"{"content":"1.2.3.4"}"#;
    let op = send(&state, "PATCH", url, &auth, body).await.ask();
    let (scope, kept) = {
        let store = state.approvals.lock().unwrap();
        let rec = store.get_any(&op).unwrap();
        let card = rec.policy_context.as_ref().and_then(|pc| pc.card.clone());
        (rec.op.act.scope.clone(), card.expect("the card is kept beside the op"))
    };
    assert!(scope.get("scope_vars").is_none() && scope.get("consent").is_none());
    let wire = scope.get("card").expect("the op carries the sealed card");
    assert_eq!(wire["gen"], 0);
    assert!(!wire["sealed"].as_str().unwrap().contains("1.2.3.4"));
    let json = crate::approval::card::open(wire["sealed"].as_str().unwrap(), &K, V, 0)
        .expect("opens under the content key");
    let card: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(card["vars"]["request.body.content"], "1.2.3.4");
    assert_eq!(kept.mac, crate::approval::card::binding_mac(&K, &json));
    approve(&state, &op);
    let other = r#"{"content":"5.6.7.8"}"#;
    send(&state, "PATCH", url, &auth, other).await.ask();
    assert_eq!(send(&state, "PATCH", url, &auth, body).await.sent().0, "Bearer cf-token");
}

/// Two retries of one shaped request chain (the inbox's `supersedes`) though
/// each carries a freshly sealed card.
#[tokio::test]
async fn retries_of_a_shaped_request_chain_despite_fresh_seals() {
    let (_dir, state) = new_state();
    Vault::new()
        .secret("CLOUDFLARE_API_TOKEN", "cf-token")
        .secret("CLOUDFLARE_ACCOUNT_ID", "cf-account")
        .unlock(&state);
    let url = "https://api.cloudflare.com/client/v4/zones/z1/dns_records/r1";
    let auth = bearer("__sprott__cloudflare__cloudflare_api_token__");
    let body = r#"{"content":"1.2.3.4"}"#;
    let a = send(&state, "PATCH", url, &auth, body).await.ask();
    let b = send(&state, "PATCH", url, &auth, body).await.ask();
    let store = state.approvals.lock().unwrap();
    let (ra, rb) = (store.get_any(&a).unwrap(), store.get_any(&b).unwrap());
    assert_ne!(ra.op.act.scope["card"]["sealed"], rb.op.act.scope["card"]["sealed"]);
    assert!(ra.intent_key.is_some());
    assert_eq!(ra.intent_key, rb.intent_key);
}

// ── tier × phantom × store × service ────────────────────────────────────────

/// A vault service with two secrets, an id-less ask rule (only a vault
/// definition can declare one) and a `[requests]` shape for scoped asks.
const ACME: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_TOKEN", "ACME_ID"]
[requests.buy]
method = "POST"
path = "/buy"
scope = ["request.body.amount"]
[[policy.rules]]
method = "POST"
path_exact = "/once"
level = "ask"
"#;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tier {
    AskAlways,
    AskOnce,
    Exact,
    Unit,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Phantoms {
    RoleLess,
    Role,
    TwoRoles,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Stores {
    Native,
    External,
    ExternalFirst,
    Broken,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Service {
    BuiltIn,
    Custom,
    Raw,
}

/// (connection, host, first KEY + role, second KEY + role)
fn shape(service: Service) -> (&'static str, &'static str, [(&'static str, &'static str); 2]) {
    match service {
        Service::BuiltIn => (
            "cloudflare",
            "api.cloudflare.com",
            [
                ("CLOUDFLARE_API_TOKEN", "cloudflare_api_token"),
                ("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id"),
            ],
        ),
        Service::Custom => ("acme", "api.acme.dev", [("ACME_TOKEN", "acme_token"), ("ACME_ID", "acme_id")]),
        Service::Raw => ("rawsvc", "api.raw.dev", [("RAW_TOKEN", "raw_token"), ("RAW_ID", "raw_id")]),
    }
}

/// Approve once, replay: forwarded with the values (a window serves again,
/// a single-use permit asks again); a broken store ahead of the KEY refuses
/// before anything is asked.
#[tokio::test]
async fn every_tier_phantom_store_and_service_replays_after_one_approval() {
    let mut cases = 0;
    for service in [Service::BuiltIn, Service::Custom, Service::Raw] {
        for tier in [Tier::AskAlways, Tier::AskOnce, Tier::Exact, Tier::Unit] {
            // Only a vault definition declares an id-less rule or, here, a
            // `[requests]` shape.
            if service != Service::Custom && matches!(tier, Tier::AskOnce | Tier::Exact) {
                continue;
            }
            for phantoms in [Phantoms::RoleLess, Phantoms::Role, Phantoms::TwoRoles] {
                for stores in [Stores::Native, Stores::External, Stores::ExternalFirst, Stores::Broken] {
                    replay_case(service, tier, phantoms, stores).await;
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 96);
}

async fn replay_case(service: Service, tier: Tier, phantoms: Phantoms, stores: Stores) {
    let case = format!("{service:?} {tier:?} {phantoms:?} {stores:?}");
    let (_dir, state) = new_state();
    let (conn, host, [(k1, r1), (k2, r2)]) = shape(service);
    let store_name = format!("matrix-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&store_name);
    let mut vault = Vault::new();
    vault = match service {
        Service::BuiltIn => vault,
        Service::Custom => vault.service("acme", ACME),
        Service::Raw => vault.raw("rawsvc", host, &[k1, k2]),
    };
    // A role-less phantom names the sole present KEY: the second is unset.
    let both = phantoms != Phantoms::RoleLess;
    let (v1, v2) = ("value-one", "value-two");
    match stores {
        Stores::Native | Stores::ExternalFirst | Stores::Broken => {
            vault = vault.secret(k1, v1);
            if both {
                vault = vault.secret(k2, v2);
            }
        }
        Stores::External => {
            ext.set(k1, v1);
            if both {
                ext.set(k2, v2);
            }
        }
    }
    vault = match stores {
        Stores::Native => vault,
        Stores::External => vault.store(&store_name, false),
        Stores::ExternalFirst | Stores::Broken => vault.store(&store_name, true),
    };
    if stores == Stores::Broken {
        ext.down.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    let (method, path, body) = match tier {
        Tier::AskAlways => {
            vault = vault.rule(conn, "t", "POST /x", AccessLevel::AskAlways, None);
            ("POST", "/x", "{}")
        }
        Tier::AskOnce => ("POST", "/once", "{}"),
        Tier::Exact => {
            vault = vault.rule(conn, "t", "POST /buy", AccessLevel::Ask, None);
            ("POST", "/buy", r#"{"amount":80}"#)
        }
        Tier::Unit => {
            vault = vault.rule(conn, "t", "POST /x", AccessLevel::Ask, None);
            ("POST", "/x", "{}")
        }
    };
    vault.unlock(&state);
    let (auth, url, want_auth, want_url) = match phantoms {
        Phantoms::RoleLess => (
            bearer(&format!("__sprott__{conn}__")),
            format!("https://{host}{path}"),
            format!("Bearer {v1}"),
            format!("https://{host}{path}"),
        ),
        Phantoms::Role => (
            bearer(&format!("__sprott__{conn}__{r1}__")),
            format!("https://{host}{path}"),
            format!("Bearer {v1}"),
            format!("https://{host}{path}"),
        ),
        Phantoms::TwoRoles => (
            bearer(&format!("__sprott__{conn}__{r1}__")),
            format!("https://{host}{path}?id=__sprott__{conn}__{r2}__"),
            format!("Bearer {v1}"),
            format!("https://{host}{path}?id={v2}"),
        ),
    };
    let first = send(&state, method, &url, &auth, body).await;
    if stores == Stores::Broken {
        let (code, _) = first.refused();
        assert_eq!(code, "store_unavailable", "{case}");
        assert_eq!(ops(&state), 0, "{case}: nothing asked");
        return;
    }
    let op = first.ask();
    let mut keys = vec![k1];
    if phantoms == Phantoms::TwoRoles {
        keys.push(k2);
    }
    keys.sort();
    assert_eq!(target(&state, &op), keys.join(", "), "{case}");
    let (level, reuse) = match tier {
        Tier::AskAlways => ("ask-always", "none"),
        Tier::AskOnce => ("ask", "none"),
        Tier::Exact => ("ask", "exact"),
        Tier::Unit => ("ask", "rule"),
    };
    {
        let approvals = state.approvals.lock().unwrap();
        let scope = &approvals.get_any(&op).unwrap().op.act.scope;
        assert_eq!(scope["level"], level, "{case}");
        assert_eq!(scope["reuse"], reuse, "{case}");
    }
    approve(&state, &op);
    let (sent_auth, sent_url) = send(&state, method, &url, &auth, body).await.sent();
    assert_eq!(sent_auth, want_auth, "{case}");
    assert_eq!(sent_url, want_url, "{case}");
    let again = send(&state, method, &url, &auth, body).await;
    match tier {
        Tier::AskAlways | Tier::AskOnce => {
            again.ask();
        }
        Tier::Exact | Tier::Unit => {
            assert_eq!(again.sent().0, want_auth, "{case}: a window serves again");
        }
    }
}

/// An `exposes` role of a minted connection (an id-token claim stored at
/// connect) is injected as it is, on an ask tier too; nothing is minted.
#[tokio::test]
async fn an_exposes_role_replays_after_approval() {
    let (_dir, state) = new_state();
    Vault::new()
        .secret("OPENAI_CODEX_REFRESH_TOKEN", "rt-codex")
        .secret("ACCOUNT_ID", "acct-7")
        .rule("openai_codex", "t", "POST /x", AccessLevel::AskAlways, None)
        .unlock(&state);
    let url = "https://api.openai.com/x";
    let auth = "Bearer x".to_string();
    let url_with = format!("{url}?account=__sprott__openai_codex__account_id__");
    let op = send(&state, "POST", &url_with, &auth, "{}").await.ask();
    assert_eq!(target(&state, &op), "ACCOUNT_ID");
    approve(&state, &op);
    let (_, sent_url) = send(&state, "POST", &url_with, &auth, "{}").await.sent();
    assert_eq!(sent_url, format!("{url}?account=acct-7"));
}

// ── what a permit binds ─────────────────────────────────────────────────────

/// A replay with another role, or an extra one, is another request: it
/// asks, for every kind of permit, and the approved replay still redeems.
#[tokio::test]
async fn a_replay_with_another_or_an_extra_role_is_not_redeemed() {
    for tier in [Tier::AskAlways, Tier::AskOnce, Tier::Exact, Tier::Unit] {
        let (_dir, state) = new_state();
        let mut vault = Vault::new()
            .service("acme", ACME)
            .secret("ACME_TOKEN", "tok")
            .secret("ACME_ID", "id");
        let (path, body) = match tier {
            Tier::AskAlways => {
                vault = vault.rule("acme", "t", "POST /x", AccessLevel::AskAlways, None);
                ("/x", "{}")
            }
            Tier::AskOnce => ("/once", "{}"),
            Tier::Exact => {
                vault = vault.rule("acme", "t", "POST /buy", AccessLevel::Ask, None);
                ("/buy", r#"{"amount":5}"#)
            }
            Tier::Unit => {
                vault = vault.rule("acme", "t", "POST /x", AccessLevel::Ask, None);
                ("/x", "{}")
            }
        };
        vault.unlock(&state);
        let url = format!("https://api.acme.dev{path}");
        let token = bearer("__sprott__acme__acme_token__");
        let id = bearer("__sprott__acme__acme_id__");
        let both = format!("{url}?i=__sprott__acme__acme_id__");
        let op = send(&state, "POST", &url, &token, body).await.ask();
        approve(&state, &op);
        send(&state, "POST", &url, &id, body).await.ask();
        send(&state, "POST", &both, &token, body).await.ask();
        assert_eq!(send(&state, "POST", &url, &token, body).await.sent().0, "Bearer tok", "{tier:?}");
    }
}

/// With no `[requests]` shape an approval covers the whole request (DESIGN
/// §4): the same replay redeems, also with a new `traceparent` or
/// `user-agent`; a body swap, an added query parameter or another port asks
/// again, and the miss names what differs, never a value.
#[tokio::test]
async fn an_approval_covers_the_whole_request() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "t", "POST /charge", AccessLevel::AskAlways, None)
        .unlock(&state);
    let url = "https://api.svc.dev/charge";
    let auth = bearer("__sprott__svc__");
    let body = r#"{"amount":5,"card":{"last4":"1111"}}"#;
    let op = send(&state, "POST", url, &auth, body).await.ask();
    approve(&state, &op);
    let replay = send_with(&state, "POST", url, &auth, &[("traceparent", "00-1-2-01"), ("user-agent", "x/1")], body);
    assert_eq!(replay.await.sent().0, "Bearer tok");
    let op = send(&state, "POST", url, &auth, body).await.ask();
    approve(&state, &op);
    for (url, body) in [
        (url, r#"{"amount":5000,"card":{"last4":"1111"}}"#),
        ("https://api.svc.dev/charge?capture=false", body),
        ("https://api.svc.dev:9443/charge", body),
    ] {
        send(&state, "POST", url, &auth, body).await.ask();
    }
    // An approved, unredeemed request for this line: a re-run that differs
    // is told where, never a value.
    let Out::Ask(_, text) = send(&state, "POST", url, &auth, r#"{"amount":5,"card":{"last4":"2222"}}"#).await
    else {
        panic!("asks");
    };
    assert!(text.contains("differs from the request approved at"), "{text}");
    assert!(text.contains("in: body.card."), "{text}");
    assert!(!text.contains("2222") && !text.contains("1111"), "no value: {text}");
    let tail: serde_json::Value = serde_json::from_str(text.trim_end().lines().last().unwrap()).unwrap();
    assert_eq!(tail["differs"]["components"], json!(["body.card"]));
    assert_eq!(send(&state, "POST", url, &auth, body).await.sent().0, "Bearer tok");
}

/// An `ask` window on a path a vault definition's `[requests]` shape matched
/// is keyed by what its consent shows (it may not narrow a single-use
/// approval, but a window is its scope and reads); a shape whose condition
/// errors makes the approval single-use; a rule's condition reads join what
/// an approval covers.
#[tokio::test]
async fn consent_and_condition_reads_are_covered_and_custom_definitions_dont_narrow() {
    const PAY: &str = r#"
[service]
id = "pay"
name = "Pay"
hosts = ["api.pay.dev"]
secrets = ["PAY_TOKEN"]
[requests.buy]
method = "POST"
path = "/buy"
scope = []
consent = "Buy for {{ request.body.amount }}"
[requests.refund]
method = "POST"
path = "/refund"
condition = "request.body.amount > 1"
scope = []
[requests.send]
method = "POST"
path = "/send"
scope = []
"#;
    let (_dir, state) = new_state();
    Vault::new()
        .service("pay", PAY)
        .secret("PAY_TOKEN", "tok")
        .rule("pay", "buy", "POST /buy", AccessLevel::Ask, None)
        .rule("pay", "refund", "POST /refund", AccessLevel::Ask, None)
        .rule("pay", "send", "POST /send", AccessLevel::AskAlways, None)
        .rule("pay", "acct", "POST /send", AccessLevel::AskAlways, Some("request.headers['x-account'] != 'dev'"))
        .unlock(&state);
    let auth = bearer("__sprott__pay__");
    // The window covers the consent's value only.
    let buy = "https://api.pay.dev/buy";
    let op = send(&state, "POST", buy, &auth, r#"{"amount":5,"note":"a"}"#).await.ask();
    approve(&state, &op);
    assert_eq!(send(&state, "POST", buy, &auth, r#"{"amount":5,"note":"b"}"#).await.sent().0, "Bearer tok");
    send(&state, "POST", buy, &auth, r#"{"amount":6,"note":"a"}"#).await.ask();
    // A shape condition that errors: single-use.
    let refund = "https://api.pay.dev/refund";
    let op = send(&state, "POST", refund, &auth, "{}").await.ask();
    {
        let approvals = state.approvals.lock().unwrap();
        let scope = &approvals.get_any(&op).unwrap().op.act.scope;
        assert_eq!(scope["single_use"], true);
        assert_eq!(scope["reuse"], "none");
    }
    // A vault definition's `scope = []` doesn't narrow a single-use approval;
    // a condition read joins what it covers.
    let send_url = "https://api.pay.dev/send";
    let prod = [("x-account", "prod")];
    let op = send_with(&state, "POST", send_url, &auth, &prod, r#"{"to":"a"}"#).await.ask();
    approve(&state, &op);
    send_with(&state, "POST", send_url, &auth, &prod, r#"{"to":"b"}"#).await.ask();
    assert_eq!(send_with(&state, "POST", send_url, &auth, &prod, r#"{"to":"a"}"#).await.sent().0, "Bearer tok");
    let op = send_with(&state, "POST", send_url, &auth, &prod, r#"{"to":"a"}"#).await.ask();
    approve(&state, &op);
    send_with(&state, "POST", send_url, &auth, &[("x-account", "staging")], r#"{"to":"a"}"#).await.ask();
    assert_eq!(send_with(&state, "POST", send_url, &auth, &prod, r#"{"to":"a"}"#).await.sent().0, "Bearer tok");
}

/// A method-override header is a reading of the method (DESIGN §6): `POST`
/// with `X-HTTP-Method-Override: DELETE` asks like the DELETE; a header that
/// isn't one method is refused; a long GET (`POST` + override + form body)
/// on a path where a `POST` rule reads the body is forwarded.
#[tokio::test]
async fn a_method_override_is_decided_as_that_method() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .floor("svc", AccessLevel::Allow, AccessLevel::Allow)
        .rule("svc", "drop", "DELETE /repos/:repo", AccessLevel::AskAlways, None)
        .rule("svc", "op", "POST /q", AccessLevel::AskAlways, Some("has(request.body.op) && request.body.op == 'drop'"))
        .unlock(&state);
    let auth = bearer("__sprott__svc__");
    let repo = "https://api.svc.dev/repos/r";
    assert_eq!(send(&state, "POST", repo, &auth, "{}").await.sent().0, "Bearer tok");
    for name in ["x-http-method-override", "X-HTTP-Method", "x-method-override"] {
        send_with(&state, "POST", repo, &auth, &[(name, "delete")], "{}").await.ask();
    }
    for bad in [&[("x-http-method-override", "DELETE, GET")][..], &[("x-http-method", "GET"), ("x-http-method", "GET")]] {
        let (code, _) = send_with(&state, "POST", repo, &auth, bad, "{}").await.refused();
        assert_eq!(code, "request_unreadable", "{bad:?}");
    }
    let long_get = [("x-http-method-override", "GET"), ("content-type", "application/x-www-form-urlencoded")];
    let q = "https://api.svc.dev/q";
    assert_eq!(send_with(&state, "POST", q, &auth, &long_get, "q=a&page=2").await.sent().0, "Bearer tok");
    send_with(&state, "POST", q, &auth, &long_get, "op=drop").await.ask();
}

/// Readings tied at the decided level under different units (here two
/// rules) make the approval single-use: a window under either rule would
/// serve requests the other decides.
#[tokio::test]
async fn tied_readings_under_different_units_are_single_use() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "edit", "POST /x", AccessLevel::Ask, None)
        .rule("svc", "drop", "DELETE /x", AccessLevel::Ask, None)
        .unlock(&state);
    let auth = bearer("__sprott__svc__");
    let url = "https://api.svc.dev/x";
    let reuse = |op: &str| {
        let approvals = state.approvals.lock().unwrap();
        let scope = &approvals.get_any(op).unwrap().op.act.scope;
        (scope["reuse"].as_str().unwrap_or_default().to_string(), scope["single_use"] == true)
    };
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    assert_eq!(reuse(&op), ("rule".to_string(), false));
    let op = send_with(&state, "POST", url, &auth, &[("x-http-method-override", "DELETE")], "{}").await.ask();
    assert_eq!(reuse(&op), ("none".to_string(), true));
}

/// A multipart/mixed batch of `application/http` requests (boundary `b`),
/// each a request line and its header lines.
fn batch_body(requests: &[&str]) -> String {
    let mut body = String::new();
    for (i, r) in requests.iter().enumerate() {
        body.push_str(&format!(
            "--b\r\nContent-Type: application/http\r\nContent-ID: <{i}>\r\n\r\n{r}\r\n\r\n"
        ));
    }
    body + "--b--\r\n"
}

/// A Google batch is decided by its requests (DESIGN §7): a batch of reads
/// is forwarded; one carrying a gated request asks, and its approval covers
/// the whole batch by content (a fresh boundary or Content-ID redeems,
/// another request asks again); a batch that can't be read one request at a
/// time asks.
#[tokio::test]
async fn a_google_batch_is_decided_by_its_requests() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .floor("svc", AccessLevel::Allow, AccessLevel::Allow)
        .rule("svc", "drop", "DELETE /items/:id", AccessLevel::AskAlways, None)
        .unlock(&state);
    let auth = bearer("__sprott__svc__");
    let url = "https://api.svc.dev/batch/items/v1";
    let mixed = |b: &str| format!("multipart/mixed; boundary={b}");
    let ct = mixed("b");
    let headers = [("content-type", ct.as_str())];
    let get = "GET /items/1 HTTP/1.1\r\n";
    let delete = "DELETE /items/1 HTTP/1.1\r\n";
    let reads = batch_body(&[get, "GET /items?page=2 HTTP/1.1\r\n"]);
    assert_eq!(send_with(&state, "POST", url, &auth, &headers, &reads).await.sent().0, "Bearer tok");
    // The same delete, overridden inside the batch.
    let overridden = "POST /items/1 HTTP/1.1\r\nX-HTTP-Method-Override: DELETE\r\n";
    send_with(&state, "POST", url, &auth, &headers, &batch_body(&[get, overridden])).await.ask();

    let gated = batch_body(&[get, delete]);
    let op = send_with(&state, "POST", url, &auth, &headers, &gated).await.ask();
    let names: Vec<String> = identity(&state, &op).components.iter().map(|(n, _)| n.clone()).collect();
    assert!(names.iter().any(|n| n.starts_with("batch[1].")), "{names:?}");
    approve(&state, &op);
    send_with(&state, "POST", url, &auth, &headers, &batch_body(&[get, delete, get])).await.ask();
    let fresh = gated.replace("--b", "--c").replace("<0>", "<x7>");
    let ct_c = mixed("c");
    let fresh_headers = [("content-type", ct_c.as_str())];
    let rerun = send_with(&state, "POST", url, &auth, &fresh_headers, &fresh);
    assert_eq!(rerun.await.sent().0, "Bearer tok");

    for unreadable in [reads.replace("--b--\r\n", ""), reads.replace(" HTTP/1.1", "")] {
        send_with(&state, "POST", url, &auth, &headers, &unreadable).await.ask();
    }
}

/// A stored user rule the daemon refuses decides (a refused `deny` denies
/// the connection), and the per-vault registry shows it on its connection
/// with why; an override of a rule the service lacks that would loosen is
/// only noted (DESIGN §2).
#[tokio::test]
async fn refused_user_rules_decide_and_show_on_their_connection() {
    let (_dir, state) = new_state();
    let vault = Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .floor("svc", AccessLevel::Allow, AccessLevel::Allow);
    let with = |rules: serde_json::Value| {
        vault.clone().policy(|p| {
            p.connections.entry("svc".into()).or_default().rules = serde_json::from_value(rules).unwrap();
        })
    };
    let notes = |state: &AppState| {
        let q = crate::server::handlers::registry::RegistryQuery {
            include: None,
            ids: None,
            view: None,
        };
        let v = crate::server::handlers::registry::vault_registry_value(state, V, &q, None).unwrap();
        v["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "svc")
            .map(|c| c["rule_notes"].clone())
            .unwrap()
    };
    let auth = bearer("__sprott__svc__");
    let url = "https://api.svc.dev/x";
    with(json!([{"override": "gone", "level": "allow"}])).unlock(&state);
    assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, "Bearer tok");
    let shown = notes(&state);
    assert_eq!(shown[0]["rule"], "gone");
    assert_eq!(shown[0]["refused"], false);
    with(json!([{"id": "old", "match": "DELETE /y", "level": "deny"}])).install(&state);
    let (code, _) = send(&state, "GET", url, &auth, "").await.refused();
    assert_eq!(code, "policy_denied");
    let shown = notes(&state);
    assert_eq!(shown[0]["rule"], "old");
    assert_eq!(shown[0]["refused"], true);
    assert!(shown[0]["why"].as_str().unwrap().contains("`match`"), "{shown}");
    with(json!([])).install(&state);
    assert_eq!(notes(&state), serde_json::Value::Null);
}

/// The permit identity is keyed by the vault's current content key: it
/// never rides the op the relay carries; an op minted before a lock and
/// approved after the unlock redeems; a daemon whose key is an earlier
/// generation's mints nothing and redeems nothing until `sprott unlock`.
#[tokio::test]
async fn the_identity_is_the_daemons_and_follows_the_content_key() {
    let (_dir, state) = new_state();
    let vault = Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "t", "POST /x", AccessLevel::AskAlways, None);
    vault.unlock(&state);
    let url = "https://api.svc.dev/x";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "POST", url, &auth, r#"{"a":1}"#).await.ask();
    let id = identity(&state, &op);
    assert_eq!(id.digest.len(), 64);
    let wire = serde_json::to_string(&state.approvals.lock().unwrap().get_any(&op).unwrap().op).unwrap();
    assert!(!wire.contains(&id.digest), "the relay never sees the identity");
    state.lock_vault(V);
    vault.unlock(&state);
    approve(&state, &op);
    assert_eq!(send(&state, "POST", url, &auth, r#"{"a":1}"#).await.sent().0, "Bearer tok");
    // Another member re-keyed: this session's key is the earlier generation's.
    let fx = crate::storage::sealed_vault::tests::rekeyed_fixture();
    let path = state.vaults.per_item_path(V).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    crate::storage::sealed_vault::write_per_item_atomic(&path, &fx.pv).unwrap();
    let before = ops(&state);
    let (code, _) = send(&state, "POST", url, &auth, r#"{"a":2}"#).await.refused();
    assert_eq!(code, "vault_locked");
    assert_eq!(ops(&state), before, "nothing minted");
}

/// A connection rebound to other KEYs after the approval: its permit is for
/// the old ones, so the replay asks.
#[tokio::test]
async fn a_rebind_to_other_keys_is_not_redeemed() {
    let (_dir, state) = new_state();
    let vault = Vault::new()
        .named("cf_work", "cloudflare", &[("CLOUDFLARE_API_TOKEN", "CF_A")])
        .secret("CF_A", "a")
        .secret("CF_B", "b")
        .rule("cf_work", "t", "POST /x", AccessLevel::AskAlways, None);
    vault.unlock(&state);
    let url = "https://api.cloudflare.com/x";
    let auth = bearer("__sprott__cf_work__cloudflare_api_token__");
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    assert_eq!(target(&state, &op), "CF_A");
    approve(&state, &op);
    vault
        .named("cf_work", "cloudflare", &[("CLOUDFLARE_API_TOKEN", "CF_B")])
        .install(&state);
    send(&state, "POST", url, &auth, "{}").await.ask();
}

/// An unrelated edit between approve and replay (another secret, another
/// role's value, another connection) keeps the approval.
#[tokio::test]
async fn an_unrelated_edit_between_approve_and_replay_keeps_the_approval() {
    let (_dir, state) = new_state();
    let vault = Vault::new()
        .secret("CLOUDFLARE_API_TOKEN", "cf-token")
        .secret("CLOUDFLARE_ACCOUNT_ID", "acct")
        .secret("OTHER", "x");
    vault.unlock(&state);
    let url = "https://api.cloudflare.com/client/v4/zones/z/dns_records/r";
    let auth = bearer("__sprott__cloudflare__cloudflare_api_token__");
    let op = send(&state, "DELETE", url, &auth, "").await.ask();
    approve(&state, &op);
    vault
        .clone()
        .secret("CLOUDFLARE_ACCOUNT_ID", "acct-2")
        .secret("OTHER", "y")
        .raw("more", "api.more.dev", &["OTHER"])
        .install(&state);
    assert_eq!(send(&state, "DELETE", url, &auth, "").await.sent().0, "Bearer cf-token");
}

// ── refusals before anything is asked ──────────────────────────────────────

/// An unknown role or an unset KEY is a 4xx at once: no op, and no widen op
/// even toward a host the connection does not anchor.
#[tokio::test]
async fn an_unknown_role_or_an_unset_key_is_a_4xx_with_no_op() {
    let (_dir, state) = new_state();
    Vault::new()
        .secret("CLOUDFLARE_API_TOKEN", "cf-token")
        .rule("cloudflare", "t", "POST /x", AccessLevel::AskAlways, None)
        .unlock(&state);
    let (code, msg) = send(&state, "POST", "https://elsewhere.dev/x", &bearer("__sprott__cloudflare__nope__"), "{}")
        .await
        .refused();
    assert_eq!(code, "unknown_role");
    assert!(msg.contains("'nope'") && msg.contains("__sprott__cloudflare__cloudflare_api_token__"), "{msg}");
    let (code, msg) = send(
        &state,
        "POST",
        "https://elsewhere.dev/x",
        &bearer("__sprott__cloudflare__cloudflare_account_id__"),
        "{}",
    )
    .await
    .refused();
    assert_eq!(code, "secret_not_set");
    assert!(msg.contains("CLOUDFLARE_ACCOUNT_ID"), "{msg}");
    let (code, _) = send(&state, "POST", "https://api.cloudflare.com/x", &bearer("__sprott__cloudflare__refresh__"), "{}")
        .await
        .refused();
    assert_eq!(code, "unknown_role");
    assert_eq!(ops(&state), 0);
    // A mint input is refused by name.
    let (code, _) = send(
        &state,
        "GET",
        "https://gmail.googleapis.com/x",
        &bearer("__sprott__gmail__gmail_refresh_token__"),
        "",
    )
    .await
    .refused();
    assert_eq!(code, "refresh_forbidden");
    assert_eq!(ops(&state), 0);
}

/// A role-less phantom with several candidates and none present names them
/// all; with the key-changed note it says they may be in rows this device
/// can't read.
#[tokio::test]
async fn an_unset_role_less_phantom_names_every_candidate() {
    let (_dir, state) = new_state();
    Vault::new().unlock(&state);
    let auth = bearer("__sprott__cloudflare__");
    let (code, msg) = send(&state, "GET", "https://api.cloudflare.com/x", &auth, "").await.refused();
    assert_eq!(code, "secret_not_set");
    assert!(msg.contains("CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID") || msg.contains("CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN"), "{msg}");
    state.mark_vault_key_changed(V);
    let (code, msg) = send(&state, "GET", "https://api.cloudflare.com/x", &bearer("__sprott__cloudflare__cloudflare_api_token__"), "")
        .await
        .refused();
    assert_eq!(code, "vault_key_changed");
    assert!(msg.contains("CLOUDFLARE_API_TOKEN is unset, or in a row this device can't read"), "{msg}");
}

/// Deny refuses before any value is looked for: a KEY in no store, an
/// external store configured, no store call.
#[tokio::test]
async fn deny_with_an_unset_key_is_the_policy_refusal_and_fetches_nothing() {
    let (_dir, state) = new_state();
    let name = format!("deny-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .store(&name, true)
        .rule("svc", "no", "DELETE /x", AccessLevel::Deny, None)
        .unlock(&state);
    let (code, _) = send(&state, "DELETE", "https://api.svc.dev/x", &bearer("__sprott__svc__"), "")
        .await
        .refused();
    assert_eq!(code, "policy_denied");
    assert_eq!(ext.calls(), 0);
}

/// A connection whose vault definition is not loaded gets the not-loaded
/// refusal, with why.
#[tokio::test]
async fn a_connection_whose_definition_is_not_loaded_is_refused() {
    let (_dir, state) = new_state();
    Vault::new()
        .service("broken", "[service]\nid = \"broken\"\n")
        .named("mine", "broken", &[])
        .unlock(&state);
    let (code, msg) = send(&state, "GET", "https://api.x.dev/x", &bearer("__sprott__mine__"), "")
        .await
        .refused();
    assert_eq!(code, "service_not_loaded");
    assert!(msg.contains("'broken'") && msg.contains("not loaded"), "{msg}");
}

// ── the permit's lifecycle ──────────────────────────────────────────────────

/// A failure between the permit lookup and its spending keeps the permit:
/// here the value can't go into the outgoing request (not UTF-8). The value
/// fixed (a value change keeps permits), the replay redeems.
#[tokio::test]
async fn a_failure_before_consume_keeps_the_permit() {
    let (_dir, state) = new_state();
    let vault = Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .rule("svc", "t", "POST /x", AccessLevel::AskAlways, None);
    vault.clone().secret_bytes("SVC_TOKEN", &[0xff, 0xfe]).unlock(&state);
    let url = "https://api.svc.dev/x";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    approve(&state, &op);
    let (code, _) = send(&state, "POST", url, &auth, "{}").await.refused();
    assert_eq!(code, "secret_encoding");
    vault.secret("SVC_TOKEN", "good").install(&state);
    assert_eq!(send(&state, "POST", url, &auth, "{}").await.sent().0, "Bearer good");
}

/// Two replays of one single-use approval: one is forwarded, the other asks.
#[tokio::test]
async fn concurrent_replays_forward_one() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "t", "POST /x", AccessLevel::AskAlways, None)
        .unlock(&state);
    let url = "https://api.svc.dev/x";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    approve(&state, &op);
    let (a, b) = tokio::join!(
        send(&state, "POST", url, &auth, "{}"),
        send(&state, "POST", url, &auth, "{}")
    );
    let sent = [&a, &b].iter().filter(|o| matches!(o, Out::Sent(..))).count();
    let asked = [&a, &b].iter().filter(|o| matches!(o, Out::Ask(..))).count();
    assert_eq!((sent, asked), (1, 1), "{} / {}", a.describe(), b.describe());
}

/// Both replays pass the permit lookup; the one that spends it second is
/// not let through, and a lock between the lookup and the spending answers
/// `VaultLocked` without minting anything.
#[tokio::test]
async fn the_permit_is_spent_once_and_a_lock_before_spending_is_vault_locked() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "t", "POST /x", AccessLevel::AskAlways, None)
        .unlock(&state);
    let url = "https://api.svc.dev/x";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    approve(&state, &op);
    let identity = identity(&state, &op);
    let snapshot = state.snapshot(V).unwrap();
    let key = || {
        crate::state::PermitKey::of(
            AccessLevel::AskAlways,
            &crate::core::policy::DecidedBy::Rule {
                id: Some("t".into()),
                label: None,
            },
            false,
            AG,
            "svc",
            "POST",
            "api.svc.dev",
            "/x",
            &identity,
            crate::state::CredentialSet::new("svc", ["SVC_TOKEN".to_string()]),
        )
    };
    let a = state.authorize(V, snapshot.clone(), BTreeMap::new(), key()).unwrap();
    let b = state.authorize(V, snapshot.clone(), BTreeMap::new(), key()).unwrap();
    assert!(state.consume(V, a).unwrap());
    assert!(!state.consume(V, b).unwrap(), "the loser goes to the portal");
    let c = state.authorize(V, snapshot, BTreeMap::new(), key());
    assert!(matches!(c, Err(crate::state::Unauthorized::NoPermit)));
}

/// A lock that lands after a replay's permit was found and before it is
/// spent (here: while its access token is being minted) answers
/// `vault_locked`; no op is minted for it.
#[tokio::test]
async fn a_lock_between_the_permit_and_its_spending_is_vault_locked() {
    let (_dir, state) = new_state();
    // A token endpoint that says when a mint reached it, then answers late.
    let reached = Arc::new(tokio::sync::Notify::new());
    let hit = reached.clone();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move || {
            let hit = hit.clone();
            async move {
                hit.notify_one();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                axum::Json(json!({ "access_token": "at", "expires_in": 3600 }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/token", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Vault::new()
        .service("acme", MINTED)
        .secret("ACME_REFRESH_TOKEN", "rt-0")
        .rule("acme", "t", "POST /x", AccessLevel::AskAlways, None)
        .unlock(&state);
    state.edit_snapshot(V, |s| {
        if let Some(crate::service::AuthDef::Oauth2(o)) = s.inputs.custom.get_mut("acme").and_then(|d| d.auth.as_mut()) {
            o.token_url = Some(url.clone());
        }
    });
    let auth = bearer("__sprott__acme__");
    let op = send(&state, "POST", "https://api.acme.dev/x", &auth, "{}").await.ask();
    approve(&state, &op);
    let before = ops(&state);
    let lock = async {
        reached.notified().await;
        state.lock_vault(V);
    };
    let (replay, ()) = tokio::join!(send(&state, "POST", "https://api.acme.dev/x", &auth, "{}"), lock);
    assert_eq!(replay.refused().0, "vault_locked");
    assert_eq!(ops(&state), before, "no op");
}

/// A Use approval while the vault is locked marks the op approved and
/// stores nothing: the replay answers `VaultLocked`, and after the unlock it
/// asks again.
#[tokio::test]
async fn a_use_approval_while_locked_stores_nothing() {
    let (_dir, state) = new_state();
    let vault = Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "t", "POST /x", AccessLevel::AskAlways, None);
    vault.unlock(&state);
    let url = "https://api.svc.dev/x";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    state.lock_vault(V);
    approve(&state, &op);
    assert!(matches!(
        state.approvals.lock().unwrap().get_any(&op).unwrap().status,
        crate::approval::ApprovalStatus::Approved
    ));
    assert_eq!(send(&state, "POST", url, &auth, "{}").await.refused().0, "vault_locked");
    vault.unlock(&state);
    send(&state, "POST", url, &auth, "{}").await.ask();
}

/// Any policy edit ends the vault's windows; one between mint and approve
/// leaves the op approved with no window; A→B→A keeps the old window ended.
#[tokio::test]
async fn a_policy_edit_ends_windows() {
    let (_dir, state) = new_state();
    let a = Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "t", "POST /x", AccessLevel::Ask, None);
    let b = a.clone().policy(|p| p.timeout = Some(120));
    a.unlock(&state);
    let url = "https://api.svc.dev/x";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    approve(&state, &op);
    assert!(matches!(send(&state, "POST", url, &auth, "{}").await, Out::Sent(..)));
    // An unrelated vault change keeps the window.
    a.clone().secret("OTHER", "x").install(&state);
    assert!(matches!(send(&state, "POST", url, &auth, "{}").await, Out::Sent(..)));
    // A→B ends it; B→A does not bring it back.
    b.install(&state);
    send(&state, "POST", url, &auth, "{}").await.ask();
    a.install(&state);
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    // An edit between mint and approve: approved, no window stored.
    b.install(&state);
    approve(&state, &op);
    assert!(matches!(
        state.approvals.lock().unwrap().get_any(&op).unwrap().status,
        crate::approval::ApprovalStatus::Approved
    ));
    send(&state, "POST", url, &auth, "{}").await.ask();
}

/// A window op minted before a lock, the policy edited while locked: after
/// the unlock its approval stores no window.
#[tokio::test]
async fn a_policy_edited_while_locked_stores_no_window_for_an_older_op() {
    let (_dir, state) = new_state();
    let a = Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "t", "POST /x", AccessLevel::Ask, None);
    a.unlock(&state);
    let url = "https://api.svc.dev/x";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    state.lock_vault(V);
    a.policy(|p| p.timeout = Some(90)).unlock(&state);
    approve(&state, &op);
    send(&state, "POST", url, &auth, "{}").await.ask();
}

// ── the host anchor ─────────────────────────────────────────────────────────

/// An unanchored host asks to widen even on a vault that keeps one row this
/// device can't read (the key-changed note); while the device's copy is
/// behind its store it says so, naming the host, instead.
#[tokio::test]
async fn widen_follows_the_behind_bit_not_the_key_changed_note() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .unlock(&state);
    state.mark_vault_key_changed(V);
    let auth = bearer("__sprott__svc__");
    assert!(matches!(send(&state, "GET", "https://new.svc.dev/x", &auth, "").await, Out::Widen(_)));
    let before = ops(&state);
    state
        .runtime(V)
        .unwrap()
        .behind
        .store(true, std::sync::atomic::Ordering::Release);
    let (code, msg) = send(&state, "GET", "https://new.svc.dev/x", &auth, "").await.refused();
    assert_eq!(code, "vault_key_changed");
    assert!(msg.contains("'new.svc.dev'") && msg.contains("sprott unlock"), "{msg}");
    assert_eq!(ops(&state), before, "no widen op");
}

// ── where values come from ──────────────────────────────────────────────────

/// A KEY of an ask-floor connection is held sealed. Served after approval;
/// retries while the approval is pending open nothing and call no store;
/// the snapshot holds no plaintext of it after the request.
#[tokio::test]
async fn a_non_resident_key_is_served_after_approval_and_stays_sealed() {
    let (_dir, state) = new_state();
    let name = format!("sealed-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    ext.set("EXT_TOKEN", "ext-7f3a");
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN", "EXT_TOKEN"])
        .secret("SVC_TOKEN", "native-7f3a")
        .store(&name, false)
        .floor("svc", AccessLevel::Ask, AccessLevel::Ask)
        .unlock(&state);
    assert_eq!(state.snapshot(V).unwrap().holds("SVC_TOKEN"), Some("sealed"));
    let url = "https://api.svc.dev/x?e=__sprott__svc__ext_token__";
    let auth = bearer("__sprott__svc__svc_token__");
    let op = send(&state, "GET", url, &auth, "").await.ask();
    assert_eq!(ext.calls(), 1, "one walk");
    for _ in 0..3 {
        send(&state, "GET", url, &auth, "").await.ask();
    }
    assert_eq!(state.seal_opens(V), 0, "nothing opened while pending");
    assert_eq!(ext.calls(), 1, "no store call while pending");
    approve(&state, &op);
    let (sent, sent_url) = send(&state, "GET", url, &auth, "").await.sent();
    assert_eq!(sent, "Bearer native-7f3a");
    assert!(sent_url.ends_with("?e=ext-7f3a"), "{sent_url}");
    assert_eq!(state.seal_opens(V), 2);
    assert_eq!(ext.calls(), 1, "the fetched value is carried, not fetched again");
    let snapshot = state.snapshot(V).unwrap();
    assert_eq!(snapshot.holds("SVC_TOKEN"), Some("sealed"));
    let dump = format!("{:?}", snapshot);
    assert!(!dump.contains("7f3a"), "{dump}");
}

/// A lock while a sealed value is about to be opened: `VaultLocked`.
#[tokio::test]
async fn a_lock_before_the_open_is_vault_locked() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .floor("svc", AccessLevel::Ask, AccessLevel::Ask)
        .unlock(&state);
    let snapshot = state.snapshot(V).unwrap();
    let at = snapshot.locate(&state, V, "SVC_TOKEN", false).await.unwrap().unwrap();
    let auth = state
        .authorize(V, snapshot, [("SVC_TOKEN".to_string(), at)].into_iter().collect(), None)
        .unwrap();
    state.lock_vault(V);
    assert!(matches!(
        state.materialize(V, &auth),
        Err(crate::state::Unreadable::Refused(crate::error::AppError::VaultLocked))
    ));
}

/// External listed before native: once a walk found a KEY in native, a
/// request makes no store call.
#[tokio::test]
async fn an_external_before_native_walk_calls_the_store_once() {
    let (_dir, state) = new_state();
    let name = format!("first-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .store(&name, true)
        .unlock(&state);
    for _ in 0..3 {
        assert_eq!(send(&state, "GET", "https://api.svc.dev/x", &bearer("__sprott__svc__"), "").await.sent().0, "Bearer tok");
    }
    assert_eq!(ext.calls(), 1);
}

/// A KEY added to an external store after a miss is found by the next
/// request: an explicit role, and a role-less phantom on a single-secret
/// connection, walk again.
#[tokio::test]
async fn a_key_added_to_an_external_store_later_is_found() {
    let (_dir, state) = new_state();
    let name = format!("later-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    Vault::new()
        .raw("one", "api.one.dev", &["ONE_TOKEN"])
        .raw("two", "api.two.dev", &["TWO_A", "TWO_B"])
        .secret("TWO_A", "a")
        .store(&name, false)
        .unlock(&state);
    let explicit = bearer("__sprott__two__two_b__");
    assert_eq!(send(&state, "GET", "https://api.two.dev/x", &explicit, "").await.refused().0, "secret_not_set");
    ext.set("TWO_B", "b");
    assert_eq!(send(&state, "GET", "https://api.two.dev/x", &explicit, "").await.sent().0, "Bearer b");

    let role_less = bearer("__sprott__one__");
    assert_eq!(send(&state, "GET", "https://api.one.dev/x", &role_less, "").await.refused().0, "secret_not_set");
    ext.set("ONE_TOKEN", "one");
    assert_eq!(send(&state, "GET", "https://api.one.dev/x", &role_less, "").await.sent().0, "Bearer one");
}

/// A role-less phantom on a two-secret connection with one KEY unset and an
/// external store configured: one walk finds the unset KEY nowhere, and
/// later requests make no store call.
#[tokio::test]
async fn a_role_less_phantom_with_one_key_unset_walks_once() {
    let (_dir, state) = new_state();
    let name = format!("roleless-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    Vault::new()
        .secret("CLOUDFLARE_API_TOKEN", "cf-token")
        .store(&name, false)
        .unlock(&state);
    let auth = bearer("__sprott__cloudflare__");
    for _ in 0..3 {
        assert_eq!(send(&state, "GET", "https://api.cloudflare.com/x", &auth, "").await.sent().0, "Bearer cf-token");
    }
    assert_eq!(ext.calls(), 1);
}

/// A role-less phantom none of whose candidates is present anywhere walks
/// each KEY once per request: the first request walks both for the first
/// time, a later one walks again only what the record said was absent.
#[tokio::test]
async fn an_unset_role_less_phantom_walks_each_key_once_per_request() {
    let (_dir, state) = new_state();
    let name = format!("unset-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    Vault::new().store(&name, false).unlock(&state);
    let auth = bearer("__sprott__cloudflare__");
    let refused = |o: Out| o.refused().0;
    assert_eq!(refused(send(&state, "GET", "https://api.cloudflare.com/x", &auth, "").await), "secret_not_set");
    assert_eq!(ext.calls(), 2);
    assert_eq!(refused(send(&state, "GET", "https://api.cloudflare.com/x", &auth, "").await), "secret_not_set");
    assert_eq!(ext.calls(), 4);
    ext.set("CLOUDFLARE_ACCOUNT_ID", "acct");
    assert_eq!(
        send(&state, "GET", "https://api.cloudflare.com/x", &auth, "").await.sent().0,
        "Bearer acct"
    );
}

/// A store in an outage refuses a KEY it precedes, at allow too, and the
/// request asks nothing.
#[tokio::test]
async fn a_broken_store_ahead_of_native_refuses_at_allow() {
    let (_dir, state) = new_state();
    let name = format!("down-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    ext.down.store(true, std::sync::atomic::Ordering::SeqCst);
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .store(&name, true)
        .unlock(&state);
    let (code, msg) = send(&state, "GET", "https://api.svc.dev/x", &bearer("__sprott__svc__"), "").await.refused();
    assert_eq!(code, "store_unavailable");
    assert!(msg.contains("'ext'"), "{msg}");
    ext.down.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(send(&state, "GET", "https://api.svc.dev/x", &bearer("__sprott__svc__"), "").await.sent().0, "Bearer tok");
}

/// The console's external key names: a walk that finds a KEY in an
/// external store adds it; after the store is removed they are gone.
#[tokio::test]
async fn external_key_names_follow_the_stores() {
    let (_dir, state) = new_state();
    let name = format!("names-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    ext.set("SVC_TOKEN", "tok");
    let vault = Vault::new().raw("svc", "api.svc.dev", &["SVC_TOKEN"]);
    vault.clone().store(&name, false).unlock(&state);
    send(&state, "GET", "https://api.svc.dev/x", &bearer("__sprott__svc__"), "").await.sent();
    assert!(state.external_key_names(V).contains("SVC_TOKEN"));
    vault.store(&name, false).install(&state);
    assert!(state.external_key_names(V).contains("SVC_TOKEN"), "kept by the next install");
    Vault::new().raw("svc", "api.svc.dev", &["SVC_TOKEN"]).no_store().install(&state);
    assert!(state.external_key_names(V).is_empty());
}

// ── residency ───────────────────────────────────────────────────────────────

/// Resident = bound to a connection whose GET floor is allow (implicit
/// default connections included); every other bound KEY is sealed; a KEY
/// nothing binds is a name only. A raw connection named like a built-in
/// takes its recipe (gmail: reads go through), a vault definition its stricter
/// defaults. A floor edit moves KEYs at the next build.
#[tokio::test]
async fn residency_follows_the_get_floor() {
    let (_dir, state) = new_state();
    let custom = r#"
[service]
id = "careful"
name = "Careful"
hosts = ["api.careful.dev"]
secrets = ["CAREFUL_KEY"]
[policy.levels]
read = "ask"
"#;
    let vault = Vault::new()
        .raw("gmail", "gmail.googleapis.com", &["MAIL_KEY"])
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .service("careful", custom)
        .secret("MAIL_KEY", "m")
        .secret("SVC_TOKEN", "s")
        .secret("CAREFUL_KEY", "c")
        .secret("GITHUB_TOKEN", "g")
        .secret("UNBOUND", "u");
    vault.unlock(&state);
    let snap = state.snapshot(V).unwrap();
    assert_eq!(snap.holds("MAIL_KEY"), Some("resident"));
    assert_eq!(snap.holds("CAREFUL_KEY"), Some("sealed"));
    assert_eq!(snap.holds("SVC_TOKEN"), Some("resident"));
    assert_eq!(snap.holds("GITHUB_TOKEN"), Some("resident"), "the implicit default connection");
    assert_eq!(snap.holds("UNBOUND"), Some("name only"));
    vault
        .clone()
        .floor("svc", AccessLevel::Ask, AccessLevel::Allow)
        .install(&state);
    assert_eq!(state.snapshot(V).unwrap().holds("SVC_TOKEN"), Some("sealed"));
    vault.install(&state);
    assert_eq!(state.snapshot(V).unwrap().holds("SVC_TOKEN"), Some("resident"));
}

/// No `{:?}` of the snapshot, the vault state, an authorized request or its
/// values prints a value, K or S.
#[tokio::test]
async fn debug_output_holds_no_plaintext() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .raw("asks", "api.asks.dev", &["SEALED_TOKEN"])
        .floor("asks", AccessLevel::Ask, AccessLevel::Ask)
        .secret("SVC_TOKEN", "plain-secret-value")
        .secret("SEALED_TOKEN", "sealed-secret-value")
        .unlock(&state);
    let snapshot = state.snapshot(V).unwrap();
    assert_eq!(snapshot.holds("SEALED_TOKEN"), Some("sealed"));
    let mut keys = BTreeMap::new();
    for key in ["SVC_TOKEN", "SEALED_TOKEN"] {
        let at = snapshot.locate(&state, V, key, false).await.unwrap().unwrap();
        keys.insert(key.to_string(), at);
    }
    let auth = state.authorize(V, snapshot.clone(), keys, None).unwrap();
    let values = state.materialize(V, &auth).unwrap();
    assert_eq!(values.get("SEALED_TOKEN"), Some(&b"sealed-secret-value"[..]));
    let runtime = state.runtime(V).unwrap();
    let dumps = [
        format!("{:?}", snapshot),
        format!("{:?}", *runtime.state.lock().unwrap()),
        format!("{:?}", auth),
        format!("{:?}", values),
    ];
    for dump in dumps {
        assert!(!dump.contains("secret-value"), "{dump}");
        assert!(!dump.contains("81, 81") && !dump.contains("0x51"), "{dump}");
    }
}

/// S lives as long as the Unlocked state: a vault-unlock on an Unlocked
/// vault and an approved write under another K keep it, so a sealed value
/// of an earlier snapshot still opens.
#[tokio::test]
async fn s_outlives_a_re_unlock_and_a_k_rotation() {
    let (_dir, state) = new_state();
    let vault = Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .floor("svc", AccessLevel::Ask, AccessLevel::Ask)
        .secret("SVC_TOKEN", "tok");
    vault.unlock(&state);
    let first = state.snapshot(V).unwrap();
    vault.unlock(&state);
    let k2 = zeroize::Zeroizing::new(vec![0x77u8; 32]);
    assert!(state.install_view(V, vault.view(), k2, false).served());
    let at = first.locate(&state, V, "SVC_TOKEN", false).await.unwrap().unwrap();
    let auth = state
        .authorize(V, first, [("SVC_TOKEN".to_string(), at)].into_iter().collect(), None)
        .unwrap();
    assert_eq!(state.materialize(V, &auth).unwrap().get("SVC_TOKEN"), Some(&b"tok"[..]));
}

// ── minted connections and stored rotations ─────────────────────────────────

/// A vault definition minting access tokens from a refresh token (its token
/// endpoint is pointed at a local server once served: the gate admits only
/// a public https one).
const MINTED: &str = r#"
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
"#;

/// A rotating token endpoint: of each family only the newest refresh token
/// `<family>-<n>` is good; a refresh answers access token `at-<family>-<n+1>`
/// and refresh token `<family>-<n+1>`. Every refresh token it was sent, in
/// order.
struct TokenEndpoint {
    url: String,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

async fn token_endpoint(expires_in: u64) -> TokenEndpoint {
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let newest: Arc<std::sync::Mutex<HashMap<String, u32>>> = Default::default();
    let (log, issued) = (seen.clone(), newest.clone());
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move |body: String| {
            let (log, issued) = (log.clone(), issued.clone());
            async move {
                let sent = url::form_urlencoded::parse(body.as_bytes())
                    .find(|(k, _)| k == "refresh_token")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                log.lock().unwrap().push(sent.clone());
                let (family, n) = sent.rsplit_once('-').unwrap_or(("", ""));
                let n: u32 = n.parse().unwrap_or(u32::MAX);
                let mut issued = issued.lock().unwrap();
                let current = *issued.entry(family.to_string()).or_insert(0);
                if n != current {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(json!({ "error": "invalid_grant" })),
                    );
                }
                issued.insert(family.to_string(), n + 1);
                (
                    axum::http::StatusCode::OK,
                    axum::Json(json!({
                        "access_token": format!("at-{}-{}", family, n + 1),
                        "expires_in": expires_in,
                        "refresh_token": format!("{}-{}", family, n + 1),
                    })),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    TokenEndpoint {
        url: format!("http://{}/token", addr),
        seen,
    }
}

impl TokenEndpoint {
    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    /// Point the served snapshot's minted definitions at this endpoint.
    fn serve(&self, state: &AppState) {
        let url = self.url.clone();
        state.edit_snapshot(V, |s| {
            for def in s.inputs.custom.values_mut() {
                if let Some(crate::service::AuthDef::Oauth2(o)) = def.auth.as_mut() {
                    o.token_url = Some(url.clone());
                }
            }
        });
    }
}

/// The vault's per-item store on disk under K, holding these secrets (what
/// a rotation writes to; the snapshot is served from the matching view).
fn store_secrets(state: &AppState, secrets: &[(&str, &str)]) {
    use crate::storage::item::{ItemPayload, VaultKeys};
    use crate::storage::sealed_vault::{read_per_item, write_per_item_atomic, PerItemVault};
    type S = sudp::primitives::StdPrimitives;
    let path = state.vaults.per_item_path(V).unwrap();
    let mut pv = read_per_item(&path).unwrap().unwrap_or_else(|| {
        PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap()
    });
    for (key, value) in secrets {
        let payload = ItemPayload::secret_live(*key, *value);
        pv.seal_and_bump::<S>(VaultKeys::single(&K), V, payload.ns, &payload.name.clone(), &payload)
            .unwrap();
    }
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    write_per_item_atomic(&path, &pv).unwrap();
}

/// What follows a token "more than an hour" later: the in-process memory of
/// rotations (one hour) is gone.
fn an_hour_passes(state: &AppState) {
    state.oauth_rotated_to.lock().unwrap().clear();
}

/// A stored rotation keeps every permit and serves the new token from the
/// snapshot it patched, past the hour the in-process rotation memory lasts,
/// rotation after rotation, with no install.
#[tokio::test]
async fn a_stored_rotation_keeps_permits_and_serves_the_newest_token() {
    let (_dir, state) = new_state();
    let tokens = token_endpoint(0).await;
    Vault::new()
        .service("acme", MINTED)
        .secret("ACME_REFRESH_TOKEN", "rt-0")
        .rule("acme", "t", "GET /x", AccessLevel::Ask, None)
        .unlock(&state);
    store_secrets(&state, &[("ACME_REFRESH_TOKEN", "rt-0")]);
    tokens.serve(&state);
    let url = "https://api.acme.dev/x";
    let auth = bearer("__sprott__acme__");
    let op = send(&state, "GET", url, &auth, "").await.ask();
    assert_eq!(target(&state, &op), "ACME_REFRESH_TOKEN");
    approve(&state, &op);
    for n in 1..=3 {
        let (sent, _) = send(&state, "GET", url, &auth, "").await.sent();
        assert_eq!(sent, format!("Bearer at-rt-{n}"), "the window and the token survive");
        assert_eq!(
            state.served_native(V, "ACME_REFRESH_TOKEN"),
            Some(format!("rt-{n}").into_bytes())
        );
        an_hour_passes(&state);
    }
    assert_eq!(tokens.seen(), vec!["rt-0", "rt-1", "rt-2"]);
}

/// A rotation stored, then one that can't be: the newest token is used
/// meanwhile and the retry stores it, after which it is served.
#[tokio::test]
async fn a_stored_then_unstored_rotation_keeps_the_newest_token() {
    let (_dir, state) = new_state();
    let tokens = token_endpoint(0).await;
    Vault::new()
        .service("acme", MINTED)
        .secret("ACME_REFRESH_TOKEN", "rt-0")
        .unlock(&state);
    store_secrets(&state, &[("ACME_REFRESH_TOKEN", "rt-0")]);
    tokens.serve(&state);
    let url = "https://api.acme.dev/x";
    let auth = bearer("__sprott__acme__");
    assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, "Bearer at-rt-1");
    let path = state.vaults.per_item_path(V).unwrap();
    let good = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, "Bearer at-rt-2");
    assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, "Bearer at-rt-3");
    assert!(state.has_pending_rotations(V));
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, good).unwrap();
    crate::auth::connect::retry_pending_rotations(&state, V).await;
    assert!(!state.has_pending_rotations(V));
    assert_eq!(state.served_native(V, "ACME_REFRESH_TOKEN"), Some(b"rt-3".to_vec()));
    an_hour_passes(&state);
    assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, "Bearer at-rt-4");
    assert_eq!(tokens.seen(), vec!["rt-0", "rt-1", "rt-2", "rt-3"]);
}

/// External store listed before native, not holding the refresh token: a
/// stored rotation lands in native, and the next request walks again and
/// takes it from there (the patch dropped the KEY's memo entry), refresh
/// after refresh.
#[tokio::test]
async fn an_external_first_store_without_the_token_serves_the_newest_rotation() {
    let (_dir, state) = new_state();
    let tokens = token_endpoint(0).await;
    let name = format!("rotate-{}", uuid::Uuid::new_v4());
    let ext = crate::store::memory::store(&name);
    Vault::new()
        .service("acme", MINTED)
        .secret("ACME_REFRESH_TOKEN", "rt-0")
        .store(&name, true)
        .unlock(&state);
    store_secrets(&state, &[("ACME_REFRESH_TOKEN", "rt-0")]);
    tokens.serve(&state);
    let url = "https://api.acme.dev/x";
    let auth = bearer("__sprott__acme__");
    for n in 1..=3 {
        assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, format!("Bearer at-rt-{n}"));
        an_hour_passes(&state);
    }
    assert_eq!(tokens.seen(), vec!["rt-0", "rt-1", "rt-2"]);
    assert_eq!(ext.calls(), 3, "one walk per patched snapshot");
}

/// A refresh token on an ask floor is sealed; a stored rotation re-seals the
/// new one, which is served hours later with no install.
#[tokio::test]
async fn a_non_resident_rotating_connection_serves_its_new_token() {
    let (_dir, state) = new_state();
    let tokens = token_endpoint(0).await;
    Vault::new()
        .service("acme", MINTED)
        .secret("ACME_REFRESH_TOKEN", "rt-0")
        .floor("acme", AccessLevel::Ask, AccessLevel::Ask)
        .unlock(&state);
    store_secrets(&state, &[("ACME_REFRESH_TOKEN", "rt-0")]);
    tokens.serve(&state);
    assert_eq!(state.snapshot(V).unwrap().holds("ACME_REFRESH_TOKEN"), Some("sealed"));
    let url = "https://api.acme.dev/x";
    let auth = bearer("__sprott__acme__");
    let op = send(&state, "GET", url, &auth, "").await.ask();
    approve(&state, &op);
    assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, "Bearer at-rt-1");
    assert_eq!(state.snapshot(V).unwrap().holds("ACME_REFRESH_TOKEN"), Some("sealed"));
    an_hour_passes(&state);
    an_hour_passes(&state);
    assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, "Bearer at-rt-2");
    assert_eq!(tokens.seen(), vec!["rt-0", "rt-1"]);
}

/// Seal `vault` as a whole-blob `vault.dat` under K (no per-item store).
fn write_whole_blob(state: &AppState, vault: &Vault) {
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};
    let mut m = sudp::state::ProtectedState::new();
    m.aux = serde_json::to_value(&vault.aux).unwrap();
    for (key, value) in &vault.secrets {
        m.put_secret(key.clone(), value.clone());
    }
    let version = sudp::state::CURRENT_VERSION;
    let mut ad = DS_SEAL.to_vec();
    ad.extend_from_slice(&version.to_be_bytes());
    let ct = ChaCha20Poly1305::seal(&K, &m.to_canonical().unwrap(), &ad).unwrap();
    let sealed: crate::storage::SealedVault = serde_json::from_value(json!({
        "version": version,
        "registry": {},
        "credentials": [],
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ct),
    }))
    .unwrap();
    let path = state.vaults.vault_path(V).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    crate::storage::sealed_vault::write_atomic(&path, &sealed).unwrap();
}

fn unlock_from_store(state: &AppState) {
    let key = crate::state::InstallKey::Unlock(zeroize::Zeroizing::new(K.to_vec()));
    assert!(state.install(V, key).served());
}

/// A whole-blob vault: an ask-floor KEY is sealed like any other and served
/// after approval.
#[tokio::test]
async fn a_whole_blob_ask_floor_key_is_sealed_and_served_after_approval() {
    let (_dir, state) = new_state();
    let vault = Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "blob-7f3a")
        .floor("svc", AccessLevel::Ask, AccessLevel::Ask);
    write_whole_blob(&state, &vault);
    unlock_from_store(&state);
    let snapshot = state.snapshot(V).unwrap();
    assert_eq!(snapshot.holds("SVC_TOKEN"), Some("sealed"));
    assert!(snapshot.readable.contains(crate::storage::sealed_vault::WHOLE_BLOB_ROW));
    let url = "https://api.svc.dev/x";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "GET", url, &auth, "").await.ask();
    approve(&state, &op);
    assert_eq!(send(&state, "GET", url, &auth, "").await.sent().0, "Bearer blob-7f3a");
}

/// Two rotating connections used alternately on a whole-blob vault: each
/// mints once. A stored rotation patches the snapshot (no install), so the
/// other connection's access token is kept.
#[tokio::test]
async fn two_rotating_connections_used_alternately_mint_once_each() {
    let (_dir, state) = new_state();
    let tokens = token_endpoint(3600).await;
    let vault = Vault::new()
        .service("acme", MINTED)
        .named("acme_two", "acme", &[("ACME_REFRESH_TOKEN", "ACME_REFRESH_TOKEN_TWO")])
        .secret("ACME_REFRESH_TOKEN", "a-0")
        .secret("ACME_REFRESH_TOKEN_TWO", "b-0");
    write_whole_blob(&state, &vault);
    unlock_from_store(&state);
    tokens.serve(&state);
    let one = bearer("__sprott__acme__");
    let two = bearer("__sprott__acme_two__");
    for _ in 0..3 {
        assert_eq!(send(&state, "GET", "https://api.acme.dev/x", &one, "").await.sent().0, "Bearer at-a-1");
        assert_eq!(send(&state, "GET", "https://api.acme.dev/x", &two, "").await.sent().0, "Bearer at-b-1");
    }
    assert_eq!(tokens.seen(), vec!["a-0", "b-0"]);
}
