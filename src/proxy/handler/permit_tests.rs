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

    /// A rule the owner adds to a connection (`body`: a regex on the body).
    fn rule(self, conn: &str, id: &str, pattern: &str, level: AccessLevel, body: Option<&str>) -> Vault {
        self.policy(|p| {
            p.connections.entry(conn.to_string()).or_default().rules.insert(
                id.to_string(),
                RuleConfig {
                    match_pattern: Some(pattern.to_string()),
                    body: body.map(crate::core::policy::BodyPattern::lenient),
                    level: Some(level),
                    ttl: Some(600),
                    ..Default::default()
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
    /// Asked for an approval: the op.
    Ask(String),
    /// Asked to widen the host: the op.
    Widen(String),
    /// Refused: the code and the message.
    No(String, String),
}

impl Out {
    fn describe(&self) -> String {
        match self {
            Out::Sent(a, u) => format!("sent ({a}) to {u}"),
            Out::Ask(op) => format!("ask {op}"),
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
            Out::Ask(op) => op.clone(),
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
    let req = Request::builder()
        .method(method)
        .uri(url)
        .header("authorization", auth)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
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
                (Some(op), StatusCode::UNAUTHORIZED) => Out::Ask(op),
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

fn bearer(phantom: &str) -> String {
    format!("Bearer {}", phantom)
}

// ── the two cases this fixes ────────────────────────────────────────────────

/// A raw connection `railway` holding RAILWAY_TOKEN, a role phantom, an
/// ask-always rule on a GraphQL delete: approve once, the replay is
/// forwarded with the token (the approval used to be spent on a replay that
/// found no value for the role, and asked again). On this tree the built-in
/// `delete-infra` reads `vars.fields` from Railway's `[requests]` shape,
/// which a raw connection has none of, so the case takes the 2.0.1 rule
/// (a body regex) as the owner's own rule on the connection.
#[tokio::test]
async fn railway_raw_role_phantom_ask_always_replay_is_forwarded() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("railway", "backboard.railway.com", &["RAILWAY_TOKEN"])
        .secret("RAILWAY_TOKEN", "rw-token")
        .rule(
            "railway",
            "delete-service",
            "POST /graphql/**",
            AccessLevel::AskAlways,
            Some("serviceDelete"),
        )
        .unlock(&state);
    let url = "https://backboard.railway.com/graphql/v2";
    let auth = bearer("__sprott__railway__railway_token__");
    let body = r#"{"query":"mutation { serviceDelete(id: \"s\") }"}"#;
    let op = send(&state, "POST", url, &auth, body).await.ask();
    assert_eq!(target(&state, &op), "RAILWAY_TOKEN");
    approve(&state, &op);
    let (sent, _) = send(&state, "POST", url, &auth, body).await.sent();
    assert_eq!(sent, "Bearer rw-token");
    // One approval, one replay.
    send(&state, "POST", url, &auth, body).await.ask();
    // A query the rule does not match is allowed and forwarded as is.
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
match = "POST /buy"
vars.amount = "/amount"
scope = ["amount"]
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

/// The body is not bound unless a `[requests]` shape binds it (P5): a
/// replay of an approved ask-always request whose body carries a fresh
/// nonce is redeemed.
#[tokio::test]
async fn a_nonce_bearing_body_replay_of_an_ask_always_approval_is_redeemed() {
    let (_dir, state) = new_state();
    Vault::new()
        .raw("svc", "api.svc.dev", &["SVC_TOKEN"])
        .secret("SVC_TOKEN", "tok")
        .rule("svc", "t", "POST /charge", AccessLevel::AskAlways, None)
        .unlock(&state);
    let url = "https://api.svc.dev/charge";
    let auth = bearer("__sprott__svc__");
    let op = send(&state, "POST", url, &auth, r#"{"nonce":"a1"}"#).await.ask();
    approve(&state, &op);
    assert_eq!(send(&state, "POST", url, &auth, r#"{"nonce":"b2"}"#).await.sent().0, "Bearer tok");
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
    assert_eq!(code, "policy_denied");
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
            "",
            crate::state::CredentialSet::new("svc", ["SVC_TOKEN".to_string()]),
        )
    };
    let a = state.authorize(V, snapshot.clone(), BTreeMap::new(), key()).unwrap();
    let b = state.authorize(V, snapshot.clone(), BTreeMap::new(), key()).unwrap();
    assert!(state.consume(V, a).unwrap());
    assert!(!state.consume(V, b).unwrap(), "the loser goes to the portal");

    let op = send(&state, "POST", url, &auth, "{}").await.ask();
    approve(&state, &op);
    let before = ops(&state);
    let c = state.authorize(V, snapshot, BTreeMap::new(), key()).unwrap();
    state.lock_vault(V);
    assert!(matches!(state.consume(V, c), Err(crate::error::AppError::VaultLocked)));
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
/// takes its recipe (gmail: read asks), a vault definition its stricter
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
    assert_eq!(snap.holds("MAIL_KEY"), Some("sealed"));
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
