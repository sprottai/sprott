//! What an unlocked vault serves requests from: one immutable [`Snapshot`],
//! built by every install ([`crate::state::AppState::install`]) and taken
//! once per request, in the same state-lock section as the request's lock
//! check (design/protocol.md §6.2).
//!
//! Authorization and value supply are separate. Policy decides from the
//! snapshot's [`PolicyInputs`]; an approval leaves a permit that carries no
//! value ([`crate::state::PermitKey`]); a value is read from here only once
//! its request is authorized. Which values are held in plaintext between
//! requests is the residency rule: a KEY bound to a connection whose GET
//! floor is `allow` is resident; every other KEY a connection binds is held
//! sealed under the seal key S ([`SealKey`]) and opened per request; a KEY
//! nothing binds is held by name only. Residency never authorizes anything.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use zeroize::{Zeroize, Zeroizing};

use crate::core::policy::{AccessLevel, DecidedBy, Policy, VarMap};
use crate::error::AppError;
use crate::service::{ServiceDef, ServiceRegistry};
use crate::storage::plaintext::{
    secret_key_for, AgentEntry, Category, Connection, Store, VaultPlaintextView,
    NATIVE_SECRETS_KIND,
};

/// Domain tag of a sealed value's associated data.
const SEAL_TAG: &[u8] = b"sprott/v1/snapshot-seal";
/// Domain tag of the policy fingerprint.
const FINGERPRINT_TAG: &[u8] = b"sprott/v1/policy-fingerprint";

// ── S ────────────────────────────────────────────────────────────────────────

/// The seal key S: random, held for as long as the vault stays Unlocked (it
/// outlives a K rotation by an approved write), dropped with K at lock, park
/// and close. A value the snapshot does not hold in plaintext is AEAD under S
/// with associated data (vault id, KEY); one that no longer opens (S changed)
/// reads as a locked vault.
#[derive(Clone)]
pub struct SealKey {
    key: Zeroizing<[u8; 32]>,
    /// Tests: how many values were opened under this S (shared by clones).
    #[cfg(test)]
    pub(crate) opens: Arc<std::sync::atomic::AtomicUsize>,
}

impl SealKey {
    pub fn fresh() -> SealKey {
        use rand::RngCore as _;
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut key[..]);
        SealKey {
            key,
            #[cfg(test)]
            opens: Default::default(),
        }
    }

    fn ad(vault_id: &str, key: &str) -> Vec<u8> {
        let mut ad = SEAL_TAG.to_vec();
        for part in [vault_id, key] {
            ad.extend_from_slice(&(part.len() as u64).to_be_bytes());
            ad.extend_from_slice(part.as_bytes());
        }
        ad
    }

    /// `value` sealed for `key` of `vault_id` (a fresh random nonce each time).
    pub fn seal(&self, vault_id: &str, key: &str, value: &[u8]) -> Vec<u8> {
        use sudp::primitives::{Aead, ChaCha20Poly1305};
        ChaCha20Poly1305::seal(&self.key[..], value, &Self::ad(vault_id, key))
            .expect("a 32-byte key seals")
    }

    /// The value [`Self::seal`] sealed, `None` when it does not open under
    /// this key (sealed under another S, or for another vault or KEY).
    pub fn open(&self, vault_id: &str, key: &str, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        use sudp::primitives::{Aead, ChaCha20Poly1305};
        #[cfg(test)]
        self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ChaCha20Poly1305::open(&self.key[..], sealed, &Self::ad(vault_id, key))
            .ok()
            .map(Zeroizing::new)
    }
}

/// Never prints the key: a `{:?}` in a log line must not undo the sealing.
impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey(<redacted>)")
    }
}

/// A value the snapshot holds.
#[derive(Clone)]
pub enum Held {
    /// A resident KEY's value.
    Plain(Zeroizing<Vec<u8>>),
    /// Any other bound KEY's value, sealed under S.
    Sealed(Vec<u8>),
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Held::Plain(_) => f.write_str("Plain(<redacted>)"),
            Held::Sealed(ct) => write!(f, "Sealed({} bytes)", ct.len()),
        }
    }
}

// ── policy inputs ───────────────────────────────────────────────────────────

/// Everything policy decides from: the vault's policy over the compiled
/// defaults (connection policies, floors, categories, the approval timeout,
/// the installed-services switch) and the vault's own service definitions
/// (their tightening policy and `[requests]` shapes); the built-in
/// definitions are compiled in. [`Self::decide`] and [`Self::rule_problem`]
/// read nothing else, and the policy fingerprint ([`Self::fingerprint`]) is a
/// hash of exactly these.
#[derive(Debug, Clone, Default)]
pub struct PolicyInputs {
    pub policy: Policy,
    /// The vault's loaded definitions (`aux.services`), by id.
    pub custom: HashMap<String, ServiceDef>,
}

impl PolicyInputs {
    /// A service definition as a connection resolves it: the vault's own
    /// first, else the compiled one.
    pub fn def<'a>(&'a self, services: &'a ServiceRegistry, id: &str) -> Option<&'a ServiceDef> {
        self.custom.get(id).or_else(|| services.get(id))
    }

    /// The decision for a request on `connection_id` (service `service_id`),
    /// as `(level, what decided it, ttl)` (PROTOCOL.md §6.4):
    ///   - the service's built-in rules merged with this connection's user
    ///     rules; the most restrictive matching rule wins (deny-override);
    ///   - else the connection / tag / global floor, else ask-always;
    ///   - a vault definition's policy only tightens: its tightening parts
    ///     decide alongside, and the stricter of the decision with and without
    ///     them stands ([`crate::core::policy::stricter`]).
    ///
    /// Pure policy: no approval is consulted here (permits are looked up
    /// after the values are located, `crate::state::AppState::authorize`).
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &self,
        services: &ServiceRegistry,
        connection_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        vars: &VarMap,
    ) -> (AccessLevel, DecidedBy, Option<u64>) {
        self.decide_with(
            services,
            connection_id,
            service_id,
            method,
            path,
            body,
            vars,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn decide_with(
        &self,
        services: &ServiceRegistry,
        connection_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        vars: &VarMap,
        with_rules: bool,
    ) -> (AccessLevel, DecidedBy, Option<u64>) {
        use crate::core::policy::{evaluate_decision, merge_levels, merge_rules, stricter};
        // Built-in rules come from the connection's service definition; the
        // user's per-connection edits merge on top, and the user's
        // per-connection default overrides the service's field-wise.
        let conn_policy = self.policy.connections.get(connection_id);
        let no_rules = HashMap::new();
        let user_rules = conn_policy.map(|c| &c.rules).unwrap_or(&no_rules);
        let user_default = conn_policy.and_then(|c| c.default.as_ref());
        let tags = services.service_tags(service_id);
        let decide = |built_in: &[crate::core::policy::PolicyRule],
                      recipe: Option<&crate::core::policy::Levels>| {
            let rules = if with_rules {
                merge_rules(built_in, user_rules)
            } else {
                Vec::new()
            };
            let levels = merge_levels(user_default, recipe);
            evaluate_decision(
                method,
                path,
                body,
                vars,
                Some(&rules),
                levels.as_ref(),
                &self.policy,
                tags,
            )
        };
        match self.custom.get(service_id).and_then(|d| d.policy.as_ref()) {
            Some(p) => stricter(decide(&[], None), decide(&p.rules, p.defaults.as_ref())),
            None => decide(
                services.default_policy_rules(service_id).unwrap_or(&[]),
                services.default_policy_levels(service_id).as_ref(),
            ),
        }
    }

    /// For a scoped request (`rs`: its matched `[requests]` shape), the first
    /// of this connection's own policy edits that cannot be enforced as
    /// written there, with the reason
    /// ([`crate::core::policy::unenforceable_user_rule`]). The proxy refuses
    /// such a request rather than ask under a rule an approval cannot bind.
    #[allow(clippy::too_many_arguments)]
    pub fn rule_problem(
        &self,
        services: &ServiceRegistry,
        connection_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        rs: &crate::service::RequestScope,
    ) -> Option<String> {
        let user_rules = &self.policy.connections.get(connection_id)?.rules;
        // The rules the edits merge onto: the vault definition's (tightening)
        // rules, else the registry definition's.
        let built_in = match self.custom.get(service_id).and_then(|d| d.policy.as_ref()) {
            Some(p) => p.rules.as_slice(),
            None => services.default_policy_rules(service_id).unwrap_or(&[]),
        };
        crate::core::policy::unenforceable_user_rule(
            built_in,
            user_rules,
            method,
            path,
            &rs.shape,
            &rs.declared,
            &rs.binds,
        )
    }

    /// Whether a connection's GET floor is `allow`: [`Self::decide`] on a
    /// `GET /` with every rule left out (the service's recipe, the owner's
    /// defaults, the tag and global floors, a vault definition's stricter
    /// defaults). The residency rule.
    fn get_floor_allows(
        &self,
        services: &ServiceRegistry,
        connection_id: &str,
        service_id: &str,
    ) -> bool {
        let (level, _, _) = self.decide_with(
            services,
            connection_id,
            service_id,
            "GET",
            "/",
            None,
            &VarMap::new(),
            false,
        );
        level == AccessLevel::Allow
    }

    /// The policy fingerprint: a hash of the canonical form of these inputs
    /// (JSON with sorted keys; a vault definition contributes its policy and
    /// its `[requests]` shapes, nothing else of it).
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        use serde_json::json;
        let custom: BTreeMap<&String, serde_json::Value> = self
            .custom
            .iter()
            .map(|(id, d)| {
                let shapes: BTreeMap<&String, serde_json::Value> = d
                    .requests
                    .iter()
                    .map(|(name, s)| {
                        // A var's address is plain data; its Debug form is stable.
                        let vars: BTreeMap<&String, String> =
                            s.vars.iter().map(|(k, v)| (k, format!("{:?}", v))).collect();
                        let shape = json!({
                            "match": s.match_pattern,
                            "vars": vars,
                            "scope": s.scope,
                            "consent": s.consent,
                        });
                        (name, shape)
                    })
                    .collect();
                let decided = json!({
                    "defaults": d.policy.as_ref().map(|p| &p.defaults),
                    "rules": d.policy.as_ref().map(|p| &p.rules),
                    "requests": shapes,
                });
                (id, decided)
            })
            .collect();
        let canonical = json!({
            "policy": serde_json::to_value(&self.policy).unwrap_or_default(),
            "custom": custom,
        });
        let mut h = Sha256::new();
        h.update(FINGERPRINT_TAG);
        h.update(serde_json::to_vec(&canonical).unwrap_or_default());
        h.finalize().into()
    }
}

// ── bindings and phantoms ───────────────────────────────────────────────────

/// What a connection's role is to a phantom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    /// A stored secret, injected as it is.
    Secret,
    /// An oauth2 `exposes` value derived at connect, injected as it is.
    Exposes,
    /// The input a minted mechanism consumes (an oauth2 refresh token, a
    /// snaplii api key): never injected.
    MintInput,
}

/// One role of a connection and the vault KEY it is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub role: String,
    pub key: String,
    pub kind: RoleKind,
}

/// The one connection-to-KEY binding (residency, the phantom check and the
/// value walk all read it): a service-backed connection's `secrets` ∪
/// `[auth].exposes` ∪ mint input, each through [`secret_key_for`] over the
/// record; a raw connection's own `secrets`, each its own KEY. `None` when
/// the connection names a service whose definition is not loaded.
pub fn bindings(rec: &Connection, def: Option<&ServiceDef>) -> Option<Vec<Bound>> {
    let Some(def) = def else {
        return rec.service.is_none().then(|| {
            rec.secrets
                .iter()
                .flatten()
                .map(|k| Bound {
                    role: k.clone(),
                    key: k.clone(),
                    kind: RoleKind::Secret,
                })
                .collect()
        });
    };
    let mint = def.mint_input_role();
    let mut out: Vec<Bound> = Vec::new();
    let mut push = |role: String, kind: RoleKind| {
        if !out.iter().any(|b| b.role.eq_ignore_ascii_case(&role)) {
            let key = secret_key_for(Some(rec), &role);
            out.push(Bound { role, key, kind });
        }
    };
    for s in def.service.secrets.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let kind = if mint.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(s)) {
            RoleKind::MintInput
        } else {
            RoleKind::Secret
        };
        push(s.to_string(), kind);
    }
    if let Some(o) = def.oauth2() {
        // Derived at connect and stored UPPERCASED.
        for e in &o.exposes {
            push(e.to_ascii_uppercase(), RoleKind::Exposes);
        }
    }
    if let Some(m) = mint {
        push(m, RoleKind::MintInput);
    }
    Some(out)
}

/// What one phantom asks for, after the phantom check (step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Want {
    /// A named role: its own KEY.
    Role(Bound),
    /// A minted connection's access token (its role-less phantom, or role
    /// `access`): minted from the mint-input KEY.
    Access(Bound),
    /// A role-less phantom on a static connection: its sole present role
    /// (step 4).
    RoleLess,
}

/// Why a phantom is refused at the phantom check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhantomRefusal {
    /// The connection has no such role.
    UnknownRole(String),
    /// The role is a mint input, which is never injected.
    RefreshForbidden,
}

/// The phantom check (static, no value read): an explicit role must exist on
/// the connection, matched against its roles exactly first, then
/// case-insensitively (the first in binding order); on a minted connection
/// `access` is its access token. A mint input is refused.
pub fn check_phantom(role: Option<&str>, roles: &[Bound]) -> Result<Want, PhantomRefusal> {
    let mint = roles.iter().find(|b| b.kind == RoleKind::MintInput);
    let Some(role) = role else {
        return Ok(match mint {
            Some(m) => Want::Access(m.clone()),
            None => Want::RoleLess,
        });
    };
    if let Some(m) = mint {
        if role.eq_ignore_ascii_case("access") {
            return Ok(Want::Access(m.clone()));
        }
    }
    let found = roles
        .iter()
        .find(|b| b.role == role)
        .or_else(|| roles.iter().find(|b| b.role.eq_ignore_ascii_case(role)));
    match found {
        Some(b) if b.kind == RoleKind::MintInput => Err(PhantomRefusal::RefreshForbidden),
        Some(b) => Ok(Want::Role(b.clone())),
        None => Err(PhantomRefusal::UnknownRole(role.to_string())),
    }
}

/// The roles a role-less phantom on a static connection may mean.
pub fn role_less_candidates(roles: &[Bound]) -> Vec<&Bound> {
    roles
        .iter()
        .filter(|b| b.kind != RoleKind::MintInput)
        .collect()
}

// ── stores ──────────────────────────────────────────────────────────────────

/// A store in the effective `store_order`: the vault's order restricted to
/// value stores, native-secrets where it is listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreRef {
    Native,
    External(String),
    /// A configured value store this device can't read (its adapter failed to
    /// build, or this build has none for its kind): a KEY it precedes answers
    /// `store_unavailable`.
    Unavailable(String),
}

/// The vault's external stores, as the snapshot serves them.
#[derive(Clone, Default)]
pub struct Stores {
    /// One live adapter per external store, built from the full fold (a
    /// store's own credential is a native item no connection binds). Sharing
    /// one instance for the snapshot's life keeps the adapter's token cache
    /// effective; the adapter zeroizes its credential on drop.
    pub adapters: BTreeMap<String, (Store, Arc<crate::store::Adapter>)>,
    /// External stores whose adapter failed to build: `(id, sanitised reason)`
    /// (the full error is in the daemon log only).
    pub errors: Vec<(String, String)>,
    pub order: Vec<StoreRef>,
}

impl Stores {
    fn build(view: &VaultPlaintextView) -> Stores {
        let mut stores = Stores::default();
        for (store_id, store) in &view.aux.stores {
            if store.kind == NATIVE_SECRETS_KIND || store.category != Category::Value {
                continue;
            }
            match crate::store::build_adapter(store_id, store, view) {
                Ok(adapter) => {
                    stores
                        .adapters
                        .insert(store_id.clone(), (store.clone(), Arc::new(adapter)));
                }
                Err(e) => {
                    tracing::warn!(store = %store_id, "external store adapter init failed: {}", e);
                    stores
                        .errors
                        .push((store_id.clone(), format!("store '{}' unavailable", store_id)));
                }
            }
        }
        stores.order = view
            .aux
            .store_order
            .iter()
            .filter_map(|id| {
                let store = view.aux.stores.get(id)?;
                if store.category != Category::Value {
                    return None;
                }
                Some(if store.kind == NATIVE_SECRETS_KIND {
                    StoreRef::Native
                } else if stores.adapters.contains_key(id) {
                    StoreRef::External(id.clone())
                } else {
                    StoreRef::Unavailable(id.clone())
                })
            })
            .collect();
        stores
    }

    /// Whether the effective order holds a store other than native-secrets.
    pub fn has_external(&self) -> bool {
        self.order.iter().any(|s| *s != StoreRef::Native)
    }
}

impl std::fmt::Debug for Stores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stores")
            .field("adapters", &self.adapters.keys().collect::<Vec<_>>())
            .field("errors", &self.errors)
            .field("order", &self.order)
            .finish()
    }
}

// ── residency ───────────────────────────────────────────────────────────────

/// Which KEYs the snapshot holds in plaintext, and which any connection binds
/// (explicitly or as an implicit default connection). Native names match
/// case-insensitively (held uppercased here), external KEYs exactly.
#[derive(Debug, Clone, Default)]
pub(crate) struct Residency {
    resident: HashSet<String>,
    resident_native: HashSet<String>,
    bound_native: HashSet<String>,
}

impl Residency {
    fn of(
        inputs: &PolicyInputs,
        services: &ServiceRegistry,
        connections: &HashMap<String, Connection>,
    ) -> Residency {
        let mut r = Residency::default();
        // Every service a connection could name without a record is its own
        // default connection (the proxy brokers `__sprott__<service>__`).
        let implicit: Vec<(String, Connection)> = services
            .iter_sorted()
            .into_iter()
            .map(|(id, _)| id.to_string())
            .chain(inputs.custom.keys().cloned())
            .filter(|id| !connections.contains_key(id))
            .map(|id| {
                let rec = Connection {
                    service: Some(id.clone()),
                    ..Default::default()
                };
                (id, rec)
            })
            .collect();
        let all = connections.iter().chain(implicit.iter().map(|(k, v)| (k, v)));
        for (id, rec) in all {
            let def = rec.service.as_deref().and_then(|s| inputs.def(services, s));
            let Some(roles) = bindings(rec, def) else {
                continue;
            };
            let service_id = rec.service.as_deref().unwrap_or(id);
            let allow = inputs.get_floor_allows(services, id, service_id);
            for b in roles {
                let upper = b.key.to_ascii_uppercase();
                if allow {
                    r.resident_native.insert(upper.clone());
                    r.resident.insert(b.key);
                }
                r.bound_native.insert(upper);
            }
        }
        r
    }

    fn native_resident(&self, name: &str) -> bool {
        self.resident_native.contains(&name.to_ascii_uppercase())
    }

    fn native_bound(&self, name: &str) -> bool {
        self.bound_native.contains(&name.to_ascii_uppercase())
    }

    fn external_resident(&self, key: &str) -> bool {
        self.resident.contains(key)
    }
}

// ── the walk memo ───────────────────────────────────────────────────────────

/// Where a request's KEY was found (step 4): a native item (by its stored
/// name), or an external store with the value the walk fetched, which step 7
/// uses as it is (never fetched again).
#[derive(Clone, Debug)]
pub enum Location {
    Native(String),
    External { store: String, value: Held },
}

#[derive(Clone, Debug)]
enum Found {
    At(Location),
    Absent,
}

/// The per-KEY walk memo: where a walk found each KEY, or that it is absent
/// from every store ("absent" is consulted only to pick among a role-less
/// phantom's candidates). Fills are single-flight per KEY; a walk error is
/// never recorded. The snapshot's only part written on the request path. Its
/// locks are leaves: neither is held while the state lock is taken.
#[derive(Default)]
pub(crate) struct Memo {
    found: Mutex<HashMap<String, Found>>,
    flights: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Clone for Memo {
    fn clone(&self) -> Memo {
        Memo {
            found: Mutex::new(self.found.lock().unwrap().clone()),
            flights: Mutex::default(),
        }
    }
}

/// Why a walk stopped.
#[derive(Debug)]
pub enum WalkError {
    /// A configured store ahead of the KEY failed, or can't be read here.
    StoreUnavailable(String),
    /// The vault locked, or went away, during the walk.
    Vault(AppError),
}

// ── the snapshot ────────────────────────────────────────────────────────────

/// Everything the request path reads from vault state, built by one install
/// and never changed after (the walk memo aside). Fields are `pub(crate)` so
/// tests can seed one; production builds every snapshot with [`Snapshot::build`].
#[derive(Clone)]
pub struct Snapshot {
    /// The connection records (`aux.connections`).
    pub connections: HashMap<String, Connection>,
    pub inputs: PolicyInputs,
    /// The vault definitions not loaded, with why.
    pub custom_skipped: HashMap<String, String>,
    /// The vault's `aux.services` entries as stored, valid or not: what
    /// `sc service ls` lists and what a `service-add` / `service-rm` card is
    /// computed against.
    pub service_entries: BTreeMap<String, crate::service::source::StoredService>,
    /// The names of the vault's console install requests.
    pub service_requests: Vec<String>,
    /// The authorized-agents table (design §11.1); presence = authorized.
    pub agents: BTreeMap<String, AgentEntry>,
    pub audit_retention_days: Option<u32>,
    pub stores: Stores,
    /// Native item names, each with its held value; `None` for a KEY no
    /// connection binds (nothing on the request path reads it).
    pub(crate) native: BTreeMap<String, Option<Held>>,
    pub(crate) residency: Residency,
    /// The store rows the build read (a whole-blob vault is one row): an
    /// install whose fold cannot read one of them is not served.
    pub readable: BTreeSet<String>,
    /// The policy fingerprint of [`Self::inputs`].
    pub fingerprint: [u8; 32],
    pub(crate) memo: Memo,
}

/// Lists what the snapshot holds and how, never a value: a `{:?}` in a log
/// line is the likeliest way a bug would expose the cache.
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let native: BTreeMap<&String, &str> = self
            .native
            .iter()
            .map(|(k, v)| {
                let how = match v {
                    Some(Held::Plain(_)) => "resident",
                    Some(Held::Sealed(_)) => "sealed",
                    None => "name only",
                };
                (k, how)
            })
            .collect();
        f.debug_struct("Snapshot")
            .field("connections", &self.connections.keys().collect::<BTreeSet<_>>())
            .field("custom", &self.inputs.custom.keys().collect::<BTreeSet<_>>())
            .field("agents", &self.agents.len())
            .field("native", &native)
            .field("stores", &self.stores)
            .field("readable", &self.readable.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl Default for Snapshot {
    fn default() -> Snapshot {
        let inputs = PolicyInputs::default();
        let fingerprint = inputs.fingerprint();
        Snapshot {
            connections: HashMap::new(),
            inputs,
            custom_skipped: HashMap::new(),
            service_entries: BTreeMap::new(),
            service_requests: Vec::new(),
            agents: BTreeMap::new(),
            audit_retention_days: None,
            stores: Stores::default(),
            native: BTreeMap::new(),
            residency: Residency::default(),
            readable: BTreeSet::new(),
            fingerprint,
            memo: Memo::default(),
        }
    }
}

impl Snapshot {
    /// Build the snapshot of a folded vault (`view`; `readable`: the rows the
    /// fold read), sealing every bound non-resident value under `seal`. The
    /// fold's plaintext is wiped before this returns.
    pub fn build(
        mut view: VaultPlaintextView,
        readable: BTreeSet<String>,
        services: &ServiceRegistry,
        vault_id: &str,
        seal: &SealKey,
    ) -> Snapshot {
        // Effective policy = the vault's sparse `aux.policy` overlaid on the
        // compiled defaults, so a policy edit decides from the next install.
        let policy = Policy::effective(view.aux.policy.as_ref());
        // Vault definitions are admitted again before they can broker (never
        // trust the stored blob), never shadow a built-in id, load only valid.
        let (custom, skipped) = crate::service::vault_custom_services(
            &view.aux.services,
            view.aux.allows_installed_services(),
            services,
        );
        for (id, reason) in &skipped {
            tracing::warn!(service = %id, "vault service definition not loaded: {}", reason);
        }
        let inputs = PolicyInputs { policy, custom };
        let connections: HashMap<String, Connection> = std::mem::take(&mut view.aux.connections)
            .into_iter()
            .collect();
        let stores = Stores::build(&view);
        let residency = Residency::of(&inputs, services, &connections);
        let mut native = BTreeMap::new();
        for (name, value) in &view.native_secrets {
            let held = if residency.native_resident(name) {
                Some(Held::Plain(Zeroizing::new(value.clone())))
            } else if residency.native_bound(name) {
                Some(Held::Sealed(seal.seal(vault_id, name, value)))
            } else {
                None
            };
            native.insert(name.clone(), held);
        }
        // The fold's plaintext goes now (a plain map, so it is wiped here).
        for value in view.native_secrets.values_mut() {
            value.zeroize();
        }
        let fingerprint = inputs.fingerprint();
        Snapshot {
            connections,
            inputs,
            custom_skipped: skipped.into_iter().collect(),
            service_entries: std::mem::take(&mut view.aux.services),
            service_requests: view.aux.service_requests.keys().cloned().collect(),
            agents: std::mem::take(&mut view.aux.agents),
            audit_retention_days: view.aux.audit_retention_days,
            stores,
            native,
            residency,
            readable,
            fingerprint,
            memo: Memo::default(),
        }
    }

    /// The native item `key` names: exact first, else case-insensitively (the
    /// first in name order).
    pub fn native_name(&self, key: &str) -> Option<&str> {
        if let Some((name, _)) = self.native.get_key_value(key) {
            return Some(name);
        }
        self.native
            .keys()
            .find(|n| n.eq_ignore_ascii_case(key))
            .map(String::as_str)
    }

    /// Every native item name (names only).
    pub fn native_names(&self) -> impl Iterator<Item = &String> {
        self.native.keys()
    }

    /// Whether `service_id` is a vault definition installed from a source and
    /// not loaded because the owner has installed services off.
    pub fn installed_service_off(&self, service_id: &str) -> bool {
        !self.inputs.policy.allow_installed_services
            && self
                .service_entries
                .get(service_id)
                .is_some_and(|e| e.is_installed())
    }

    /// Tests: how native item `name` is held ("resident", "sealed" or "name
    /// only"), `None` when there is no such item.
    #[cfg(test)]
    pub(crate) fn holds(&self, name: &str) -> Option<&'static str> {
        Some(match self.native.get(name)? {
            Some(Held::Plain(_)) => "resident",
            Some(Held::Sealed(_)) => "sealed",
            None => "name only",
        })
    }

    /// The value native item `name` holds, `None` when it holds none.
    pub(crate) fn held_native(&self, name: &str) -> Option<&Held> {
        self.native.get(name).and_then(Option::as_ref)
    }

    /// A copy with native item `key` holding `value` (plaintext for a
    /// resident KEY, sealed under `seal` otherwise) and `key`'s walk memo
    /// entry dropped: when native is listed first but the KEY was found in a
    /// later store, the value now in native must win on the re-walk.
    pub(crate) fn with_value(
        &self,
        vault_id: &str,
        key: &str,
        value: &[u8],
        seal: &SealKey,
    ) -> Snapshot {
        let mut next = self.clone();
        let held = if self.residency.native_resident(key) {
            Some(Held::Plain(Zeroizing::new(value.to_vec())))
        } else if self.residency.native_bound(key) {
            Some(Held::Sealed(seal.seal(vault_id, key, value)))
        } else {
            None
        };
        next.native.insert(key.to_string(), held);
        next.memo
            .found
            .lock()
            .unwrap()
            .retain(|k, _| !k.eq_ignore_ascii_case(key));
        next
    }

    fn memo_get(&self, key: &str) -> Option<Found> {
        self.memo.found.lock().unwrap().get(key).cloned()
    }

    fn memo_put(&self, key: &str, found: Found) {
        self.memo.found.lock().unwrap().insert(key.to_string(), found);
    }

    /// Where `key` is (step 4): a memo entry says where a walk found it;
    /// else one walk of the effective store_order (native: a name lookup;
    /// external: a fetch, sealed under S at once for a non-resident KEY) is
    /// recorded. `Ok(None)`: absent from every store. With `use_absent`, a
    /// recorded "absent" is taken as is; without, it walks again, so a KEY
    /// added to an external store later is found. Locates only: never opens
    /// a sealed value.
    pub async fn locate(
        &self,
        state: &crate::state::AppState,
        vault_id: &str,
        key: &str,
        use_absent: bool,
    ) -> Result<Option<Location>, WalkError> {
        let recorded = |found: Option<Found>| match found {
            Some(Found::At(l)) => Some(Some(l)),
            Some(Found::Absent) if use_absent => Some(None),
            _ => None,
        };
        if let Some(r) = recorded(self.memo_get(key)) {
            return Ok(r);
        }
        let flight = self
            .memo
            .flights
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_default()
            .clone();
        let _one = flight.lock().await;
        // Filled while this request waited for the walk in flight.
        if let Some(r) = recorded(self.memo_get(key)) {
            return Ok(r);
        }
        for store in &self.stores.order {
            match store {
                StoreRef::Native => {
                    if let Some(name) = self.native_name(key) {
                        let at = Location::Native(name.to_string());
                        self.memo_put(key, Found::At(at.clone()));
                        return Ok(Some(at));
                    }
                }
                StoreRef::Unavailable(id) => return Err(WalkError::StoreUnavailable(id.clone())),
                StoreRef::External(id) => {
                    let Some((_, adapter)) = self.stores.adapters.get(id) else {
                        return Err(WalkError::StoreUnavailable(id.clone()));
                    };
                    match adapter.resolve(key).await {
                        Ok(Some(bytes)) => {
                            let bytes = Zeroizing::new(bytes);
                            let (seal, external_keys) =
                                state.fill_context(vault_id).map_err(WalkError::Vault)?;
                            let value = if self.residency.external_resident(key) {
                                Held::Plain(bytes)
                            } else {
                                Held::Sealed(seal.seal(vault_id, key, &bytes))
                            };
                            external_keys.note(id, key);
                            let at = Location::External {
                                store: id.clone(),
                                value,
                            };
                            self.memo_put(key, Found::At(at.clone()));
                            return Ok(Some(at));
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            // The full error stays in the daemon log.
                            tracing::warn!(store = %id, key = %key, "external store failed: {}", e);
                            return Err(WalkError::StoreUnavailable(id.clone()));
                        }
                    }
                }
            }
        }
        self.memo_put(key, Found::Absent);
        Ok(None)
    }
}
