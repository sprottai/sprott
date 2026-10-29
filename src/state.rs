//! Top-level application state.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::approval::ApprovalStore;
use crate::config::Config;
use crate::passkey::challenge::ChallengeStore;
use crate::service::ServiceRegistry;
use crate::storage::VaultDir;

/// Broadcast payload for the per-vault SSE channel. The receiver-side filter
/// is on `vault_id`; subscribers belonging to other vaults drop the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub vault_id: String,
    pub approval_id: String,
    /// One of "pending" | "approved" | "rejected" | "cancelled".
    pub kind: String,
    /// Summary of the approved Operation (act.kind, target, scope) — present
    /// for pending. Frontend uses it to render the request card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_summary: Option<Value>,
    /// Cached upstream response for broker (Use) approvals after approve —
    /// `{status, headers, body, body_base64}` JSON. Present for approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_preview: Option<Value>,
    /// Rejection reason — present for rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Broadcast channel capacity. Lagging subscribers (typically tabs sleeping
/// in a background pinch) will drop events older than this — they reconnect
/// fresh and lose history, which is acceptable for a watcher UI.
const EVENT_CHANNEL_CAPACITY: usize = 128;

// ── Vault state (PROTOCOL.md §6.3) ───────────────────────────────────────────
//
// Per-vault runtime state. The daemon boots Locked; only the SUDP
// `Custom("vault-unlock")` op takes a vault to Unlocked, where it serves from
// one immutable snapshot ([`crate::snapshot::Snapshot`]) per install. No
// auto-lock timer; a lock is user-initiated (`Custom("vault-lock")`) or a
// device park.

/// How long an approved single-use permit stays redeemable (approve time +
/// this). Generous on purpose: the replay is agent-driven, and an agent that
/// only acts when its user next prompts it can take many minutes. Safety
/// comes from single use and exact request binding, not from this window.
pub const ASK_ALWAYS_REPLAY_WINDOW_SECS: u64 = 1800;

/// The request line a request-bound permit was approved for: the approving
/// agent, the request line, the bound-values digest, and the tier that
/// minted it. Host is lowercased.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpGrantKey {
    pub agent: String,
    pub conn: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub scope_digest: String,
    pub tier: crate::approval::reuse::BoundTier,
}

impl OpGrantKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent: &str,
        conn: &str,
        method: &str,
        host: &str,
        path: &str,
        scope_digest: &str,
        tier: &crate::approval::reuse::BoundTier,
    ) -> OpGrantKey {
        OpGrantKey {
            agent: agent.to_string(),
            conn: conn.to_string(),
            method: method.to_string(),
            host: host.to_ascii_lowercase(),
            path: path.to_string(),
            scope_digest: scope_digest.to_string(),
            tier: tier.clone(),
        }
    }
}

/// The credentials a request used: its connection's service id and the
/// KEYs its phantoms resolved (sorted, in the binding's spelling): a role
/// phantom's KEY, a minted connection's mint-input KEY for its access
/// phantom, an `exposes` role's own KEY. Part of every permit's key, so a
/// replay with another or an extra role, or after the connection was rebound
/// to other KEYs, does not redeem. Plain data, no values: a value change
/// keeps an approval (whoever writes a value already knows it).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialSet {
    pub service: String,
    pub keys: Vec<String>,
}

impl CredentialSet {
    pub fn new(service: &str, keys: impl IntoIterator<Item = String>) -> CredentialSet {
        let keys: BTreeSet<String> = keys.into_iter().collect();
        CredentialSet {
            service: service.to_string(),
            keys: keys.into_iter().collect(),
        }
    }

    /// The op's `act.target`: the KEYs joined with ", ".
    pub fn target(&self) -> String {
        self.keys.join(", ")
    }
}

/// What a permit was approved for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PermitFor {
    /// An ask-always approval, an ask a rule with no id decided, or a scoped
    /// ask: exactly the approved request line, under its tier.
    Request(OpGrantKey),
    /// An unscoped ask a rule or a floor decided: that unit, for the
    /// approving agent, the connection and the destination host.
    Unit {
        agent: String,
        conn: String,
        host: String,
        unit: crate::approval::reuse::GrantUnit,
    },
}

/// The key a permit is stored and looked up under: what it was approved for,
/// and with which credentials. No value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermitKey {
    pub of: PermitFor,
    pub credentials: CredentialSet,
}

impl PermitKey {
    /// The key an approval of a request decided `(level, decided_by)` is
    /// stored under, and the one its replay is looked up under: by what
    /// [`crate::approval::Reuse`] it permits, the request line and its tier
    /// ([`crate::approval::reuse::BoundTier`]) for `none` and `exact`, the
    /// unit for `rule` and `floor`; with the credentials the request
    /// resolved. The proxy and approve both call this, so they cannot
    /// disagree. `None` for a decision that mints no op (allow, deny).
    #[allow(clippy::too_many_arguments)]
    pub fn of(
        level: crate::core::policy::AccessLevel,
        decided_by: &crate::core::policy::DecidedBy,
        scoped: bool,
        agent: &str,
        conn: &str,
        method: &str,
        host: &str,
        path: &str,
        scope_digest: &str,
        credentials: CredentialSet,
    ) -> Option<PermitKey> {
        let reuse = crate::approval::Reuse::of(level, decided_by, scoped, method)?;
        let of = match reuse.unit() {
            Some(unit) => PermitFor::Unit {
                agent: agent.to_string(),
                conn: conn.to_string(),
                host: host.to_ascii_lowercase(),
                unit,
            },
            None => {
                let tier =
                    crate::approval::reuse::BoundTier::of(level, decided_by, scoped, method)?;
                PermitFor::Request(OpGrantKey::new(
                    agent,
                    conn,
                    method,
                    host,
                    path,
                    scope_digest,
                    &tier,
                ))
            }
        };
        Some(PermitKey { of, credentials })
    }

    /// Spent by the request that redeems it (ask-always, an id-less rule's
    /// ask), or a window reused until it expires (`exact`, a unit).
    pub fn single_use(&self) -> bool {
        match &self.of {
            PermitFor::Request(k) => k.tier.single_use(),
            PermitFor::Unit { .. } => false,
        }
    }
}

/// The permits of an Unlocked vault (key → Unix expiry). They live only in
/// Unlocked, so a lock, park or close drops them all.
#[derive(Debug, Default)]
pub struct Permits(HashMap<PermitKey, u64>);

impl Permits {
    /// Store a permit; expired ones are swept.
    fn insert(&mut self, key: PermitKey, expires_at: u64, now: u64) {
        self.0.retain(|_, exp| *exp > now);
        self.0.insert(key, expires_at);
    }

    /// Is `key` live? An expired one is dropped.
    fn live(&mut self, key: &PermitKey, now: u64) -> bool {
        match self.0.get(key) {
            Some(exp) if *exp > now => true,
            Some(_) => {
                self.0.remove(key);
                false
            }
            None => false,
        }
    }

    /// Spend `key`: removed if present; `false` when it was not (or had
    /// expired).
    fn take(&mut self, key: &PermitKey, now: u64) -> bool {
        matches!(self.0.remove(key), Some(exp) if exp > now)
    }

    /// Drop every window (decision D: a policy change ends them).
    fn end_windows(&mut self) {
        self.0.retain(|k, _| k.single_use());
    }

    #[cfg(test)]
    pub(crate) fn all(&self) -> Vec<(PermitKey, u64)> {
        self.0.iter().map(|(k, e)| (k.clone(), *e)).collect()
    }
}

/// Minted OAuth access tokens, keyed by `sha256(refresh token)` hex (§5: a
/// rotated or reconnected refresh token is a natural miss), each with its
/// Unix expiry. Outside the snapshot, so an install keeps them; dropped at
/// lock. Expired ones are swept on insert.
#[derive(Default)]
pub struct OauthAccess(HashMap<String, (zeroize::Zeroizing<Vec<u8>>, u64)>);

impl std::fmt::Debug for OauthAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OauthAccess({} tokens)", self.0.len())
    }
}

/// Key NAMES the external stores expose, per store (never values): what the
/// console's registry and entries listings add to the native names. Each
/// install starts from the previous set, keeping the names of the stores it
/// still has; a background listing after the install replaces each store's
/// names when its listing succeeds (an empty result included), and every
/// walk that finds a KEY in an external store adds it. Advisory: resolution
/// authority stays with the adapters.
#[derive(Clone, Default)]
pub struct ExternalKeys(Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>);

impl ExternalKeys {
    /// A new set for an install with these external stores: each keeps the
    /// names it had, a store no longer configured has none.
    fn carried(&self, stores: &crate::snapshot::Stores) -> ExternalKeys {
        let old = self.0.lock().unwrap();
        let kept = old
            .iter()
            .filter(|(id, _)| stores.adapters.contains_key(*id))
            .map(|(id, names)| (id.clone(), names.clone()))
            .collect();
        ExternalKeys(Arc::new(Mutex::new(kept)))
    }

    /// Every name, across stores.
    pub fn names(&self) -> HashSet<String> {
        self.0.lock().unwrap().values().flatten().cloned().collect()
    }

    /// A walk found `key` in `store`.
    pub(crate) fn note(&self, store: &str, key: &str) {
        self.0
            .lock()
            .unwrap()
            .entry(store.to_string())
            .or_default()
            .insert(key.to_string());
    }

    /// `store` listed `names`.
    fn listed(&self, store: &str, names: Vec<String>) {
        self.0
            .lock()
            .unwrap()
            .insert(store.to_string(), names.into_iter().collect());
    }
}

impl std::fmt::Debug for ExternalKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExternalKeys({} names)", self.names().len())
    }
}

/// `sha256(token)` hex: how a refresh token is keyed in memory.
fn refresh_token_hash(token: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(token)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// A provider-rotated refresh token not stored in the vault yet: `new` is the
/// only valid copy (the provider refuses `old` now), `old` is the value the
/// store still holds at its slot. Every mint input is followed through these
/// ([`AppState::current_refresh_token`]); an entry means "not stored".
#[derive(Clone)]
pub struct PendingRotation {
    pub old: zeroize::Zeroizing<Vec<u8>>,
    pub new: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for PendingRotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingRotation(<redacted>)")
    }
}

pub enum VaultState {
    Locked,
    Unlocked {
        /// What requests are served from, replaced whole by every served
        /// install and by a stored rotation's patch.
        snapshot: Arc<crate::snapshot::Snapshot>,
        /// What approvals authorize; no values ([`PermitKey`]).
        permits: Permits,
        /// Minted OAuth access tokens, kept across installs.
        oauth_access: OauthAccess,
        /// The console's external key names ([`ExternalKeys`]).
        external_keys: ExternalKeys,
        /// The retained state key `K` (zeroized on drop): a pull or a write
        /// is folded under it without another passkey ("vault key resident
        /// while unlocked", as 1Password). Dropped with the rest of this
        /// variant at lock, park and close.
        state_key: zeroize::Zeroizing<Vec<u8>>,
        /// The seal key S the snapshot's non-resident values are sealed
        /// under, with this variant's lifetime.
        seal_key: crate::snapshot::SealKey,
    },
}

/// Never prints K, S, a value or a token: a `{:?}` in a log line must not
/// expose what the snapshot keeps sealed.
impl std::fmt::Debug for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultState::Locked => f.write_str("Locked"),
            VaultState::Unlocked {
                snapshot,
                permits,
                oauth_access,
                external_keys,
                seal_key,
                ..
            } => f
                .debug_struct("Unlocked")
                .field("snapshot", snapshot)
                .field("permits", &permits.0.len())
                .field("oauth_access", oauth_access)
                .field("external_keys", external_keys)
                .field("state_key", &"<redacted>")
                .field("seal_key", seal_key)
                .finish(),
        }
    }
}

/// The key an install folds the store under ([`AppState::install`]).
pub enum InstallKey {
    /// The vault-unlock op's grant: the only install that may take a Locked
    /// vault to Unlocked.
    Unlock(zeroize::Zeroizing<Vec<u8>>),
    /// An approved write's grant: served only while Unlocked, and then held
    /// as the vault's key.
    Grant(zeroize::Zeroizing<Vec<u8>>),
    /// The key held while Unlocked (sync pulls, the daemon's own writes, the
    /// connect exchange), read under the build mutex.
    Held,
}

/// What an install did ([`AppState::install`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installed {
    /// The new snapshot is served.
    Served,
    /// The current snapshot is kept (the vault-unlock op unlocks nothing):
    /// the new fold cannot read a row the served snapshot read, or the store
    /// could not be folded at all. Noted as key-changed when the key is why,
    /// and as behind while Unlocked.
    Refused,
    /// The vault is not Unlocked at the swap (locked, parked or gone), and
    /// only the vault-unlock op unlocks it: nothing is served.
    NotUnlocked,
}

impl Installed {
    pub fn served(self) -> bool {
        self == Installed::Served
    }
}

/// A request step 6 let through ([`AppState::authorize`]): the snapshot it
/// was decided on, where its KEYs are, and the single-use permit step 8
/// spends. Only `authorize` builds one, and step 7
/// ([`AppState::materialize`]) takes nothing else.
pub struct Authorized {
    snapshot: Arc<crate::snapshot::Snapshot>,
    keys: BTreeMap<String, crate::snapshot::Location>,
    consume: Option<PermitKey>,
}

/// A location may carry a value the walk fetched: never printed.
impl std::fmt::Debug for Authorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorized")
            .field("keys", &self.keys.keys().collect::<Vec<_>>())
            .field("consume", &self.consume)
            .finish_non_exhaustive()
    }
}

/// Why step 6 did not let a request through.
#[derive(Debug)]
pub enum Unauthorized {
    /// No live permit: the caller mints an op and opens the portal.
    NoPermit,
    /// The vault is gone or not Unlocked.
    Refused(crate::error::AppError),
}

/// The values of an authorized request's KEYs (step 7), by KEY: plaintext
/// that lives only for this request and is zeroized when it is dropped.
#[derive(Default)]
pub struct Values(BTreeMap<String, zeroize::Zeroizing<Vec<u8>>>);

impl Values {
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.0.get(key).map(|v| v.as_slice())
    }
}

impl std::fmt::Debug for Values {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.keys().map(|k| format!("{}: <redacted>", k)))
            .finish()
    }
}

/// Why step 7 could not read a value.
#[derive(Debug)]
pub enum Unreadable {
    /// A native KEY step 4 found holds no value (a build inconsistency):
    /// fail closed.
    NotHeld(String),
    /// The vault is gone or not Unlocked (or S changed since the snapshot).
    Refused(crate::error::AppError),
}

/// A loopback OAuth connect awaiting its `?code&state` redirect. Points a
/// pending `state` (RFC 6749) at the (vault, connection) whose sealed
/// `connecting` entry holds the matching code_verifier, and carries the
/// loopback PORT its provider will redirect to (allowlist-checked at
/// registration — `ServiceRegistry::loopback_allowlist`): 8765 for the
/// canonical callback, 1455 for openai_codex's registered one.
#[derive(Clone)]
pub struct PendingLoopback {
    pub vault_id: String,
    pub conn_id: String,
    pub port: u16,
    inserted_at: std::time::Instant,
}

/// Why the sync did not apply a local change ([`AppState::note_sync`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncNote {
    /// A person's change to the record: it changed elsewhere meanwhile and
    /// was set aside (`sc sync` asks to re-run it).
    ChangedElsewhere(String),
    /// Sprott's automatic upgrade of this vault paused on the record: it
    /// changed elsewhere meanwhile; the upgrade retries.
    UpgradePaused(String),
    /// Refused, with why (a full sentence).
    Refused(String),
}

impl SyncNote {
    /// The note as a sentence; `None` for a set-aside change (`sc sync`
    /// words that one itself).
    pub fn sentence(&self) -> Option<String> {
        match self {
            SyncNote::ChangedElsewhere(_) => None,
            SyncNote::UpgradePaused(r) => Some(format!(
                "Sprott's automatic upgrade of this vault paused: {} changed elsewhere meanwhile; it retries at the next unlock",
                r
            )),
            SyncNote::Refused(why) => Some(why.clone()),
        }
    }
}

/// The key a pending rotation's note is kept under in the sync notes.
pub(crate) fn rotation_note_key(conn_id: &str) -> String {
    format!("rotation {}", conn_id)
}

/// Process-wide daemon state. All state with a vault lifetime is reached
/// through `vault_runtimes`; tombstones retain only the refusal reason and host
/// anchors needed to intercept requests after the runtime is gone.
pub struct AppState {
    pub config: Config,
    pub vaults: VaultDir,
    pub vault_runtimes: Mutex<HashMap<String, Arc<crate::vault_runtime::VaultRuntime>>>,
    pub vault_tombstones: Mutex<HashMap<String, crate::vault_runtime::Tombstone>>,
    /// Team-edition extension hooks (team-edition §9 open/closed split). The
    /// open build leaves the [`crate::team_hooks::NoopHooks`] default (no team
    /// policy); the closed `sprott-ee` overlay injects real ones via
    /// [`AppState::with_team_hooks`]. Serve-time team policy (the offline lease,
    /// etc.) lives behind these, never inline in open core.
    pub team: std::sync::Arc<dyn crate::team_hooks::TeamHooks>,
    pub challenges: Mutex<ChallengeStore>,
    pub approvals: Mutex<ApprovalStore>,
    /// Batch-approve root memo (design/batch-approve.md §Daemon verify 5):
    /// `credential_id ‖ "|" ‖ op_ids.join(",")` → (Merkle root over the
    /// batch's stored β's, expiry = max sibling expiry). PURE MEMO of a
    /// function of the daemon's own op store — it only skips the sibling
    /// loads + rebuild on later rows of the same batch; the WebAuthn verify
    /// and every per-row check still run on every row, so a stale or
    /// adversarial entry can never approve anything (a wrong root just fails
    /// signature verification). Bounded: entries expire with their batch and
    /// the map is hard-capped (oldest-expiry evicted).
    pub batch_roots: Mutex<HashMap<String, ([u8; 32], u64)>>,
    pub services: ServiceRegistry,
    pub events: broadcast::Sender<ApprovalEvent>,
    /// The canonical JSON of the runtimes' host unions last written to disk, so the hot
    /// CONNECT path rewrites the durable cache only when the anchor set actually
    /// changes. Host names only — non-sensitive.
    pub host_unions_persisted: Mutex<String>,
    /// Daemon HPKE outer-envelope keypair (PROTOCOL.md §4.2.1 M1). Loaded
    /// once at startup, used to open pending-passkey seals (cross-device
    /// add-passkey) and — in future — `[HPKE: MUST]` grant submissions.
    pub sc: crate::crypto::envelope::ScKeyPair,
    /// This device's standing in the account principal ledger and the account's
    /// admitted agents (DESIGN-principal-ledger-enforced W2/W3/W6). Fail closed:
    /// nothing serves until a decision is loaded ([`crate::principal_ledger::init_gate`]).
    pub ledger: Mutex<crate::principal_ledger::LedgerGate>,
    /// Serializes ledger pulls (the loop and the on-miss re-pull) and stamps the
    /// last one, so an agent miss re-pulls at most once per 2 s. tokio Mutex:
    /// held across the fetch.
    pub ledger_sync: tokio::sync::Mutex<Option<std::time::Instant>>,
    /// Authorization codes this daemon has already REDEEMED (sha256-hex → when).
    /// An OAuth code is single-use: a stale write (a buggy web Save, a
    /// cross-device echo, or a pull that re-introduces the `connecting` entry
    /// before our success push lands) can resurrect a code we already consumed.
    /// Re-exchanging it earns `invalid_grant`, which the connect state machine
    /// would misread as a terminal failure and use to clobber the live
    /// connection. This is the idempotency key: skip any code already here.
    /// Daemon-local + NEVER synced (so no stale write can revert it); in-memory
    /// (a restart empties it, by which point the cloud has converged). Entries
    /// self-reap after `REDEEMED_CODE_TTL` (codes expire ~10min upstream).
    pub oauth_redeemed_codes: Mutex<HashMap<String, std::time::Instant>>,
    /// sha256(authorization code) → when this daemon first tried to exchange
    /// it and failed transiently (the retry window counts from it).
    pub oauth_code_first_tried: Mutex<HashMap<String, std::time::Instant>>,
    /// (vault, sha256(refresh token)) → the token a refresh in this process
    /// rotated it to, and when: a mint that read the replaced token (before
    /// it waited for the vault write lock, or from a fresh decrypt) follows
    /// it instead of sending a token the provider refuses (some revoke the
    /// whole token family on such a reuse). Entries self-reap.
    pub oauth_rotated_to: Mutex<HashMap<(String, String), (zeroize::Zeroizing<String>, std::time::Instant)>>,
    /// Random per daemon PROCESS (hex). Rides every op-relay register so the
    /// backend can cancel a previous process's pending rows: the op store is
    /// in-memory and poll tasks spawn only at mint, so a pre-restart row can
    /// never apply (design/approvals-inbox.md D1, restart zombies).
    pub boot_id: String,
    /// The device egress proxy the resident proxy's forward hop tunnels through,
    /// in a swappable cell so `sprott config set/unset proxy` HOT-reloads it via
    /// `/proxy/reload` — no daemon restart, no vault re-unlock. Shared with the
    /// hudsucker forward connector (see `proxy::upstream`); the reqwest side
    /// swaps via `core::forward::reload_egress_proxy`.
    pub egress_proxy: crate::proxy::upstream::EgressProxyCell,
    /// In-flight loopback OAuth connects awaiting their `?code&state` redirect on
    /// the shared 8765 callback. `state` → the (vault, connection) whose sealed
    /// `connecting` entry holds the matching code_verifier. Populated each sync
    /// tick from a `connecting` entry that carries a `state` and no code yet;
    /// consumed + removed when `auth::loopback` catches the redirect. In-memory +
    /// daemon-local; entries self-reap at the 2h ceiling (`LOOPBACK_PENDING_TTL`)
    /// so an abandoned consent never lingers.
    pub oauth_pending: Mutex<HashMap<String, PendingLoopback>>,
    /// Guard so each on-demand loopback listener runs as a SINGLE shared
    /// instance PER PORT: a port is present while its listener task is live.
    /// `auth::loopback::ensure_running` inserts and spawns only on a fresh
    /// port, so N concurrent connects share ONE listener per port (the daemon
    /// never races itself into a port conflict). A port is removed when its
    /// task exits (idle self-close or bind failure).
    pub oauth_listener_running: Mutex<std::collections::HashSet<u16>>,
    /// Secret values a local CLI deposited for a pending write op
    /// (`connection-add` / `secret-set`), keyed by their salted digest. The op
    /// carries ONLY the digest in `act.scope` — the full op JSON rides to the
    /// cloud op-relay for the grant page, so plaintext values must never be in
    /// it (and the salt keeps a weak value from being brute-forced from the
    /// public digest). Approving the op binds the digest via β; the act then
    /// takes the stash, re-verifies the digest, and writes the values. In-memory
    /// + daemon-local; entries self-reap after their own op-window TTL.
    pub op_payloads: Mutex<HashMap<String, OpPayloadEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultWriteRevoked(pub crate::vault_runtime::TombstoneReason);

impl std::fmt::Display for VaultWriteRevoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("vault access revoked")
    }
}

impl VaultWriteRevoked {
    pub fn app_error(self) -> crate::error::AppError {
        match self.0 {
            crate::vault_runtime::TombstoneReason::Removed => {
                crate::error::AppError::VaultAccessRevoked
            }
            crate::vault_runtime::TombstoneReason::Deleted => crate::error::AppError::VaultDeleted,
            crate::vault_runtime::TombstoneReason::DeviceRevoked => {
                crate::error::AppError::LedgerDeviceRevoked
            }
        }
    }
}

/// One deposited value-set awaiting its op's approval. See
/// [`AppState::op_payloads`].
pub struct OpPayloadEntry {
    inserted_at: std::time::Instant,
    ttl: std::time::Duration,
    nonce: [u8; 32],
    pub values: std::collections::BTreeMap<String, String>,
}

pub(crate) fn host_anchors_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join("host-anchors.json")
}

/// Deterministic (sorted vids + hosts) JSON of the host-anchor union, so an
/// unchanged set has a stable string for the skip-rewrite compare and the file
/// on disk is stable across boots.
fn canonical_unions_json(map: &HashMap<String, Vec<String>>) -> String {
    // This vault-keyed map is only the on-disk host-anchor transfer format.
    // AppState::new immediately moves every entry into its VaultRuntime.
    let sorted: std::collections::BTreeMap<&str, Vec<&str>> = map
        .iter()
        .map(|(k, v)| {
            let mut hs: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
            hs.sort_unstable();
            (k.as_str(), hs)
        })
        .collect();
    serde_json::to_string(&sorted).unwrap_or_default()
}

/// Load the durable host-anchor union (host names only — non-sensitive). Best
/// effort: any read/parse error yields an empty map (falls back to the
/// pre-persistence behaviour of blind-until-unlock).
fn load_host_unions(state_dir: &std::path::Path) -> (HashMap<String, Vec<String>>, String) {
    match std::fs::read(host_anchors_path(state_dir)) {
        Ok(bytes) => match serde_json::from_slice::<HashMap<String, Vec<String>>>(&bytes) {
            Ok(map) => {
                let json = canonical_unions_json(&map);
                (map, json)
            }
            Err(_) => (HashMap::new(), String::new()),
        },
        Err(_) => (HashMap::new(), String::new()),
    }
}

impl AppState {
    /// Inject the closed `sprott-ee` team hooks (team-edition §9). The open
    /// build leaves the [`crate::team_hooks::NoopHooks`] default; the overlay's
    /// `main` calls this on the fresh `AppState` before it is wrapped in `Arc`.
    /// Chainable.
    pub fn with_team_hooks(
        mut self,
        hooks: std::sync::Arc<dyn crate::team_hooks::TeamHooks>,
    ) -> Self {
        self.team = hooks;
        self
    }

    pub fn new(config: Config) -> Self {
        let vaults = VaultDir::new(&config.state_dir);
        // Durable host-anchor union (host names only): lets a daemon restarted
        // while a vault is still locked keep MITMing that vault's brokered hosts.
        let (loaded_unions, loaded_unions_json) = load_host_unions(&config.state_dir);
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let runtimes = loaded_unions
            .into_iter()
            .map(|(vid, hosts)| {
                let runtime = crate::vault_runtime::VaultRuntime::new(vid.clone(), hosts);
                (vid, Arc::new(runtime))
            })
            .collect();
        let sc = crate::crypto::envelope::ScKeyPair::load_or_generate()
            .expect("sc_sk load/generate failed. Check ~/.sprott/crypto perms");
        Self {
            config,
            vaults,
            vault_runtimes: Mutex::new(runtimes),
            vault_tombstones: Mutex::new(HashMap::new()),
            team: std::sync::Arc::new(crate::team_hooks::NoopHooks),
            challenges: Mutex::new(ChallengeStore::new()),
            approvals: Mutex::new(ApprovalStore::new()),
            batch_roots: Mutex::new(HashMap::new()),
            services: ServiceRegistry::load(),
            events,
            host_unions_persisted: Mutex::new(loaded_unions_json),
            sc,
            ledger: Mutex::new(crate::principal_ledger::LedgerGate::default()),
            ledger_sync: tokio::sync::Mutex::new(None),
            oauth_redeemed_codes: Mutex::new(HashMap::new()),
            oauth_code_first_tried: Mutex::new(HashMap::new()),
            oauth_rotated_to: Mutex::new(HashMap::new()),
            boot_id: {
                use rand::RngCore as _;
                let mut b = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut b);
                b.iter().map(|x| format!("{:02x}", x)).collect()
            },
            egress_proxy: crate::proxy::upstream::new_cell(),
            oauth_pending: Mutex::new(HashMap::new()),
            oauth_listener_running: Mutex::new(std::collections::HashSet::new()),
            op_payloads: Mutex::new(HashMap::new()),
        }
    }

    /// The only entrance to vault-scoped runtime state. The map and tombstone
    /// locks are always acquired in this order; neither is held for I/O.
    pub fn runtime(
        &self,
        vault_id: &str,
    ) -> Result<Arc<crate::vault_runtime::VaultRuntime>, crate::vault_runtime::VaultGone> {
        let mut runtimes = self.vault_runtimes.lock().unwrap();
        if let Some(runtime) = runtimes.get(vault_id) {
            if !runtime.is_closed() {
                return Ok(runtime.clone());
            }
        }
        if let Some(tombstone) = self.vault_tombstones.lock().unwrap().get(vault_id) {
            return Err(crate::vault_runtime::VaultGone {
                reason: tombstone.reason,
            });
        }
        let runtime = Arc::new(crate::vault_runtime::VaultRuntime::new(
            vault_id.to_string(),
            Vec::new(),
        ));
        runtimes.insert(vault_id.to_string(), runtime.clone());
        Ok(runtime)
    }

    pub fn mark_vault_closing(
        &self,
        vault_id: &str,
        reason: crate::vault_runtime::TombstoneReason,
    ) {
        let runtimes = self.vault_runtimes.lock().unwrap();
        let runtime = runtimes.get(vault_id);
        let hosts = runtime
            .map(|runtime| {
                runtime.mark_closed();
                runtime.last_host_union.lock().unwrap().clone()
            });
        let mut tombstones = self.vault_tombstones.lock().unwrap();
        let existing = tombstones.get(vault_id).cloned();
        let reason = existing
            .as_ref()
            .map(|tombstone| tombstone.reason.merge(reason))
            .unwrap_or(reason);
        let hosts = hosts
            .or_else(|| existing.map(|tombstone| tombstone.hosts))
            .unwrap_or_default();
        tombstones.insert(
            vault_id.to_string(),
            crate::vault_runtime::Tombstone { reason, hosts },
        );
    }

    pub fn runtime_if_present(
        &self,
        vault_id: &str,
    ) -> Option<Arc<crate::vault_runtime::VaultRuntime>> {
        self.vault_runtimes
            .lock()
            .unwrap()
            .get(vault_id)
            .filter(|runtime| !runtime.is_closed())
            .cloned()
    }

    pub fn runtime_ids(&self) -> Vec<String> {
        self.vault_runtimes.lock().unwrap().keys().cloned().collect()
    }

    pub fn tombstone_reason(
        &self,
        vault_id: &str,
    ) -> Option<crate::vault_runtime::TombstoneReason> {
        self.vault_tombstones
            .lock()
            .unwrap()
            .get(vault_id)
            .map(|t| t.reason)
    }

    pub fn vault_gone_error(&self, vault_id: &str) -> Option<crate::error::AppError> {
        match self.tombstone_reason(vault_id)? {
            crate::vault_runtime::TombstoneReason::Removed => {
                Some(crate::error::AppError::VaultAccessRevoked)
            }
            crate::vault_runtime::TombstoneReason::Deleted => {
                Some(crate::error::AppError::VaultDeleted)
            }
            crate::vault_runtime::TombstoneReason::DeviceRevoked => {
                Some(crate::error::AppError::LedgerDeviceRevoked)
            }
        }
    }

    /// Re-admit a tombstoned vault with a fresh runtime. `None` while a runtime for it
    /// is still present: a closing one whose `close_vault` has not run yet must not be
    /// replaced (that would leave two writers); discovery retries on its next pass.
    pub fn restore_vault(&self, vault_id: &str) -> Option<Arc<crate::vault_runtime::VaultRuntime>> {
        let mut runtimes = self.vault_runtimes.lock().unwrap();
        if runtimes.contains_key(vault_id) {
            return None;
        }
        let hosts = self
            .vault_tombstones
            .lock()
            .unwrap()
            .remove(vault_id)
            .map(|t| t.hosts)
            .unwrap_or_default();
        let runtime = Arc::new(crate::vault_runtime::VaultRuntime::new(
            vault_id.to_string(),
            hosts,
        ));
        runtimes.insert(vault_id.to_string(), runtime.clone());
        Some(runtime)
    }

    pub async fn close_vault(
        &self,
        vault_id: &str,
        reason: crate::vault_runtime::TombstoneReason,
        delete_disk: bool,
    ) {
        let runtime = {
            let mut runtimes = self.vault_runtimes.lock().unwrap();
            let runtime = runtimes.remove(vault_id);
            let existing = self.vault_tombstones.lock().unwrap().get(vault_id).cloned();
            let reason = existing
                .as_ref()
                .map(|tombstone| tombstone.reason.merge(reason))
                .unwrap_or(reason);
            let hosts = runtime
                .as_ref()
                .map(|r| r.last_host_union.lock().unwrap().clone())
                .or_else(|| {
                    existing.as_ref().map(|tombstone| tombstone.hosts.clone())
                })
                .unwrap_or_default();
            if let Some(runtime) = runtime.as_ref() {
                runtime.mark_closed();
            }
            self.vault_tombstones.lock().unwrap().insert(
                vault_id.to_string(),
                crate::vault_runtime::Tombstone { reason, hosts },
            );
            (runtime, reason)
        };
        let (runtime, reason) = runtime;
        if let Some(runtime) = runtime {
            runtime.close(self, reason).await;
        } else {
            self.oauth_pending
                .lock()
                .unwrap()
                .retain(|_, pending| pending.vault_id != vault_id);
            let rejection = reason.rejection_reason();
            let rejected = self
                .approvals
                .lock()
                .unwrap()
                .reject_vault(vault_id, rejection);
            for approval_id in rejected {
                let _ = self.events.send(ApprovalEvent {
                    vault_id: vault_id.to_string(),
                    approval_id,
                    kind: "rejected".into(),
                    op_summary: None,
                    response_preview: None,
                    reason: Some(rejection.into()),
                });
            }
        }
        if delete_disk {
            if let Err(error) = crate::sync::remove_vault_dir(&self.config.state_dir, vault_id) {
                tracing::warn!(vault = %vault_id, "vault close: local copy removal failed: {}", error);
            }
        }
        if let Err(error) = crate::cli::active::forget_vault(vault_id) {
            tracing::warn!(vault = %vault_id, "vault close: failed to forget catalog entry: {}", error);
        }
    }

    pub fn audit_for_vault(
        &self,
        vault_id: &str,
    ) -> crate::error::Result<Arc<crate::audit::AuditStore>> {
        // Only a vault held on disk gets a runtime for its audit log.
        if !self.vaults.dir_for(vault_id)?.exists() {
            return Err(self.vault_gone_error(vault_id).unwrap_or(crate::error::AppError::NotFound));
        }
        let runtime = self
            .runtime(vault_id)
            .map_err(crate::vault_runtime::VaultGone::app_error)?;
        let mut slot = runtime.audit.lock().unwrap();
        if let Some(store) = slot.as_ref() {
            return Ok(store.clone());
        }
        if runtime.is_closed() {
            return Err(self
                .vault_gone_error(vault_id)
                .unwrap_or(crate::error::AppError::VaultAccessRevoked));
        }
        let vault_dir = self.vaults.dir_for(vault_id)?;
        if !vault_dir.exists() {
            return Err(crate::error::AppError::NotFound);
        }
        let store = Arc::new(crate::audit::AuditStore::open(
            &self.vaults.audit_path(vault_id)?,
        )?);
        Ok(slot.get_or_insert_with(|| store.clone()).clone())
    }

    /// Stash-lifetime ceiling. Each entry carries its own TTL — the vault's
    /// approval window + slack (see op_payload.rs), so the stash strictly
    /// outlives every moment its op is still approvable. The "user approved
    /// but the deposited value had already expired" failure was exactly a
    /// fixed 300s here under a longer op window; per-entry TTLs from the ONE
    /// policy knob make that class structurally impossible. The ceiling only
    /// bounds a pathological policy value.
    const MAX_OP_PAYLOAD_TTL: std::time::Duration = std::time::Duration::from_secs(86_460);
    /// Flood cap. A human runs one `sc connect` at a time; 32 concurrent
    /// pending stashes is already pathological.
    const MAX_OP_PAYLOADS: usize = 32;

    /// Salted commitment over a value-set: `sha256(DS ‖ nonce ‖ canonical(values))`.
    /// BTreeMap serialization is key-sorted, so `to_vec` is canonical.
    fn op_payload_digest(
        nonce: &[u8; 32],
        values: &std::collections::BTreeMap<String, String>,
    ) -> String {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(b"safeclaw/v1/op-payload");
        h.update(nonce);
        h.update(serde_json::to_vec(values).unwrap_or_default());
        h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Deposit a value-set; returns the digest the op's `act.scope` must carry.
    /// `None` when the stash is full (flood guard).
    pub fn op_payload_insert(
        &self,
        values: std::collections::BTreeMap<String, String>,
        ttl: std::time::Duration,
    ) -> Option<String> {
        use rand::RngCore as _;
        let ttl = ttl.min(Self::MAX_OP_PAYLOAD_TTL);
        let mut m = self.op_payloads.lock().unwrap();
        let now = std::time::Instant::now();
        m.retain(|_, e| now.duration_since(e.inserted_at) < e.ttl);
        if m.len() >= Self::MAX_OP_PAYLOADS {
            return None;
        }
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let digest = Self::op_payload_digest(&nonce, &values);
        m.insert(
            digest.clone(),
            OpPayloadEntry {
                inserted_at: now,
                ttl,
                nonce,
                values,
            },
        );
        Some(digest)
    }

    /// The KEY names a live (unexpired) stash holds, without consuming it or
    /// exposing a value: the mint-time card reads which keys an op writes.
    pub fn op_payload_keys(&self, digest: &str) -> Option<Vec<String>> {
        let m = self.op_payloads.lock().unwrap();
        let entry = m.get(digest)?;
        if entry.inserted_at.elapsed() >= entry.ttl {
            return None;
        }
        Some(entry.values.keys().cloned().collect())
    }

    /// Consume the stash for an approved op. Single-use (removed on take);
    /// expired entries and digest mismatches (defense-in-depth recompute)
    /// yield `None` — the caller fails the act closed.
    pub fn op_payload_take(
        &self,
        digest: &str,
    ) -> Option<std::collections::BTreeMap<String, String>> {
        let entry = self.op_payloads.lock().unwrap().remove(digest)?;
        if entry.inserted_at.elapsed() >= entry.ttl {
            return None;
        }
        if Self::op_payload_digest(&entry.nonce, &entry.values) != digest {
            return None;
        }
        Some(entry.values)
    }

    /// Publish the ledger standing. Anything but `Open` evicts K from every
    /// vault at once (park / lock / wipe); data stays on disk.
    pub fn set_ledger(&self, gate: crate::principal_ledger::LedgerGate) {
        let open = gate.device == crate::principal_ledger::DeviceGate::Open;
        *self.ledger.lock().unwrap() = gate;
        if !open {
            let runtimes: Vec<_> = self.vault_runtimes.lock().unwrap().values().cloned().collect();
            for runtime in runtimes {
                runtime.set_locked();
            }
        }
    }

    /// Why this device may not unlock or broker right now (the ledger standing),
    /// or `None` when it is admitted and within the lease.
    pub fn ledger_refusal(&self) -> Option<crate::error::AppError> {
        use crate::principal_ledger::DeviceGate;
        match self.ledger.lock().unwrap().device {
            DeviceGate::Open => None,
            DeviceGate::NotAdmitted => Some(crate::error::AppError::DeviceNotAdmitted),
            DeviceGate::AccountMissing => Some(crate::error::AppError::DeviceAccountMissing),
            DeviceGate::Stale => Some(crate::error::AppError::LedgerStale),
            DeviceGate::Revoked => Some(crate::error::AppError::LedgerDeviceRevoked),
        }
    }

    /// Does the account ledger admit agent `agent_id` (latest event an admit)?
    /// `false` with no verified decision (fail closed).
    pub fn agent_admitted(&self, agent_id: &str) -> bool {
        self.ledger
            .lock()
            .unwrap()
            .agents
            .as_ref()
            .is_some_and(|a| a.contains(agent_id))
    }

    /// Tests: an admitted, in-lease device with these admitted agents.
    #[cfg(test)]
    pub fn open_ledger_for_tests(&self, agents: &[&str]) {
        self.set_ledger(crate::principal_ledger::LedgerGate {
            device: crate::principal_ledger::DeviceGate::Open,
            agents: Some(agents.iter().map(|s| s.to_string()).collect()),
            checked_at: Some(crate::util::now_unix()),
        });
    }

    /// TTL for the redeemed-code ledger. OAuth authorization codes expire
    /// ~10min after issue; 15min covers clock skew, then entries self-reap.
    const REDEEMED_CODE_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

    /// Record that this daemon successfully redeemed `code` — the idempotency
    /// key that stops a stale re-introduction from re-exchanging it. See
    /// [`Self::oauth_redeemed_codes`].
    pub fn note_code_redeemed(&self, code: &str) {
        let mut m = self.oauth_redeemed_codes.lock().unwrap();
        Self::reap_redeemed(&mut m);
        m.insert(crate::api_key::sha256_hex(code), std::time::Instant::now());
    }

    /// True iff this daemon already redeemed `code` — a re-exchange would be a
    /// no-win `invalid_grant`, so the connect machine skips it.
    pub fn was_code_redeemed(&self, code: &str) -> bool {
        let mut m = self.oauth_redeemed_codes.lock().unwrap();
        Self::reap_redeemed(&mut m);
        m.contains_key(&crate::api_key::sha256_hex(code))
    }

    /// When this daemon first tried `code` (now, on the first ask). Entries
    /// self-reap like the redeemed ledger: a code is dead long before.
    pub fn code_first_tried(&self, code: &str) -> std::time::Instant {
        let mut m = self.oauth_code_first_tried.lock().unwrap();
        Self::reap_redeemed(&mut m);
        *m.entry(crate::api_key::sha256_hex(code))
            .or_insert_with(std::time::Instant::now)
    }

    fn reap_redeemed(m: &mut HashMap<String, std::time::Instant>) {
        let now = std::time::Instant::now();
        m.retain(|_, t| now.duration_since(*t) < Self::REDEEMED_CODE_TTL);
    }

    /// Ceiling on how long a loopback connect stays matchable while awaiting its
    /// redirect. The primary driver is "there's an unfinished connect"; this 2h
    /// cap is the backstop so an abandoned consent never keeps the entry alive
    /// forever. Generous on purpose — the listener is benign (`auth::loopback`).
    const LOOPBACK_PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(2 * 60 * 60);

    /// Register (or refresh) a loopback connect awaiting its `?code&state`
    /// redirect. Idempotent — a repeated sync tick re-inserts the same mapping
    /// harmlessly (and refreshes its 2h clock).
    pub fn note_loopback_pending(&self, state: &str, vault_id: &str, conn_id: &str, port: u16) {
        if state.is_empty() {
            return;
        }
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.insert(
            state.to_string(),
            PendingLoopback {
                vault_id: vault_id.to_string(),
                conn_id: conn_id.to_string(),
                port,
                inserted_at: std::time::Instant::now(),
            },
        );
    }

    /// Resolve + REMOVE the (vault, connection) for a caught `state`, or `None`
    /// if unknown/expired. Removal makes the match single-use: a replayed
    /// redirect finds nothing (and gets the bland 404).
    pub fn take_loopback_pending(&self, state: &str) -> Option<PendingLoopback> {
        if state.is_empty() {
            return None;
        }
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.remove(state)
    }

    /// True iff some loopback connect is awaiting a redirect on `port` (reaps
    /// expired entries first). Drives that port's on-demand listener: non-empty
    /// ⇒ keep (or open) its window; empty ⇒ let it self-close.
    pub fn has_loopback_pending_on(&self, port: u16) -> bool {
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.values().any(|p| p.port == port)
    }

    /// The distinct ports with a connect currently awaiting a redirect — one
    /// on-demand listener per entry (`auth::loopback::ensure_running`).
    pub fn pending_loopback_ports(&self) -> Vec<u16> {
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        let mut ports: Vec<u16> = m.values().map(|p| p.port).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Drop any pending-loopback entries for a (vault, connection) that reached a
    /// terminal state (completed / failed), so the on-demand listener can close
    /// promptly instead of lingering to the 2h cap. The auto-catch path already
    /// took its entry out; this covers the paste-fallback path, whose pre-seal
    /// registered an entry no redirect ever consumed.
    pub fn clear_loopback_for_conn(&self, vault_id: &str, conn_id: &str) {
        let mut m = self.oauth_pending.lock().unwrap();
        m.retain(|_, p| !(p.vault_id == vault_id && p.conn_id == conn_id));
    }

    fn reap_loopback(m: &mut HashMap<String, PendingLoopback>) {
        let now = std::time::Instant::now();
        m.retain(|_, p| now.duration_since(p.inserted_at) < Self::LOOPBACK_PENDING_TTL);
    }

    /// Emit an event into the broadcast channel. Silently swallows the "no
    /// active subscribers" case (it's normal — happens before any /try tab is
    /// connected).
    pub fn emit_event(&self, ev: ApprovalEvent) {
        let _ = self.events.send(ev);
    }

    /// True iff this vault is currently Locked (including "never unlocked
    /// since process boot").
    pub fn is_vault_locked(&self, vault_id: &str) -> bool {
        // A read: a vault with no runtime (never unlocked here, or closed) is
        // locked, and asking must not create one.
        let Some(runtime) = self.runtime_if_present(vault_id) else {
            return true;
        };
        let state = runtime.state.lock().unwrap();
        !matches!(*state, VaultState::Unlocked { .. })
    }

    pub fn mark_vault_key_changed(&self, vault_id: &str) {
        if let Ok(runtime) = self.runtime(vault_id) {
            runtime
                .key_changed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    pub fn clear_vault_key_changed(&self, vault_id: &str) {
        if let Some(runtime) = self.runtime_if_present(vault_id) {
            runtime
                .key_changed
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }

    pub fn is_vault_key_changed(&self, vault_id: &str) -> bool {
        self.runtime_if_present(vault_id).is_some_and(|runtime| {
            runtime
                .key_changed
                .load(std::sync::atomic::Ordering::Acquire)
        })
    }

    /// True when at least one vault is currently unlocked.
    pub fn has_unlocked_vault(&self) -> bool {
        let runtimes: Vec<_> = self.vault_runtimes.lock().unwrap().values().cloned().collect();
        runtimes
            .iter()
            .any(|runtime| matches!(*runtime.state.lock().unwrap(), VaultState::Unlocked { .. }))
    }

    /// Install the vault's snapshot from its store: the one way a snapshot is
    /// built (the vault-unlock op, sync pulls, every write the daemon serves).
    /// Under the vault's build mutex: read the key and the store, fold, build
    /// the snapshot, swap. The caller may hold the vault write lock (lock
    /// order: write lock → build mutex → state lock); the install never
    /// takes it.
    ///
    /// Only [`InstallKey::Unlock`] takes a Locked vault to Unlocked; on an
    /// Unlocked vault it keeps the permits and the minted access tokens like
    /// every other install. Every other install replaces the snapshot only
    /// while the vault is Unlocked at the swap. No install touches the
    /// permits, except that a snapshot whose policy fingerprint differs from
    /// the served one's ends every window permit in the same swap (decision
    /// D). Every fold is tolerant (a row the key cannot read is skipped), and
    /// every install but the vault-unlock op's is refused when its fold
    /// cannot read a row the served snapshot read: the served snapshot stays.
    /// A served install sets or clears key-changed from the rows it could not
    /// read, and clears behind; a refused one sets behind while Unlocked, and
    /// key-changed when the key is why. The snapshot is sealed under the held
    /// S when the build starts Unlocked, else under a fresh one, and the swap
    /// installs that S. The ledger gate and the runtime's close are checked
    /// under the state lock, so no install undoes a lock, park or close.
    pub fn install(&self, vault_id: &str, key: InstallKey) -> Installed {
        let runtime = match key {
            InstallKey::Unlock(_) => self.runtime(vault_id).ok(),
            _ => self.runtime_if_present(vault_id),
        };
        let Some(runtime) = runtime else {
            return Installed::NotUnlocked;
        };
        runtime.with_build_lock(|| self.install_under_build_lock(&runtime, vault_id, key))
    }

    fn install_under_build_lock(
        &self,
        runtime: &crate::vault_runtime::VaultRuntime,
        vault_id: &str,
        key: InstallKey,
    ) -> Installed {
        use std::sync::atomic::Ordering;
        let unlock = matches!(key, InstallKey::Unlock(_));
        let (k, held_seal) = {
            let state = runtime.state.lock().unwrap();
            let held_seal = match &*state {
                VaultState::Unlocked { seal_key, .. } => Some(seal_key.clone()),
                VaultState::Locked => None,
            };
            let k = match key {
                InstallKey::Unlock(k) | InstallKey::Grant(k) => k,
                InstallKey::Held => match &*state {
                    VaultState::Unlocked { state_key, .. } => state_key.clone(),
                    VaultState::Locked => return Installed::NotUnlocked,
                },
            };
            (k, held_seal)
        };
        let seal = held_seal.unwrap_or_else(crate::snapshot::SealKey::fresh);
        let folded = crate::server::handlers::metadata::fold_store_with_key(self, vault_id, &k);
        let (view, rows) = match folded {
            Ok(folded) => folded,
            Err(e) => {
                tracing::warn!(vault = %vault_id, "install: the store could not be folded, the served snapshot stays: {}", e);
                let state = runtime.state.lock().unwrap();
                if matches!(*state, VaultState::Unlocked { .. }) {
                    runtime.behind.store(true, Ordering::Release);
                    // A key that opens nothing reads no row the served
                    // snapshot read.
                    if !unlock && matches!(e, crate::error::AppError::Unauthorized(_)) {
                        runtime.key_changed.store(true, Ordering::Release);
                    }
                }
                return Installed::Refused;
            }
        };
        let snapshot =
            crate::snapshot::Snapshot::build(view, rows.readable, &self.services, vault_id, &seal);
        #[cfg(test)]
        {
            let hook = runtime.before_swap.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        self.swap(runtime, vault_id, snapshot, &rows.unreadable, k, seal, unlock)
    }

    /// The swap of [`Self::install`], under the build mutex: `snapshot`
    /// (sealed under `seal`) becomes the one served, unless the rules there
    /// say otherwise.
    #[allow(clippy::too_many_arguments)]
    fn swap(
        &self,
        runtime: &crate::vault_runtime::VaultRuntime,
        vault_id: &str,
        snapshot: crate::snapshot::Snapshot,
        unreadable: &BTreeSet<String>,
        k: zeroize::Zeroizing<Vec<u8>>,
        seal: crate::snapshot::SealKey,
        unlock: bool,
    ) -> Installed {
        use std::sync::atomic::Ordering;
        let snapshot = Arc::new(snapshot);
        let external_keys = {
            // Checked under the state lock: close() marks the runtime closed,
            // and a park publishes the ledger gate, before either stores
            // Locked under this lock, so their Locked is always the last.
            let mut state = runtime.state.lock().unwrap();
            if runtime.is_closed() {
                return Installed::NotUnlocked;
            }
            // A parked or locked device holds no K (I3).
            if self.ledger.lock().unwrap().device != crate::principal_ledger::DeviceGate::Open {
                tracing::warn!(vault = %vault_id, "install refused: this device is not admitted to serve");
                return Installed::NotUnlocked;
            }
            match &*state {
                VaultState::Locked if !unlock => return Installed::NotUnlocked,
                VaultState::Unlocked { snapshot: served, .. }
                    if !unlock && !served.readable.is_disjoint(unreadable) =>
                {
                    runtime.key_changed.store(true, Ordering::Release);
                    runtime.behind.store(true, Ordering::Release);
                    tracing::warn!(vault = %vault_id, "install refused: the key cannot read rows the served snapshot reads (rotated K?); the served snapshot stays until `sprott unlock`");
                    return Installed::Refused;
                }
                _ => {}
            }
            let external_keys = if let VaultState::Unlocked {
                snapshot: served,
                permits,
                external_keys,
                state_key,
                seal_key,
                ..
            } = &mut *state
            {
                if served.fingerprint != snapshot.fingerprint {
                    permits.end_windows();
                }
                *external_keys = external_keys.carried(&snapshot.stores);
                *served = snapshot.clone();
                *state_key = k;
                *seal_key = seal;
                external_keys.clone()
            } else {
                let external_keys = ExternalKeys::default();
                *state = VaultState::Unlocked {
                    snapshot: snapshot.clone(),
                    permits: Permits::default(),
                    oauth_access: OauthAccess::default(),
                    external_keys: external_keys.clone(),
                    state_key: k,
                    seal_key: seal,
                };
                external_keys
            };
            runtime
                .key_changed
                .store(!unreadable.is_empty(), Ordering::Release);
            runtime.behind.store(false, Ordering::Release);
            external_keys
        };
        // Team lease clock: a served install read the vault as it is now.
        self.record_cloud_contact(vault_id);
        // Background external-key listing: one list() per store, so the
        // console's registry and entries see the flat namespace without a
        // network call on their read path. The task holds only the shared
        // adapters and this install's names slot, never AppState, so a later
        // install simply orphans it. Handle::try_current keeps plain #[test]
        // callers (no runtime) safe.
        let adapters: Vec<(String, Arc<crate::store::Adapter>)> = snapshot
            .stores
            .adapters
            .iter()
            .map(|(id, (_, a))| (id.clone(), a.clone()))
            .collect();
        if !adapters.is_empty() {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let vid = vault_id.to_string();
                rt.spawn(async move {
                    for (store_id, adapter) in adapters {
                        match adapter.list().await {
                            Ok(names) => {
                                tracing::info!(vault = %vid, store = %store_id, keys = names.len(), "external store keys listed");
                                external_keys.listed(&store_id, names);
                            }
                            // Accessor-only SAs can't list; the walk still
                            // finds their keys (and adds them here).
                            Err(e) => tracing::warn!(vault = %vid, store = %store_id, "external key listing failed: {}", e),
                        }
                    }
                });
            }
        }
        Installed::Served
    }

    /// Tests: serve the snapshot of `view` (sealed under the held S, or a
    /// fresh one) through the install's swap, as the vault-unlock op
    /// (`unlock`) or another install would.
    #[cfg(test)]
    pub fn install_view(
        &self,
        vault_id: &str,
        view: crate::storage::plaintext::VaultPlaintextView,
        state_key: zeroize::Zeroizing<Vec<u8>>,
        unlock: bool,
    ) -> Installed {
        let runtime = if unlock {
            self.runtime(vault_id).ok()
        } else {
            self.runtime_if_present(vault_id)
        };
        let Some(runtime) = runtime else {
            return Installed::NotUnlocked;
        };
        runtime.with_build_lock(|| {
            let held = match &*runtime.state.lock().unwrap() {
                VaultState::Unlocked { seal_key, .. } => Some(seal_key.clone()),
                VaultState::Locked => None,
            };
            let seal = held.unwrap_or_else(crate::snapshot::SealKey::fresh);
            let snapshot = crate::snapshot::Snapshot::build(
                view,
                BTreeSet::new(),
                &self.services,
                vault_id,
                &seal,
            );
            self.swap(&runtime, vault_id, snapshot, &BTreeSet::new(), state_key, seal, unlock)
        })
    }

    /// Tests: put a vault Unlocked serving `snapshot` (its fingerprint
    /// recomputed from its inputs) under this key, as the vault-unlock op
    /// would (nothing while parked or closed). Production builds every
    /// snapshot through [`Self::install`].
    #[cfg(test)]
    pub fn unlock_vault(
        &self,
        vault_id: String,
        mut snapshot: crate::snapshot::Snapshot,
        state_key: zeroize::Zeroizing<Vec<u8>>,
    ) {
        let Ok(runtime) = self.runtime(&vault_id) else {
            return;
        };
        snapshot.fingerprint = snapshot.inputs.fingerprint();
        runtime.with_build_lock(|| {
            let held = match &*runtime.state.lock().unwrap() {
                VaultState::Unlocked { seal_key, .. } => Some(seal_key.clone()),
                VaultState::Locked => None,
            };
            let seal = held.unwrap_or_else(crate::snapshot::SealKey::fresh);
            self.swap(&runtime, &vault_id, snapshot, &BTreeSet::new(), state_key, seal, true)
        });
    }

    /// Tests: change the served snapshot in place (a definition's token
    /// endpoint pointed at a local server, which the gate would refuse).
    #[cfg(test)]
    pub fn edit_snapshot(&self, vault_id: &str, f: impl FnOnce(&mut crate::snapshot::Snapshot)) {
        let runtime = self.runtime_if_present(vault_id).expect("a runtime");
        let mut state = runtime.state.lock().unwrap();
        if let VaultState::Unlocked { snapshot, .. } = &mut *state {
            f(Arc::make_mut(snapshot));
        }
    }

    /// Tests: every permit an Unlocked vault holds, with its expiry.
    #[cfg(test)]
    pub fn permits(&self, vault_id: &str) -> Vec<(PermitKey, u64)> {
        let Some(runtime) = self.runtime_if_present(vault_id) else {
            return Vec::new();
        };
        let state = runtime.state.lock().unwrap();
        match &*state {
            VaultState::Unlocked { permits, .. } => permits.all(),
            VaultState::Locked => Vec::new(),
        }
    }

    /// Tests: how many values were opened under the vault's S so far.
    #[cfg(test)]
    pub fn seal_opens(&self, vault_id: &str) -> usize {
        let runtime = self.runtime_if_present(vault_id).expect("a runtime");
        let state = runtime.state.lock().unwrap();
        match &*state {
            VaultState::Unlocked { seal_key, .. } => {
                seal_key.opens.load(std::sync::atomic::Ordering::SeqCst)
            }
            VaultState::Locked => 0,
        }
    }

    /// Tests: the value native item `name` serves (read as held, or opened
    /// under S), `None` while Locked or when it holds none.
    #[cfg(test)]
    pub fn served_native(&self, vault_id: &str, name: &str) -> Option<Vec<u8>> {
        let runtime = self.runtime_if_present(vault_id)?;
        let state = runtime.state.lock().unwrap();
        let VaultState::Unlocked {
            snapshot, seal_key, ..
        } = &*state
        else {
            return None;
        };
        match snapshot.held_native(name)? {
            crate::snapshot::Held::Plain(v) => Some(v.to_vec()),
            crate::snapshot::Held::Sealed(ct) => {
                seal_key.open(vault_id, name, ct).map(|v| v.to_vec())
            }
        }
    }

    /// Clone the retained state key `K` for an Unlocked vault, or `None` when
    /// the vault is Locked. Used by the cloud-sync refresh to re-decrypt a
    /// freshly-pulled sealed blob without a passkey.
    pub fn cloned_state_key(&self, vault_id: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let runtime = self.runtime_if_present(vault_id)?;
        let state = runtime.state.lock().unwrap();
        match &*state {
            VaultState::Unlocked { state_key, .. } => Some(state_key.clone()),
            _ => None,
        }
    }

    /// Lock a vault: K, S, the snapshot, the permits and the minted access
    /// tokens are dropped ([`crate::vault_runtime::VaultRuntime::set_locked`]).
    pub fn lock_vault(&self, vault_id: &str) {
        if let Some(runtime) = self.runtime_if_present(vault_id) {
            runtime.set_locked();
        }
    }

    /// The snapshot an Unlocked vault serves, `None` while it is Locked.
    /// Every reader of vault content outside the request path reads it.
    pub fn snapshot(&self, vault_id: &str) -> Option<Arc<crate::snapshot::Snapshot>> {
        let runtime = self.runtime_if_present(vault_id)?;
        let state = runtime.state.lock().unwrap();
        match &*state {
            VaultState::Unlocked { snapshot, .. } => Some(snapshot.clone()),
            VaultState::Locked => None,
        }
    }

    /// The key names an Unlocked vault's external stores expose (empty while
    /// Locked).
    pub fn external_key_names(&self, vault_id: &str) -> HashSet<String> {
        let Some(runtime) = self.runtime_if_present(vault_id) else {
            return HashSet::new();
        };
        let state = runtime.state.lock().unwrap();
        match &*state {
            VaultState::Unlocked { external_keys, .. } => external_keys.names(),
            VaultState::Locked => HashSet::new(),
        }
    }

    /// Whether the served snapshot is behind the store: the last install
    /// was refused while Unlocked
    /// ([`crate::vault_runtime::VaultRuntime::behind`]).
    pub fn is_vault_behind(&self, vault_id: &str) -> bool {
        self.runtime_if_present(vault_id).is_some_and(|runtime| {
            runtime
                .behind
                .load(std::sync::atomic::Ordering::Acquire)
        })
    }

    /// Why a request cannot go on with this vault: the vault-gone error once
    /// its runtime is closed, else `VaultLocked`.
    fn not_serving(&self, vault_id: &str) -> crate::error::AppError {
        self.vault_gone_error(vault_id)
            .unwrap_or(crate::error::AppError::VaultLocked)
    }

    /// What a walk that found a KEY in an external store needs (step 4),
    /// read under the state lock: S, and the console's external key names.
    pub(crate) fn fill_context(
        &self,
        vault_id: &str,
    ) -> Result<(crate::snapshot::SealKey, ExternalKeys), crate::error::AppError> {
        let read = self.runtime_if_present(vault_id).and_then(|runtime| {
            let state = runtime.state.lock().unwrap();
            if runtime.is_closed() {
                return None;
            }
            Some(match &*state {
                VaultState::Unlocked {
                    seal_key,
                    external_keys,
                    ..
                } => Ok((seal_key.clone(), external_keys.clone())),
                VaultState::Locked => Err(crate::error::AppError::VaultLocked),
            })
        });
        read.unwrap_or_else(|| Err(self.not_serving(vault_id)))
    }

    /// Step 6: may this request go on? `permit` is the key an approval of it
    /// would be stored under (`None` for a request policy allows: there is
    /// nothing to look up, and nothing to spend). Under the state lock: the
    /// vault-gone error when its runtime is closed, `VaultLocked` when it is
    /// not Unlocked; else the permit must be live, and a window only when the
    /// request was decided on a snapshot with the current policy
    /// fingerprint. A single-use permit is carried to step 8
    /// ([`Self::consume`]), which spends it: two replays may both pass here,
    /// and the one that loses there goes to the portal.
    pub fn authorize(
        &self,
        vault_id: &str,
        snapshot: Arc<crate::snapshot::Snapshot>,
        keys: BTreeMap<String, crate::snapshot::Location>,
        permit: Option<PermitKey>,
    ) -> Result<Authorized, Unauthorized> {
        let Some(key) = permit else {
            return Ok(Authorized {
                snapshot,
                keys,
                consume: None,
            });
        };
        let now = now_secs();
        let found = self.runtime_if_present(vault_id).and_then(|runtime| {
            let mut state = runtime.state.lock().unwrap();
            if runtime.is_closed() {
                return None;
            }
            Some(match &mut *state {
                VaultState::Unlocked {
                    snapshot: current,
                    permits,
                    ..
                } => {
                    let current_policy = current.fingerprint == snapshot.fingerprint;
                    Ok((key.single_use() || current_policy) && permits.live(&key, now))
                }
                VaultState::Locked => Err(crate::error::AppError::VaultLocked),
            })
        });
        match found {
            None => Err(Unauthorized::Refused(self.not_serving(vault_id))),
            Some(Err(e)) => Err(Unauthorized::Refused(e)),
            Some(Ok(false)) => Err(Unauthorized::NoPermit),
            Some(Ok(true)) => Ok(Authorized {
                snapshot,
                keys,
                consume: key.single_use().then_some(key),
            }),
        }
    }

    /// Step 7: the values of an authorized request's KEYs. A resident value
    /// is read as held; a sealed one is opened under S while holding the
    /// state lock (the vault-gone error when its runtime is closed,
    /// `VaultLocked` when it is not Unlocked, or when S changed since the
    /// snapshot was built); a value the step-4 walk fetched is used as it
    /// carried it, never fetched again. A native KEY step 4 found that holds
    /// no value fails closed.
    pub fn materialize(&self, vault_id: &str, auth: &Authorized) -> Result<Values, Unreadable> {
        use crate::snapshot::{Held, Location};
        let mut out = BTreeMap::new();
        // (KEY, the name it was sealed for, the sealed value)
        let mut sealed: Vec<(&String, &str, &Vec<u8>)> = Vec::new();
        for (key, at) in &auth.keys {
            let (name, held) = match at {
                Location::Native(name) => match auth.snapshot.held_native(name) {
                    Some(held) => (name.as_str(), held),
                    None => return Err(Unreadable::NotHeld(key.clone())),
                },
                Location::External { value, .. } => (key.as_str(), value),
            };
            match held {
                Held::Plain(v) => {
                    out.insert(key.clone(), v.clone());
                }
                Held::Sealed(ct) => sealed.push((key, name, ct)),
            }
        }
        if !sealed.is_empty() {
            let opened = self.runtime_if_present(vault_id).and_then(|runtime| {
                let state = runtime.state.lock().unwrap();
                if runtime.is_closed() {
                    return None;
                }
                Some(match &*state {
                    VaultState::Unlocked { seal_key, .. } => sealed
                        .iter()
                        .map(|(key, name, ct)| {
                            seal_key
                                .open(vault_id, name, ct)
                                .map(|v| ((*key).clone(), v))
                                .ok_or(crate::error::AppError::VaultLocked)
                        })
                        .collect::<Result<Vec<_>, _>>(),
                    VaultState::Locked => Err(crate::error::AppError::VaultLocked),
                })
            });
            match opened {
                None => return Err(Unreadable::Refused(self.not_serving(vault_id))),
                Some(Err(e)) => return Err(Unreadable::Refused(e)),
                Some(Ok(values)) => out.extend(values),
            }
        }
        Ok(Values(out))
    }

    /// Step 8, for every request, allow included: under the state lock, the
    /// vault-gone error when its runtime is closed, `VaultLocked` when it is
    /// not Unlocked; a single-use permit is spent here (removed if present;
    /// an expired one counts as absent). `Ok(false)`: another request spent
    /// it first.
    pub fn consume(
        &self,
        vault_id: &str,
        auth: Authorized,
    ) -> Result<bool, crate::error::AppError> {
        let now = now_secs();
        let done = self.runtime_if_present(vault_id).and_then(|runtime| {
            let mut state = runtime.state.lock().unwrap();
            if runtime.is_closed() {
                return None;
            }
            Some(match &mut *state {
                VaultState::Unlocked { permits, .. } => Ok(match &auth.consume {
                    Some(key) => permits.take(key, now),
                    None => true,
                }),
                VaultState::Locked => Err(crate::error::AppError::VaultLocked),
            })
        });
        done.unwrap_or_else(|| Err(self.not_serving(vault_id)))
    }

    /// Store an approval's permit (approve, once its op is marked approved).
    /// Only while Unlocked: permits live there, so approving on a Locked
    /// vault leaves nothing to redeem. A window is stored only when the op
    /// was minted under the served snapshot's policy (`window_fp`: the
    /// mint-time fingerprint its approval record carries), checked here
    /// under the state lock; otherwise the op stays approved and its replay
    /// asks again. Expired permits are swept. `false` when nothing was stored.
    pub fn permit_insert(
        &self,
        vault_id: &str,
        key: PermitKey,
        expires_at: u64,
        window_fp: Option<[u8; 32]>,
    ) -> bool {
        let now = now_secs();
        let Some(runtime) = self.runtime_if_present(vault_id) else {
            return false;
        };
        let mut state = runtime.state.lock().unwrap();
        let VaultState::Unlocked {
            snapshot, permits, ..
        } = &mut *state
        else {
            return false;
        };
        if !key.single_use() && window_fp != Some(snapshot.fingerprint) {
            return false;
        }
        permits.insert(key, expires_at, now);
        true
    }

    /// Serve a rotated refresh token the store took, without an install. The
    /// caller holds the build mutex and wrote the store under it. Only while
    /// Unlocked, the served snapshot is replaced by a copy with native item
    /// `key` holding `value` (plaintext for a resident KEY, sealed under S
    /// otherwise) and `key`'s walk memo entry dropped. The permits, the
    /// minted access tokens, the external key names and the behind note stay
    /// as they are (the copy is as far behind the store as the original).
    pub(crate) fn patch_rotated_locked(
        &self,
        runtime: &crate::vault_runtime::VaultRuntime,
        vault_id: &str,
        key: &str,
        value: &[u8],
    ) {
        let (served, seal) = {
            let state = runtime.state.lock().unwrap();
            match &*state {
                VaultState::Unlocked {
                    snapshot, seal_key, ..
                } => (snapshot.clone(), seal_key.clone()),
                VaultState::Locked => return,
            }
        };
        let patched = Arc::new(served.with_value(vault_id, key, value, &seal));
        let mut state = runtime.state.lock().unwrap();
        if runtime.is_closed() {
            return;
        }
        // No install swaps while the build mutex is held; a lock may have
        // landed meanwhile, and then there is nothing to patch.
        if let VaultState::Unlocked { snapshot, .. } = &mut *state {
            if Arc::ptr_eq(snapshot, &served) {
                *snapshot = patched;
            }
        }
    }

    /// Retention setting for this vault's audit log. `None` when the vault
    /// is locked (so the daemon has no view into aux) OR when the user
    /// hasn't configured a retention (keep-forever default). The audit
    /// list handler treats both cases the same: skip prune.
    pub fn audit_retention_days(&self, vault_id: &str) -> Option<u32> {
        self.snapshot(vault_id)?.audit_retention_days
    }

    /// Resolve a `connection_id` to its service for an Unlocked vault
    /// (CONNECTION_SCHEMA.md §6). An explicit `aux.connections` entry names its
    /// `service`; otherwise the connection IS its own default — `conn == service`
    /// — which keeps unconnected/API-key services and the default OAuth
    /// connection resolvable. Locked vault → falls back to `conn`
    /// (the caller's locked-gate rejects before any real use).
    pub fn resolve_connection_service(&self, vault_id: &str, conn: &str) -> String {
        self.snapshot(vault_id)
            .and_then(|s| s.connections.get(conn).and_then(|c| c.service.clone()))
            .unwrap_or_else(|| conn.to_string())
    }

    /// A custom (per-vault `aux.services`) service definition, cloned out so no
    /// state lock is held across a forward. `None` when the vault is locked or
    /// the id isn't a custom service.
    pub fn custom_service(
        &self,
        vault_id: &str,
        service_id: &str,
    ) -> Option<crate::service::ServiceDef> {
        self.snapshot(vault_id)?
            .inputs
            .custom
            .get(service_id)
            .cloned()
    }

    /// True when `service_id` is an installed service of the unlocked vault
    /// that is not loaded because its owner has installed services off.
    pub fn installed_service_off(&self, vault_id: &str, service_id: &str) -> bool {
        self.snapshot(vault_id)
            .is_some_and(|s| s.installed_service_off(service_id))
    }

    /// The names of an unlocked vault's console install requests.
    pub fn service_request_names(&self, vault_id: &str) -> Vec<String> {
        self.snapshot(vault_id)
            .map(|s| s.service_requests.clone())
            .unwrap_or_default()
    }

    /// The per-vault async write lock — serializes anything that reseals the
    /// vault body (connect exchange, oauth refresh-token rotation) so two writers
    /// can't clobber each other. Same map the connect + sync paths use inline.
    /// Acquire the per-vault persistence lock and then re-check the revocation
    /// latch, closing the race with a writer that was queued before teardown.
    pub async fn vault_write_guard(
        &self,
        vault_id: &str,
    ) -> Result<crate::vault_runtime::VaultWriteGuard, VaultWriteRevoked> {
        let runtime = self
            .runtime(vault_id)
            .map_err(|gone| VaultWriteRevoked(gone.reason))?;
        runtime.write_guard().await.map_err(|_| {
            VaultWriteRevoked(
                self.tombstone_reason(vault_id)
                    .unwrap_or(crate::vault_runtime::TombstoneReason::Removed),
            )
        })
    }

    pub fn is_vault_revoked(&self, vault_id: &str) -> bool {
        self.vault_tombstones.lock().unwrap().contains_key(vault_id)
    }

    /// The minted OAuth access token cached under `sha256(refresh_token)` hex
    /// (§5). `None` if locked, never minted, or past its expiry (dropped then).
    pub fn oauth_access_lookup(&self, vault_id: &str, refresh_hash: &str) -> Option<Vec<u8>> {
        let now = now_secs();
        let runtime = self.runtime_if_present(vault_id)?;
        let mut state = runtime.state.lock().unwrap();
        let VaultState::Unlocked { oauth_access, .. } = &mut *state else {
            return None;
        };
        match oauth_access.0.get(refresh_hash) {
            Some((token, exp)) if now < *exp => Some(token.to_vec()),
            Some(_) => {
                oauth_access.0.remove(refresh_hash);
                None
            }
            None => None,
        }
    }

    /// Cache a freshly-minted OAuth `access_token` under `sha256(refresh_token)`
    /// hex (§5), for every tier: a short-lived derived credential, and minting
    /// per request would rotate the refresh token on every request at a
    /// rotating provider. `expires_at` should be the provider-reported absolute
    /// expiry minus a small safety margin (the broker uses ~60s) so we refresh
    /// before the upstream would reject. Expired tokens are swept. No-op when
    /// the vault is locked at the time of the call.
    pub fn oauth_access_insert(
        &self,
        vault_id: &str,
        refresh_hash: &str,
        value: Vec<u8>,
        expires_at: u64,
    ) {
        let now = now_secs();
        let Some(runtime) = self.runtime_if_present(vault_id) else {
            return;
        };
        let mut state = runtime.state.lock().unwrap();
        if let VaultState::Unlocked { oauth_access, .. } = &mut *state {
            oauth_access.0.retain(|_, (_, exp)| now < *exp);
            oauth_access.0.insert(
                refresh_hash.to_string(),
                (zeroize::Zeroizing::new(value), expires_at),
            );
        }
    }

    /// Mark an OAuth connection's refresh_token as dead (invalid_grant at /use).
    /// Surfaced via `/registry` as `needs_reauth` so the console prompts reconnect.
    pub fn oauth_mark_reauth(&self, vault_id: &str, conn_id: &str) {
        if let Ok(runtime) = self.runtime(vault_id) {
            runtime
                .oauth_reauth_needed
                .lock()
                .unwrap()
                .insert(conn_id.to_string());
        }
    }

    /// Clear a connection's reauth flag (a refresh succeeded).
    pub fn oauth_clear_reauth(&self, vault_id: &str, conn_id: &str) {
        if let Some(runtime) = self.runtime_if_present(vault_id) {
            runtime.oauth_reauth_needed.lock().unwrap().remove(conn_id);
        }
    }

    /// True iff `(vault, conn)`'s refresh_token was flagged dead.
    pub fn oauth_needs_reauth(&self, vault_id: &str, conn_id: &str) -> bool {
        self.runtime_if_present(vault_id)
            .is_some_and(|runtime| runtime.oauth_reauth_needed.lock().unwrap().contains(conn_id))
    }

    /// Clear ALL reauth flags for a vault (a fresh connect just landed; any
    /// still-dead token re-marks on the next /use).
    pub fn oauth_clear_reauth_vault(&self, vault_id: &str) {
        if let Some(runtime) = self.runtime_if_present(vault_id) {
            runtime.oauth_reauth_needed.lock().unwrap().clear();
        }
    }

    /// The policy decision for a request, from a snapshot's policy inputs and
    /// this daemon's compiled services ([`crate::snapshot::PolicyInputs::decide`]):
    /// `(effective level, what decided it, ttl seconds)`, or why the request
    /// can't be read. Pure policy.
    pub fn evaluate_request_decision(
        &self,
        inputs: &crate::snapshot::PolicyInputs,
        connection_id: &str,
        service_id: &str,
        request: &crate::core::request::Request<'_>,
    ) -> Result<crate::core::policy::Decision, crate::core::request::Unreadable> {
        inputs.decide(&self.services, connection_id, service_id, request)
    }

    // `connection_rule_problem` went with `when` and `body` (step 3 covers
    // condition reads).

    /// Keep why a change of `item_id` was not applied (see
    /// the vault runtime's sync notes).
    pub fn note_sync(&self, vault_id: &str, item_id: &str, note: SyncNote) {
        if let Ok(runtime) = self.runtime(vault_id) {
            runtime
                .sync_conflicts
                .lock()
                .unwrap()
                .insert(item_id.to_string(), note);
        }
    }

    /// A write or push of `item_id` landed: an earlier note on it is settled.
    pub fn clear_sync_conflict(&self, vault_id: &str, item_id: &str) {
        if let Some(runtime) = self.runtime_if_present(vault_id) {
            runtime.sync_conflicts.lock().unwrap().remove(item_id);
        }
    }

    /// The records of `vault_id` whose change was set aside because they
    /// changed elsewhere meanwhile, sorted, each once.
    pub fn sync_conflict_records(&self, vault_id: &str) -> Vec<String> {
        let Some(runtime) = self.runtime_if_present(vault_id) else {
            return Vec::new();
        };
        let set: std::collections::BTreeSet<String> = runtime
            .sync_conflicts
            .lock()
            .unwrap()
            .values()
            .filter_map(|n| match n {
                SyncNote::ChangedElsewhere(r) => Some(r.clone()),
                _ => None,
            })
            .collect();
        set.into_iter().collect()
    }

    /// Every other note of `vault_id` as a sentence, sorted, each once.
    pub fn sync_note_lines(&self, vault_id: &str) -> Vec<String> {
        let Some(runtime) = self.runtime_if_present(vault_id) else {
            return Vec::new();
        };
        let set: std::collections::BTreeSet<String> = runtime
            .sync_conflicts
            .lock()
            .unwrap()
            .values()
            .filter_map(SyncNote::sentence)
            .collect();
        set.into_iter().collect()
    }

    /// The pull at unlock of `vault_id` failed with `error`; it is retried.
    pub fn note_catch_up(&self, vault_id: &str, error: &str) {
        if let Ok(runtime) = self.runtime(vault_id) {
            *runtime.catch_up_failure.lock().unwrap() = Some(error.to_string());
        }
    }

    /// A rotated refresh token of `conn_id` (`role`) was not stored (`why`):
    /// kept to store again, and noted for `sc status` / `sc sync`.
    pub fn note_rotation_pending(
        &self,
        vault_id: &str,
        conn_id: &str,
        role: &str,
        old: &[u8],
        token: &str,
        why: &str,
    ) {
        if let Ok(runtime) = self.runtime(vault_id) {
            let mut pending = runtime.pending_rotations.lock().unwrap();
            let slot = (conn_id.to_string(), role.to_string());
            // A rotation of a token that was itself still pending (the store
            // failed twice in a row): the store still holds the FIRST
            // replaced value, so the chain keeps it as `old`, or the retry
            // would find the slot "changed" and drop the only valid token.
            let old = match pending.get(&slot) {
                Some(p) if p.new.as_bytes() == old => p.old.clone(),
                _ => zeroize::Zeroizing::new(old.to_vec()),
            };
            pending.insert(
                slot,
                PendingRotation {
                    old,
                    new: zeroize::Zeroizing::new(token.to_string()),
                },
            );
        }
        self.note_sync(
            vault_id,
            &rotation_note_key(conn_id),
            SyncNote::Refused(format!(
                "connection {}: the provider's new refresh token could not be stored in the vault ({}); this device uses it, and it is stored as soon as the vault can be written",
                conn_id, why
            )),
        );
    }

    /// The rotated refresh tokens of `vault_id` not stored yet, taken.
    pub fn take_pending_rotations(&self, vault_id: &str) -> Vec<((String, String), PendingRotation)> {
        self.runtime_if_present(vault_id)
            .map(|runtime| std::mem::take(&mut *runtime.pending_rotations.lock().unwrap()))
            .map(|m| m.into_iter().collect())
            .unwrap_or_default()
    }

    /// The rotated refresh token of `(conn_id, role)` was stored (or a newer
    /// one was): nothing is pending for that slot any more, and its note is
    /// settled.
    pub fn drop_pending_rotation(&self, vault_id: &str, conn_id: &str, role: &str) {
        if let Some(runtime) = self.runtime_if_present(vault_id) {
            runtime
                .pending_rotations
                .lock()
                .unwrap()
                .remove(&(conn_id.to_string(), role.to_string()));
        }
        self.clear_rotation_note(vault_id, conn_id);
    }

    /// The rotated refresh token pending for connection `conn_id` that
    /// replaced `value`, if any (`value` as the store still holds it, or as a
    /// fresh decrypt read it).
    pub fn pending_rotation_of(
        &self,
        vault_id: &str,
        conn_id: &str,
        value: &[u8],
    ) -> Option<zeroize::Zeroizing<String>> {
        let runtime = self.runtime_if_present(vault_id)?;
        let pending = runtime.pending_rotations.lock().unwrap();
        pending
            .iter()
            .find(|((c, _), p)| c == conn_id && p.old.as_slice() == value)
            .map(|(_, p)| p.new.clone())
    }

    /// How long a rotation is remembered for [`Self::current_refresh_token`]:
    /// past it every reader holds the rotated token anyway.
    const ROTATED_TO_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

    /// A refresh in this process rotated `old` to `new` (`vault_id`).
    pub fn note_rotated_to(&self, vault_id: &str, old: &[u8], new: &str) {
        let mut m = self.oauth_rotated_to.lock().unwrap();
        let now = std::time::Instant::now();
        m.retain(|_, (_, at)| now.duration_since(*at) < Self::ROTATED_TO_TTL);
        m.insert(
            (vault_id.to_string(), refresh_token_hash(old)),
            (zeroize::Zeroizing::new(new.to_string()), now),
        );
    }

    /// The refresh token connection `conn_id` holds NOW, given a `value` read
    /// earlier: `value` followed through the rotations made since (by this
    /// process, then any still pending a store). `None` when `value` is
    /// current.
    pub fn current_refresh_token(
        &self,
        vault_id: &str,
        conn_id: &str,
        value: &[u8],
    ) -> Option<zeroize::Zeroizing<String>> {
        let mut current: Option<zeroize::Zeroizing<String>> = None;
        // Bounded: a chain is a handful of rotations; never loop on a cycle.
        for _ in 0..16 {
            let at = current.as_ref().map(|c| c.as_bytes()).unwrap_or(value);
            let next = {
                let m = self.oauth_rotated_to.lock().unwrap();
                m.get(&(vault_id.to_string(), refresh_token_hash(at)))
                    .filter(|(_, when)| when.elapsed() < Self::ROTATED_TO_TTL)
                    .map(|(t, _)| t.clone())
            }
            .or_else(|| self.pending_rotation_of(vault_id, conn_id, at));
            match next {
                Some(n) if n.as_bytes() != at => current = Some(n),
                _ => break,
            }
        }
        current
    }

    /// Any rotated refresh token of `vault_id` not stored yet?
    pub fn has_pending_rotations(&self, vault_id: &str) -> bool {
        self.runtime_if_present(vault_id)
            .is_some_and(|runtime| !runtime.pending_rotations.lock().unwrap().is_empty())
    }

    /// A pending rotation of `conn_id` was stored: its note is settled.
    pub fn clear_rotation_note(&self, vault_id: &str, conn_id: &str) {
        self.clear_sync_conflict(vault_id, &rotation_note_key(conn_id));
    }

    /// The pull after unlock of `vault_id` landed (or the vault locked).
    pub fn clear_catch_up(&self, vault_id: &str) {
        if let Some(runtime) = self.runtime_if_present(vault_id) {
            runtime.catch_up_failure.lock().unwrap().take();
        }
    }

    /// Why the changes from the cloud since unlock are not pulled yet.
    pub fn catch_up_failure(&self, vault_id: &str) -> Option<String> {
        self.runtime_if_present(vault_id)
            .and_then(|runtime| runtime.catch_up_failure.lock().unwrap().clone())
    }

    /// Record a successful cloud contact for this vault (sync pull/push, or
    /// unlock — a human is present). Feeds the shared-vault offline lease.
    pub fn record_cloud_contact(&self, vault_id: &str) {
        if let Ok(runtime) = self.runtime(vault_id) {
            *runtime.cloud_contact.lock().unwrap() = Some(std::time::Instant::now());
        }
    }

    /// Seconds since the last cloud contact, `None` if never recorded (treated
    /// as fresh by callers — the entry appears at unlock).
    pub fn cloud_contact_age_secs(&self, vault_id: &str) -> Option<u64> {
        self.runtime_if_present(vault_id).and_then(|runtime| {
            runtime
                .cloud_contact
                .lock()
                .unwrap()
                .map(|t| t.elapsed().as_secs())
        })
    }

    /// Is this vault SHARED? Server-authoritative (team §4): the `kind` the
    /// server stamps on the `/blob` sync envelope, cached in `vault_shared`.
    /// An absent entry (never synced, or an old server without the field) is
    /// PRIVATE — the fail-safe default so a personal vault, and any pre-sync
    /// state, is never leased (review H1 is structurally impossible here: a
    /// private vault's `kind` never reads shared). Independent of unlock state,
    /// unlike the old E2E members-map derivation this replaces.
    pub fn vault_is_shared(&self, vault_id: &str) -> bool {
        self.runtime_if_present(vault_id)
            .and_then(|runtime| *runtime.shared.lock().unwrap())
            .unwrap_or(false)
    }

    /// Record the server-authoritative sharedness (`kind`) for a vault, from the
    /// `/blob` sync envelope. `true` = shared, `false` = private. Called by the
    /// sync path whenever a fresh envelope carries the field; absent-field pulls
    /// leave the last known value untouched (see `sync::apply_vault_kind`).
    pub fn set_vault_shared(&self, vault_id: &str, shared: bool) {
        if let Ok(runtime) = self.runtime(vault_id) {
            *runtime.shared.lock().unwrap() = Some(shared);
        }
    }

    /// Eagerly seed `vault_shared` from the known-vaults catalog `kind` (server-
    /// authoritative, mirrored on every discovery, available WITHOUT unlocking a
    /// blob). Called at startup and after discovery so `vault_is_shared` is
    /// reliable before the first serve. DENYLIST normalization (shared iff `kind`
    /// is `team`/`shared`; `personal`/`private`/anything else = not shared) so a
    /// vocabulary drift never strips a personal vault. Only vaults with a known
    /// `kind` are seeded; the signed-envelope path still refreshes the live value.
    pub fn hydrate_shared_from_catalog(&self) {
        for kv in crate::cli::active::known_vaults() {
            if kv.kind.is_some() {
                self.set_vault_shared(&kv.vault, Self::kind_str_is_shared(kv.kind.as_deref()));
            }
        }
    }

    /// DENYLIST normalization of a server `kind` string to sharedness: shared iff
    /// `kind` is `team` or `shared` (case-insensitive); `personal` / `private` /
    /// `None` / anything else = NOT shared, so a vocabulary drift or a renamed kind
    /// never strips a personal vault from serving. Bridges the two `kind`
    /// vocabularies (discovery `personal/team/shared`, blob envelope `shared/private`).
    pub fn kind_str_is_shared(kind: Option<&str>) -> bool {
        matches!(
            kind.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
            Some("team") | Some("shared")
        )
    }

    /// Mark (or clear) a vault as needing a daemon upgrade — the cloud returned
    /// `SC_UPGRADE_REQUIRED` for its sync (design 甲). Set by the sync path on that
    /// signal, cleared on a successful sync. The broker reads it to fail loudly with
    /// an actionable "run `sc upgrade`" to the agent.
    pub fn set_vault_upgrade_required(&self, vault_id: &str, required: bool) {
        if let Ok(runtime) = self.runtime(vault_id) {
            runtime
                .upgrade_required
                .store(required, std::sync::atomic::Ordering::Release);
        }
    }

    /// Is this vault flagged `SC_UPGRADE_REQUIRED` (daemon too old for its format)?
    pub fn is_vault_upgrade_required(&self, vault_id: &str) -> bool {
        self.runtime_if_present(vault_id).is_some_and(|runtime| {
            runtime
                .upgrade_required
                .load(std::sync::atomic::Ordering::Acquire)
        })
    }

    /// Does this vault's reach mask let `agent_id` use `connection_id`?
    /// (team §8.1 — ONE pipeline: the proxy deny, the registry annotation and
    /// GET /vaults all read THIS.) The verdict:
    ///   - `Some(false)` — the agent IS in the authorized-agents table and its
    ///     mask denies this connection (the only denial the proxy acts on).
    ///   - `Some(true)` — in the table, mask allows.
    ///   - `None` — vault locked, OR `agent_id` is not in the `ag_`-keyed table.
    ///     The caller treats `None` as "no mask restriction" (allow): this is the
    ///     legacy Basic-auth path (api-key prefix, never in an `ag_`-keyed table)
    ///     during the dual-auth window. True fail-closed ("not in table = deny")
    ///     is enforced by the AIK proxy path once bearers retire (§11.6).
    pub fn agent_mask_allows(
        &self,
        vault_id: &str,
        agent_id: &str,
        connection_id: &str,
    ) -> Option<bool> {
        self.snapshot(vault_id)?
            .agents
            .get(agent_id)
            .map(|e| e.connections.allows(connection_id))
    }

    /// Is `agent_id` present in this vault's authorized-agents table (§11)?
    /// Presence = authorized: the UIK-signed `ag_`-keyed table is the daemon's
    /// only authz source, and dropping a row is the revoke. Used by the hop-A AIK
    /// PoP proxy path to decide whether a crypto-verified `ag_…` may use this
    /// vault at all — distinct from [`agent_mask_allows`], which only restricts
    /// WHICH connections an already-authorized agent may reach. `false` when the
    /// vault is locked or the agent isn't in the table (fail-closed — the AIK path
    /// is opt-in and dual-authed with the legacy api-key, so this never bricks a
    /// legacy agent, whose api-key prefix simply isn't an `ag_` and takes the
    /// hash-set path instead).
    pub fn agent_is_authorized(&self, vault_id: &str, agent_id: &str) -> bool {
        self.snapshot(vault_id)
            .is_some_and(|s| s.agents.contains_key(agent_id))
    }

    /// Is `agent_id` present in the authorized-agents table of ANY currently
    /// UNLOCKED vault this daemon holds (§11)? The ACCOUNT-scoped check for the
    /// api-face reads (registry / op-poll / `/vaults`) — those aren't tied to a
    /// single vault, so a hop-A AIK PoP that proves possession of `ag_…` is a
    /// valid agent of this account for those cross-vault reads iff it's
    /// authorized on at least one vault. `false` if no unlocked vault authorizes
    /// it (fail-closed; dual-auth with the legacy api-key covers the transition).
    pub fn agent_is_authorized_any(&self, agent_id: &str) -> bool {
        let runtimes: Vec<_> = self.vault_runtimes.lock().unwrap().values().cloned().collect();
        runtimes.iter().any(|runtime| {
            matches!(&*runtime.state.lock().unwrap(), VaultState::Unlocked { snapshot, .. } if snapshot.agents.contains_key(agent_id))
        })
    }

    /// Which of `candidates` this agent is ALLOWED to reach in this vault —
    /// evaluated through `AgentMask::allows` so the blacklist and `All` resolve
    /// identically (team §8.1 ONE pipeline: same verdict as the proxy deny).
    /// `Some(set)` = the subset of `candidates` reachable under this agent's mask;
    /// `None` = vault locked OR `agent_id` is not in the authorized-agents table
    /// (the caller masks nothing — the legacy allow of the dual-auth window, since
    /// a legacy api-key prefix is never in the `ag_`-keyed table). Used by the
    /// registry/vaults surfaces to annotate rows without N lock round-trips.
    pub fn agent_allowed_connections(
        &self,
        vault_id: &str,
        agent_id: &str,
        candidates: &[String],
    ) -> Option<Vec<String>> {
        self.snapshot(vault_id)?.agents.get(agent_id).map(|entry| {
            candidates
                .iter()
                .filter(|id| entry.connections.allows(id))
                .cloned()
                .collect()
        })
    }

    /// The approval-hold window (seconds): how long a pending `ask` op waits
    /// for the passkey gesture before it expires. This is the user's
    /// `aux.policy.timeout` ("Approval timeout" in the console), or a 30-minute
    /// default. THE one approval window (SSOT): op.rs stamps it onto every
    /// ceremony op, the broker ask path mints with it, the op-payload stash
    /// and the relay poll budget derive from it. DISTINCT from the post-approval `ask`-once grant window (the
    /// rule/floor `ttl`) — a long grant window must not stretch the deadline the
    /// user has to actually approve. Falls back to the default when the vault is
    /// locked or sets no timeout.
    pub fn policy_approval_hold(&self, vault_id: &str) -> u64 {
        self.snapshot(vault_id)
            .map(|s| s.inputs.approval_hold())
            .unwrap_or(crate::snapshot::DEFAULT_APPROVAL_HOLD)
    }

    // ── Proxy-facing accessors (resident phantom-only proxy) ─────────────────

    /// Clone a connection record out of the unlocked routing snapshot. `None`
    /// when the vault is Locked or the connection id is unknown.
    /// All connections of one vault (id → record), empty when locked. Used by
    /// the agent-face `/vaults` index.
    pub fn connections_snapshot(
        &self,
        vault_id: &str,
    ) -> Vec<(String, crate::storage::plaintext::Connection)> {
        self.snapshot(vault_id)
            .map(|s| {
                s.connections
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn connection_snapshot(
        &self,
        vault_id: &str,
        conn: &str,
    ) -> Option<crate::storage::plaintext::Connection> {
        self.snapshot(vault_id)?.connections.get(conn).cloned()
    }

    /// This vault's per-vault custom (`aux.services`) definitions, from the
    /// served snapshot. The OAuth connect-finisher resolves a custom service's
    /// exchange config against these — the global `self.services` registry holds
    /// built-ins only. Empty when the vault is Locked or none are authored.
    pub fn custom_services_snapshot(
        &self,
        vault_id: &str,
    ) -> std::collections::HashMap<String, crate::service::ServiceDef> {
        self.snapshot(vault_id)
            .map(|s| s.inputs.custom.clone())
            .unwrap_or_default()
    }

    /// The exact FQDNs a connection's credential may egress to, resolved
    /// through the compiled registry and the vault's custom services. `None`
    /// when the vault is Locked or the connection id is unknown.
    pub fn resolved_hosts_for(&self, vault_id: &str, conn: &str) -> Option<Vec<String>> {
        let snapshot = self.snapshot(vault_id)?;
        let conn_rec = snapshot.connections.get(conn)?;
        // custom-FIRST (see proxy::handler)
        let def = conn_rec
            .service
            .as_deref()
            .and_then(|s| snapshot.inputs.def(&self.services, s));
        Some(crate::core::host::resolved_hosts(conn_rec, def))
    }

    /// True iff `host` is in the union of `resolved_hosts` over the connections
    /// of all unlocked vaults, OR in a locked vault's remembered union
    /// (each runtime's `last_host_union`). Decides MITM-vs-blind-tunnel at CONNECT time: only
    /// hosts a connection anchors are decrypted; everything else is a blind
    /// tunnel. Including locked vaults' last-known anchors means a phantom sent
    /// while locked reaches `pipeline`'s explicit `vault_locked` refusal instead
    /// of tunneling to the upstream literally; phantom-less traffic to those
    /// hosts still forwards untouched. Not vid-scoped on purpose — we MITM (and
    /// can return a precise error) even when the CONNECT's vid userinfo is
    /// wrong or absent.
    pub fn host_in_any_known_union(&self, host: &str) -> bool {
        let runtimes: Vec<_> = self.vault_runtimes.lock().unwrap().values().cloned().collect();
        let mut remembered = HashMap::new();
        let mut hit = false;
        for runtime in runtimes {
            let unlocked_hosts = {
                let state = runtime.state.lock().unwrap();
                match &*state {
                    VaultState::Unlocked { snapshot, .. } => {
                        let mut hosts = Vec::new();
                        for conn_rec in snapshot.connections.values() {
                            let def = conn_rec
                                .service
                                .as_deref()
                                .and_then(|s| snapshot.inputs.def(&self.services, s));
                            for resolved in crate::core::host::resolved_hosts(conn_rec, def) {
                                hosts.push(resolved.to_ascii_lowercase());
                            }
                        }
                        hosts.sort_unstable();
                        hosts.dedup();
                        Some(hosts)
                    }
                    VaultState::Locked => None,
                }
            };
            if let Some(hosts) = unlocked_hosts {
                *runtime.last_host_union.lock().unwrap() = hosts;
            }
            let hosts = runtime.last_host_union.lock().unwrap().clone();
            hit |= hosts
                .iter()
                .any(|anchor| crate::core::host::host_anchor_matches(host, anchor));
            if !hosts.is_empty() {
                remembered.insert(runtime.vault_id.clone(), hosts);
            }
        }
        for (vid, tombstone) in self.vault_tombstones.lock().unwrap().iter() {
            hit |= tombstone
                .hosts
                .iter()
                .any(|anchor| crate::core::host::host_anchor_matches(host, anchor));
            if !tombstone.hosts.is_empty() {
                remembered.insert(vid.clone(), tombstone.hosts.clone());
            }
        }
        let json = canonical_unions_json(&remembered);
        let mut persisted = self.host_unions_persisted.lock().unwrap();
        if *persisted != json {
            if let Err(error) =
                std::fs::write(host_anchors_path(&self.config.state_dir), json.as_bytes())
            {
                tracing::warn!("proxy: persist host-anchors failed: {}", error);
            } else {
                *persisted = json;
            }
        }
        hit
    }
}

/// Unix seconds now.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::snapshot::{PolicyInputs, Snapshot};
    use std::path::PathBuf;

    /// The ask-always tier (single-use).
    fn aa() -> crate::approval::reuse::BoundTier {
        crate::approval::reuse::BoundTier::AskAlways
    }

    /// A scoped ask's `exact` tier (a window), here under the write floor.
    fn ex() -> crate::approval::reuse::BoundTier {
        use crate::approval::reuse::{BoundTier, Class, GrantUnit};
        BoundTier::Exact(GrantUnit::Floor(Class::Write))
    }

    fn test_state() -> AppState {
        let cfg = Config {
            state_dir: PathBuf::from(format!("/tmp/sprott-test-{}", std::process::id())),
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
        {
            let s = AppState::new(cfg);
            s.open_ledger_for_tests(&[]);
            s
        }
    }

    #[test]
    fn a_parked_device_never_gets_k_back() {
        let s = test_state();
        s.set_ledger(crate::principal_ledger::LedgerGate::default()); // parked
        s.unlock_vault(
            "v".into(),
            Snapshot::default(),
            zeroize::Zeroizing::new(vec![7u8; 32]),
        );
        assert!(
            s.is_vault_locked("v"),
            "a refresh that cloned K before the park must not reinstall it"
        );
        s.open_ledger_for_tests(&[]);
        s.unlock_vault(
            "v".into(),
            Snapshot::default(),
            zeroize::Zeroizing::new(vec![7u8; 32]),
        );
        assert!(!s.is_vault_locked("v"));
    }

    #[test]
    fn kind_str_is_shared_is_a_denylist() {
        // Shared iff team/shared (case- and space-tolerant).
        assert!(AppState::kind_str_is_shared(Some("team")));
        assert!(AppState::kind_str_is_shared(Some("shared")));
        assert!(AppState::kind_str_is_shared(Some("  TEAM ")));
        // Everything else (incl. unknown / None) is NOT shared, so a personal
        // vault is never stripped from serving by a vocabulary drift.
        assert!(!AppState::kind_str_is_shared(Some("personal")));
        assert!(!AppState::kind_str_is_shared(Some("private")));
        assert!(!AppState::kind_str_is_shared(Some("solo")));
        assert!(!AppState::kind_str_is_shared(None));
    }

    #[test]
    fn default_build_is_personal_edition() {
        // The default build wires NoopHooks: the open-source PERSONAL edition,
        // which does not serve team vaults. The sync path leaves SHARED vaults to
        // the official build (see `build_serves_shared` / `leave_shared_to_official`
        // in sync.rs); the official build's EeHooks override this to `true`.
        assert!(!test_state().team.serves_shared_vaults());
    }

    /// The op-payload stash is single-use and digest-verified: a deposit is
    /// retrievable exactly once by its returned digest, and an unknown digest
    /// (wrong, replayed, or post-restart) fails closed.
    #[test]
    fn op_payload_deposit_is_single_use_and_digest_bound() {
        let state = test_state();
        let mut values = std::collections::BTreeMap::new();
        values.insert("MIMO_API_TOKEN".to_string(), "s3cret".to_string());
        let digest = state
            .op_payload_insert(values.clone(), std::time::Duration::from_secs(300))
            .expect("stash slot");
        // Two deposits of the SAME values must not collide (fresh salt each).
        let digest2 = state
            .op_payload_insert(values.clone(), std::time::Duration::from_secs(300))
            .expect("stash slot");
        assert_ne!(digest, digest2, "salted digests must differ per deposit");
        assert_eq!(state.op_payload_take(&digest), Some(values));
        assert_eq!(state.op_payload_take(&digest), None, "single-use");
        assert_eq!(state.op_payload_take("deadbeef"), None, "unknown digest");
    }

    fn unlock_empty(state: &AppState, vault_id: &str) {
        state.unlock_vault(
            vault_id.to_string(),
            Snapshot::default(),
            zeroize::Zeroizing::new(Vec::new()),
        );
    }

    fn far() -> u64 {
        now_secs() + 600
    }

    fn creds(keys: &[&str]) -> CredentialSet {
        CredentialSet::new("svc", keys.iter().map(|k| k.to_string()))
    }

    /// A request-bound permit's key.
    #[allow(clippy::too_many_arguments)]
    fn bound(
        agent: &str,
        conn: &str,
        method: &str,
        host: &str,
        path: &str,
        digest: &str,
        tier: &crate::approval::reuse::BoundTier,
        keys: &[&str],
    ) -> PermitKey {
        PermitKey {
            of: PermitFor::Request(OpGrantKey::new(
                agent, conn, method, host, path, digest, tier,
            )),
            credentials: creds(keys),
        }
    }

    /// Steps 6 and 8 for a request with this permit key: let through, and
    /// its single-use permit spent?
    fn redeem(state: &AppState, vid: &str, key: PermitKey) -> bool {
        let Some(snapshot) = state.snapshot(vid) else {
            return false;
        };
        match state.authorize(vid, snapshot, BTreeMap::new(), Some(key)) {
            Ok(auth) => state.consume(vid, auth).unwrap(),
            Err(_) => false,
        }
    }

    /// One approval = one replay: a single-use permit is spent by the request
    /// that redeems it.
    #[test]
    fn a_single_use_permit_is_spent_once() {
        let state = test_state();
        unlock_empty(&state, "v1");
        let key = || bound("agA", "svc", "POST", "api.x.com", "/v2/purchase", "", &aa(), &["K"]);
        assert!(state.permit_insert("v1", key(), far(), None));
        assert!(redeem(&state, "v1", key()));
        assert!(!redeem(&state, "v1", key()), "spent");
    }

    /// The $80/$180 hole: a permit is bound to the request the user approved.
    /// A replay whose method, host, path, connection, agent, bound values or
    /// tier differs misses, without spending it; the host compares
    /// case-insensitively.
    #[test]
    fn a_request_bound_permit_misses_any_other_request() {
        let state = test_state();
        unlock_empty(&state, "v1");
        let d80 = crate::service::scope_digest(&[("amount".into(), "80".into())]);
        let d180 = crate::service::scope_digest(&[("amount".into(), "180".into())]);
        let k = |agent: &str, conn: &str, m: &str, h: &str, p: &str, d: &str| {
            bound(agent, conn, m, h, p, d, &aa(), &["K"])
        };
        state.permit_insert("v1", k("agA", "svc", "POST", "api.x.com", "/buy", &d80), far(), None);
        for other in [
            k("agA", "svc", "POST", "api.x.com", "/refund", &d80),
            k("agA", "svc", "DELETE", "api.x.com", "/buy", &d80),
            k("agA", "svc", "POST", "api.y.com", "/buy", &d80),
            k("agA", "other", "POST", "api.x.com", "/buy", &d80),
            k("agB", "svc", "POST", "api.x.com", "/buy", &d80),
            k("agA", "svc", "POST", "api.x.com", "/buy", &d180),
            bound("agA", "svc", "POST", "api.x.com", "/buy", &d80, &ex(), &["K"]),
        ] {
            assert!(!redeem(&state, "v1", other));
        }
        assert!(redeem(&state, "v1", k("agA", "svc", "POST", "API.X.COM", "/buy", &d80)));
    }

    /// A permit is keyed by the credentials the request resolved: another
    /// KEY, an extra KEY or another service misses, for a request-bound
    /// permit and a unit window alike.
    #[test]
    fn a_permit_serves_only_the_same_credentials() {
        use crate::approval::reuse::{Class, GrantUnit};
        let state = test_state();
        unlock_empty(&state, "v1");
        let fp = state.snapshot("v1").unwrap().fingerprint;
        let unit = |keys: &[&str], service: &str| PermitKey {
            of: PermitFor::Unit {
                agent: "agA".into(),
                conn: "svc".into(),
                host: "api.x.com".into(),
                unit: GrantUnit::Floor(Class::Read),
            },
            credentials: CredentialSet::new(service, keys.iter().map(|k| k.to_string())),
        };
        assert!(state.permit_insert("v1", unit(&["A"], "svc"), far(), Some(fp)));
        assert!(!redeem(&state, "v1", unit(&["B"], "svc")));
        assert!(!redeem(&state, "v1", unit(&["A", "B"], "svc")));
        assert!(!redeem(&state, "v1", unit(&["A"], "other")));
        assert!(redeem(&state, "v1", unit(&["A"], "svc")));
        assert!(redeem(&state, "v1", unit(&["A"], "svc")), "a window is not spent");

        let one = |keys: &[&str]| bound("agA", "svc", "DELETE", "api.x.com", "/x", "", &aa(), keys);
        state.permit_insert("v1", one(&["A"]), far(), None);
        assert!(!redeem(&state, "v1", one(&["A", "B"])));
        assert!(redeem(&state, "v1", one(&["A"])));
    }

    /// An expired permit is absent, at the lookup and when it is spent.
    #[test]
    fn an_expired_permit_is_absent() {
        let state = test_state();
        unlock_empty(&state, "v1");
        let key = || bound("agA", "svc", "POST", "h", "/p", "", &aa(), &["K"]);
        state.permit_insert("v1", key(), 0, None);
        assert!(!redeem(&state, "v1", key()));
    }

    /// A scoped ask's `exact` permit is a window: the same request reuses it,
    /// another bound value misses without disturbing it.
    #[test]
    fn an_exact_window_is_reused_not_spent() {
        let state = test_state();
        unlock_empty(&state, "v1");
        let fp = state.snapshot("v1").unwrap().fingerprint;
        let d = |q: &str| crate::service::scope_digest(&[("q".into(), q.into())]);
        let key = |q: &str| bound("agA", "svc", "POST", "api.x.com", "/search", &d(q), &ex(), &["K"]);
        assert!(state.permit_insert("v1", key("alpha"), far(), Some(fp)));
        assert!(redeem(&state, "v1", key("alpha")));
        assert!(redeem(&state, "v1", key("alpha")));
        assert!(!redeem(&state, "v1", key("beta")));
        assert!(redeem(&state, "v1", key("alpha")));
    }

    /// Permits live only in Unlocked: none is stored on a locked vault, and a
    /// lock drops them all.
    #[test]
    fn permits_live_only_while_unlocked() {
        let state = test_state();
        let key = || bound("agA", "svc", "POST", "h", "/p", "", &aa(), &["K"]);
        assert!(!state.permit_insert("v1", key(), far(), None), "locked");
        unlock_empty(&state, "v1");
        assert!(state.permit_insert("v1", key(), far(), None));
        state.lock_vault("v1");
        unlock_empty(&state, "v1");
        assert!(!redeem(&state, "v1", key()), "the lock dropped it");
    }

    /// A window is stored only under the policy the op was minted under, and
    /// a request decided on an older snapshot's policy does not redeem one.
    #[test]
    fn a_window_follows_the_policy_fingerprint() {
        use crate::approval::reuse::{Class, GrantUnit};
        let state = test_state();
        unlock_empty(&state, "v1");
        let before = state.snapshot("v1").unwrap();
        let key = || PermitKey {
            of: PermitFor::Unit {
                agent: "agA".into(),
                conn: "svc".into(),
                host: "h".into(),
                unit: GrantUnit::Floor(Class::Read),
            },
            credentials: creds(&["K"]),
        };
        assert!(!state.permit_insert("v1", key(), far(), None), "a window needs its fingerprint");
        assert!(!state.permit_insert("v1", key(), far(), Some([9u8; 32])), "another policy");
        assert!(state.permit_insert("v1", key(), far(), Some(before.fingerprint)));
        // A policy edit: the served snapshot's fingerprint changes and the
        // window ends in the same swap.
        let mut edited = Snapshot::default();
        edited.inputs.policy.timeout = Some(60);
        state.unlock_vault("v1".into(), edited, zeroize::Zeroizing::new(Vec::new()));
        assert!(!redeem(&state, "v1", key()));
        let after = state.snapshot("v1").unwrap();
        assert!(state.permit_insert("v1", key(), far(), Some(after.fingerprint)));
        // A request still holding the pre-edit snapshot misses the window.
        let stale = state.authorize("v1", before, BTreeMap::new(), Some(key()));
        assert!(matches!(stale, Err(Unauthorized::NoPermit)));
        assert!(redeem(&state, "v1", key()));
    }

    /// A unit window is keyed by the decision a later request's own policy
    /// re-run yields: the same rule and class, or the same floor class; the
    /// agent and host are part of it.
    #[test]
    fn a_unit_window_matches_the_rerun_decision() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Levels, Policy, RuleConfig};
        let mut rules = std::collections::HashMap::new();
        rules.insert(
            "big".to_string(),
            RuleConfig {
                condition: Some(crate::core::policy::Condition::lenient("request.body.amount > 100")),
                level: Some(AccessLevel::AskAlways),
                ..RuleConfig::selecting("POST /pay")
            },
        );
        rules.insert(
            "pay".to_string(),
            RuleConfig {
                level: Some(AccessLevel::Ask),
                ttl: Some(60),
                ..RuleConfig::selecting("POST /pay")
            },
        );
        let mut policy = Policy::default();
        policy.connections.insert(
            "shop".to_string(),
            ConnectionPolicy {
                default: Some(Levels {
                    read: Some(AccessLevel::Ask),
                    write: Some(AccessLevel::Ask),
                    ttl: Some(300),
                }),
                rules,
            },
        );
        let state = test_state();
        let vid = "v-ledger";
        let mut snapshot = Snapshot::default();
        snapshot.inputs.policy = policy;
        state.unlock_vault(vid.to_string(), snapshot, zeroize::Zeroizing::new(Vec::new()));
        let fp = state.snapshot(vid).unwrap().fingerprint;
        let key_of = |agent: &str, method: &str, path: &str, host: &str, amount: Option<&str>| {
            let body = amount.map(|a| format!("{{\"amount\": {a}}}")).unwrap_or_default();
            let request = crate::core::request::Request::new(
                crate::core::request::RequestInput {
                    method,
                    path,
                    host,
                    body: Some(body.as_bytes()),
                    ..Default::default()
                },
                crate::core::request::BodyFormat::Json,
                Default::default(),
            );
            let inputs = state.snapshot(vid).unwrap().inputs.clone();
            let (level, by, _) = state
                .evaluate_request_decision(&inputs, "shop", "shop", &request)
                .unwrap();
            PermitKey::of(level, &by, false, agent, "shop", method, host, path, "", creds(&["K"]))
                .unwrap()
        };
        let approve = |key: PermitKey| assert!(state.permit_insert(vid, key, far(), Some(fp)));
        approve(key_of("agA", "POST", "/pay", "api.shop.com", Some("50")));
        assert!(redeem(&state, vid, key_of("agA", "POST", "/pay", "api.shop.com", Some("70"))));
        // Same path, but `when` now picks the stricter rule: not this unit.
        assert!(!redeem(&state, vid, key_of("agA", "POST", "/pay", "api.shop.com", Some("150"))));
        // The floor is a different unit; another agent or host misses.
        assert!(!redeem(&state, vid, key_of("agA", "POST", "/other", "api.shop.com", None)));
        assert!(!redeem(&state, vid, key_of("agB", "POST", "/pay", "api.shop.com", Some("50"))));
        assert!(!redeem(&state, vid, key_of("agA", "POST", "/pay", "evil.shop.com", Some("50"))));

        approve(key_of("agA", "GET", "/a", "api.shop.com", None));
        assert!(redeem(&state, vid, key_of("agA", "GET", "/b", "API.shop.com", None)));
        assert!(
            !redeem(&state, vid, key_of("agA", "DELETE", "/a", "api.shop.com", None)),
            "read never serves a write"
        );
    }

    /// A path that declares a `[requests]` shape is keyed per request (an
    /// `exact` window bound to its values), never by its unit: approving one
    /// value-less scoped ask opens nothing another value could ride.
    #[test]
    fn a_scoped_path_is_keyed_by_its_request() {
        use crate::core::policy::{AccessLevel, DecidedBy};
        let by = DecidedBy::Rule {
            id: Some("purchase".into()),
            label: None,
        };
        let key = |scoped: bool, digest: &str| {
            PermitKey::of(
                AccessLevel::Ask,
                &by,
                scoped,
                "agA",
                "shop",
                "POST",
                "api.shop.com",
                "/buy",
                digest,
                creds(&["K"]),
            )
            .unwrap()
        };
        assert!(matches!(key(false, "").of, PermitFor::Unit { .. }));
        let scoped = key(true, "");
        assert!(matches!(&scoped.of, PermitFor::Request(k) if !k.tier.single_use()));
        assert_ne!(scoped, key(true, "d80"));
        assert_ne!(scoped, key(false, ""));
        // Allow and deny mint nothing.
        assert!(PermitKey::of(
            AccessLevel::Allow,
            &by,
            false,
            "agA",
            "shop",
            "POST",
            "h",
            "/buy",
            "",
            creds(&["K"])
        )
        .is_none());
    }

    /// A vault (`aux.services`) definition's policy only tightens: its deny
    /// and ask rules and stricter defaults decide alongside the vault's own
    /// policy, the stricter of the two stands, and an `allow` it declares
    /// changes nothing. The owner's per-connection setting still loosens.
    #[test]
    fn vault_definition_policy_only_tightens() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Levels, Policy};
        let src = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_KEY"]
[policy.levels]
read = "allow"
write = "ask"
[[policy.rules]]
method = "DELETE"
path_exact = "/v1/things"
level = "deny"
[[policy.rules]]
method = "POST"
path_exact = "/v1/pay"
level = "allow"
"#;
        let mut aux = std::collections::BTreeMap::new();
        aux.insert("acme".to_string(), src.into());
        let state = test_state();
        let (custom, skipped) = crate::service::vault_custom_services(&aux, true, &state.services);
        assert!(skipped.is_empty(), "{skipped:?}");
        let decide = |policy: &Policy, m: &str, p: &str| {
            let inputs = PolicyInputs {
                policy: policy.clone(),
                custom: custom.clone(),
            };
            state
                .evaluate_request_decision(&inputs, "acme", "acme", &crate::core::request::Request::bare(m, p))
                .unwrap()
                .0
        };
        // Global floor allow: the deny rule and the write default tighten;
        // the definition's allow rule and read default change nothing.
        let open = Policy::default();
        assert_eq!(decide(&open, "DELETE", "/v1/things"), AccessLevel::Deny);
        assert_eq!(decide(&open, "POST", "/v1/pay"), AccessLevel::Ask);
        assert_eq!(decide(&open, "GET", "/v1/things"), AccessLevel::Allow);
        // The owner's stricter floor is never loosened by the definition.
        let mut strict = Policy::default();
        strict.default = Some(Levels {
            read: Some(AccessLevel::AskAlways),
            write: Some(AccessLevel::AskAlways),
            ttl: None,
        });
        assert_eq!(decide(&strict, "POST", "/v1/pay"), AccessLevel::AskAlways);
        assert_eq!(decide(&strict, "GET", "/v1/things"), AccessLevel::AskAlways);
        assert_eq!(decide(&strict, "DELETE", "/v1/things"), AccessLevel::Deny);
        // The owner's own per-connection default is consent to loosen.
        let mut owner = Policy::default();
        owner.connections.insert(
            "acme".to_string(),
            ConnectionPolicy {
                default: Some(Levels {
                    read: None,
                    write: Some(AccessLevel::Allow),
                    ttl: None,
                }),
                rules: Default::default(),
            },
        );
        assert_eq!(decide(&owner, "POST", "/v1/pay"), AccessLevel::Allow);
        assert_eq!(decide(&owner, "DELETE", "/v1/things"), AccessLevel::Deny);
    }

    /// The policy fingerprint changes with any policy input and with nothing
    /// else: a vault definition counts by its policy and its `[requests]`
    /// shapes only.
    #[test]
    fn the_policy_fingerprint_covers_exactly_the_policy_inputs() {
        use crate::core::policy::{AccessLevel, Levels, Policy};
        let def = |hosts: &str, write: &str, scope: &str| {
            let src = format!(
                "[service]\nid = \"acme\"\nname = \"Acme\"\nhosts = [{hosts}]\nsecrets = [\"ACME_KEY\"]\n\
                 [policy.levels]\nwrite = \"{write}\"\n\
                 [requests.pay]\nmethod = \"POST\"\npath = \"/pay\"\nscope = [{scope}]\n"
            );
            crate::service::gate::admit_toml(&src).unwrap()
        };
        let with = |policy: Policy, d: crate::service::ServiceDef| {
            PolicyInputs {
                policy,
                custom: [("acme".to_string(), d)].into_iter().collect(),
            }
            .fingerprint()
        };
        let base = with(Policy::default(), def("\"api.acme.dev\"", "ask", "\"request.body.amount\""));
        assert_eq!(base, with(Policy::default(), def("\"api.acme.dev\"", "ask", "\"request.body.amount\"")));
        assert_eq!(
            base,
            with(Policy::default(), def("\"api.acme.dev\", \"x.acme.dev\"", "ask", "\"request.body.amount\"")),
            "a definition's hosts are not policy"
        );
        assert_ne!(base, with(Policy::default(), def("\"api.acme.dev\"", "ask-always", "\"request.body.amount\"")));
        assert_ne!(base, with(Policy::default(), def("\"api.acme.dev\"", "ask", "\"request.body.amount\", \"request.body.to\"")));
        let mut timeout = Policy::default();
        timeout.timeout = Some(60);
        assert_ne!(base, with(timeout, def("\"api.acme.dev\"", "ask", "\"request.body.amount\"")));
        let mut floor = Policy::default();
        floor.default = Some(Levels {
            read: Some(AccessLevel::Ask),
            write: None,
            ttl: None,
        });
        assert_ne!(base, with(floor, def("\"api.acme.dev\"", "ask", "\"request.body.amount\"")));
    }
}

/// [`AppState::install`]: who may unlock, what a refresh or write may swap,
/// and the races a lock, park or newer refresh used to lose.
#[cfg(test)]
mod install_tests {
    use super::*;
    use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
    use crate::storage::sealed_vault::{read_per_item, write_per_item_atomic, PerItemVault};
    type S = sudp::primitives::StdPrimitives;

    const V: &str = "v-install";
    /// The vault's key on this device.
    const K: [u8; 32] = [0x41; 32];
    /// A key this device does not have.
    const OTHER: [u8; 32] = [0x42; 32];

    /// A state on its own temp dir, admitted to serve.
    fn install_state() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
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
        state.open_ledger_for_tests(&[]);
        (dir, Arc::new(state))
    }

    /// Seal `payload` into `V`'s store under `key` at its next version (the
    /// store is created on first use), as a pull adopting it would; its row.
    fn put(state: &AppState, key: &[u8], payload: ItemPayload) -> String {
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
        let (id, _) = pv
            .seal_and_bump::<S>(
                VaultKeys::single(key),
                V,
                payload.ns,
                &payload.name.clone(),
                &payload,
            )
            .unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_per_item_atomic(&path, &pv).unwrap();
        id
    }

    fn put_secret(state: &AppState, key: &[u8], name: &str, value: &str) -> String {
        put(state, key, ItemPayload::secret_live(name, value))
    }

    /// FOO = `value`, served to agents through the raw connection `foo`.
    fn vault_with_foo(state: &AppState, value: &str) -> String {
        put(
            state,
            &K,
            ItemPayload::live(
                ItemNs::Connection,
                "foo",
                serde_json::json!({ "hosts": ["api.example.com"], "secrets": ["FOO"] }),
            ),
        );
        put_secret(state, &K, "FOO", value)
    }

    /// Row `id` now reads only under a key this device does not have.
    fn reseal_elsewhere(state: &AppState, id: &str) {
        let path = state.vaults.per_item_path(V).unwrap();
        let mut pv = read_per_item(&path).unwrap().unwrap();
        let ct = &mut pv.items.get_mut(id).unwrap().ct;
        let last = ct.len() - 1;
        ct[last] ^= 1;
        write_per_item_atomic(&path, &pv).unwrap();
    }

    fn unlock(state: &AppState, key: &[u8]) -> Installed {
        state.install(V, InstallKey::Unlock(zeroize::Zeroizing::new(key.to_vec())))
    }

    /// The secret names the served snapshot holds (`None`: locked).
    fn served_names(state: &AppState) -> Option<std::collections::BTreeSet<String>> {
        Some(state.snapshot(V)?.native_names().cloned().collect())
    }

    fn names(xs: &[&str]) -> Option<std::collections::BTreeSet<String>> {
        Some(xs.iter().map(|s| s.to_string()).collect())
    }

    /// Run `f` once, inside the next install, right before its swap.
    fn before_swap(state: &AppState, f: impl FnOnce() + Send + 'static) {
        *state.runtime(V).unwrap().before_swap.lock().unwrap() = Some(Box::new(f));
    }

    /// The vault-unlock op folds tolerantly: one row its key cannot open is
    /// skipped and noted as a key change; the vault unlocks and serves the
    /// rest.
    #[test]
    fn an_unlock_with_one_unopenable_row_unlocks_and_notes_the_key_change() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        put_secret(&state, &OTHER, "ZED", "z");
        assert_eq!(unlock(&state, &K), Installed::Served);
        assert!(!state.is_vault_locked(V));
        assert!(state.is_vault_key_changed(V));
        assert_eq!(served_names(&state), names(&["FOO"]));
        assert_eq!(state.served_native(V, "FOO"), Some(b"v1".to_vec()));
    }

    /// Only the vault-unlock op unlocks: a refresh or an approved write's
    /// install on a Locked vault serves nothing.
    #[test]
    fn only_the_unlock_op_unlocks() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        assert_eq!(state.install(V, InstallKey::Held), Installed::NotUnlocked);
        let grant = InstallKey::Grant(zeroize::Zeroizing::new(K.to_vec()));
        assert_eq!(state.install(V, grant), Installed::NotUnlocked);
        assert!(state.is_vault_locked(V));
        assert_eq!(unlock(&state, &K), Installed::Served);
        assert!(!state.is_vault_locked(V));
    }

    /// A park that lands while the vault-unlock install builds its snapshot wins:
    /// the gate is checked under the state lock, at the swap.
    #[test]
    fn a_park_racing_an_unlock_leaves_the_vault_locked() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        let parking = state.clone();
        before_swap(&state, move || {
            parking.set_ledger(crate::principal_ledger::LedgerGate::default())
        });
        assert_eq!(unlock(&state, &K), Installed::NotUnlocked);
        assert!(state.is_vault_locked(V));
        assert!(state.cloned_state_key(V).is_none(), "no K held");
    }

    /// A lock that lands while a refresh builds its snapshot wins: the refresh
    /// never re-unlocks the vault.
    #[test]
    fn a_refresh_racing_a_lock_leaves_the_vault_locked() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        assert!(unlock(&state, &K).served());
        put_secret(&state, &K, "BAR", "b");
        let locking = state.clone();
        before_swap(&state, move || locking.lock_vault(V));
        crate::sync::refresh_after_item_pull(&state, V);
        assert!(state.is_vault_locked(V));
        assert!(state.cloned_state_key(V).is_none(), "no K held");
    }

    /// Two refreshes: the one that read the store earlier swaps first, the
    /// newer one waits for it on the build mutex and then serves the newer
    /// store. An older refresh never swaps over a newer one.
    #[test]
    fn an_older_refresh_never_swaps_over_a_newer_one() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        assert!(unlock(&state, &K).served());
        let newer: Arc<Mutex<Option<std::thread::JoinHandle<Installed>>>> = Default::default();
        let (pulling, slot) = (state.clone(), newer.clone());
        // Refresh A has read v1. Before it swaps, a pull lands v2 and starts
        // refresh B, which waits for A on the build mutex (unserialized, it
        // would swap v2 now and A's v1 would land over it).
        before_swap(&state, move || {
            put_secret(&pulling, &K, "FOO", "v2");
            let (done, finished) = std::sync::mpsc::channel();
            let b = pulling.clone();
            *slot.lock().unwrap() = Some(std::thread::spawn(move || {
                let installed = b.install(V, InstallKey::Held);
                let _ = done.send(());
                installed
            }));
            let waited = finished.recv_timeout(std::time::Duration::from_millis(300));
            assert!(waited.is_err(), "B swaps only after A");
        });
        assert!(state.install(V, InstallKey::Held).served());
        let b = newer.lock().unwrap().take().unwrap().join().unwrap();
        assert!(b.served());
        assert_eq!(state.served_native(V, "FOO"), Some(b"v2".to_vec()));
    }

    /// A rotated refresh token stored while an install that read the store
    /// earlier builds its snapshot: the rotation's store write and patch wait
    /// for that install's swap and land on its snapshot, so the new token is
    /// served.
    #[test]
    fn a_rotation_stored_during_an_install_is_served() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "rt-1");
        assert!(unlock(&state, &K).served());
        let rotation: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Default::default();
        let (rotating, slot) = (state.clone(), rotation.clone());
        // A refresh has read rt-1. Before it swaps, the provider rotates the
        // token and the broker stores rt-2.
        before_swap(&state, move || {
            let (done, finished) = std::sync::mpsc::channel();
            let r = rotating.clone();
            *slot.lock().unwrap() = Some(std::thread::spawn(move || {
                let stored = crate::auth::connect::persist_rotated_refresh_locked(
                    &r, V, "foo", "FOO", b"rt-1", "rt-2", false,
                );
                assert_eq!(stored, Ok(crate::auth::connect::RotationStored::Written));
                let _ = done.send(());
            }));
            let waited = finished.recv_timeout(std::time::Duration::from_millis(300));
            assert!(waited.is_err(), "the rotation waits for the swap");
        });
        assert!(state.install(V, InstallKey::Held).served());
        rotation.lock().unwrap().take().unwrap().join().unwrap();
        assert_eq!(state.served_native(V, "FOO"), Some(b"rt-2".to_vec()));
    }

    /// A pull that adds a row this key cannot read (a newer member's, a
    /// re-key not caught up with) is served: no row the served snapshot read
    /// is lost. The new row is noted as a key change.
    #[test]
    fn a_pull_adding_an_unreadable_row_is_served() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        assert!(unlock(&state, &K).served());
        assert!(!state.is_vault_key_changed(V));
        put_secret(&state, &K, "BAR", "b");
        put_secret(&state, &OTHER, "ZED", "z");
        crate::sync::refresh_after_item_pull(&state, V);
        assert_eq!(served_names(&state), names(&["BAR", "FOO"]));
        assert!(state.is_vault_key_changed(V));
    }

    /// `sprott set` on a vault holding a row from a newer client (a body this
    /// build cannot parse): the write lands and is served.
    #[tokio::test]
    async fn a_write_beside_a_newer_clients_row_is_served() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        put(
            &state,
            &K,
            ItemPayload::live(
                ItemNs::Connection,
                "newer",
                serde_json::json!({ "hosts": 5 }),
            ),
        );
        assert!(unlock(&state, &K).served());
        assert!(state.is_vault_key_changed(V));
        let resp = set_secret(&state, "BAR", "b").await;
        assert_eq!(resp["written"], true);
        assert!(resp.get("served").is_none(), "{resp}");
        assert_eq!(served_names(&state), names(&["BAR", "FOO"]));
    }

    /// A row the served snapshot read that no longer reads under the held key
    /// (re-sealed under a key this device lacks): the install is refused and
    /// the served snapshot stays; the write is stored and says it is served
    /// after `sprott unlock`.
    #[tokio::test]
    async fn a_readable_row_turning_unreadable_refuses_the_install() {
        let (_dir, state) = install_state();
        let foo = vault_with_foo(&state, "v1");
        assert!(unlock(&state, &K).served());
        reseal_elsewhere(&state, &foo);
        let resp = set_secret(&state, "BAR", "b").await;
        assert_eq!(resp["written"], true);
        assert_eq!(resp["served"], false);
        assert_eq!(resp["served_message"], crate::error::STORED_NOT_SERVED_MSG);
        assert_eq!(
            served_names(&state),
            names(&["FOO"]),
            "the served snapshot stays"
        );
        assert_eq!(state.served_native(V, "FOO"), Some(b"v1".to_vec()));
        assert!(state.is_vault_key_changed(V));
        let stored = crate::server::handlers::metadata::fold_store_with_key(&state, V, &K)
            .unwrap()
            .0;
        assert_eq!(stored.native_secrets["BAR"], b"b", "stored");
        // A sync's refresh is refused the same way; a re-unlock serves what
        // the key reads.
        crate::sync::refresh_after_item_pull(&state, V);
        assert_eq!(served_names(&state), names(&["FOO"]));
        assert!(unlock(&state, &K).served());
        assert_eq!(served_names(&state), names(&["BAR"]));
    }

    /// An install refused for a reason other than the key (the store can't
    /// be read): the served snapshot stays and the vault is behind its store,
    /// shown on the status line, so `sprott unlock` proceeds on the Unlocked
    /// vault; the key-changed note is not set. A served install clears it.
    #[test]
    fn an_install_refused_for_an_io_error_marks_the_vault_behind() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        assert!(unlock(&state, &K).served());
        let path = state.vaults.per_item_path(V).unwrap();
        let good = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(state.install(V, InstallKey::Held), Installed::Refused);
        assert!(state.is_vault_behind(V));
        assert!(!state.is_vault_key_changed(V));
        assert_eq!(state.served_native(V, "FOO"), Some(b"v1".to_vec()));
        let held = crate::server::handlers::metadata::held_lines(&state, V);
        assert!(held.contains(&crate::error::VAULT_BEHIND_STATUS_MSG.to_string()), "{held:?}");
        assert!(crate::cli::unlock::unlock_still_needed(&held));
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, good).unwrap();
        assert!(state.install(V, InstallKey::Held).served());
        assert!(!state.is_vault_behind(V));
        assert!(!crate::cli::unlock::unlock_still_needed(
            &crate::server::handlers::metadata::held_lines(&state, V)
        ));
        // A lock clears it too.
        state.runtime(V).unwrap().behind.store(true, std::sync::atomic::Ordering::Release);
        state.lock_vault(V);
        assert!(!state.is_vault_behind(V));
    }

    /// A stored rotation patches the served snapshot without an install: the
    /// new token is served, and a vault that was behind stays behind (the
    /// patched copy is as far behind the store as the original).
    #[test]
    fn a_rotation_patch_serves_the_token_and_leaves_behind_set() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "rt-1");
        let bar = put_secret(&state, &K, "BAR", "b");
        assert!(unlock(&state, &K).served());
        reseal_elsewhere(&state, &bar);
        assert_eq!(state.install(V, InstallKey::Held), Installed::Refused);
        assert!(state.is_vault_behind(V));
        let stored = crate::auth::connect::persist_rotated_refresh_locked(
            &state, V, "foo", "FOO", b"rt-1", "rt-2", false,
        );
        assert_eq!(stored, Ok(crate::auth::connect::RotationStored::Written));
        assert_eq!(state.served_native(V, "FOO"), Some(b"rt-2".to_vec()));
        assert!(state.is_vault_behind(V), "a patch is not an install");
    }

    /// The vault-unlock op on an Unlocked vault keeps its permits, its
    /// minted access tokens and S; a lock drops them all.
    #[test]
    fn a_re_unlock_keeps_permits_tokens_and_s() {
        let (_dir, state) = install_state();
        vault_with_foo(&state, "v1");
        assert!(unlock(&state, &K).served());
        let key = PermitKey {
            of: PermitFor::Request(OpGrantKey::new(
                "ag",
                "foo",
                "POST",
                "api.example.com",
                "/x",
                "",
                &crate::approval::reuse::BoundTier::AskAlways,
            )),
            credentials: CredentialSet::new("foo", ["FOO".to_string()]),
        };
        assert!(state.permit_insert(V, key.clone(), now_secs() + 600, None));
        state.oauth_access_insert(V, "h", b"at".to_vec(), u64::MAX);
        // Count one open under the held S (it fails: nothing was sealed so).
        let (seal, _) = state.fill_context(V).unwrap();
        assert!(seal.open(V, "FOO", b"not sealed").is_none());
        assert_eq!(state.seal_opens(V), 1);
        assert!(unlock(&state, &K).served());
        assert_eq!(state.permits(V).len(), 1);
        assert_eq!(state.oauth_access_lookup(V, "h"), Some(b"at".to_vec()));
        assert_eq!(state.seal_opens(V), 1, "the same S");
        state.lock_vault(V);
        assert!(unlock(&state, &K).served());
        assert!(state.permits(V).is_empty());
        assert_eq!(state.oauth_access_lookup(V, "h"), None);
    }

    /// `POST /v/{vid}/secret` (the unlocked `sprott set`).
    async fn set_secret(state: &Arc<AppState>, key: &str, value: &str) -> serde_json::Value {
        let axum::Json(v) = crate::server::handlers::secret_set_local::create(
            axum::extract::State(state.clone()),
            axum::extract::Path(V.to_string()),
            axum::Json(serde_json::json!({ "key": key, "value": value })),
        )
        .await
        .unwrap();
        v
    }
}
