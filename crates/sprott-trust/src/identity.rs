//! Self-certifying ids, signature verification, and the canonical signing-input
//! builders that config signatures, re-key events, root succession, and the
//! server-signed sync envelope are all computed over. The daemon's `identity`
//! module re-exports everything here and adds the signing principals (UIK / AIK).
//!
//! ## Cross-language parity
//!
//! Config records are signed in the browser (TS `@sudp-protocol/authorizer` +
//! `lib/vault-grant.ts`) and verified by the daemon (Rust), so [`config_sig_input`]
//! and [`derive_id`] MUST be byte-identical across Rust and TS. The pinned
//! vectors in the daemon's `identity` tests are the contract; the TS side pins the
//! same values. Change one side, change both — and never edit an expected value
//! just to make a test pass; find why the two diverged.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

// ── Domain-separation labels (Sprott namespace; disjoint from sudp/v1/*) ──

/// Owner UIK signature over a config singleton (policy / stores / store_order /
/// audit_retention_days / services / members). See [`config_sig_input`].
pub const DS_CONFIG_SIG: &[u8] = b"safeclaw/v1/config-sig";

/// Owner-signed re-key event (a `generation` bump). See [`rekey_sig_input`].
pub const DS_REKEY: &[u8] = b"safeclaw/v1/rekey";

/// Creator-signed role grant on a keyset cred (the owner-authority anchor for
/// "who is an owner") — the root-signed CHECKPOINT base of the delegation fold.
/// See [`role_grant_input`].
pub const DS_ROLE_GRANT: &[u8] = b"safeclaw/v1/role-grant";

/// An owner-signed delegation event (add/promote/demote/remove) appended to the
/// keyset's delegation log — the any-owner, issuance-time-authority half of the
/// owner-set fold (design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md
/// §1.1). See [`delegation_event_input`].
pub const DS_DELEGATION: &[u8] = b"safeclaw/v1/delegation-event";

/// A root-succession certificate: the CURRENT root signs the NEXT root's id +
/// pubkey, so the daemon can follow a short chain from the TOFU-pinned genesis
/// root to the current root (creator transfer / offboard). See
/// [`root_succession_input`].
pub const DS_ROOT_SUCCESSION: &[u8] = b"safeclaw/v1/root-succession";

/// An owner-signed account principal-ledger event (§15,
/// design/agent-device-identity-mtls.md): the account owner (UIK) ADMITs or
/// REVOKEs an account-scoped principal (a device `dev_…` or an agent `ag_…`). The
/// ACCOUNT-level analog of [`DS_DELEGATION`] (which is per-vault): the anchor is
/// the account's own owner-UIK (the account id self-certifies it,
/// `derive_id(User, uik_pub) == account_id`), so a daemon verifies the ledger
/// against the UIK it already learned at pairing. See [`principal_event_input`].
pub const DS_PRINCIPAL_EVENT: &[u8] = b"safeclaw/v1/principal-event";

/// Domain tag for a vault-DELETE tombstone (§15 leg A, per-vault drop). The vault
/// OWNER signs this so a daemon destroys local state on OWNER intent, not a server
/// flipping a cleartext `status:"deleted"` field. Verified against the vault's
/// fold-owner set (the same genesis-anchored authority as [`DS_DELEGATION`]). See
/// [`vault_tombstone_input`].
pub const DS_VAULT_TOMBSTONE: &[u8] = b"safeclaw/v1/vault-tombstone";

/// Reserved for a UIK lineage succession certificate (old UIK signs the new
/// UIK). Nothing signs or verifies one today; the tag stays so it is never
/// reused for another input.
pub const DS_SUCCESSION: &[u8] = b"safeclaw/v1/uik-succession";

/// Server-key signature over the whole sync envelope. See [`server_envelope_input`].
pub const DS_SERVER_ENVELOPE: &[u8] = b"safeclaw/v1/server-envelope";

/// Server-key signature over a fresh "last real contact" token. See
/// [`contact_token_input`].
pub const DS_CONTACT_TOKEN: &[u8] = b"safeclaw/v1/contact-token";

/// A device's per-request proof-of-possession over a daemon→cloud request (the
/// DIK half of mutual mTLS, hop-B). Railway terminates TLS, so hop-B can't be a
/// real client-cert handshake — instead the daemon signs each request with its
/// DIK and the Node backend verifies the signature against the device's
/// registered `dev_` pubkey. See [`device_request_signature_input`].
pub const DS_DEVICE_REQ: &[u8] = b"safeclaw/v1/device-req";

/// An agent's per-CONNECT proof-of-possession over the local forward proxy (the
/// AIK half of mutual mTLS, hop-A). A standard client can't present a client cert
/// to a forward proxy, so the AIK identity rides a signed token in the
/// `Proxy-Authorization` header instead. See [`agent_proxy_pop_input`].
pub const DS_AGENT_PROXY_POP: &[u8] = b"safeclaw/v1/agent-proxy-pop";

/// Domain tag for the **per-record signature** (SUDP extension A1.2/A1.3,
/// `design/sudp-identity-signing-revision.md`). This is the SUDP-protocol-layer
/// record signature — hence the `sudp/v1/*` family (C.4 domain decision) rather
/// than `safeclaw/v1/*` — even though the primitive lives here in core (the sudp
/// crate stays a pure codec, §B). It signs the CIPHERTEXT hash + the plaintext
/// `type`/`status`, so BOTH a blind server (write-gate / clean state) and every
/// reader (the trust wall) can verify without decrypting.
pub const DS_ITEM_SIG: &[u8] = b"sudp/v1/item-sig";

/// Append a length-prefixed field: `u32_be(len) ‖ bytes`. Identical to
/// the daemon's `storage::item` `push_lp` and sudp's `record_aad`
/// so all length-prefixed constructions agree byte-for-byte. Length-prefixing
/// removes splicing ambiguity between adjacent variable-length fields.
fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ── Self-certifying ids ────────────────────────────────────────────────────

/// Which principal an id names. The prefix makes ids self-describing and keeps
/// user and agent id spaces disjoint even at equal hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    /// A human principal (UIK). Prints as `us_…`.
    User,
    /// An agent principal (AIK). Prints as `ag_…`.
    Agent,
    /// A device principal (DIK) — one machine's identity to the cloud. Prints as
    /// `dev_…`. Symmetric with AIK (design/agent-device-identity-mtls.md §0);
    /// replaces the bearer device pair token.
    Device,
}

impl IdKind {
    fn prefix(self) -> &'static str {
        match self {
            IdKind::User => "us",
            IdKind::Agent => "ag",
            IdKind::Device => "dev",
        }
    }
}

/// Derive the self-certifying id of a principal from its Ed25519 public key:
/// `"{us|ag}_" ‖ base32_lower_nopad(SHA-256(pubkey)[..20])`.
///
/// The id IS a commitment to the pubkey (ETH-address / SSH-fingerprint style),
/// so a colluding server cannot swap the key behind an id. 20 bytes → 32 base32
/// chars; lower-cased for a friendly, case-insensitive, URL/DNS-safe token.
pub fn derive_id(kind: IdKind, pubkey: &[u8; 32]) -> String {
    let digest = sha256(pubkey);
    let body = BASE32_NOPAD.encode(&digest[..20]).to_lowercase();
    format!("{}_{}", kind.prefix(), body)
}

/// Verify a detached Ed25519 signature over `msg` by `pubkey`. Uses
/// `verify_strict` (rejects the small-order / malleable edge cases), and treats
/// a malformed public key as a failed verification (never a panic). This is the
/// reader-side wall: every daemon calls it before applying a signed record.
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}

// ── Canonical signing inputs (length-prefixed, domain-separated) ────────────
//
// Fixed-width scalars (version / generation / format / epoch / issued_at) are
// appended as big-endian bytes directly (unambiguous at fixed width); every
// variable-length field is `push_lp`'d.

/// Signing input for a config singleton (UIK-signed; reader-verified).
///
/// ```text
/// lp(DS_CONFIG_SIG) ‖ lp(vault_id) ‖ lp(item_ns) ‖ u64_be(version)
///   ‖ status(1) ‖ lp(SHA-256(body_or_empty)) ‖ lp(signer_id)
/// ```
///
/// `body = Some(canonical_bytes)` for a live record, `None` for a tombstone;
/// `status` = `1` live / `0` tombstone, so a live signature can never be
/// replayed as a tombstone (and vice versa). Hashing the (already-canonical)
/// body keeps the input bounded. `signer_id` (the owner's `us_…`) binds the
/// signature to a specific principal. The caller canonicalizes the body (JCS)
/// before hashing — see the config-signing layer for the body parity vector.
pub fn config_sig_input(
    vault_id: &str,
    item_ns: &str,
    version: u64,
    body: Option<&[u8]>,
    signer_id: &str,
) -> Vec<u8> {
    let status: u8 = if body.is_some() { 1 } else { 0 };
    let body_hash = sha256(body.unwrap_or(&[]));
    let mut out = Vec::new();
    push_lp(&mut out, DS_CONFIG_SIG);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, item_ns.as_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.push(status);
    push_lp(&mut out, &body_hash);
    push_lp(&mut out, signer_id.as_bytes());
    out
}

/// Signing input for a **per-record signature** (SUDP extension A1.2/A1.3,
/// `design/sudp-identity-signing-revision.md`): a principal's signature over one
/// sealed record, binding its plaintext `type`/`status` to the sealed body.
///
/// ```text
/// lp(DS_ITEM_SIG) ‖ lp(record_type) ‖ lp(item_id) ‖ u64_be(version)
///   ‖ lp(vault_id) ‖ status(1) ‖ lp(SHA-256(sealed_body)) ‖ lp(principal_id)
/// ```
///
/// Crucially the hash is over the **sealed body (ciphertext)**, not the plaintext
/// — so a blind server AND every reader can verify the signature WITHOUT the key
/// (the server does the write-gate for clean state; the reader is the trust wall,
/// A1.5). `record_type` is the plaintext ns token (`secret`/`connection`/`policy`/
/// `agent`/…) that the server gates on (A1.4 role×type) and the reader cross-binds
/// to the decrypted record. `status` = `1` live / `0` tombstone (a delete is a
/// signed record state; the signer+type decide who may delete). `item_id` is the
/// blinded HMAC id (unchanged addressing). `principal_id` = the signer's self-id
/// (`us_`/`dev_`/`ag_`) — a UIK for human writes, the DIK/AIK for automatic
/// (daemon/agent) writes (A2). One signature does all three jobs: authorization
/// (role×type), integrity/author identity, and rollback resistance (version is
/// bound + the caller keeps version monotone).
pub fn record_signature_input(
    record_type: &str,
    item_id: &[u8],
    version: u64,
    vault_id: &str,
    sealed_body: &[u8],
    status_live: bool,
    principal_id: &str,
) -> Vec<u8> {
    let body_hash = sha256(sealed_body);
    let mut out = Vec::new();
    push_lp(&mut out, DS_ITEM_SIG);
    push_lp(&mut out, record_type.as_bytes());
    push_lp(&mut out, item_id);
    out.extend_from_slice(&version.to_be_bytes());
    push_lp(&mut out, vault_id.as_bytes());
    out.push(if status_live { 1 } else { 0 });
    push_lp(&mut out, &body_hash);
    push_lp(&mut out, principal_id.as_bytes());
    out
}

/// Signing input for a **device request proof-of-possession** (hop-B of the
/// mutual-mTLS transport, `design/agent-device-identity-mtls.md` §9.1). The
/// daemon signs every cloud request with its DIK so the Node backend can verify
/// "this request really came from an authorized device" WITHOUT a client-cert
/// handshake (Railway terminates TLS before the app ever sees the connection).
///
/// ```text
/// lp(DS_DEVICE_REQ) ‖ lp(method) ‖ lp(path) ‖ u64_be(timestamp)
///   ‖ lp(SHA-256(body)) ‖ lp(device_id)
/// ```
///
/// Every field binds so a captured signature can't be replayed onto a different
/// request: `method`+`path` pin the endpoint (pass `path` including the query
/// string, exactly as it appears on the wire, so it matches byte-for-byte at the
/// verifier), `timestamp` (unix seconds) bounds the replay window, the body hash
/// pins the payload (use `&[]` for a bodyless GET — its SHA-256 is a fixed
/// constant both sides compute), and `device_id` (the `dev_…` self-id) tells the
/// verifier which registered pubkey to check. This is a Sprott transport-auth
/// concern, not part of the SUDP sealed-record protocol, so it lives in the
/// `safeclaw/v1/*` domain (unlike the `sudp/v1/item-sig` record signature).
///
/// hop-B is ADDITIVE: the daemon keeps sending its bearer device-key too, so an
/// un-upgraded backend (that ignores the signature header) still authenticates,
/// and a backend that has not yet migrated the device pubkey column verifies
/// nothing and falls back to the bearer. Nothing bricks in any upgrade order.
pub fn device_request_signature_input(
    method: &str,
    path: &str,
    timestamp: u64,
    body: &[u8],
    device_id: &str,
) -> Vec<u8> {
    let body_hash = sha256(body);
    let mut out = Vec::new();
    push_lp(&mut out, DS_DEVICE_REQ);
    push_lp(&mut out, method.as_bytes());
    push_lp(&mut out, path.as_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    push_lp(&mut out, &body_hash);
    push_lp(&mut out, device_id.as_bytes());
    out
}

/// Signing input for an **agent proxy-connect proof-of-possession** (hop-A of the
/// mutual-mTLS transport, `design/agent-device-identity-mtls.md` §9.1). An agent
/// reaches the daemon through a standard forward proxy (`HTTP_PROXY`), whose only
/// client-auth channel is the `Proxy-Authorization` header on each `CONNECT` — a
/// standard client cannot present a client cert to a forward proxy, so hop-A (like
/// hop-B under Railway) rides an application-layer signature, not TLS mutual auth.
/// The `sc` transport signs this with the agent's AIK per CONNECT; the daemon
/// verifies it against the vault's authorized-agents table.
///
/// ```text
/// lp(DS_AGENT_PROXY_POP) ‖ lp(vault_id) ‖ lp(target) ‖ u64_be(timestamp) ‖ lp(agent_id)
/// ```
///
/// `vault_id` = the CONNECT's proxy-auth username (which vault the agent is using),
/// `target` = the CONNECT authority `host:port` the tunnel opens to (binds the
/// token to that destination so a captured one can't be replayed elsewhere within
/// the window), `timestamp` = unix seconds (freshness/replay window), `agent_id` =
/// the AIK self-id (`ag_…`). The daemon rebuilds this from the CONNECT context +
/// the token's carried pubkey (deriving `agent_id`) and verifies the signature,
/// then checks `agent_id ∈` the authorized-agents table. Per-CONNECT, not
/// per-request: one CONNECT opens a reused tunnel, and the proxy only sees
/// `Proxy-Authorization` at CONNECT time.
pub fn agent_proxy_pop_input(
    vault_id: &str,
    target: &str,
    timestamp: u64,
    agent_id: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_AGENT_PROXY_POP);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, target.as_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    push_lp(&mut out, agent_id.as_bytes());
    out
}

/// Signing input for an owner-signed re-key event (DP-S1 `generation` bump).
///
/// ```text
/// lp(DS_REKEY) ‖ lp(vault_id) ‖ u64_be(generation) ‖ lp(k_commitment) ‖ lp(signer_id)
///   ‖ u64_be(membership_len) ‖ lp(membership_hash)
/// ```
///
/// `k_commitment` = a one-way commitment to the new content key `K'` (e.g. a
/// KCV) so a signed generation is bound to the specific new key and an old
/// signed event can't be replayed to force a different key. The signature is
/// what makes a `generation` bump trustworthy: an unsigned bump is ignored, so a
/// malicious backend cannot storm fake generations to DoS unlock (SM §3.2 ⚠).
///
/// **Membership anti-rollback (delegation-log-review-findings.md C2, owner-signed).**
/// `membership_len` + `membership_hash` = [`membership_commitment`] over the delegation-log
/// PREFIX current at re-key time (all events at the current role-epoch, sorted).
/// Because a re-key is owner-signed and the daemon RATCHETS `generation` (refuses a
/// lower one), binding the membership head here lets a device REFUSE a keyset that serves
/// the current generation but a rolled-back log (e.g. an omitted `remove`): the
/// prefix would not hash to `membership_hash`. Low-frequency by construction (only on
/// re-key / offboard, not on every add), and the server can't forge it (no owner
/// key). A truly-fresh device against a permanent consistent OLD snapshot is still
/// inherent to cloud-blind — but that bubble is fragile (new content is under the
/// new K it can't open).
pub fn rekey_sig_input(
    vault_id: &str,
    generation: u64,
    k_commitment: &[u8],
    signer_id: &str,
    membership_len: u64,
    membership_hash: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_REKEY);
    push_lp(&mut out, vault_id.as_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    push_lp(&mut out, k_commitment);
    push_lp(&mut out, signer_id.as_bytes());
    out.extend_from_slice(&membership_len.to_be_bytes());
    push_lp(&mut out, membership_hash);
    out
}

/// A one-way commitment to the delegation-log PREFIX for the membership anti-rollback
/// binding in [`rekey_sig_input`]. `sigs` = the Ed25519 signatures of the first
/// `membership_len` delegation events at the current role-epoch, in the SAME
/// deterministic `(seq, sig)` order the fold applies them (each `sig` is a
/// commitment to its event's full content). Byte-identical across daemon / backend /
/// browser:
///
/// ```text
/// SHA-256( "safeclaw/v1/membership-commit" ‖ u64_be(membership_len) ‖ sig_1 ‖ … ‖ sig_N )
/// ```
pub fn membership_commitment(sigs: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"safeclaw/v1/membership-commit");
    buf.extend_from_slice(&(sigs.len() as u64).to_be_bytes());
    for s in sigs {
        buf.extend_from_slice(s);
    }
    sha256(&buf)
}

/// Signing input for a creator-signed role grant on a keyset cred — the
/// owner-authority anchor (design/identity-uik-aik.md §4.3 RESOLVED). Role is an
/// attribute ON the keyset cred, signed by the vault's ROOT owner (the creator);
/// a daemon derives the owner-set by verifying each cred's `role_sig` against the
/// TOFU-pinned `creator_sig_pub`. This roots role in genesis, closing finding #1
/// (single-version self-consistency let any member self-sign `{me: owner}`).
///
/// ```text
/// lp(DS_ROLE_GRANT) ‖ lp(vault_id) ‖ lp(user_id) ‖ lp(role) ‖ u64_be(role_epoch)
/// ```
///
/// `role` is the lowercase serde token of [`crate::MemberRole`]
/// (`"admin"` / `"member"`; a grant signed before the admin rename carries `"owner"`,
/// which still verifies as admin). The variable-length fields are length-prefixed (so a
/// `(vault, user, role)` triple can't be spliced into another); the trailing epoch
/// is appended as a fixed-width big-endian `u64`, EXACTLY as [`rekey_sig_input`]
/// appends `generation`.
///
/// **Role-epoch binding (delegation-log-impl-spec.md §0, design/identity-uik-aik.md
/// §4.3).** This grant is the root-signed CHECKPOINT of the owner-set. It is bound
/// to `role_epoch` — the role-checkpoint epoch, ORTHOGONAL to the K-rotation
/// `generation` (memory: "generation ⊥ chain 正交"). A checkpoint grant signed at
/// `role_epoch = E` is honored only while the keyset's DERIVED epoch is `E` — the
/// epoch is derived from the root-signed succession/compaction chain
/// (`resolve_current_root`), never a stored scalar. Compaction (root-only) is a
/// SELF-succession that advances the epoch to `E+1`, re-signing every surviving owner
/// and dropping demoted/removed ones — so a colluding server that replays a stale
/// grant fails verification at the new epoch (and can't forge the epoch upward
/// without a root signature).
/// Between checkpoints, any-owner add/remove rides the delegation log
/// ([`delegation_event_input`]), not this checkpoint. K-eviction bumps `generation`
/// independently and does NOT invalidate checkpoint grants (they bind `role_epoch`).
pub fn role_grant_input(vault_id: &str, user_id: &str, role: &str, role_epoch: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_ROLE_GRANT);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, user_id.as_bytes());
    push_lp(&mut out, role.as_bytes());
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Signing input for an owner-signed delegation event — the any-owner,
/// issuance-time-authority half of the owner-set fold (design/identity-uik-aik.md
/// §4.3, delegation-log-impl-spec.md §1.1).
///
/// ```text
/// lp(DS_DELEGATION) ‖ lp(vault_id) ‖ lp(op) ‖ lp(subject_id) ‖ lp(role)
///   ‖ lp(granter_id) ‖ u64_be(seq) ‖ u64_be(role_epoch)
/// ```
///
/// `op` ∈ {`"set"`, `"remove"`}: `set` inserts `subject_id → role` (add / promote /
/// demote); `remove` drops `subject_id` (NON-CASCADE — touches only the subject).
/// `role` is the lowercase [`crate::MemberRole`] token for `set`
/// (`"admin"` / `"member"`, legacy `"owner"` = admin), empty for `remove`.
/// `granter_id` is the signing admin's `us_…`; the event is honored by the fold
/// iff `granter_id` is an ADMIN in the role set folded up to this event (so a member can't grant, and issuance-time authority survives the
/// granter's later removal). `seq` is monotone within `role_epoch` (rollback guard);
/// `role_epoch` binds the event to the current checkpoint so a compaction that folds
/// the log invalidates replays of pre-compaction events at the new epoch.
pub fn delegation_event_input(
    vault_id: &str,
    op: &str,
    subject_id: &str,
    role: &str,
    granter_id: &str,
    seq: u64,
    role_epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_DELEGATION);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, op.as_bytes());
    push_lp(&mut out, subject_id.as_bytes());
    push_lp(&mut out, role.as_bytes());
    push_lp(&mut out, granter_id.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Signing input for an owner-signed **account principal-ledger event** (§15,
/// design/agent-device-identity-mtls.md): the account owner ADMITs or REVOKEs an
/// account-scoped principal (device / agent). The ACCOUNT-level counterpart of
/// [`delegation_event_input`] — same shape (append-only, owner-signed, monotone
/// `seq`), but anchored to the ACCOUNT's owner-UIK instead of a vault genesis
/// root: devices/agents are account-scoped and must stay revocable even with 0
/// vaults, so they cannot ride a per-vault anchor.
///
/// ```text
/// lp(DS_PRINCIPAL_EVENT) ‖ lp(account_id) ‖ lp(op) ‖ lp(principal_id)
///   ‖ u64_be(seq) ‖ lp(owner_id)
/// ```
///
/// `op` ∈ {`"admit"`, `"revoke"`}. `principal_id` is the self-certifying `dev_…`/
/// `ag_…` id, which already commits to the principal's pubkey — so the event binds
/// the key WITHOUT carrying it (the principal presents its pubkey at connect time
/// and the daemon checks `derive_id(kind, pubkey) == principal_id ∈` the folded
/// ledger). `owner_id` is the signing account owner's `us_…`; the daemon honors
/// the event iff `owner_id`'s UIK is the account anchor (`derive_id(User,
/// uik_pub) == account_id`). `seq` is monotone (rollback guard): a daemon refuses
/// a ledger that drops a higher-seq `revoke`. On a VERIFIED `revoke` of ITSELF, a
/// device locks + wipes all local vaults + logs out (killing the bearer
/// device-key alone only parks — delivery-before-hard-kill).
///
/// Contract C1 (grant-v3): the input ENDS with `lp(sc_pk)`: the device's raw
/// 32-byte X25519 grant-seal key for a device admit, empty for an agent admit
/// and for every revoke. The owner admits the device AND the one daemon key a
/// browser may seal a grant to, in one signature.
pub fn principal_event_input(
    account_id: &str,
    op: &str,
    principal_id: &str,
    seq: u64,
    owner_id: &str,
    sc_pk: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_PRINCIPAL_EVENT);
    push_lp(&mut out, account_id.as_bytes());
    push_lp(&mut out, op.as_bytes());
    push_lp(&mut out, principal_id.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    push_lp(&mut out, owner_id.as_bytes());
    push_lp(&mut out, sc_pk);
    out
}

/// Domain tag of the grant v3 identity signature (contract C3).
pub const DS_GRANT_ID: &[u8] = b"safeclaw/v1/grant-id";

/// Domain tag of the owner-signed principal-ledger head (contract C4).
pub const DS_PRINCIPAL_HEAD: &[u8] = b"safeclaw/v1/principal-head";

/// `SHA256(lp(k_enc) ‖ lp(k_ct))`: the seal hash a grant v3 `id_sig` binds (C3).
pub fn grant_seal_hash(k_enc: &[u8], k_ct: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + k_enc.len() + k_ct.len());
    push_lp(&mut buf, k_enc);
    push_lp(&mut buf, k_ct);
    sha256(&buf)
}

/// Signing input of a grant v3 identity signature (contract C3), one per op row:
///
/// ```text
/// lp("safeclaw/v1/grant-id") ‖ lp(vault_id) ‖ lp(op_id) ‖ lp(beta) ‖ lp(credential_id)
///   ‖ lp(SHA256(lp(k_enc) ‖ lp(k_ct))) ‖ lp(sc_pk) ‖ lp(id)
/// ```
///
/// `beta` is the op's 32-byte binding (the daemon's `crypto::binding::binding_for_op`
/// under `DOMAIN_STANDARD`), `credential_id` the raw passkey credential id, `sc_pk`
/// the raw X25519 key the K seal is sealed to, `id` the approver's `us_…`. Binding
/// the seal hash and `sc_pk` stops a relay from moving a signature onto another
/// seal or daemon; binding `credential_id` makes passkey → person cryptographic.
#[allow(clippy::too_many_arguments)]
pub fn grant_id_input(
    vault_id: &str,
    op_id: &str,
    beta: &[u8],
    credential_id: &[u8],
    k_enc: &[u8],
    k_ct: &[u8],
    sc_pk: &[u8],
    id: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_GRANT_ID);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, op_id.as_bytes());
    push_lp(&mut out, beta);
    push_lp(&mut out, credential_id);
    push_lp(&mut out, &grant_seal_hash(k_enc, k_ct));
    push_lp(&mut out, sc_pk);
    push_lp(&mut out, id.as_bytes());
    out
}

/// Domain tag of the approval-card binding (request-model design §5).
pub const DS_GRANT_CARD: &[u8] = b"sprott/v1/grant-card";

/// The signing input of a grant whose op carries a sealed approval card:
/// [`grant_id_input`], then `lp("sprott/v1/grant-card") ‖ lp(card_mac)`, where
/// `card_mac` is the daemon's `approval::card::binding_mac` of the card as the
/// approver opened it. A console that never opened the card can't produce it.
pub fn with_card_binding(mut input: Vec<u8>, card_mac: &[u8; 32]) -> Vec<u8> {
    push_lp(&mut input, DS_GRANT_CARD);
    push_lp(&mut input, card_mac);
    input
}

/// `SHA256(lp(sig_1) ‖ … ‖ lp(sig_n))` over the ledger's event signatures in
/// `seq` order: the `events_hash` an owner-signed ledger head commits to (C4).
pub fn principal_events_hash<S: AsRef<[u8]>>(sigs: &[S]) -> [u8; 32] {
    let mut buf = Vec::new();
    for s in sigs {
        push_lp(&mut buf, s.as_ref());
    }
    sha256(&buf)
}

/// Signing input of the owner-signed principal-ledger head (contract C4):
///
/// ```text
/// lp("safeclaw/v1/principal-head") ‖ lp(anchor) ‖ u64_be(max_seq) ‖ lp(events_hash)
/// ```
///
/// `anchor` is the account owner's `us_…` id (UTF-8), the same string the events'
/// `account_id` carries. Closes a forged or truncated ledger tail.
pub fn principal_head_input(anchor: &str, max_seq: u64, events_hash: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_PRINCIPAL_HEAD);
    push_lp(&mut out, anchor.as_bytes());
    out.extend_from_slice(&max_seq.to_be_bytes());
    push_lp(&mut out, events_hash);
    out
}

/// Canonical bytes a vault OWNER signs to tombstone (delete) a vault (§15 leg A):
///
/// ```text
/// lp(DS_VAULT_TOMBSTONE) ‖ lp(vault_id)
/// ```
///
/// The `vault_id` is a unique, never-reused UUID, so binding it alone is replay-safe
/// (a signed tombstone can only ever name the one vault it deletes; there is no later
/// vault with the same id to replay it onto). A daemon honors the tombstone iff the
/// signer is an owner in the vault's fold-owner set — the same genesis-anchored
/// authority that gates [`delegation_event_input`]. This raises "delete a vault
/// locally" from "the server flips a cleartext status field" to "forge an owner
/// signature": [`DS_SERVER_ENVELOPE`] is server-signed and does NOT cover `status`,
/// so the destroy signal needed its own OWNER-signed channel.
pub fn vault_tombstone_input(vault_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_VAULT_TOMBSTONE);
    push_lp(&mut out, vault_id.as_bytes());
    out
}

/// Signing input for a root-succession certificate — the CURRENT root signs the
/// NEXT root's id + signing pubkey, so a daemon follows a short chain from the
/// TOFU-pinned genesis root to the current root (creator transfer / offboard;
/// design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md §1.2).
///
/// ```text
/// lp(DS_ROOT_SUCCESSION) ‖ lp(vault_id) ‖ lp(old_root_id) ‖ lp(new_root_id)
///   ‖ lp(new_root_sig_pub) ‖ u64_be(role_epoch)
/// ```
///
/// The `new_root_sig_pub` (raw 32 bytes) is bound in the signature so the server
/// cannot swap in a root pubkey of its choosing; `old_root_id` must equal
/// `derive_id(current root)` at verification; `role_epoch` must strictly increase
/// along the chain (rollback guard).
pub fn root_succession_input(
    vault_id: &str,
    old_root_id: &str,
    new_root_id: &str,
    new_root_sig_pub: &[u8; 32],
    role_epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_ROOT_SUCCESSION);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, old_root_id.as_bytes());
    push_lp(&mut out, new_root_id.as_bytes());
    push_lp(&mut out, new_root_sig_pub);
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Signing input for the server-signed sync envelope (server key signs; daemon
/// verifies against a pinned server public key).
///
/// ```text
/// lp(DS_SERVER_ENVELOPE) ‖ lp(vault_id) ‖ lp(kind) ‖ u64_be(format)
///   ‖ u64_be(membership_epoch) ‖ u64_be(issued_at) ‖ lp(nonce)
/// ```
///
/// Signs the server-authoritative operational facts (SM §9): sharedness `kind`,
/// format version, membership epoch, freshness. Defends the daemon's local cache
/// against local tampering (flip a bool / forge a value) — NOT against a
/// malicious server (which is the authority here).
pub fn server_envelope_input(
    vault_id: &str,
    kind: &str,
    format: u64,
    membership_epoch: u64,
    issued_at: u64,
    nonce: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_SERVER_ENVELOPE);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, kind.as_bytes());
    out.extend_from_slice(&format.to_be_bytes());
    out.extend_from_slice(&membership_epoch.to_be_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    push_lp(&mut out, nonce);
    out
}

/// Signing input for a fresh "last real contact" token (server key signs). The
/// offline lease computes staleness from the newest VALID token, so a daemon
/// that forges its local `last_contact` clock cannot extend the lease — it can't
/// mint a token without the server key (SM §9 "真正的防绕点是联系时间戳").
///
/// ```text
/// lp(DS_CONTACT_TOKEN) ‖ lp(vault_id) ‖ lp(account_id) ‖ u64_be(issued_at) ‖ lp(nonce)
/// ```
pub fn contact_token_input(
    vault_id: &str,
    account_id: &str,
    issued_at: u64,
    nonce: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_CONTACT_TOKEN);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, account_id.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    push_lp(&mut out, nonce);
    out
}
