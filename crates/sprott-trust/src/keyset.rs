//! The v2 (UIK) keyset layer: members, their roles and the owner-signed
//! delegation state, as the daemon stores them and the backend serves them.
//! Moved from the daemon's `storage::sealed_vault` and `storage::plaintext`,
//! which re-export these items at their old paths.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Membership role inside a shared vault. Two tiers by design (team §7.1/§5.15):
/// `Admin` = manage (config, members, reveal, approve anyone's request, kill
/// switch); `Member` = edit (content). Several admins are the norm; the LAST
/// admin can never be removed or demoted (§7.9). (The single billing "owner" of
/// a team is a server-side product label held by one admin; it is not a role
/// and never appears in signed data.)
///
/// Wire tokens: writers emit `"admin"` / `"member"`. Records signed before the
/// rename carry `"owner"`, which reads as [`MemberRole::LegacyOwner`]: the SAME
/// role as `Admin` (`==` treats them as equal, [`MemberRole::is_admin`] is
/// true), but it keeps its spelling so a re-emitted record still carries the
/// exact bytes its signature covers. Never construct `LegacyOwner` in new code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Admin,
    /// The least-privilege default: a cred that loads without an explicit role
    /// (legacy row, serde default) is a `Member`, never an `Admin`. This is the
    /// fail-closed choice for the admin-authority anchor — a missing role can
    /// never silently confer admin powers.
    #[default]
    Member,
    /// The pre-rename spelling of [`MemberRole::Admin`] (`"owner"`), read from
    /// records signed before the rename. Equal to `Admin` in every comparison.
    #[serde(rename = "owner")]
    LegacyOwner,
}

impl MemberRole {
    /// Does this role carry admin authority? (`Admin`, or its legacy `"owner"`
    /// spelling.)
    pub fn is_admin(self) -> bool {
        matches!(self, MemberRole::Admin | MemberRole::LegacyOwner)
    }
}

/// Roles compare by MEANING, not spelling: a legacy `"owner"` record is an admin.
impl PartialEq for MemberRole {
    fn eq(&self, other: &Self) -> bool {
        self.is_admin() == other.is_admin()
    }
}

impl Eq for MemberRole {}

/// Serde helper: encode bytes as STANDARD base64 (matching the frontend `toBase64`)
/// and decode LENIENTLY (accept standard OR url-safe, padded or not) — the same
/// mixed-encoding tolerance as [`decode_keys_data_field`]. Used for the delegation
/// log / root-succession signature + pubkey byte fields so a keyset's `/keys` wire
/// shape (what the browser writes) round-trips byte-for-byte through the daemon AND
/// equals the on-disk `vault.dat` representation — ONE SSOT encoding for both, so
/// `serde_json::to_value(&uik.delegation_log)` yields exactly the wire the frontend
/// and backend agree on (no separate hand-rolled converter).
mod b64_std {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let norm: String = s
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                other => other,
            })
            .collect();
        let norm = norm.trim_end_matches('=');
        let pad = norm.len() % 4;
        let padded = if pad == 0 {
            norm.to_string()
        } else {
            let mut t = norm.to_string();
            t.push_str(&"=".repeat(4 - pad));
            t
        };
        STANDARD
            .decode(padded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// A `/keys` data field that is not base64 ([`decode_keys_data_field`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysFieldError(pub base64::DecodeError);

impl std::fmt::Display for KeysFieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "keys data field not base64: {}", self.0)
    }
}

impl std::error::Error for KeysFieldError {}

/// LENIENT base64 decode for a `/keys` row `data` field, mirroring the
/// frontend's `fromBase64` (lib/safeclaw-crypto.ts): the frontend writes these
/// fields with MIXED encodings — `x`/`y`/`prf_salt`/`wrapped_key` are STANDARD
/// base64 (`toBase64`, has `+`/`/`/`=`) while `x25519_pub` is base64url — and its
/// reader accepts BOTH. So the daemon must NOT use a strict base64url decoder
/// (it would reject `+`/`/`/`=` and fail to unwrap `K`). Normalize url→std
/// (`-`→`+`, `_`→`/`), re-pad to a multiple of 4, then STANDARD-decode.
/// This is EXCLUSIVELY for `/keys` data fields; the `cid` row PK stays strict
/// base64url-nopad (`decode_credential_id`), and content item `ct`/id bytes stay
/// strict base64url-nopad (the per-item stack, `b64url_bytes`).
pub fn decode_keys_data_field(s: &str) -> Result<Vec<u8>, KeysFieldError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let std: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let std = std.trim_end_matches('=');
    let pad = std.len() % 4;
    let padded = if pad == 0 {
        std.to_string()
    } else {
        let mut t = std.to_string();
        t.push_str(&"=".repeat(4 - pad));
        t
    };
    STANDARD
        .decode(padded.as_bytes())
        .map_err(KeysFieldError)
}

/// The v2 (UIK) material carried alongside one credential (device) row — the
/// per-row half of `custody → UIK → K`. `K` is HPKE-sealed to the member's UIK
/// X25519 **encryption public key** (team-shared-vault-security-model.md §1/§2:
/// "K 用该成员的 UIK 公钥封装成一份"). Logically the seal is per-MEMBER (one
/// `enc_pub` per person), but it is stored per-credential-ROW so the keyset sync
/// carries it losslessly: `/keys` rows are cid-keyed, and a daemon re-pushes an
/// adopted row verbatim without needing to map the credential back to its member
/// (it cannot — that needs the member's root). The copies across one member's
/// devices are identical and tiny; the "no duplication" rule (§2) targets ITEM
/// storage explosion, not these keyset seals. Cloud-visible by design.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UikCred {
    /// The account primary key `us_…` of the member this credential belongs to.
    /// Carried so offboarding can drop every credential of a departed member.
    pub user_id: String,
    /// The member's UIK Ed25519 **signing** public key (raw 32 bytes). Published
    /// so any reader can verify this member's config / role signatures (§9):
    /// `user_id = derive_id(sig_pub)` is one-way, so the pubkey itself must be
    /// carried. The creator's `sig_pub` is the vault's config-integrity trust
    /// anchor (only owner-signed config is honored; a malicious server can't
    /// forge it). Same across a member's devices (per-person, like `enc_pub`).
    #[serde(default)]
    pub sig_pub: Vec<u8>,
    /// The member's UIK X25519 encryption public key (raw 32 bytes). The owner
    /// seals `K` here on join / re-key (needs only this PUBLIC key); the member
    /// derives the same key from its unwrapped root and opens the seal.
    pub enc_pub: Vec<u8>,
    /// HPKE encapsulated key for the K-seal.
    pub k_encapped: Vec<u8>,
    /// HPKE ciphertext = `Seal(K)` to `enc_pub`, `info = uik-kseal ‖ vault_id`
    /// (the daemon's `crypto::vault_key::seal_k_to_uik`).
    pub k_ct: Vec<u8>,
    /// This member's role in the vault — an owner-signed attribute riding on the
    /// SAME record as membership (SSOT: the keyset cred is SM §1's single home
    /// for "who is a member"; role rides it, so there is one representation, no
    /// in-vault membership to drift). Verified via `role_sig`. `#[serde(default)]` =
    /// `Member` (least privilege) for legacy rows that predate this field, so a
    /// missing role never confers owner powers.
    #[serde(default)]
    pub role: MemberRole,
    /// The vault CREATOR's Ed25519 signature over
    /// [`crate::identity::role_grant_input`]`(vault_id, user_id, role, generation)`
    /// (raw 64 bytes), signed at the keyset's `generation`. The daemon derives the
    /// owner-set by verifying this against the TOFU-pinned `creator_sig_pub`
    /// ([`KeysetUik::creator_sig_pub`]) at the CURRENT `generation`: a cred is
    /// honored at its `role` iff its `role_sig` verifies under the pinned creator AT
    /// that generation. This roots role in genesis (closing finding #1 — a member
    /// can no longer self-sign `{me: owner}`) and binds the grant to the role epoch
    /// (F3-b — a re-key generation bump invalidates a stale grant, so a
    /// demoted/offboarded person's replayed grant fails verification). May be empty
    /// for a legacy cred (then the cred is NOT an owner: an empty/invalid `role_sig`
    /// fails verification).
    #[serde(default)]
    pub role_sig: Vec<u8>,
    /// The vault's previous content keys, sealed under the current one (the
    /// row's `uik_prev_content_ct`; an owner sets it on every member's row at
    /// a re-key and on an invite): open rows a re-key has not moved yet
    /// (the daemon's `storage::item::material_with_prev`). Empty when there is
    /// none. Carried as sealed: every write of this entry keeps it, and this
    /// process never makes a new one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prev_content_ct: Vec<u8>,
}

/// The v2 (UIK) layer of a keyset — the `custody → UIK → K` layering
/// (team-shared-vault-security-model.md §5, sudp-identity-signing-revision.md
/// §B3). Present (`Some`) iff the keyset is v2. In v2, each
/// `SealedCredential.wrapped_key` holds `Wrap_{W_c}(UIK root)` (the classic
/// custody slot, re-purposed from wrapping `K` to wrapping the identity root),
/// and `K` is recovered from that credential's per-row seal in `creds`. A v1
/// keyset has `uik = None` and its `wrapped_key` is the classic `Wrap_{W_c}(K)`.
/// An owner-signed DP-S1 re-key event (team-shared-vault-security-model.md §3.2 /
/// sudp-identity-signing-revision.md A1.7). Proves a `generation` bump + content-
/// key rotation was authorized by an owner — so a malicious backend can neither
/// storm fake generations (unlock DoS) nor swap in a content key it chose (the
/// commitment binds the signature to the actual new content key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyProof {
    /// The generation this event authorizes (must equal `KeysetUik::generation`).
    pub generation: u64,
    /// A one-way commitment to the new content key ([`rekey_commitment`]), so the
    /// signature is bound to the specific rotated key (anti content-swap).
    pub k_commitment: Vec<u8>,
    /// The owner's Ed25519 signature over [`crate::identity::rekey_sig_input`].
    pub sig: Vec<u8>,
    /// The signing owner's `us_…` (must be an owner in the verified membership).
    pub signer_id: String,
    /// Membership anti-rollback (owner-signed): the number of delegation events at the
    /// current role-epoch captured at re-key time. `0` = empty prefix.
    #[serde(default)]
    pub membership_len: u64,
    /// [`crate::identity::membership_commitment`] over that prefix's event signatures, in
    /// `(seq, sig)` order. The fold refuses a keyset whose delegation-log prefix does
    /// not hash to this (a server serving the current generation with a rolled-back
    /// log — e.g. an omitted `remove` — fails the check).
    #[serde(default, with = "b64_std")]
    pub membership_hash: Vec<u8>,
}

impl RekeyProof {
    /// Whether `sig` is a valid signature over [`crate::identity::rekey_sig_input`]
    /// by the published cred key of `signer_id` ([`KeysetUik::signer_key`]).
    /// Whether that signer may re-key is the caller's check.
    pub fn signature_valid(&self, uik: &KeysetUik, vault_id: &str) -> bool {
        let Ok(sig) = <[u8; 64]>::try_from(self.sig.as_slice()) else {
            return false;
        };
        let Some(signer_pub) = uik.signer_key(&self.signer_id) else {
            return false;
        };
        let input = crate::identity::rekey_sig_input(
            vault_id,
            self.generation,
            &self.k_commitment,
            &self.signer_id,
            self.membership_len,
            &self.membership_hash,
        );
        crate::identity::verify(&signer_pub, &input, &sig)
    }
}

/// An owner-signed delegation event — the any-owner, issuance-time-authority half
/// of the owner-set fold (design/identity-uik-aik.md §4.3,
/// delegation-log-impl-spec.md §1.2). Appended to [`KeysetUik::delegation_log`]
/// between root-signed checkpoints so ANY current owner (not just the root/creator)
/// can add / promote / demote / remove without a re-key. The fold honors an event
/// iff its `granter_id` is an Owner in the owner-set folded up to this event's `seq`
/// — so a member can't grant, and the fact "granter WAS an owner when they signed"
/// survives the granter's own later removal (NON-CASCADE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEvent {
    /// `"set"` (insert `subject_id → role`: add / promote / demote) or `"remove"`
    /// (drop `subject_id`; touches ONLY the subject — non-cascade).
    pub op: String,
    /// The `us_…` whose role this event changes.
    pub subject_id: String,
    /// The role for a `"set"` (ignored for `"remove"`). `#[serde(default)]` = Member.
    #[serde(default)]
    pub role: MemberRole,
    /// The signing owner's `us_…`. Must be an Owner in the fold up to `seq`.
    pub granter_id: String,
    /// The granter's Ed25519 signing pubkey (raw 32 bytes), carried INLINE and
    /// SELF-CERTIFYING: the fold requires `derive_id(granter_sig_pub) == granter_id`,
    /// then verifies `sig` under it. Carrying it in the event (rather than resolving it
    /// from the granter's cred row) is load-bearing: it makes verification immune to a
    /// spoofed cred row that lies about `(user_id, sig_pub)`, AND keeps the event
    /// verifiable AFTER the granter's own cred row is deleted at offboard — so removing
    /// a granter never drops whom they added (NON-CASCADE survives eviction).
    #[serde(default, with = "b64_std")]
    pub granter_sig_pub: Vec<u8>,
    /// Monotone ordering within `role_epoch` (rollback / reorder guard).
    pub seq: u64,
    /// The checkpoint epoch this event rides on. An event whose `role_epoch` differs
    /// from the keyset's current (succession-derived) `role_epoch` is a pre-compaction
    /// replay → ignored by the fold.
    pub role_epoch: u64,
    /// `granter`'s Ed25519 over [`crate::identity::delegation_event_input`] (64 bytes).
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
}

impl DelegationEvent {
    /// Does `sig` verify under `granter_pub` over this event's signing input
    /// ([`crate::identity::delegation_event_input`])? A `remove` signs an empty
    /// role; a `set` signs its role token, which a legacy admin event spells
    /// `"owner"` and a new one `"admin"` (either verifies the admin role, never
    /// another role). The one check both the adopt filter and the fold run.
    pub fn signature_verifies(&self, vault_id: &str, granter_pub: &[u8; 32]) -> bool {
        let Ok(sig) = <[u8; 64]>::try_from(self.sig.as_slice()) else {
            return false;
        };
        let role_toks: &[&str] = if self.op == "remove" {
            &[""]
        } else {
            role_sig_tokens(self.role)
        };
        role_toks.iter().any(|tok| {
            let input = crate::identity::delegation_event_input(
                vault_id,
                &self.op,
                &self.subject_id,
                tok,
                &self.granter_id,
                self.seq,
                self.role_epoch,
            );
            crate::identity::verify(granter_pub, &input, &sig)
        })
    }
}

/// A root-succession certificate — the CURRENT root signs the NEXT root's id +
/// signing pubkey, letting the daemon follow a short chain from the TOFU-pinned
/// GENESIS root to the current root (creator transfer / offboard;
/// design/identity-uik-aik.md §4.3). A succession is always paired with a
/// checkpoint re-cut at `role_epoch` by the NEW root (the new root re-signs every
/// surviving grant, so the fold verifies checkpoint grants under the new root).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootSuccession {
    /// The retiring root's `us_…` (must equal `derive_id(current root)` when applied).
    pub old_root_id: String,
    /// The incoming root's `us_…` (must equal `derive_id(new_root_sig_pub)`).
    pub new_root_id: String,
    /// The incoming root's UIK Ed25519 signing pubkey (raw 32 bytes), bound in the
    /// signature so a colluding server can't swap in a root key of its choosing. For a
    /// pure COMPACTION (no ownership change) this equals the current root's pubkey and
    /// `old_root_id == new_root_id` — a self-succession that only advances `role_epoch`.
    #[serde(with = "b64_std")]
    pub new_root_sig_pub: Vec<u8>,
    /// The checkpoint epoch at which the transfer / compaction takes effect (strictly
    /// increasing along the chain — rollback guard, and the SOLE source of the current
    /// `role_epoch`, which is DERIVED from this chain rather than stored as a
    /// separately-forgeable scalar).
    pub role_epoch: u64,
    /// `old_root`'s Ed25519 over [`crate::identity::root_succession_input`] (64 bytes).
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeysetUik {
    /// `cid_b64 → per-credential UIK material` (same cid key as the credential /
    /// `/keys` row). Membership = holding one of these seals (SM §1).
    #[serde(default)]
    pub creds: BTreeMap<String, UikCred>,
    /// DP-S1 re-key epoch (team-shared-vault-security-model.md §3.2). `0` = never
    /// re-keyed (the K-seals carry a bundle whose content half is the original
    /// content key). An offboard/compromise re-key rotates the content key and
    /// bumps this, gated by an owner-signed re-key event
    /// ([`crate::identity::rekey_sig_input`]). A daemon that sees a higher, signed
    /// generation drops its old content key and re-unlocks under the new one.
    #[serde(default)]
    pub generation: u64,
    /// The owner-signed proof for the CURRENT `generation` (present iff
    /// `generation > 0`). A daemon refuses to fold a re-keyed vault whose proof is
    /// missing/invalid — so a backend can't forge a re-key.
    #[serde(default)]
    pub rekey_proof: Option<RekeyProof>,
    /// The vault's ROOT owner — the CREATOR's UIK Ed25519 signing pubkey (raw
    /// 32 bytes). This is the genesis anchor for role authority (design/
    /// identity-uik-aik.md §4.3 RESOLVED): the owner-set is derived by verifying
    /// each cred's `role_sig` against THIS key ([`Self`]'s creds →
    /// `resolve_membership_trust`). TOFU-pinned SET-ONCE by the daemon (first-seen
    /// wins; a non-empty pin is NEVER overwritten), so a colluding backend can't
    /// swap the anchor to forge an owner-set. On a v2 keyset that carries creds,
    /// empty here (serde default) means the anchor was never pinned — a colluding
    /// backend can STRIP it, so that state FAILS CLOSED ([`MembershipTrust::Untrusted`](crate::trust::MembershipTrust::Untrusted):
    /// ALL owner-config is dropped, NOT downgraded to integrity-only). Only a
    /// legacy v1 keyset (`uik == None`) reads config integrity-only.
    #[serde(default)]
    pub creator_sig_pub: Vec<u8>,
    /// Append-only owner-signed delegation events since the last checkpoint — the
    /// any-owner half of the owner-set fold ([`DelegationEvent`]). Empty right after
    /// a compaction. A fresh daemon folds `checkpoint(role_epoch) ∘ delegation_log`.
    #[serde(default)]
    pub delegation_log: Vec<DelegationEvent>,
    /// Root-succession + compaction chain from the GENESIS `creator_sig_pub` to the
    /// current root ([`RootSuccession`]). Empty = creator is still root at genesis
    /// epoch 0. The daemon walks it to resolve BOTH the current root AND the current
    /// `role_epoch` (the role-checkpoint epoch, ORTHOGONAL to the K-rotation
    /// `generation` — memory "generation ⊥ chain 正交"). `role_epoch` is DERIVED from
    /// this root-signed chain, not stored as a separate scalar: a pure compaction is a
    /// SELF-succession (`old_root == new_root`) that only advances the epoch, so the
    /// epoch can never be forged upward without a valid root signature (closing the
    /// generation-brick class of DoS by construction — [`resolve_current_root`](crate::trust::resolve_current_root)).
    #[serde(default)]
    pub root_succession: Vec<RootSuccession>,
    /// `cid_b64 → us_…` for OTHER members' passkeys the membership serves as
    /// approval-verification material only (`approver: true` credentials: a
    /// vault admin's passkeys, so this daemon can verify an admin approving its
    /// op). Their WebAuthn pubkeys go into the registry; they seat nobody and
    /// unlock nothing here, are never this device's own passkeys, and never
    /// count toward who the requester is. Who is an admin is still the verified
    /// role fold alone. Local only (never pushed).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub approver_cids: BTreeMap<String, String>,
}

impl KeysetUik {
    /// The signing pubkey of the published cred whose self-certifying id is
    /// `signer_id`, or `None` when no cred carries one.
    pub fn signer_key(&self, signer_id: &str) -> Option<[u8; 32]> {
        self.creds.values().find_map(|c| {
            let k = <[u8; 32]>::try_from(c.sig_pub.as_slice()).ok()?;
            (crate::identity::derive_id(crate::identity::IdKind::User, &k) == signer_id)
                .then_some(k)
        })
    }
}

/// A one-way commitment to a content key for a re-key event: `SHA-256(domain ‖
/// content_key)`. Byte-identical to the browser's `rekeyCommitment`
/// (lib/uik-crypto.ts). Binds a signed `generation` to the specific content key.
pub fn rekey_commitment(content_key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"safeclaw/v1/rekey-kc");
    h.update(content_key);
    h.finalize().into()
}

/// Every token a signature over `role` may have been made with, the record's own
/// spelling (its serde token, the EXACT bytes signed in
/// [`crate::identity::role_grant_input`] / [`crate::identity::delegation_event_input`])
/// first. An admin was signed as `"owner"` before the rename and as
/// `"admin"` after; both mean the same role, so a signature over either verifies
/// it (this also tolerates another implementation that re-spells a legacy record).
/// No token ever verifies a DIFFERENT role: `"member"` is never tried for an admin.
pub fn role_sig_tokens(role: MemberRole) -> &'static [&'static str] {
    match role {
        MemberRole::Admin => &["admin", "owner"],
        MemberRole::LegacyOwner => &["owner", "admin"],
        MemberRole::Member => &["member"],
    }
}

