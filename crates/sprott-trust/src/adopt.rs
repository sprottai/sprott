//! Adopting served membership into a keyset's UIK layer: the served triple
//! (`GET /membership`, fmt=2) and format-1 `/keys` rows. Pure (no registry, no
//! I/O); the daemon's `sync` runs these in its adopt, between its own registry
//! and credential writes. On an empty keyset they give the keyset a fresh
//! daemon would fold.

use std::collections::BTreeMap;

use crate::keyset::{
    decode_keys_data_field, DelegationEvent, KeysFieldError, KeysetUik, MemberRole, RekeyProof,
    RootSuccession, UikCred,
};
use crate::trust::fold_roles_of;

/// The text the daemon's `AppError::BadRequest` gives a [`KeysFieldError`]. The
/// adopt errors below carry it, so a sync error reads as it did before these
/// moved here.
fn bad_request(e: KeysFieldError) -> String {
    format!("Bad request: {}", e)
}

/// One row of a `/keys` pull. `data` is the cloud-VISIBLE keyset material (it is
/// what gives you `K`, so it can't be sealed under `K`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KeyRow {
    pub cid: String,
    pub version: u64,
    #[allow(dead_code)]
    pub seq: u64,
    pub data: KeyRowData,
}

/// The `data` blob of a `/keys` row — mirrors the frontend `VaultKeyData`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KeyRowData {
    pub x: String,
    pub y: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub x25519_pub: Option<String>,
    pub prf_salt: String,
    pub wrapped_key: String,
    /// Optional key-check value (KCV) `v_c` — present once enrolled/backfilled
    /// against a build that computes it; absent on older rows.
    #[serde(default)]
    pub wc_check: Option<String>,
    /// v2 (UIK) fields — present iff this vault is a `custody → UIK → K` keyset
    /// (team-shared-vault-security-model.md §5). In v2, `wrapped_key` wraps the
    /// UIK root (not `K`), and `K` is recovered from the per-credential seal
    /// below. All four travel together; `uik` is `Some` on the keyset once any
    /// row carries them. Base64 (lenient-decoded like the other data fields).
    /// `uik_user_id` = the member's `us_…` account key.
    #[serde(default)]
    pub uik_user_id: Option<String>,
    /// The member's UIK Ed25519 signing public key (config/role sig verify).
    #[serde(default)]
    pub uik_sig_pub: Option<String>,
    /// The member's UIK X25519 encryption public key.
    #[serde(default)]
    pub uik_enc_pub: Option<String>,
    /// HPKE encapsulated key for the K-seal.
    #[serde(default)]
    pub uik_k_encapped: Option<String>,
    /// HPKE ciphertext = `Seal(K)` to `uik_enc_pub`.
    #[serde(default)]
    pub uik_k_ct: Option<String>,
    /// This member's role (`"admin"` / `"member"`; a legacy `"owner"` is an admin),
    /// an admin-signed attribute on the cred (design/identity-uik-aik.md §4.3).
    /// Absent on a legacy row ⇒ defaults to `Member` (least privilege) on adopt.
    #[serde(default)]
    pub uik_role: Option<MemberRole>,
    /// The CREATOR's Ed25519 signature over
    /// `role_grant_input(vault, user, role, generation)` (base64, raw 64 bytes),
    /// signed at the keyset `generation` — verified against the pinned
    /// `uik_creator_sig_pub` at the CURRENT generation to derive the owner-set
    /// (F3-b generation-binding). Absent on a legacy row ⇒ the cred is not an owner.
    #[serde(default)]
    pub uik_role_sig: Option<String>,
    /// The vault's previous content keys, sealed under the current one (std
    /// base64; set by an owner on each member's row at a re-key and on an
    /// invite). Kept on the cred entry as sealed and written back with the
    /// row; never made here.
    #[serde(default)]
    pub uik_prev_content_ct: Option<String>,
    /// The vault's ROOT owner (creator) UIK signing pubkey (base64, raw 32 bytes).
    /// Keyset-LEVEL but carried REDUNDANTLY on every row (like `uik_generation`).
    /// TOFU-pinned SET-ONCE by the daemon on adopt — first-seen wins, a non-empty
    /// local pin is NEVER overwritten (a backend can't swap the role anchor).
    #[serde(default)]
    pub uik_creator_sig_pub: Option<String>,
    /// DP-S1 re-key epoch (team-shared-vault-security-model.md §3.2). Keyset-LEVEL
    /// but carried REDUNDANTLY on every row of a re-keyed vault (all rows share
    /// it), mirroring how the uik cred fields ride here. Absent / `0` = gen-0
    /// (never re-keyed) — the daemon then treats the vault as gen 0 (additive).
    #[serde(default)]
    pub uik_generation: Option<u64>,
    /// The owner-signed proof authorizing the current `uik_generation` (present iff
    /// generation > 0). JSON `{generation, k_commitment(b64), sig(b64), signer_id}`
    /// — the daemon decodes it into a `RekeyProof` and refuses to fold a re-keyed
    /// keyset whose proof is missing/invalid (`verify_rekey_proof`).
    #[serde(default)]
    pub uik_rekey_proof: Option<serde_json::Value>,
    /// The append-only owner-signed DELEGATION LOG (any-owner add/promote/demote/remove
    /// since the last checkpoint) — keyset-LEVEL, carried REDUNDANTLY on every row like
    /// the anchor + generation. JSON array of `DelegationEvent` (sig as STANDARD b64).
    /// Adopted as an append-only UNION (`adopt_delegation_meta`); the authoritative
    /// owner-set is re-derived from signatures in `fold_roles`. Absent on a
    /// gen-0 / no-delegation vault.
    #[serde(default)]
    pub uik_delegation_log: Option<serde_json::Value>,
    /// The root-succession + compaction chain (`RootSuccession` array, JSON; pubkey/sig
    /// as STANDARD b64) — the root-signed source of BOTH the current root and the
    /// derived `role_epoch`. Carried REDUNDANTLY on every row; adopted as an append-only
    /// union. Absent = the creator is still the genesis root at epoch 0.
    #[serde(default)]
    pub uik_root_succession: Option<serde_json::Value>,
}

/// Upsert a credential's v2 UIK material into `uik`, promoting the keyset to v2
/// if it was v1 (`uik == None`; owner-driven join / re-key sealed `K` to
/// `enc_pub`). Idempotent by `cid_b64`. The entry's previous content keys
/// ([`UikCred::prev_content_ct`]) are kept; [`set_uik_prev_content_ct`]
/// replaces them.
#[allow(clippy::too_many_arguments)]
pub fn set_uik_cred(
    uik: &mut Option<KeysetUik>,
    cid_b64: String,
    user_id: String,
    sig_pub: Vec<u8>,
    enc_pub: Vec<u8>,
    k_encapped: Vec<u8>,
    k_ct: Vec<u8>,
    role: MemberRole,
    role_sig: Vec<u8>,
) {
    let creds = &mut uik.get_or_insert_with(KeysetUik::default).creds;
    let prev_content_ct = creds
        .get(&cid_b64)
        .map(|c| c.prev_content_ct.clone())
        .unwrap_or_default();
    creds.insert(
        cid_b64,
        UikCred {
            user_id,
            sig_pub,
            enc_pub,
            k_encapped,
            k_ct,
            role,
            role_sig,
            prev_content_ct,
        },
    );
}

/// Set the previous content keys an entry carries, as sealed (an adopted
/// row's `uik_prev_content_ct`). A no-op for an entry that is not stored.
pub fn set_uik_prev_content_ct(uik: &mut Option<KeysetUik>, cid_b64: &str, sealed: Vec<u8>) {
    if let Some(c) = uik.as_mut().and_then(|u| u.creds.get_mut(cid_b64)) {
        c.prev_content_ct = sealed;
    }
}

/// Adopt a pulled `/keys` row's v2 UIK fields (base64, lenient-decoded like
/// the other keyset data fields, [`decode_keys_data_field`]) so the sync layer
/// never handles raw key bytes. Promotes the keyset to v2. `prev_content_ct_b64`:
/// the row's sealed previous content keys; a row without them keeps what the
/// entry holds (a re-key replaces it; the seal binds the generation, so a stale
/// one never opens). A field that is not base64 changes nothing.
#[allow(clippy::too_many_arguments)]
pub fn set_uik_cred_b64(
    uik: &mut Option<KeysetUik>,
    cid_b64: &str,
    user_id: &str,
    sig_pub_b64: &str,
    enc_pub_b64: &str,
    k_encapped_b64: &str,
    k_ct_b64: &str,
    role: MemberRole,
    role_sig_b64: &str,
    prev_content_ct_b64: Option<&str>,
) -> Result<(), KeysFieldError> {
    let prev_content_ct = prev_content_ct_b64
        .filter(|s| !s.is_empty())
        .map(decode_keys_data_field)
        .transpose()?;
    let sig_pub = decode_keys_data_field(sig_pub_b64)?;
    let enc_pub = decode_keys_data_field(enc_pub_b64)?;
    let k_encapped = decode_keys_data_field(k_encapped_b64)?;
    let k_ct = decode_keys_data_field(k_ct_b64)?;
    // Role signature is base64 (raw 64-byte Ed25519); an empty string = a
    // legacy row with no grant (decodes to an empty vec → not an owner).
    let role_sig = if role_sig_b64.is_empty() {
        Vec::new()
    } else {
        decode_keys_data_field(role_sig_b64)?
    };
    set_uik_cred(
        uik,
        cid_b64.to_string(),
        user_id.to_string(),
        sig_pub,
        enc_pub,
        k_encapped,
        k_ct,
        role,
        role_sig,
    );
    if let Some(sealed) = prev_content_ct {
        set_uik_prev_content_ct(uik, cid_b64, sealed);
    }
    Ok(())
}

/// The keyset half of adopting another member's passkey served as
/// approval-verification material (`approver: true`): `cid → identity_id` into
/// [`KeysetUik::approver_cids`] (so the signer resolves). An entry an earlier
/// adoption keyed under this cid (a seat it took for the device's own) is
/// dropped: the member's seat is keyed under their `us_…`. The daemon writes the
/// passkey's WebAuthn pubkey into its registry first, and labels nothing when
/// that write fails.
pub fn set_approver_label(uik: &mut Option<KeysetUik>, cid_b64: &str, identity_id: &str) {
    let uik = uik.get_or_insert_with(KeysetUik::default);
    uik.creds.remove(cid_b64);
    uik.approver_cids
        .insert(cid_b64.to_string(), identity_id.to_string());
}

/// Seat the members of a served `verify(anchor, members, proof)` membership
/// TRIPLE (fmt=2, end-to-end) into `uik`: the conversion half of the daemon's
/// `adopt_membership_triple`, with no registry write, no creator pin, and no
/// delegation or re-key state (the daemon runs [`adopt_creator_pin`] before it,
/// and its approver labels, [`adopt_delegation_meta`] and [`adopt_rekey_meta`]
/// after it). The caller's OWN member is keyed under its credential cid(s) (so v2
/// unlock's `uik.creds[own_cid]` lookup finds the K-seal); OTHER members are keyed
/// under their `us_…` id (the fold iterates `creds.values()`; the map key is
/// irrelevant there).
///
/// `Ok(None)`: the triple has no `members` or `identities` object, which seats
/// nobody, and the daemon adopts nothing more from it. `Ok(Some(n))`: `n`
/// members seated.
pub fn adopt_into(
    uik: &mut Option<KeysetUik>,
    body: &serde_json::Value,
) -> Result<Option<usize>, String> {
    // The caller's OWN credentials: identity_id → [cid]. The daemon keys its own member's
    // seal under these cids so the grant's credential_id resolves at v2 unlock.
    // (`approver: true` entries are other members' passkeys: never the caller's own.)
    let mut cids_by_member: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    if let Some(creds) = body.get("credentials").and_then(|v| v.as_array()) {
        for c in creds {
            if c.get("approver").and_then(|v| v.as_bool()) == Some(true) {
                continue;
            }
            if let (Some(cid), Some(idid)) = (
                c.get("cid").and_then(|v| v.as_str()),
                c.get("identity_id").and_then(|v| v.as_str()),
            ) {
                cids_by_member
                    .entry(idid.to_string())
                    .or_default()
                    .push(cid.to_string());
            }
        }
    }

    let (Some(members), Some(identities)) = (
        body.get("members").and_then(|v| v.as_object()),
        body.get("identities").and_then(|v| v.as_object()),
    ) else {
        return Ok(None); // an anchor with no members/identities seats nobody
    };

    let mut adopted = 0usize;
    for (id, m) in members {
        let ident = identities.get(id);
        // The FOLD self-certifies a checkpoint on `sig_pub` + `role_sig` (authority), NOT on
        // K-delivery — so seat a cred whenever `sig_pub` is present, defaulting the delivery
        // fields (enc_pub / k_encapped / k_ct) to empty when absent. Those are used only to
        // UNLOCK the daemon's OWN cred (which always carries them); for other members they are
        // inert. This matches the backend/frontend fold (which seat from sig_pub+role_sig
        // alone) so the owner-set is identical across all three even for a member whose
        // nullable `enc_pub` / K fields are missing. A member with no `sig_pub` can't be
        // self-certified → skip (fail-closed); the delegation log still folds them from sigs.
        let Some(sig_pub) = ident
            .and_then(|i| i.get("sig_pub"))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        let enc_pub = ident
            .and_then(|i| i.get("enc_pub"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let k_encapped = m.get("k_encapped").and_then(|v| v.as_str()).unwrap_or("");
        let k_ct = m.get("k_ct").and_then(|v| v.as_str()).unwrap_or("");
        // A bad/absent role token degrades to Member (least privilege) — NEVER `?`-fail the
        // whole pull (that would leave the keyset stale), matching the frontend's coercion.
        let role: MemberRole = m
            .get("role")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let role_sig = m.get("role_sig").and_then(|v| v.as_str()).unwrap_or("");
        // The member entry's sealed previous content keys (the row form's
        // `uik_prev_content_ct`), kept on every cred entry of the member.
        let prev_content_ct = m.get("prev_content_ct").and_then(|v| v.as_str());
        // Key the OWN member under its credential cid(s); OTHER members under their us_id.
        let keys: Vec<String> = match cids_by_member.get(id) {
            Some(cids) if !cids.is_empty() => cids.clone(),
            _ => vec![id.clone()],
        };
        for key in keys {
            set_uik_cred_b64(
                uik,
                &key,
                id,
                sig_pub,
                enc_pub,
                k_encapped,
                k_ct,
                role,
                role_sig,
                prev_content_ct,
            )
            .map_err(|e| format!("adopt uik seal {}: {}", id, bad_request(e)))?;
        }
        adopted += 1;
    }
    Ok(Some(adopted))
}

/// The UIK half of one format-1 `/keys` row: the v2 (UIK) per-credential K-seal
/// riding in the row, seated under its cid (all four seal fields and the user id
/// travel together; a partial set = a malformed row whose UIK adoption is skipped
/// rather than store a half seal). No registry or credential write and no creator
/// pin: the daemon's `adopt_key_rows` does those around it.
pub fn adopt_key_row_uik(uik: &mut Option<KeysetUik>, row: &KeyRow) -> Result<(), String> {
    if let (Some(uid), Some(sig), Some(enc), Some(encapped), Some(ct)) = (
        row.data.uik_user_id.as_deref(),
        row.data.uik_sig_pub.as_deref(),
        row.data.uik_enc_pub.as_deref(),
        row.data.uik_k_encapped.as_deref(),
        row.data.uik_k_ct.as_deref(),
    ) {
        // Role rides the SAME record (SSOT): a missing role token defaults to
        // Member (least privilege), a missing signature leaves the cred a
        // non-owner (fails `resolve_membership_trust`'s verify).
        let role = row.data.uik_role.unwrap_or_default();
        let role_sig = row.data.uik_role_sig.as_deref().unwrap_or("");
        set_uik_cred_b64(
            uik,
            &row.cid,
            uid,
            sig,
            enc,
            encapped,
            ct,
            role,
            role_sig,
            row.data.uik_prev_content_ct.as_deref(),
        )
        .map_err(|e| format!("adopt uik seal {}: {}", row.cid, bad_request(e)))?;
    }
    Ok(())
}

/// TOFU-pin the vault's ROOT owner (creator) UIK signing pubkey onto the keyset
/// (design/identity-uik-aik.md §4.3 — the owner-authority genesis anchor).
/// FIRST-SEEN WINS: adopt `creator_sig_pub` only when the local copy is empty;
/// NEVER overwrite a non-empty pin. A colluding backend could otherwise serve a
/// keyset claiming a DIFFERENT creator pubkey to forge an owner-set (self-promote
/// via a key it controls); pinning set-once makes the anchor immutable after the
/// first successful adopt (mirrors `adopt_rekey_meta`'s monotonic generation
/// rule). An empty / absent value is a no-op (a legacy row carries no anchor).
pub fn adopt_creator_pin(
    uik: &mut Option<KeysetUik>,
    creator_sig_pub_b64: &Option<String>,
) -> Result<(), String> {
    let Some(b64) = creator_sig_pub_b64.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let pub_bytes = decode_keys_data_field(b64)
        .map_err(|e| format!("creator_sig_pub: {}", bad_request(e)))?;
    if pub_bytes.is_empty() {
        return Ok(());
    }
    let uik = uik.get_or_insert_with(KeysetUik::default);
    // Set-once: a non-empty pin is the immutable genesis anchor; leave it.
    if uik.creator_sig_pub.is_empty() {
        uik.creator_sig_pub = pub_bytes;
    }
    Ok(())
}

/// Adopt a `/keys` row's keyset-LEVEL DELEGATION state — the append-only
/// `delegation_log` (owner-signed add/promote/demote/remove events) and the
/// `root_succession` chain (root transfers + compactions, the derived-`role_epoch`
/// source). Both are keyset-wide (carried REDUNDANTLY on every row, like the anchor
/// and generation) and APPEND-ONLY: the daemon UNIONS incoming entries into its local
/// copy and NEVER shrinks it, so a colluding server serving a stale/shorter set can't
/// roll back the owner-set — rollback-safety BY CONSTRUCTION. Unlike `generation`
/// (a stored scalar gating K selection, hence verify-before-ratchet), the owner-set is
/// RE-DERIVED from signatures every fold ([`fold_roles_of`] /
/// [`resolve_current_root`](crate::trust::resolve_current_root)), so a forged
/// event/cert adopted here is simply INERT — the fold ignores it. Adopt only
/// screens for well-formedness (32-byte pubkeys / 64-byte sigs) + de-duplicates, to
/// keep a re-delivered row from growing the log unboundedly. A vault with no UIK
/// layer (v1) is a no-op.
pub fn adopt_delegation_meta(
    uik: &mut Option<KeysetUik>,
    vault_id: &str,
    delegation_log: &Option<serde_json::Value>,
    root_succession: &Option<serde_json::Value>,
) -> Result<(), String> {
    if uik.is_none() {
        return Ok(()); // v1 / no UIK layer — nothing to adopt
    }
    // ── Root-succession / compaction chain (append-only union) ──
    if let Some(v) = root_succession {
        let incoming: Vec<RootSuccession> = serde_json::from_value(v.clone())
            .map_err(|e| format!("parse root_succession: {}", e))?;
        let uik = uik.as_mut().unwrap();
        for s in incoming {
            // Storage hygiene: keep only well-formed certs (32-byte pubkey, 64-byte
            // sig). Whether the cert actually chains from the current root is decided
            // at fold time by `resolve_current_root` — a garbage cert stored here is
            // inert (never advances the root).
            if <[u8; 32]>::try_from(s.new_root_sig_pub.as_slice()).is_err()
                || <[u8; 64]>::try_from(s.sig.as_slice()).is_err()
            {
                continue;
            }
            let dup = uik.root_succession.iter().any(|e| {
                e.old_root_id == s.old_root_id
                    && e.new_root_id == s.new_root_id
                    && e.role_epoch == s.role_epoch
                    && e.sig == s.sig
            });
            if !dup {
                uik.root_succession.push(s);
            }
        }
    }
    // ── Delegation log (append-only union) ──
    if let Some(v) = delegation_log {
        let incoming: Vec<DelegationEvent> = serde_json::from_value(v.clone())
            .map_err(|e| format!("parse delegation_log: {}", e))?;
        let uik = uik.as_mut().unwrap();
        for e in incoming {
            // SIG-VERIFY-AT-ADOPT: only store an event that SELF-VERIFIES — its inline
            // `granter_sig_pub` derives to `granter_id` AND its signature checks out.
            // (Enabled by the self-certifying inline key.) This keeps a colluding
            // server from bloating the log with well-formed junk events that every
            // later fold would re-verify (a sticky CPU DoS), and stops a junk event
            // from ever entering the fold to contend for a seq slot. The AUTHORITY
            // check — granter is an Owner in the fold — still happens at fold time
            // (it needs the full owner-set context).
            let Ok(granter_pub) = <[u8; 32]>::try_from(e.granter_sig_pub.as_slice()) else {
                continue;
            };
            if crate::identity::derive_id(crate::identity::IdKind::User, &granter_pub)
                != e.granter_id
            {
                continue;
            }
            if !e.signature_verifies(vault_id, &granter_pub) {
                continue; // signature does not self-verify → junk, do not store
            }
            let dup = uik.delegation_log.iter().any(|x| {
                x.op == e.op
                    && x.subject_id == e.subject_id
                    && x.granter_id == e.granter_id
                    && x.seq == e.seq
                    && x.role_epoch == e.role_epoch
                    && x.sig == e.sig
            });
            if !dup {
                uik.delegation_log.push(e);
            }
        }
    }
    Ok(())
}

/// Apply a `/keys` row's keyset-LEVEL DP-S1 re-key metadata onto the keyset's UIK
/// layer: `generation` + the owner-signed `RekeyProof`. Both are keyset-wide (a
/// re-keyed vault repeats them on every row). VERIFY-BEFORE-RATCHET: a
/// strictly-higher proposed generation `G` advances the local monotonic
/// generation (and stores the proof) ONLY when the accompanying proof is present,
/// is FOR `G`, and is signed by an OWNER in the current folded owner-set
/// ([`fold_roles_of`]) with a valid signature over
/// [`crate::identity::rekey_sig_input`]. Otherwise the higher generation is
/// IGNORED (neither `generation` nor `rekey_proof` change) — this is what stops a
/// current member forging `uik_generation: 999` with no valid owner proof from
/// ratcheting the fleet into the fold-time `verify_rekey_proof` `Unauthorized`
/// brick (a sticky DoS). `fold_view`'s `verify_rekey_proof` keeps the additional
/// k_commitment↔real-K binding check (defense in depth). A row with no / `0`
/// generation leaves the keyset untouched (gen-0 vaults never carry them → stay
/// gen 0, additive).
pub fn adopt_rekey_meta(
    uik: &mut Option<KeysetUik>,
    vault_id: &str,
    generation: Option<u64>,
    proof: &Option<serde_json::Value>,
) -> Result<(), String> {
    let Some(generation) = generation.filter(|g| *g > 0) else {
        return Ok(());
    };
    // DP-S1 generation is a MONOTONIC ratchet: only CONSIDER a STRICTLY HIGHER
    // generation. A malicious backend could otherwise serve an OLDER keyset (with
    // its genuine, still-valid older proof) to roll a daemon's generation BACKWARD
    // and undo a forward-secret re-key. A generation `<=` what we already hold is
    // ignored — we overwrite NEITHER `generation` NOR `rekey_proof`. (A stale/equal
    // adopt short-circuits here BEFORE the signature work below.)
    let current = uik.as_ref().map(|u| u.generation).unwrap_or(0);
    if generation <= current {
        return Ok(());
    }
    // VERIFY-BEFORE-RATCHET (HIGH-severity generation-ratchet DoS fix). The old
    // code ratcheted `generation` on UNVERIFIED input — it stored ANY higher
    // proposed generation and deferred the owner-signature check to fold-time
    // `verify_rekey_proof`. A current MEMBER could then PUT its own keyset row with
    // `uik_generation: 999` and no valid proof; every daemon pulled it, advanced to
    // 999, and `verify_rekey_proof` then failed → `fold_view` returned
    // `Unauthorized` → EVERY request for the vault was denied (a sticky fleet
    // brick). We now REQUIRE a valid owner-signed proof AT the proposed generation
    // `G` BEFORE advancing: a forged bump is IGNORED (local generation untouched),
    // so the fleet never ratchets into the fold-time brick. The k_commitment↔real-K
    // binding stays at fold-time `verify_rekey_proof` (K isn't available here) —
    // defense in depth.
    let Some(p) = proof.as_ref() else {
        return Ok(()); // higher generation with NO proof = a forged bump → ignore
    };
    // The proof must be FOR generation `G` (not a valid proof for some other gen
    // spliced onto a `G` claim).
    if p.get("generation").and_then(|v| v.as_u64()) != Some(generation) {
        return Ok(());
    }
    let signer_id = p
        .get("signer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let k_commitment = p
        .get("k_commitment")
        .and_then(|v| v.as_str())
        .map(decode_keys_data_field)
        .transpose()
        .map_err(|e| format!("k_commitment: {}", bad_request(e)))?
        .unwrap_or_default();
    let sig_bytes = p
        .get("sig")
        .and_then(|v| v.as_str())
        .map(decode_keys_data_field)
        .transpose()
        .map_err(|e| format!("sig: {}", bad_request(e)))?
        .unwrap_or_default();
    // Membership anti-rollback commitment (Part 2): the re-key proof binds the
    // delegation-log prefix current at re-key time (owner-signed). Absent/0 = empty.
    let membership_len = p
        .get("membership_len")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let membership_hash = p
        .get("membership_hash")
        .and_then(|v| v.as_str())
        .map(decode_keys_data_field)
        .transpose()
        .map_err(|e| format!("membership_hash: {}", bad_request(e)))?
        .unwrap_or_default();
    let candidate = RekeyProof {
        generation,
        k_commitment,
        sig: sig_bytes,
        signer_id,
        membership_len,
        membership_hash,
    };
    // The signer must have been an OWNER when it signed: in the owner-set folded over
    // the log prefix the proof commits (`membership_len` events at the current
    // role_epoch), so an admin demoted after re-keying still signed with authority. A
    // K-rotation (`generation` bump) is ORTHOGONAL to the role checkpoint
    // (`role_epoch`) under the two-counter model, so the set is folded at the current
    // role_epoch, NOT re-derived at the proposed `generation`. A member's self-signed
    // proof fails here (a member is not an owner).
    let roles_at = match uik.as_ref() {
        Some(u) => fold_roles_of(u, vault_id, Some(candidate.membership_len as usize)),
        None => BTreeMap::new(),
    };
    if !roles_at
        .get(&candidate.signer_id)
        .is_some_and(|r| r.is_admin())
    {
        return Ok(());
    }
    // Signed under the signer's published sig pubkey (C.1 anchor): a keyset cred
    // whose derived id matches `signer_id` — a backend-minted key isn't in the
    // keyset. A malformed or non-verifying signature → ignore (don't ratchet).
    if !uik
        .as_ref()
        .is_some_and(|uik| candidate.signature_valid(uik, vault_id))
    {
        return Ok(());
    }
    // Verified owner-signed proof at `G`: NOW ratchet forward + store the proof.
    let uik = uik.get_or_insert_with(KeysetUik::default);
    uik.generation = generation;
    uik.rekey_proof = Some(candidate);
    Ok(())
}
