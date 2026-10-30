//! Membership trust and the role fold (genesis, root succession, checkpoint
//! grants, the delegation log, the re-key proof), the honoring rules for
//! owner-config and agent rows, and who may approve. Moved from the daemon's
//! `storage::sealed_vault`, which keeps thin wrappers at the old names.

use std::collections::BTreeMap;

use crate::keyset::{
    decode_keys_data_field, rekey_commitment, role_sig_tokens, DelegationEvent, KeysetUik,
    MemberRole, RootSuccession,
};

/// C.3 — verify + unwrap a signed **owner-config** item body (team-shared-vault-
/// security-model.md §9: owner-authored config is integrity-protected by a UIK
/// signature; the reader/daemon verifying it is "the real wall" against a
/// malicious/compromised server rewriting policy).
///
/// A signed body is `{ data, uik_sig, uik_sign_pub }`; the signature covers
/// [`crate::identity::config_sig_input`]`(vault, config_name, version,
/// JCS(data), derive_id(sign_pub))`. Returns:
///   - `Some(data)` — a valid signed wrapper, OR a legacy/v1 raw body (no
///     `uik_sig`). Whether a raw body is HONORED is the caller's trust decision:
///     only a [`MembershipTrust::NoUik`] (legacy v1) keyset honors it.
///   - `None` — DROP it: a signed wrapper that FAILED (bad sig, malformed, or a
///     signer whose pubkey is NOT a published member key — the anti-forgery
///     anchor from C.1). Dropping falls the field to its safe default (A1.6:
///     isolate the bad record, never crash, safe-default security-relevant config).
///
/// `config_name` is the addressing-independent logical name (`policy`, `stores`,
/// …) so the same signature verifies whether the item rode legacy `aux:<name>`
/// or the unified ns. The browser signer is `lib/uik-crypto.ts` (JCS parity via
/// `sudp::canonical`, byte-identical to the browser `canonicalize`).
/// Integrity-verify an owner-config body (the C.3 half — no role authorization).
/// Returns:
///   - `None` — a signed wrapper that FAILED (bad/malformed sig, or a signer
///     whose pubkey is NOT a published member key = the C.1 anti-forgery anchor).
///   - `Some((data, None))` — a legacy/v1 raw body (no `uik_sig`), no signer.
///     Integrity says nothing about authorization: callers honor it ONLY on a
///     [`MembershipTrust::NoUik`] keyset (a v2 keyset drops it).
///   - `Some((data, Some(signer_id)))` — a valid signature; `signer_id` = the
///     signing member's `us_…` (for D's role authorization by the caller).
pub fn verify_config_sig(
    body: serde_json::Value,
    uik: Option<&KeysetUik>,
    vault_id: &str,
    config_name: &str,
    version: u64,
) -> Option<(serde_json::Value, Option<String>)> {
    // Not a signed wrapper → legacy raw body, no signer (the caller decides; only
    // a NoUik keyset honors it).
    let obj = match &body {
        serde_json::Value::Object(o) if o.contains_key("uik_sig") => o,
        _ => return Some((body, None)),
    };
    // A malformed signed wrapper is a DROP (fail-closed), not a legacy pass —
    // a present-but-broken `uik_sig` must never silently fall through unsigned.
    let sig_b64 = obj.get("uik_sig").and_then(|v| v.as_str())?;
    let sign_pub_b64 = obj.get("uik_sign_pub").and_then(|v| v.as_str())?;
    let data = obj.get("data")?.clone();
    let sig_vec = decode_keys_data_field(sig_b64).ok()?;
    let sign_pub_vec = decode_keys_data_field(sign_pub_b64).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    let sign_pub: [u8; 32] = sign_pub_vec.as_slice().try_into().ok()?;
    // Anti-server-forgery: the signer's pubkey MUST be a published member key
    // (the C.1 keyset anchor). A wrapper self-signed with a server-minted key is
    // rejected — the server can't add its key to the keyset with a valid K-seal.
    let known = uik.is_some_and(|u| u.creds.values().any(|c| c.sig_pub == sign_pub_vec));
    if !known {
        return None;
    }
    let signer_id = crate::identity::derive_id(crate::identity::IdKind::User, &sign_pub);
    let canonical = sudp::canonical::canonicalize(&data);
    let input = crate::identity::config_sig_input(
        vault_id,
        config_name,
        version,
        Some(&canonical),
        &signer_id,
    );
    if crate::identity::verify(&sign_pub, &input, &sig) {
        Some((data, Some(signer_id)))
    } else {
        None
    }
}

/// A1.2/A1.5 — verify a per-record **sidecar** signature (`StoredItem.sig`/`signer`)
/// over the record's CIPHERTEXT, by a keyset MEMBER (a UIK — `us_…`). This is the
/// daemon-side (trust wall) verification of the new signed-record scheme: unlike
/// [`verify_config_sig`] (the sig lives INSIDE the sealed body and covers the
/// plaintext), here the sig is a plaintext sidecar covering `record_signature_input`
/// over the ciphertext — so the same signature a blind server verified at write is
/// re-verified here. Returns the signer's `us_…` iff the signature verifies AND the
/// signer's pubkey is a published keyset cred (the anti-server-forgery anchor); else
/// `None` (drop). `item_id_raw` = the 32-byte blinded id; `status_live` = live vs
/// tombstone. DIK (`dev_…`) signers are NOT resolved here (device pubkeys aren't in
/// the keyset) — that path is served separately; this covers the UIK-signed
/// owner-config + authorized-agents records.
pub fn verify_record_sidecar_sig(
    ct: &[u8],
    uik: Option<&KeysetUik>,
    vault_id: &str,
    item_id_raw: &[u8],
    record_type: &str,
    version: u64,
    status_live: bool,
    sig_b64: &str,
    signer_id: &str,
) -> Option<String> {
    let sig_vec = decode_keys_data_field(sig_b64).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    // Resolve the signer's pubkey from the published keyset creds and bind it to the
    // claimed `signer_id` (self-certifying: id = fold of pubkey). A server-minted
    // key isn't in the keyset (it can't add one with a valid K-seal) → rejected.
    let sign_pub = uik?.signer_key(signer_id)?;
    let input = crate::identity::record_signature_input(
        record_type,
        item_id_raw,
        version,
        vault_id,
        ct,
        status_live,
        signer_id,
    );
    if crate::identity::verify(&sign_pub, &input, &sig) {
        Some(signer_id.to_string())
    } else {
        None
    }
}

/// Fold one NATIVE authorized-agents row (`ItemNs::Agent`, wire id == ag_id; the
/// caller enforces the id) — design/agent-device-identity-mtls.md §11.1, design/
/// agent-authz-cleartext-cutover.md. Returns the row body to honor, or `None` to
/// drop it (that `ag_id` is then simply not authorized). Per trust state:
///   - [`MembershipTrust::Verified`] (v2): honored ONLY with a valid sidecar item-sig
///     (A1.2: `record_signature_input`, type `"agent"`, over the ciphertext, by a
///     published keyset member) whose signer is a vault OWNER or the row's own
///     `owner` (a member authorizing their OWN agent). An unsigned row, or one that
///     carries only a legacy in-body `{data,uik_sig}` wrapper, is DROPPED: without
///     the sidecar any K-holding member could write an authorization row.
///   - [`MembershipTrust::NoUik`] (legacy v1): integrity-only. There are no member
///     keys (single-person vault), so nothing can be signed and the K-seal (AEAD) is
///     the only gate: a plain unsigned row is honored; anything claiming a signature
///     is dropped (it can't verify against an empty keyset).
///   - [`MembershipTrust::Untrusted`]: everything is dropped (fail closed).
#[allow(clippy::too_many_arguments)]
pub fn fold_agent_record(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    uik: Option<&KeysetUik>,
    vault_id: &str,
    item_id_raw: &[u8],
    version: u64,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    match trust {
        MembershipTrust::Untrusted => None,
        MembershipTrust::NoUik => {
            if stored_sig.is_some() || body.get("uik_sig").is_some() {
                return None;
            }
            Some(body)
        }
        MembershipTrust::Verified(membership) => {
            let sig = stored_sig?;
            let signer = stored_signer?;
            let sid = verify_record_sidecar_sig(
                ct,
                uik,
                vault_id,
                item_id_raw,
                "agent",
                version,
                true,
                sig,
                signer,
            )?;
            let owner = body
                .get("owner")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let is_owner = membership.get(&sid).is_some_and(|r| r.is_admin());
            if is_owner || sid == owner {
                Some(body)
            } else {
                None
            }
        }
    }
}

/// Fold one owner-config record (`ns`: a native kind, or a legacy `aux` row).
/// `config_name` is the sidecar record type (the daemon's `storage::item::ItemRule::signature_type`).
/// With a keyset only an owner's sidecar signature counts (A1.2). A native
/// record is sidecar-only: the old in-body wrapper (`{data, uik_sig, ..}`),
/// whose signature is not bound to the record's name, counts only on a legacy
/// `aux:<field>` row ([`unwrap_verified_config`]). Without a keyset an
/// unsigned body is honored; a native body claiming a signature is not.
/// Returns the raw `data` to honor (the daemon then parses it) or `None` to
/// drop.
#[allow(clippy::too_many_arguments)]
pub fn fold_owner_config_record(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    uik: Option<&KeysetUik>,
    vault_id: &str,
    item_id_raw: &[u8],
    is_legacy_aux: bool,
    config_name: &str,
    version: u64,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    let Some(sig) = stored_sig else {
        if !is_legacy_aux {
            return match trust {
                MembershipTrust::NoUik if body.get("uik_sig").is_none() => Some(body),
                _ => None,
            };
        }
        return unwrap_verified_config(body, uik, vault_id, config_name, version, trust);
    };
    let signer = stored_signer?;
    let sid = verify_record_sidecar_sig(
        ct, uik, vault_id, item_id_raw, config_name, version, true, sig, signer,
    )?;
    match trust {
        MembershipTrust::Untrusted => None,
        MembershipTrust::NoUik => Some(body),
        MembershipTrust::Verified(membership) => {
            if membership.get(&sid).is_some_and(|r| r.is_admin()) {
                Some(body)
            } else {
                None
            }
        }
    }
}

/// Whether a grant's signer may approve an op ([`approval_authority`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalAuthority {
    /// The signer is the requester.
    Requester,
    /// The signer is an admin of the vault.
    Admin,
    /// Anyone else; carries the reason.
    Refused(String),
}

/// The three-state trust an owner-config reader derives from the KEYSET's UIK
/// anchor (design/identity-uik-aik.md §4.3, team-shared-vault-security-model.md
/// §9). This REPLACES the old `Option<BTreeMap<..>>` membership signal, which
/// conflated two very different "no owner-set" cases into `None` and so
/// FAIL-OPENED: a v2 keyset whose `creator_sig_pub` a colluding server had
/// STRIPPED looked identical to a legacy v1 vault and silently downgraded to
/// integrity-only, letting a colluding member's signed owner-config be honored.
/// The three states keep those cases distinct:
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipTrust {
    /// Legacy v1 keyset (`keyset.uik == None`) — no UIK layer, never re-keyable.
    /// Owner-config is honored on integrity alone (additive; pre-signing vaults).
    NoUik,
    /// A v2 keyset with a valid 32-byte pinned creator anchor. Owner-config is
    /// gated by this derived owner-set (`user_id → role`); an empty map is fine
    /// (it just means every SIGNED owner-config item drops).
    Verified(BTreeMap<String, MemberRole>),
    /// A v2 keyset that carries credentials but has NO valid creator anchor
    /// (`creator_sig_pub` empty / not 32 bytes). This is the server-strippable
    /// state (`adopt_creator_pin` only pins a non-empty value), so it FAILS
    /// CLOSED: ALL owner-config (signed OR legacy-raw) and ALL agent rows are
    /// dropped → the fields fall to their safe defaults. Never downgrade this to
    /// integrity-only.
    Untrusted,
}

/// C.3 + D — verify AND authorize an owner-config item body (team-shared-vault-
/// security-model.md §9 + §附 role×type: owner-authored config is honored only
/// when signed by an **owner**; the reader/daemon verifying it is "the real
/// wall"). Composes [`verify_config_sig`] (integrity) with role authorization,
/// keyed on the [`MembershipTrust`] state:
///   - [`MembershipTrust::NoUik`] (legacy v1) ⇒ integrity-only: a valid or unsigned
///     body is honored (additive — pre-signing vaults);
///   - [`MembershipTrust::Verified`] (v2, anchor pinned) ⇒ owner-gated: a valid
///     signature is honored only if the signer is an **owner** in the derived
///     owner-set; everything else is DROPPED (an unsigned legacy-raw body, which
///     any K-holding member could have written; a non-owner member; an unknown
///     signer; a bad/forged signature);
///   - [`MembershipTrust::Untrusted`] (v2, anchor stripped) ⇒ FAIL CLOSED: EVERYTHING
///     the owner-config path would otherwise honor is dropped, signed or not, so
///     a colluding member's config is never honored via integrity-only.
/// Dropping falls the field to its safe default (A1.6).
pub fn unwrap_verified_config(
    body: serde_json::Value,
    uik: Option<&KeysetUik>,
    vault_id: &str,
    config_name: &str,
    version: u64,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    match verify_config_sig(body, uik, vault_id, config_name, version) {
        None => None,
        Some((data, signer)) => match trust {
            // Anchor stripped: drop everything the owner-config path would honor.
            MembershipTrust::Untrusted => None,
            // Legacy v1: integrity-only (additive) — signed or unsigned honored.
            MembershipTrust::NoUik => Some(data),
            // Verified v2: honored ONLY when signed by an OWNER in the derived
            // owner-set. An unsigned legacy-raw body is dropped (a K-holding
            // member could have written it).
            MembershipTrust::Verified(membership) => match signer {
                Some(signer_id) if membership.get(&signer_id).is_some_and(|r| r.is_admin()) => {
                    Some(data)
                }
                _ => None,
            },
        },
    }
}

/// Resolve the CURRENT root's Ed25519 signing pubkey AND the current `role_epoch` by
/// walking the [`KeysetUik::root_succession`] chain from the TOFU-pinned GENESIS root
/// (`creator_sig_pub`) (design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md
/// §1.2). The `role_epoch` is DERIVED here (not stored): a pure COMPACTION is a
/// SELF-succession (`old_root == new_root`, same pubkey) that only advances the
/// epoch, so the epoch can never be forged upward without a valid root signature.
///
/// A hop from the current `(root, epoch)` is VALID iff: `old_root_id ==
/// derive_id(current root)` (chains from the current root, so the server can't fork
/// it onto a key it controls), `role_epoch` STRICTLY increases (rollback guard),
/// `new_root_id == derive_id(new_root_sig_pub)` (id/pubkey bound), and the `sig`
/// verifies under the CURRENT root over [`crate::identity::root_succession_input`].
///
/// The walk is ORDER-ROBUST: at each step it SEARCHES the whole chain for a valid
/// extending hop (rather than reading in slice order), so a colluding server cannot
/// block a legitimate successor by reordering / prepending a bogus cert. Among
/// multiple valid extensions of the same root (a root that equivocated), the
/// lowest-`role_epoch` (ties broken by `new_root_id`) is taken for determinism; the
/// loop terminates because each step strictly increases the epoch. An unverifiable
/// succession never advances the root (fail-closed forward), so a forged succession
/// can't install a server-chosen root. Returns `None` iff the genesis anchor itself
/// is absent / not 32 bytes (the server-strippable state → callers fail closed).
pub fn resolve_current_root(uik: &KeysetUik, vault_id: &str) -> Option<([u8; 32], u64)> {
    let mut cur = <[u8; 32]>::try_from(uik.creator_sig_pub.as_slice()).ok()?;
    let mut cur_epoch: u64 = 0;
    loop {
        let cur_id = crate::identity::derive_id(crate::identity::IdKind::User, &cur);
        // Find the lowest-epoch valid hop extending the current root (order-robust +
        // deterministic under equivocation).
        let mut best: Option<(&RootSuccession, [u8; 32])> = None;
        for s in &uik.root_succession {
            if s.old_root_id != cur_id || s.role_epoch <= cur_epoch {
                continue;
            }
            let Ok(new_pub) = <[u8; 32]>::try_from(s.new_root_sig_pub.as_slice()) else {
                continue;
            };
            if s.new_root_id != crate::identity::derive_id(crate::identity::IdKind::User, &new_pub)
            {
                continue; // id/pubkey mismatch
            }
            let Ok(sig) = <[u8; 64]>::try_from(s.sig.as_slice()) else {
                continue;
            };
            let input = crate::identity::root_succession_input(
                vault_id,
                &s.old_root_id,
                &s.new_root_id,
                &new_pub,
                s.role_epoch,
            );
            if !crate::identity::verify(&cur, &input, &sig) {
                continue; // signature by anyone but the current root
            }
            // Prefer the lowest epoch; break ties on new_root_id for determinism.
            let better = match &best {
                None => true,
                Some((b, _)) => {
                    s.role_epoch < b.role_epoch
                        || (s.role_epoch == b.role_epoch && s.new_root_id < b.new_root_id)
                }
            };
            if better {
                best = Some((s, new_pub));
            }
        }
        match best {
            Some((s, new_pub)) => {
                cur = new_pub;
                cur_epoch = s.role_epoch;
            }
            None => return Some((cur, cur_epoch)),
        }
    }
}

/// Verify a keyset's DP-S1 re-key state (team-shared-vault-security-model.md
/// §3.2). A gen-0 keyset (or a v1 vault) is trivially valid. A re-keyed keyset
/// (`generation > 0`) is trusted only if it carries an owner-signed
/// [`RekeyProof`](crate::keyset::RekeyProof) that: matches the generation; commits
/// to the ACTUAL content key in use (anti content-swap by a backend); is signed by a key that is a
/// published keyset member (C.1 anchor) AND an OWNER in the verified owner-set
/// (D); with a valid signature over [`crate::identity::rekey_sig_input`]. A
/// missing or invalid proof on a re-keyed vault ⇒ `false` (the daemon refuses to
/// fold it), which is what stops a backend forging a generation bump (unlock
/// DoS). An [`MembershipTrust::Untrusted`] keyset (v2 anchor stripped) has no
/// confirmable owner, so a re-keyed (`generation > 0`) keyset is likewise refused
/// — a DoS a colluding server can already cause by stripping the anchor, NOT a
/// privilege escalation.
pub fn verify_rekey_proof(
    uik: Option<&KeysetUik>,
    trust: &MembershipTrust,
    vault_id: &str,
    content_key: &[u8],
) -> bool {
    let Some(uik) = uik else {
        return true; // v1 / no UIK layer — not re-keyable
    };
    if uik.generation == 0 {
        return true; // never re-keyed
    }
    // A re-key must be authorized by an OWNER, so a confirmed owner-set is
    // required. `uik` is present here, so `trust` is Verified or Untrusted;
    // Untrusted (anchor stripped) ⇒ no confirmable owner ⇒ refuse the bump.
    let MembershipTrust::Verified(_) = trust else {
        return false;
    };
    let Some(proof) = uik.rekey_proof.as_ref() else {
        return false; // gen > 0 with no proof = a forged bump
    };
    if proof.generation != uik.generation {
        return false;
    }
    // The signature must commit to the content key actually delivered (a backend
    // can't pair a valid signed generation with a content key it chose).
    if proof.k_commitment.as_slice() != rekey_commitment(content_key).as_slice() {
        return false;
    }
    // The signer must have been an ADMIN when it signed (D): in the fold of the log
    // prefix the proof commits, which `trust` being Verified has just checked against
    // the served log. Not today's roles: an admin who re-keyed and was later demoted
    // still signed with authority, and the vault must stay readable. (`is_admin`, not
    // a pattern: a legacy `"owner"` grant reads as `LegacyOwner`, also an admin.)
    let admin = fold_roles_of(uik, vault_id, Some(prefix_len(proof.membership_len)))
        .get(&proof.signer_id)
        .is_some_and(|r| r.is_admin());
    if !admin {
        return false;
    }
    // Signed under a PUBLISHED member key whose id matches the claimed signer
    // (C.1 anchor) — a backend-minted key isn't in the keyset.
    proof.signature_valid(uik, vault_id)
}

/// The role fold of `uik` (the daemon's `PerItemVault::fold_roles`): the checkpoint under the
/// current root, then the delegation log in `(seq, sig)` order. `limit`: fold only the
/// first `limit` events of that order, which is the prefix a re-key proof commits
/// (`membership_len`, [`membership_prefix_ok`]), so a proof's signer is judged by the
/// roles at the time it signed (issuance-time authority, as for log events).
pub fn fold_roles_of(
    uik: &KeysetUik,
    vault_id: &str,
    limit: Option<usize>,
) -> BTreeMap<String, MemberRole> {
    let mut map: BTreeMap<String, MemberRole> = BTreeMap::new();
    let Some((root_pub, role_epoch)) = resolve_current_root(uik, vault_id) else {
        return map; // no resolvable root → no confirmable owner
    };
    let root_id = crate::identity::derive_id(crate::identity::IdKind::User, &root_pub);
    // Genesis: the current root is an owner (TOFU-pinned anchor + succession).
    map.insert(root_id.clone(), MemberRole::Admin);
    // Checkpoint: root-signed grants @ the current (succession-derived) role_epoch
    // (depth-1 → a fresh daemon verifies with no history).
    for cred in uik.creds.values() {
        // The root's ownership is the genesis pin — a checkpoint grant must NEVER
        // overwrite/demote it (defense in depth for "the owner-set always contains
        // the root as Owner").
        if cred.user_id == root_id {
            continue;
        }
        // Self-certifying: the cred's `user_id` label MUST derive from its
        // `sig_pub`, so a spoofed `(user_id, sig_pub)` pair can't seat a phantom
        // owner keyed on a label the server chose.
        let Ok(cred_pub) = <[u8; 32]>::try_from(cred.sig_pub.as_slice()) else {
            continue;
        };
        if crate::identity::derive_id(crate::identity::IdKind::User, &cred_pub) != cred.user_id {
            continue;
        }
        let Ok(sig) = <[u8; 64]>::try_from(cred.role_sig.as_slice()) else {
            continue; // no / malformed grant → not in the checkpoint
        };
        // A legacy admin grant was signed over `"owner"`, a new one over
        // `"admin"`: either spelling of the cred's OWN role verifies it.
        let granted = role_sig_tokens(cred.role).iter().any(|tok| {
            let input = crate::identity::role_grant_input(vault_id, &cred.user_id, tok, role_epoch);
            crate::identity::verify(&root_pub, &input, &sig)
        });
        if granted {
            map.insert(cred.user_id.clone(), cred.role);
        }
    }
    // Delegation log: apply in a DETERMINISTIC total order; only events on the
    // current role_epoch (a pre-compaction replay carries an older epoch → ignored).
    let mut events: Vec<&DelegationEvent> = uik
        .delegation_log
        .iter()
        .filter(|e| e.role_epoch == role_epoch)
        .collect();
    // Sort by (seq, sig) — NOT seq alone: a stable sort by seq leaves same-seq
    // order at the mercy of storage/Vec order, which the server controls, so the
    // three implementations (daemon / backend / browser) could pick different
    // same-seq winners. Breaking the tie on the signature bytes makes the winner
    // deterministic and server-independent.
    events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
    if let Some(n) = limit {
        events.truncate(n);
    }
    let mut last_seq: Option<u64> = None;
    for e in events {
        if matches!(last_seq, Some(ls) if e.seq <= ls) {
            continue; // a seq already CONSUMED by a validated event
        }
        // Issuance-time authority: the granter must be an Owner in the fold SO FAR.
        // A junk / non-owner event must NOT consume the seq slot (else it could
        // suppress a legitimate same-seq event — the dup guard would then drop the
        // real one), so `last_seq` advances ONLY AFTER full validation below.
        if !map.get(&e.granter_id).is_some_and(|r| r.is_admin()) {
            continue;
        }
        // The granter's verifying key rides INLINE and is SELF-CERTIFYING: it must
        // derive to `granter_id`. This makes the event immune to a poisoned cred row
        // (which lies about `sig_pub`) AND keeps it verifiable after the granter's
        // own cred row is deleted at offboard (so NON-CASCADE survives eviction).
        let Ok(granter_pub) = <[u8; 32]>::try_from(e.granter_sig_pub.as_slice()) else {
            continue;
        };
        if crate::identity::derive_id(crate::identity::IdKind::User, &granter_pub) != e.granter_id {
            continue;
        }
        if !e.signature_verifies(vault_id, &granter_pub) {
            continue;
        }
        // VALIDATED (owner + self-certifying key + signature): now consume the seq
        // slot, so a later same-seq event is a dup (equivocation) and is dropped.
        last_seq = Some(e.seq);
        // The creator (root) is seated at the base for ISSUANCE-TIME authority (so
        // grants they signed verify), but is a NORMAL owner in the FINAL set: any
        // owner (incl. the creator themselves) can be removed/demoted via the log
        // (creator-offboard is just a `remove`). The ONLY invariant is the
        // owner-set is never EMPTIED — a remove/demote that would drop the LAST
        // owner is ignored (last-owner guard; also enforced at write time in the
        // console). This replaces the old "root is permanently immune" rule.
        let admin_count =
            |m: &BTreeMap<String, MemberRole>| m.values().filter(|r| r.is_admin()).count();
        match e.op.as_str() {
            "remove" => {
                if map.get(&e.subject_id).is_some_and(|r| r.is_admin()) && admin_count(&map) <= 1 {
                    continue; // last-admin guard: never empty the admin set
                }
                map.remove(&e.subject_id); // NON-CASCADE: only the subject
            }
            "set" => {
                // A demote (admin → member) of the last admin would empty it → skip.
                if !e.role.is_admin()
                    && map.get(&e.subject_id).is_some_and(|r| r.is_admin())
                    && admin_count(&map) <= 1
                {
                    continue;
                }
                map.insert(e.subject_id.clone(), e.role);
            }
            _ => {} // unknown op → ignore
        }
    }
    map
}

/// A re-key proof's committed log length (`membership_len`) as a count of
/// events. Saturates where `usize` is narrower than `u64` (wasm32), so a 32-bit
/// build reaches the 64-bit daemon's verdict: no log holds that many events.
pub(crate) fn prefix_len(membership_len: u64) -> usize {
    usize::try_from(membership_len).unwrap_or(usize::MAX)
}

/// Membership anti-rollback check (delegation-log-review-findings.md C2): the current
/// re-key proof committed a delegation-log PREFIX (`membership_len` events at the current
/// role-epoch, in `(seq, sig)` order, hashed to `membership_hash`). Recompute that
/// commitment over the SERVED log's prefix and compare — a mismatch means the server
/// rolled the log back (e.g. omitted a `remove`) or altered it, so the owner-set
/// can't be trusted. A proof with `membership_len == 0` (empty prefix) commits nothing
/// beyond "the log was empty at re-key". Returns `true` (no rollback detected) when
/// there is no proof. Because the daemon ratchets `generation` (won't adopt a lower
/// one) and this binds the log to that generation, a server can't serve the CURRENT
/// generation with a rolled-back log.
pub fn membership_prefix_ok(uik: &KeysetUik, vault_id: &str) -> bool {
    let Some(proof) = uik.rekey_proof.as_ref() else {
        return true; // no re-key → nothing committed to roll back
    };
    if proof.generation == 0 {
        return true;
    }
    let role_epoch = resolve_current_root(uik, vault_id)
        .map(|(_, e)| e)
        .unwrap_or(0);
    let mut events: Vec<&DelegationEvent> = uik
        .delegation_log
        .iter()
        .filter(|e| e.role_epoch == role_epoch)
        .collect();
    events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
    let n = prefix_len(proof.membership_len);
    if events.len() < n {
        return false; // the server dropped committed events
    }
    let prefix_sigs: Vec<&[u8]> = events.iter().take(n).map(|e| e.sig.as_slice()).collect();
    crate::identity::membership_commitment(&prefix_sigs).as_slice() == proof.membership_hash.as_slice()
}

/// Whether an owner-config TOMBSTONE counts as honored, by the same trust
/// rules as a live record ([`fold_owner_config_record`]): without a keyset an
/// unsigned one; with one, only an owner's sidecar signature over the
/// tombstone (`status_live = false`).
#[allow(clippy::too_many_arguments)]
pub fn owner_config_tombstone_honored(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    uik: Option<&KeysetUik>,
    vault_id: &str,
    item_id_raw: &[u8],
    record_type: &str,
    version: u64,
    trust: &MembershipTrust,
) -> bool {
    match trust {
        MembershipTrust::Untrusted => false,
        MembershipTrust::NoUik => stored_sig.is_none(),
        MembershipTrust::Verified(membership) => {
            let (Some(sig), Some(signer)) = (stored_sig, stored_signer) else {
                return false;
            };
            verify_record_sidecar_sig(
                ct,
                uik,
                vault_id,
                item_id_raw,
                record_type,
                version,
                false,
                sig,
                signer,
            )
            .is_some_and(|sid| membership.get(&sid).is_some_and(|r| r.is_admin()))
        }
    }
}

/// How an owner-config row reads under `trust`: a tombstone by
/// [`owner_config_tombstone_honored`], a live body by
/// [`fold_owner_config_record`]. `None` = not honored; `Some(None)` = an
/// honored tombstone; `Some(Some(data))` = honored live data. `is_legacy_aux`
/// (the record's ns is a legacy `aux` row) and `record_type` are those of the
/// opened record; `stored_sig`, `stored_signer`, `ct` and `version` are the
/// stored row's.
#[allow(clippy::too_many_arguments)]
pub fn honored_owner_config(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    version: u64,
    uik: Option<&KeysetUik>,
    vault_id: &str,
    item_id_raw: &[u8],
    is_legacy_aux: bool,
    record_type: &str,
    tombstone: bool,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<Option<serde_json::Value>> {
    if tombstone {
        return owner_config_tombstone_honored(
            stored_sig,
            stored_signer,
            ct,
            uik,
            vault_id,
            item_id_raw,
            record_type,
            version,
            trust,
        )
        .then_some(None);
    }
    fold_owner_config_record(
        stored_sig,
        stored_signer,
        ct,
        uik,
        vault_id,
        item_id_raw,
        is_legacy_aux,
        record_type,
        version,
        body,
        trust,
    )
    .map(Some)
}

/// Resolve the KEYSET's [`MembershipTrust`] — the owner-authority anchor state
/// (design/identity-uik-aik.md §4.3 RESOLVED). This REPLACES the old in-vault
/// `resolve_verified_membership`, which trusted a membership by single-version
/// self-consistency and so let any member self-sign `{me: owner}` and
/// self-promote (finding #1). Role is now rooted at genesis, and the return
/// distinguishes the three trust states so a missing anchor can NEVER
/// fail-open to integrity-only on a v2 keyset:
///
/// - `uik == None` ⇒ [`MembershipTrust::NoUik`] (legacy v1 — integrity-only,
///   single-person vaults with no member keys to sign anything).
/// - `uik` present but `creator_sig_pub` is NOT a valid 32-byte key AND the
///   keyset already carries credentials ⇒ [`MembershipTrust::Untrusted`]. This is
///   the server-strippable state (`adopt_creator_pin` only pins non-empty), so
///   it FAILS CLOSED — callers drop ALL owner-config, not just unsigned.
/// - `uik` present with a valid 32-byte `creator_pub` ⇒ [`MembershipTrust::Verified`]:
///   for each keyset cred, verify its `role_sig` over
///   [`crate::identity::role_grant_input`]`(vault_id, user_id, role, generation)`
///   under `creator_pub` at the CURRENT `uik.generation` (F3-b generation-
///   binding: the grant is bound to the owner-signed DP-S1 role epoch, so a
///   stale grant signed at an OLD generation fails here after a re-key bump and
///   the cred drops from the owner-set — a colluding server can't replay a
///   demoted/offboarded person's grant). A cred that verifies is inserted at its
///   `role`; one that fails (empty/forged sig, a role the creator never signed,
///   or a grant signed at a different generation) is dropped — it is NOT an
///   owner. The creator's OWN cred is included by the SAME rule
///   (its role=Owner, self-signed under `creator_pub`); no special case. An
///   empty owner-set is a valid `Verified` result (all signed owner-config
///   drops). A `uik` with no anchor AND no creds yet is a fresh bootstrap with
///   nothing to authorize — `Verified(∅)` (every owner-config and agent row drops).
pub fn resolve_membership_trust(uik: Option<&KeysetUik>, vault_id: &str) -> MembershipTrust {
    let Some(uik) = uik else {
        return MembershipTrust::NoUik; // legacy v1 — integrity-only (additive)
    };
    // Resolve the CURRENT root by walking the succession chain from the pinned
    // GENESIS anchor. `None` = the genesis anchor is absent / not 32 bytes: a v2
    // keyset that already carries creds but has NO resolvable root is the
    // server-strippable state → FAIL CLOSED (`Untrusted`); an anchor-less keyset
    // with NO creds is a fresh bootstrap: nothing to authorize → empty Verified
    // set (every owner-config / agent row drops, signed or not).
    if resolve_current_root(uik, vault_id).is_none() {
        return if uik.creds.is_empty() {
            MembershipTrust::Verified(BTreeMap::new())
        } else {
            MembershipTrust::Untrusted
        };
    }
    // Membership anti-rollback (C2): the current re-key proof committed the
    // delegation-log prefix — if the SERVED log doesn't match it, the server
    // rolled the membership back (e.g. omitted a `remove`); the owner-set can't be
    // trusted → FAIL CLOSED. (Owner-signed + generation-ratcheted, so the server
    // can't forge a fresh commitment or serve the current generation with a
    // tampered log.)
    if !membership_prefix_ok(uik, vault_id) {
        return MembershipTrust::Untrusted;
    }
    MembershipTrust::Verified(fold_roles_of(uik, vault_id, None))
}

/// May `signer` (the approver's `us_…`, already proven by a verified grant v3
/// `id_sig`) approve an op that `requester` (the account whose daemon raised
/// it) is waiting on? The requester always may. Anyone else must be an ADMIN
/// of the vault per the current, VERIFIED role fold; a v1 keyset (a personal
/// vault) has no fold, so only the requester approves there. An untrusted
/// fold (no confirmable admin) still lets the requester approve their own op.
pub fn approval_authority(
    uik: Option<&KeysetUik>,
    vault_id: &str,
    requester: &std::collections::BTreeSet<String>,
    signer: &str,
) -> ApprovalAuthority {
    if requester.contains(signer) {
        return ApprovalAuthority::Requester;
    }
    match resolve_membership_trust(uik, vault_id) {
        MembershipTrust::Verified(roles)
            if roles.get(signer).is_some_and(|r| r.is_admin()) =>
        {
            ApprovalAuthority::Admin
        }
        _ => ApprovalAuthority::Refused(format!(
            "{} is neither the requester nor an admin of this vault; \
             only the requester or a vault admin can approve this request",
            signer
        )),
    }
}
