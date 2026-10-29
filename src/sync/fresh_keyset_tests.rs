//! A daemon with no prior state and `sprott_trust::adopt::fresh_keyset` adopt
//! the same keyset from the same served membership: the daemon's real adopt
//! (`adopt_pulled_membership`, `adopt_pulled_key_rows`, into an empty state
//! dir) against the crate's, on triples and `/keys` rows (re-keyed, delegated,
//! root succession, approver credentials, decode errors). The console folds
//! with the crate's, as wasm.
//!
//! The cases also make the wasm crate's fixtures
//! (`crates/sprott-trust-wasm/fixtures/cases.json`): inputs to its JSON API
//! and the verdicts expected, the fold's from this daemon's adopt and its
//! `fold_view`. The test fails when the file differs; `SPROTT_TRUST_FIXTURES=write`
//! rewrites it.

use super::*;
use crate::crypto::vault_key::UikRoot;
use crate::identity::IdKind;
use crate::storage::item::VaultKeys;
use crate::storage::sealed_vault::PerItemVault;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use sprott_trust::adopt::{fresh_keyset, Served};
use sprott_trust::trust as rules;
use sprott_trust::{ApprovalAuthority, DelegationEvent, KeysetUik, MemberRole, MembershipTrust};
use sudp::primitives::StdPrimitives;

const VAULT: &str = "v-fresh-keyset";
/// The content key the re-key proofs commit to, and one they do not.
const K1: [u8; 32] = [0x4b; 32];
const K2: [u8; 32] = [0x4c; 32];

fn enc(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn person(seed: u8) -> UikRoot {
    UikRoot::from_root([seed; 32])
}

fn pub_of(p: &UikRoot) -> [u8; 32] {
    p.signing().public_bytes()
}

/// `signer`'s checkpoint grant of `role` to `subject` at `epoch`.
fn grant(signer: &UikRoot, subject: &str, role: &str, epoch: u64) -> Vec<u8> {
    signer
        .signing()
        .sign(&crate::identity::role_grant_input(
            VAULT, subject, role, epoch,
        ))
        .to_vec()
}

/// A delegation event signed by `granter` (`remove` signs an empty role).
fn event(
    granter: &UikRoot,
    op: &str,
    subject: &str,
    role: MemberRole,
    seq: u64,
    epoch: u64,
) -> DelegationEvent {
    let tok = if op == "remove" {
        ""
    } else {
        sprott_trust::role_sig_tokens(role)[0]
    };
    let gid = granter.user_id();
    let sig = granter
        .signing()
        .sign(&crate::identity::delegation_event_input(
            VAULT, op, subject, tok, &gid, seq, epoch,
        ))
        .to_vec();
    DelegationEvent {
        op: op.into(),
        subject_id: subject.into(),
        role,
        granter_id: gid,
        granter_sig_pub: pub_of(granter).to_vec(),
        seq,
        role_epoch: epoch,
        sig,
    }
}

fn log(events: &[&DelegationEvent]) -> Value {
    serde_json::to_value(events).unwrap()
}

/// `old` hands the root to `new` at `epoch` (a compaction when both are the
/// same), as served.
fn succession(old: &UikRoot, new: &UikRoot, epoch: u64) -> Value {
    let (old_id, new_id) = (old.user_id(), new.user_id());
    let sig = old
        .signing()
        .sign(&crate::identity::root_succession_input(
            VAULT,
            &old_id,
            &new_id,
            &pub_of(new),
            epoch,
        ));
    json!({
        "old_root_id": old_id,
        "new_root_id": new_id,
        "new_root_sig_pub": enc(&pub_of(new)),
        "role_epoch": epoch,
        "sig": enc(&sig),
    })
}

/// `signer`'s re-key proof for `generation` to content key `k`, committing
/// the delegation-log prefix `prefix` (in seq order).
fn rekey_proof(signer: &UikRoot, generation: u64, k: &[u8], prefix: &[&DelegationEvent]) -> Value {
    let commit = sprott_trust::rekey_commitment(k);
    let sigs: Vec<&[u8]> = prefix.iter().map(|e| e.sig.as_slice()).collect();
    let hash = crate::identity::membership_commitment(&sigs);
    let id = signer.user_id();
    let sig = signer.signing().sign(&crate::identity::rekey_sig_input(
        VAULT,
        generation,
        &commit,
        &id,
        prefix.len() as u64,
        &hash,
    ));
    json!({
        "generation": generation,
        "k_commitment": enc(&commit),
        "sig": enc(&sig),
        "signer_id": id,
        "membership_len": prefix.len(),
        "membership_hash": enc(&hash),
    })
}

/// A served membership triple: `creator`'s anchor, the members `(person,
/// role token, role_sig)`, this device's own credential (the creator's), and
/// `proof`.
fn triple(creator: &UikRoot, members: &[(&UikRoot, &str, Option<Vec<u8>>)], proof: Value) -> Value {
    let mut ms = serde_json::Map::new();
    let mut ids = serde_json::Map::new();
    for (who, role, sig) in members {
        let mut m = json!({ "role": role, "k_encapped": enc(&[1; 32]), "k_ct": enc(&[2; 48]) });
        if let Some(s) = sig {
            m["role_sig"] = json!(enc(s));
        }
        ms.insert(who.user_id(), m);
        ids.insert(
            who.user_id(),
            json!({ "sig_pub": enc(&pub_of(who)), "enc_pub": enc(&[9; 32]) }),
        );
    }
    json!({
        "anchor": enc(&pub_of(creator)),
        "members": ms,
        "identities": ids,
        "credentials": [{
            "cid": URL_SAFE_NO_PAD.encode(b"own-credential"),
            "identity_id": creator.user_id(),
            "x": "eA", "y": "eQ", "device_name": "Mac",
        }],
        "proof": proof,
        "keyset_seq": 5,
    })
}

/// A format-1 `/keys` row of `who` (a UIK seat when `role` is given).
fn key_row(cid: &[u8], version: u64, who: &UikRoot, role: Option<(&str, Option<Vec<u8>>)>) -> Value {
    let mut data = json!({
        "x": enc(&[0xaa; 32]), "y": enc(&[0xbb; 32]), "device_name": "Dev",
        "prf_salt": enc(&[3; 32]), "wrapped_key": enc(&[4; 48]),
    });
    if let Some((role, sig)) = role {
        data["uik_user_id"] = json!(who.user_id());
        data["uik_sig_pub"] = json!(enc(&pub_of(who)));
        data["uik_enc_pub"] = json!(enc(&[9; 32]));
        data["uik_k_encapped"] = json!(enc(&[1; 32]));
        data["uik_k_ct"] = json!(enc(&[2; 48]));
        data["uik_role"] = json!(role);
        if let Some(s) = sig {
            data["uik_role_sig"] = json!(enc(&s));
        }
    }
    json!({ "cid": URL_SAFE_NO_PAD.encode(cid), "version": version, "seq": version, "data": data })
}

#[derive(Clone)]
enum Wire {
    Triple(Value),
    Rows(Value),
}

impl Wire {
    fn fold_input(&self, require_signed: bool) -> Value {
        match self {
            Wire::Triple(t) => {
                json!({ "vault_id": VAULT, "triple": t, "require_signed": require_signed })
            }
            Wire::Rows(r) => {
                json!({ "vault_id": VAULT, "rows": r, "require_signed": require_signed })
            }
        }
    }
}

fn parse_rows(rows: &Value) -> Result<Vec<KeyRow>, String> {
    serde_json::from_value(rows.clone()).map_err(|e| format!("parse keys array: {}", e))
}

/// The store a daemon with an empty state dir holds after its real adopt of
/// `wire`, or the adopt's error (it then stores nothing).
fn daemon_adopt(wire: &Wire) -> Result<PerItemVault, String> {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let out = rt.block_on(async {
        match wire {
            Wire::Triple(body) => {
                adopt_pulled_membership(dir.path(), VAULT, StoreLock::Boot, body).await
            }
            Wire::Rows(rows) => {
                let rows = parse_rows(rows)?;
                adopt_pulled_key_rows(dir.path(), VAULT, StoreLock::Boot, &rows, Some(1)).await
            }
        }
    });
    let stored = read_per_item_store(dir.path(), VAULT);
    match out {
        Ok(_) => Ok(stored.expect("an adopt stores the keyset")),
        Err(e) => {
            assert!(stored.is_none(), "a failed adopt stores nothing");
            Err(e)
        }
    }
}

fn fresh(wire: &Wire) -> Result<Option<KeysetUik>, String> {
    match wire {
        Wire::Triple(body) => fresh_keyset(VAULT, Served::Membership(body)),
        Wire::Rows(rows) => fresh_keyset(VAULT, Served::KeyRows(&parse_rows(rows)?)),
    }
}

/// The trust the console acts on, from this daemon's adopt.
fn console_trust(daemon: &Result<PerItemVault, String>, require_signed: bool) -> MembershipTrust {
    match daemon {
        Err(_) => MembershipTrust::Untrusted,
        Ok(pv) => match rules::resolve_membership_trust(pv.keyset.uik.as_ref(), VAULT) {
            MembershipTrust::NoUik if require_signed => MembershipTrust::Untrusted,
            t => t,
        },
    }
}

/// The `fold` output for this daemon's adopt; `rekey_ok` is whether its
/// `fold_view` opens the vault under content key `k`.
fn expected_fold(daemon: &Result<PerItemVault, String>, require_signed: bool, k: Option<&[u8]>) -> Value {
    let uik = daemon.as_ref().ok().and_then(|pv| pv.keyset.uik.as_ref());
    let (state, admins, members): (&str, Vec<String>, Vec<String>) =
        match console_trust(daemon, require_signed) {
            MembershipTrust::NoUik => ("no_uik", vec![], vec![]),
            MembershipTrust::Untrusted => ("untrusted", vec![], vec![]),
            MembershipTrust::Verified(roles) => (
                "verified",
                roles
                    .iter()
                    .filter(|(_, r)| r.is_admin())
                    .map(|(id, _)| id.clone())
                    .collect(),
                roles.keys().cloned().collect(),
            ),
        };
    let root = uik.and_then(|u| rules::resolve_current_root(u, VAULT));
    let mut out = json!({
        "state": state,
        "trusted": state != "untrusted",
        "admins": admins,
        "members": members,
        "role_epoch": root.map_or(0, |(_, e)| e),
        "root_id": root.map_or(String::new(), |(p, _)| crate::identity::derive_id(IdKind::User, &p)),
        "root_pub_b64": root.map(|(p, _)| enc(&p)),
        "generation": uik.map_or(0, |u| u.generation),
    });
    if let Some(k) = k {
        out["rekey_ok"] = json!(match daemon {
            Err(_) => false,
            Ok(pv) => pv
                .fold_view::<StdPrimitives>(VaultKeys::single(k), VAULT)
                .is_ok(),
        });
    }
    if let Err(e) = daemon {
        out["adopt_error"] = json!(e);
    }
    out
}

struct Scenario {
    name: &'static str,
    wire: Wire,
}

/// The people of the cases: the creator, admins by delegation, a member, and
/// someone outside the vault.
struct Cast {
    c: UikRoot,
    a: UikRoot,
    b: UikRoot,
    m: UikRoot,
    x: UikRoot,
}

fn cast() -> Cast {
    Cast {
        c: person(0x11),
        a: person(0x33),
        b: person(0x44),
        m: person(0x55),
        x: person(0x66),
    }
}

fn scenarios(p: &Cast) -> Vec<Scenario> {
    let (c, a, b, m, x) = (&p.c, &p.a, &p.b, &p.m, &p.x);
    let (cid, aid, bid, mid) = (c.user_id(), a.user_id(), b.user_id(), m.user_id());
    let c_admin = || (c, "admin", Some(grant(c, &cid, "admin", 0)));
    let m_member = || (m, "member", Some(grant(c, &mid, "member", 0)));
    let gen0 = json!({ "generation": 0 });
    let mut out = Vec::new();
    let mut add = |name: &'static str, wire: Wire| out.push(Scenario { name, wire });

    // The creator makes A an admin; A, a non-root admin, makes B one.
    let e_ca = event(c, "set", &aid, MemberRole::Admin, 1, 0);
    let e_ab = event(a, "set", &bid, MemberRole::Admin, 2, 0);
    add(
        "triple_delegated",
        Wire::Triple(triple(
            c,
            &[c_admin(), (a, "member", None), (b, "member", None), m_member()],
            json!({ "delegation_log": log(&[&e_ca, &e_ab]), "succession": [], "generation": 0 }),
        )),
    );
    // Re-keyed to generation 1 by the creator, committing K1.
    add(
        "triple_rekeyed",
        Wire::Triple(triple(
            c,
            &[c_admin(), m_member()],
            json!({ "generation": 1, "rekey_proof": rekey_proof(c, 1, &K1, &[]) }),
        )),
    );
    // A generation bump with no proof is not taken.
    add(
        "triple_rekey_unproven",
        Wire::Triple(triple(c, &[c_admin(), m_member()], json!({ "generation": 7 }))),
    );
    // A member's proof is not taken.
    add(
        "triple_rekey_by_member",
        Wire::Triple(triple(
            c,
            &[c_admin(), m_member()],
            json!({ "generation": 2, "rekey_proof": rekey_proof(m, 2, &K1, &[]) }),
        )),
    );
    // A re-keys as an admin, and is demoted afterwards: the proof still holds.
    let e_ca_member = event(c, "set", &aid, MemberRole::Member, 2, 0);
    add(
        "triple_rekey_signer_demoted",
        Wire::Triple(triple(
            c,
            &[c_admin(), (a, "member", None)],
            json!({
                "delegation_log": log(&[&e_ca, &e_ca_member]),
                "generation": 1,
                "rekey_proof": rekey_proof(a, 1, &K1, &[&e_ca]),
            }),
        )),
    );
    // The creator hands the root to B at epoch 1; B re-signs the checkpoint.
    add(
        "triple_succession",
        Wire::Triple(triple(
            c,
            &[
                (c, "member", Some(grant(b, &cid, "member", 1))),
                (b, "admin", Some(grant(b, &bid, "admin", 1))),
                (m, "admin", Some(grant(b, &mid, "admin", 1))),
            ],
            json!({ "succession": [succession(c, b, 1)], "generation": 0 }),
        )),
    );
    // A compaction to epoch 1 that does not re-sign M's admin grant drops it.
    add(
        "triple_compaction",
        Wire::Triple(triple(
            c,
            &[c_admin(), (m, "admin", Some(grant(c, &mid, "admin", 0)))],
            json!({ "succession": [succession(c, c, 1)], "generation": 0 }),
        )),
    );
    // Another member's passkeys served for approvals: one adopted, one with no
    // pubkey, one whose cid does not decode (skipped, the adopt goes on).
    let mut t = triple(c, &[c_admin(), m_member()], gen0.clone());
    let creds = t["credentials"].as_array_mut().unwrap();
    creds.push(json!({ "cid": URL_SAFE_NO_PAD.encode(b"admin-key"), "identity_id": cid, "x": "ax", "y": "ay", "approver": true }));
    creds.push(json!({ "cid": "YmFk", "identity_id": cid, "approver": true }));
    creds.push(json!({ "cid": "a+b/", "identity_id": cid, "x": "bx", "y": "by", "approver": true }));
    add("triple_approvers", Wire::Triple(t));
    // The device's own credential id does not decode: the adopt fails.
    let mut t = triple(c, &[c_admin(), m_member()], gen0.clone());
    t["credentials"][0]["cid"] = json!("own+credential");
    add("triple_bad_own_cid", Wire::Triple(t));
    // A member's sealed key is not base64: the adopt fails.
    let mut t = triple(c, &[c_admin(), m_member()], gen0.clone());
    t["members"][mid.as_str()]["k_ct"] = json!("not base64!");
    add("triple_bad_member_field", Wire::Triple(t));
    // No anchor: nothing is adopted.
    let mut t = triple(c, &[c_admin(), m_member()], gen0.clone());
    t["anchor"] = Value::Null;
    add("triple_no_anchor", Wire::Triple(t));
    // An anchor that is not a key: untrusted.
    let mut t = triple(c, &[c_admin(), m_member()], gen0.clone());
    t["anchor"] = json!(enc(&[7; 16]));
    add("triple_short_anchor", Wire::Triple(t));
    // The proof commits two events, the log served holds one: untrusted.
    let e_c_remove_a = event(c, "remove", &aid, MemberRole::Member, 2, 0);
    add(
        "triple_prefix_rollback",
        Wire::Triple(triple(
            c,
            &[c_admin(), (a, "member", None)],
            json!({
                "delegation_log": log(&[&e_ca]),
                "generation": 1,
                "rekey_proof": rekey_proof(c, 1, &K1, &[&e_ca, &e_c_remove_a]),
            }),
        )),
    );
    // An unknown role token reads as member.
    add(
        "triple_unknown_role",
        Wire::Triple(triple(
            c,
            &[c_admin(), (m, "superuser", Some(grant(c, &mid, "member", 0)))],
            gen0.clone(),
        )),
    );
    // A delegation log that does not parse: the adopt fails.
    add(
        "triple_bad_delegation_log",
        Wire::Triple(triple(
            c,
            &[c_admin(), m_member()],
            json!({ "delegation_log": "not a log", "generation": 0 }),
        )),
    );
    // An anchor with no members pins the anchor and adopts nothing more.
    let mut t = triple(
        c,
        &[c_admin()],
        json!({ "generation": 1, "rekey_proof": rekey_proof(c, 1, &K1, &[]) }),
    );
    t.as_object_mut().unwrap().remove("members");
    add("triple_no_members", Wire::Triple(t));

    // Rows: a legacy personal vault.
    add(
        "rows_v1",
        Wire::Rows(json!([key_row(b"c-cred", 1, c, None)])),
    );
    // Rows of a re-keyed vault, carrying the log; C's row at an older version
    // comes last, and a repeat of C's row at the same version (whose
    // `prf_salt` does not decode) is skipped, its log still unioned.
    let e_cm = event(c, "set", &mid, MemberRole::Admin, 1, 0);
    let e_cx = event(c, "set", &x.user_id(), MemberRole::Member, 2, 0);
    let proof = rekey_proof(c, 2, &K1, &[&e_cm]);
    let mut c_row = key_row(b"c-cred", 2, c, Some(("admin", Some(grant(c, &cid, "admin", 0)))));
    let mut m_row = key_row(b"m-cred", 1, m, Some(("member", Some(grant(c, &mid, "member", 0)))));
    for row in [&mut c_row, &mut m_row] {
        row["data"]["uik_creator_sig_pub"] = json!(enc(&pub_of(c)));
        row["data"]["uik_generation"] = json!(2);
        row["data"]["uik_rekey_proof"] = proof.clone();
        row["data"]["uik_delegation_log"] = log(&[&e_cm]);
    }
    let mut repeat = c_row.clone();
    repeat["data"]["prf_salt"] = json!("!!");
    repeat["data"]["uik_delegation_log"] = log(&[&e_cm, &e_cx]);
    let old_c = key_row(b"c-cred", 1, c, Some(("member", None)));
    add(
        "rows_rekeyed",
        Wire::Rows(json!([c_row, m_row, repeat, old_c])),
    );
    let mut bad = key_row(b"c-cred", 1, c, None);
    bad["data"]["prf_salt"] = json!("!!");
    add("rows_bad_prf_salt", Wire::Rows(json!([bad])));
    let mut bad = key_row(b"c-cred", 1, c, None);
    bad["cid"] = json!("a+b");
    add("rows_bad_cid", Wire::Rows(json!([bad])));
    let mut bad = key_row(b"c-cred", 1, c, None);
    bad["data"]["wc_check"] = json!("@@");
    add("rows_bad_wc_check", Wire::Rows(json!([bad])));
    let mut bad = key_row(b"c-cred", 1, c, None);
    bad.as_object_mut().unwrap().remove("seq");
    add("rows_missing_seq", Wire::Rows(json!([bad])));
    out
}

/// A row signature by `signer` over `ct` (the sidecar the honoring rules read).
fn sidecar(signer: &UikRoot, record_type: &str, item_id: &[u8], version: u64, ct: &[u8], live: bool) -> String {
    enc(&signer
        .signing()
        .sign(&crate::identity::record_signature_input(
            record_type,
            item_id,
            version,
            VAULT,
            ct,
            live,
            &signer.user_id(),
        )))
}

fn with(base: &Value, extra: Value) -> Value {
    let mut v = base.clone();
    for (k, x) in extra.as_object().unwrap() {
        v[k.as_str()] = x.clone();
    }
    v
}

fn case(name: &str, call: &str, input: Value, expected: Value) -> Value {
    json!({ "name": name, "call": call, "input": input, "expected": expected })
}

#[test]
fn fresh_keyset_matches_a_fresh_daemon_adopt() {
    let p = cast();
    let (cid, aid, bid, mid) = (p.c.user_id(), p.a.user_id(), p.b.user_id(), p.m.user_id());
    let sorted = |ids: &[&String]| {
        let mut v: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        v.sort();
        json!(v)
    };
    let mut cases: Vec<Value> = Vec::new();
    let mut adopted: std::collections::BTreeMap<&str, (Wire, Result<PerItemVault, String>)> =
        Default::default();

    for s in scenarios(&p) {
        let daemon = daemon_adopt(&s.wire);
        let crate_side = fresh(&s.wire);
        match (&daemon, &crate_side) {
            (Ok(pv), Ok(uik)) => assert_eq!(
                serde_json::to_value(&pv.keyset.uik).unwrap(),
                serde_json::to_value(uik).unwrap(),
                "{}: the same keyset",
                s.name
            ),
            (Err(d), Err(c)) => assert_eq!(d, c, "{}: the same adopt error", s.name),
            _ => panic!(
                "{}: daemon {:?} vs fresh_keyset {:?}",
                s.name,
                daemon.as_ref().map(|_| ()),
                crate_side.as_ref().map(|_| ())
            ),
        }
        let out = expected_fold(&daemon, false, None);
        cases.push(case(
            &format!("fold {}", s.name),
            "fold",
            s.wire.fold_input(false),
            out,
        ));
        adopted.insert(s.name, (s.wire, daemon));
    }

    // What the cases are for, said by hand.
    let fold_of = |name: &str, require_signed: bool, k: Option<&[u8]>| {
        expected_fold(&adopted[name].1, require_signed, k)
    };
    let f = fold_of("triple_delegated", false, None);
    assert_eq!(f["state"], "verified");
    assert_eq!(f["admins"], sorted(&[&cid, &aid, &bid]));
    assert_eq!(f["members"], sorted(&[&cid, &aid, &bid, &mid]));
    let f = fold_of("triple_rekeyed", false, Some(&K1[..]));
    assert_eq!((f["generation"].clone(), f["rekey_ok"].clone()), (json!(1), json!(true)));
    assert_eq!(fold_of("triple_rekeyed", false, Some(&K2[..]))["rekey_ok"], false);
    for name in ["triple_rekey_unproven", "triple_rekey_by_member", "triple_no_members"] {
        let f = fold_of(name, false, Some(&K1[..]));
        assert_eq!((f["generation"].clone(), f["rekey_ok"].clone()), (json!(0), json!(true)), "{}", name);
    }
    let f = fold_of("triple_rekey_signer_demoted", false, Some(&K1[..]));
    assert_eq!((f["generation"].clone(), f["rekey_ok"].clone()), (json!(1), json!(true)));
    assert_eq!(f["admins"], sorted(&[&cid]));
    let f = fold_of("triple_succession", false, None);
    assert_eq!((f["root_id"].clone(), f["role_epoch"].clone()), (json!(bid), json!(1)));
    assert_eq!(f["admins"], sorted(&[&bid, &mid]));
    assert_eq!(f["members"], sorted(&[&cid, &bid, &mid]));
    assert_eq!(fold_of("triple_compaction", false, None)["admins"], sorted(&[&cid]));
    let approvers = adopted["triple_approvers"].1.as_ref().unwrap();
    assert_eq!(
        approvers.keyset.uik.as_ref().unwrap().approver_cids.len(),
        1,
        "only the approver credential with a pubkey and a decodable cid is labeled"
    );
    for name in [
        "triple_bad_own_cid",
        "triple_bad_member_field",
        "triple_bad_delegation_log",
        "rows_bad_prf_salt",
        "rows_bad_cid",
        "rows_bad_wc_check",
        "rows_missing_seq",
    ] {
        let f = fold_of(name, false, None);
        assert_eq!(f["state"], "untrusted", "{}", name);
        assert!(f["adopt_error"].is_string(), "{}", name);
    }
    for (name, state) in [
        ("triple_no_anchor", "no_uik"),
        ("rows_v1", "no_uik"),
        ("triple_short_anchor", "untrusted"),
        ("triple_prefix_rollback", "untrusted"),
    ] {
        assert_eq!(fold_of(name, false, None)["state"], state, "{}", name);
    }
    assert_eq!(fold_of("triple_no_anchor", true, None)["state"], "untrusted");
    assert_eq!(fold_of("triple_prefix_rollback", false, Some(&K1[..]))["rekey_ok"], false);
    assert_eq!(fold_of("triple_unknown_role", false, None)["members"], sorted(&[&cid, &mid]));
    let f = fold_of("rows_rekeyed", false, Some(&K1[..]));
    assert_eq!((f["generation"].clone(), f["rekey_ok"].clone()), (json!(2), json!(true)));
    assert_eq!(f["admins"], sorted(&[&cid, &mid]));
    assert_eq!(f["members"], sorted(&[&cid, &mid, &p.x.user_id()]));

    // More fold cases: a vault that requires signatures, content keys.
    for (name, require_signed, k) in [
        ("triple_no_anchor", true, None),
        ("rows_v1", true, Some(&K1)),
        ("triple_rekeyed", false, Some(&K1)),
        ("triple_rekeyed", false, Some(&K2)),
        ("triple_rekey_unproven", false, Some(&K1)),
        ("triple_rekey_signer_demoted", false, Some(&K1)),
        ("triple_prefix_rollback", false, Some(&K1)),
        ("triple_bad_own_cid", false, Some(&K1)),
        ("rows_rekeyed", false, Some(&K1)),
    ] {
        let mut input = adopted[name].0.fold_input(require_signed);
        let mut label = format!("fold {}", name);
        if require_signed {
            label.push_str(" require_signed");
        }
        if let Some(k) = k {
            input["content_key_b64"] = json!(enc(k));
            label.push_str(if k == &K1 { " K1" } else { " K2" });
        }
        cases.push(case(&label, "fold", input, fold_of(name, require_signed, k.map(|k| &k[..]))));
    }
    // Both shapes given: the triple is read. Neither: an empty `/keys` pull.
    let mut both = adopted["triple_delegated"].0.fold_input(false);
    if let Wire::Rows(r) = &adopted["rows_v1"].0 {
        both["rows"] = r.clone();
    }
    cases.push(case("fold triple over rows", "fold", both, fold_of("triple_delegated", false, None)));
    cases.push(case(
        "fold nothing served",
        "fold",
        json!({ "vault_id": VAULT, "require_signed": false }),
        fold_of("rows_v1", false, None),
    ));
    cases.push(case(
        "fold without require_signed",
        "fold",
        json!({ "vault_id": VAULT }),
        json!({ "error": "require_signed is missing" }),
    ));
    cases.push(case(
        "fold input not an object",
        "fold",
        json!([1, 2]),
        json!({ "error": "input is not a JSON object" }),
    ));

    // Row honoring, on the delegated vault (C, A, B admins; M a member) unless
    // said otherwise; the daemon's rules on its own adopt agree.
    let base = |name: &str, require_signed: bool| adopted[name].0.fold_input(require_signed);
    let item = [0x21u8; 32];
    let ct = b"sealed record".to_vec();
    let policy = json!({ "levels": { "read": "allow" } });
    let native = |signer: Option<&UikRoot>, live_sig: bool, tombstone: bool| {
        let mut v = json!({
            "item_id_b64": URL_SAFE_NO_PAD.encode(item), "record_type": "policy",
            "is_legacy_aux": false, "tombstone": tombstone,
            "ct_b64": URL_SAFE_NO_PAD.encode(&ct), "version": 3, "body": policy,
        });
        if let Some(s) = signer {
            v["sig"] = json!(sidecar(s, "policy", &item, 3, &ct, live_sig));
            v["signer"] = json!(s.user_id());
        }
        v
    };
    let honored = |data: Value| json!({ "honored": true, "data": data });
    let dropped = json!({ "honored": false, "data": null });
    let wrapper_data = json!({ "default": "ask" });
    let wrapper_sig = p.a.signing().sign(&crate::identity::config_sig_input(
        VAULT,
        "policy",
        4,
        Some(sudp::canonical::canonicalize(&wrapper_data).as_slice()),
        &aid,
    ));
    let legacy = |tombstone: bool, signer: Option<&UikRoot>| {
        let mut v = json!({
            "item_id_b64": URL_SAFE_NO_PAD.encode(item), "record_type": "policy",
            "is_legacy_aux": true, "tombstone": tombstone,
            "ct_b64": URL_SAFE_NO_PAD.encode(&ct), "version": 4,
            "body": { "data": wrapper_data, "uik_sig": enc(&wrapper_sig), "uik_sign_pub": enc(&pub_of(&p.a)) },
        });
        if let Some(s) = signer {
            v["sig"] = json!(sidecar(s, "policy", &item, 4, &ct, !tombstone));
            v["signer"] = json!(s.user_id());
        }
        v
    };
    let owner_config_cases = [
        ("admin signed", "triple_delegated", false, native(Some(&p.c), true, false), honored(policy.clone())),
        ("member signed", "triple_delegated", false, native(Some(&p.m), true, false), dropped.clone()),
        ("admin signed tombstone", "triple_delegated", false, native(Some(&p.c), false, true), honored(Value::Null)),
        ("tombstone with a live signature", "triple_delegated", false, native(Some(&p.c), true, true), dropped.clone()),
        ("unsigned", "triple_delegated", false, native(None, true, false), dropped.clone()),
        ("legacy in-body admin signature", "triple_delegated", false, legacy(false, None), honored(wrapper_data.clone())),
        ("legacy tombstone", "triple_delegated", false, legacy(true, Some(&p.c)), dropped.clone()),
        ("unsigned without a UIK layer", "triple_no_anchor", false, native(None, true, false), honored(policy.clone())),
        ("unsigned without a UIK layer, signatures required", "triple_no_anchor", true, native(None, true, false), dropped.clone()),
        ("admin signed on an untrusted fold", "triple_short_anchor", false, native(Some(&p.c), true, false), dropped.clone()),
        ("admin signed after a failed adopt", "triple_bad_own_cid", false, native(Some(&p.c), true, false), dropped.clone()),
    ];
    for (label, scenario, rs, row, expected) in owner_config_cases {
        // The daemon's rule on its adopt (a legacy row reads only live).
        let daemon = &adopted[scenario].1;
        let got = match daemon {
            Err(_) => None,
            Ok(pv) => {
                let sig = row.get("sig").and_then(|v| v.as_str());
                let signer = row.get("signer").and_then(|v| v.as_str());
                let (legacy, tomb) = (row["is_legacy_aux"] == true, row["tombstone"] == true);
                if legacy && tomb {
                    None
                } else {
                    rules::honored_owner_config(
                        sig,
                        signer,
                        &ct,
                        row["version"].as_u64().unwrap(),
                        pv.keyset.uik.as_ref(),
                        VAULT,
                        &item,
                        legacy,
                        "policy",
                        tomb,
                        row["body"].clone(),
                        &console_trust(daemon, rs),
                    )
                }
            }
        };
        assert_eq!(
            json!({ "honored": got.is_some(), "data": got.flatten() }),
            expected,
            "owner_config {}",
            label
        );
        cases.push(case(&format!("owner_config {}", label), "owner_config", with(&base(scenario, rs), row), expected));
    }

    let agent = |signer: Option<&UikRoot>, owner: &str, tombstone: bool| {
        let mut v = json!({
            "item_id_b64": URL_SAFE_NO_PAD.encode(item), "tombstone": tombstone,
            "ct_b64": URL_SAFE_NO_PAD.encode(&ct), "version": 2,
            "body": { "owner": owner, "name": "build bot" },
        });
        if let Some(s) = signer {
            v["sig"] = json!(sidecar(s, "agent", &item, 2, &ct, true));
            v["signer"] = json!(s.user_id());
        }
        v
    };
    let agent_cases = [
        ("member's own agent", "triple_delegated", false, agent(Some(&p.m), &mid, false), true),
        ("member signs another's agent", "triple_delegated", false, agent(Some(&p.m), &bid, false), false),
        ("admin signs a member's agent", "triple_delegated", false, agent(Some(&p.a), &mid, false), true),
        ("unsigned", "triple_delegated", false, agent(None, &mid, false), false),
        ("tombstone", "triple_delegated", false, agent(Some(&p.c), &mid, true), false),
        ("unsigned without a UIK layer", "triple_no_anchor", false, agent(None, &mid, false), true),
        ("unsigned without a UIK layer, signatures required", "triple_no_anchor", true, agent(None, &mid, false), false),
    ];
    for (label, scenario, rs, row, ok) in agent_cases {
        let daemon = &adopted[scenario].1;
        let got = match daemon {
            Ok(pv) if row["tombstone"] != true => rules::fold_agent_record(
                row.get("sig").and_then(|v| v.as_str()),
                row.get("signer").and_then(|v| v.as_str()),
                &ct,
                pv.keyset.uik.as_ref(),
                VAULT,
                &item,
                2,
                row["body"].clone(),
                &console_trust(daemon, rs),
            ),
            _ => None,
        };
        assert_eq!(got.is_some(), ok, "agent_record {}", label);
        let expected = json!({ "honored": ok, "data": if ok { row["body"].clone() } else { Value::Null } });
        cases.push(case(&format!("agent_record {}", label), "agent_record", with(&base(scenario, rs), row), expected));
    }

    let signed = |signer: &UikRoot, live: bool, claimed_live: bool| {
        json!({
            "record_type": "policy", "item_id_b64": URL_SAFE_NO_PAD.encode(item), "version": 3,
            "ct_b64": URL_SAFE_NO_PAD.encode(&ct), "live": claimed_live,
            "sig": sidecar(signer, "policy", &item, 3, &ct, live), "signer": signer.user_id(),
        })
    };
    for (label, scenario, row, expected) in [
        ("a member's signature", "triple_delegated", signed(&p.m, true, true), json!(mid)),
        ("a signature over the other status", "triple_delegated", signed(&p.c, true, false), Value::Null),
        ("someone outside the keyset", "triple_delegated", signed(&p.x, true, true), Value::Null),
        ("after a failed adopt", "triple_bad_own_cid", signed(&p.c, true, true), Value::Null),
    ] {
        let daemon = &adopted[scenario].1;
        let got = daemon.as_ref().ok().and_then(|pv| {
            rules::verify_record_sidecar_sig(
                &ct,
                pv.keyset.uik.as_ref(),
                VAULT,
                &item,
                "policy",
                3,
                row["live"] == true,
                row["sig"].as_str().unwrap(),
                row["signer"].as_str().unwrap(),
            )
        });
        assert_eq!(json!(got), expected, "sidecar_signer {}", label);
        cases.push(case(&format!("sidecar_signer {}", label), "sidecar_signer", with(&base(scenario, false), row), expected));
    }

    for (label, scenario, requester, signer, expected) in [
        ("the requester", "triple_delegated", &mid, &mid, "requester"),
        ("an admin", "triple_delegated", &mid, &aid, "admin"),
        ("a member for another", "triple_delegated", &aid, &mid, "refused"),
        ("without a UIK layer", "triple_no_anchor", &mid, &cid, "refused"),
        ("the requester on an untrusted fold", "triple_prefix_rollback", &cid, &cid, "requester"),
        ("an admin on an untrusted fold", "triple_prefix_rollback", &aid, &cid, "refused"),
    ] {
        if let Ok(pv) = &adopted[scenario].1 {
            let got = match pv.approval_authority(VAULT, &[requester.clone()].into(), signer) {
                ApprovalAuthority::Requester => "requester",
                ApprovalAuthority::Admin => "admin",
                ApprovalAuthority::Refused(_) => "refused",
            };
            assert_eq!(got, expected, "approval_authority {}", label);
        }
        cases.push(case(
            &format!("approval_authority {}", label),
            "approval_authority",
            with(&base(scenario, false), json!({ "requester": [requester], "signer": signer })),
            json!(expected),
        ));
    }

    let root = |r: &UikRoot, epoch: u64| {
        json!({ "root_pub_b64": enc(&pub_of(r)), "root_id": r.user_id(), "role_epoch": epoch })
    };
    for (label, input, expected) in [
        (
            "a transfer",
            json!({ "vault_id": VAULT, "genesis_b64": enc(&pub_of(&p.c)), "succession": [succession(&p.c, &p.b, 1)] }),
            root(&p.b, 1),
        ),
        (
            "no succession",
            json!({ "vault_id": VAULT, "genesis_b64": enc(&pub_of(&p.c)) }),
            root(&p.c, 0),
        ),
        (
            "a certificate not by the root",
            json!({ "vault_id": VAULT, "genesis_b64": enc(&pub_of(&p.c)), "succession": [succession(&p.m, &p.b, 1)] }),
            root(&p.c, 0),
        ),
        (
            "a genesis that is not a key",
            json!({ "vault_id": VAULT, "genesis_b64": enc(&[7; 16]) }),
            Value::Null,
        ),
        (
            "no genesis",
            json!({ "vault_id": VAULT }),
            json!({ "error": "genesis_b64 is missing" }),
        ),
    ] {
        cases.push(case(&format!("resolve_current_root {}", label), "resolve_current_root", input, expected));
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/sprott-trust-wasm/fixtures/cases.json");
    let doc = json!({
        "about": "Inputs to the sprott-trust-wasm JSON API and the verdicts expected. Made by the daemon test sync::fresh_keyset_tests; SPROTT_TRUST_FIXTURES=write rewrites it.",
        "cases": cases,
    });
    if std::env::var("SPROTT_TRUST_FIXTURES").as_deref() == Ok("write") {
        // One case per line.
        let lines: Vec<String> = cases.iter().map(|c| c.to_string()).collect();
        let text = format!(
            "{{\"about\": {},\n\"cases\": [\n{}\n]}}\n",
            doc["about"],
            lines.join(",\n")
        );
        std::fs::write(&path, text).unwrap();
    }
    let on_disk: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        on_disk == doc,
        "{} differs from the cases: SPROTT_TRUST_FIXTURES=write rewrites it",
        path.display()
    );
}
