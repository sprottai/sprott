//! The JSON API over `sprott-trust` the console calls. Keys are snake_case;
//! bytes are base64 (read leniently: standard or url-safe, padded or not;
//! written standard and padded).
//!
//! The fold input, shared by every call but [`resolve_current_root`]:
//!
//! ```json
//! { "vault_id": "...", "triple": {...}?, "rows": [...]?, "require_signed": bool }
//! ```
//!
//! `triple` is the `GET /membership` body, `rows` the `keys` array of a `GET
//! /keys` body. The keyset is the one a daemon with no prior state adopts from
//! them ([`sprott_trust::adopt::fresh_keyset`]); `triple` is read when both are
//! given (a format-2 vault serves only the triple to a daemon), and neither is
//! an empty `/keys` pull. A failed adopt reads as untrusted. `require_signed`:
//! the vault requires signatures (the console's session holds a UIK root for
//! it), so a keyset without a UIK layer reads as untrusted, not as a legacy
//! personal vault.

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Map, Value};
use sprott_trust::adopt::{fresh_keyset, KeyRow, Served};
use sprott_trust::identity::{derive_id, IdKind};
use sprott_trust::trust::{self as rules, resolve_membership_trust};
use sprott_trust::{decode_keys_data_field, ApprovalAuthority, KeysetUik, MembershipTrust};

type Out = Result<Value, String>;

/// Parse `input`, run `f`, and give its result or `{"error": ...}` as JSON.
fn call(input: &str, f: fn(&Value) -> Out) -> String {
    let out = serde_json::from_str::<Value>(input)
        .map_err(|e| format!("input is not JSON: {}", e))
        .and_then(|v| match v {
            Value::Object(_) => f(&v),
            _ => Err("input is not a JSON object".to_string()),
        });
    match out {
        Ok(v) => v.to_string(),
        Err(e) => json!({ "error": e }).to_string(),
    }
}

/// `v[k]`, with JSON `null` read as absent.
fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k).filter(|x| !x.is_null())
}

fn req_str<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    get(v, k)
        .ok_or_else(|| format!("{} is missing", k))?
        .as_str()
        .ok_or_else(|| format!("{} is not a string", k))
}

fn opt_str<'a>(v: &'a Value, k: &str) -> Result<Option<&'a str>, String> {
    get(v, k)
        .map(|x| x.as_str().ok_or_else(|| format!("{} is not a string", k)))
        .transpose()
}

fn req_bool(v: &Value, k: &str) -> Result<bool, String> {
    get(v, k)
        .ok_or_else(|| format!("{} is missing", k))?
        .as_bool()
        .ok_or_else(|| format!("{} is not a boolean", k))
}

fn opt_bool(v: &Value, k: &str) -> Result<Option<bool>, String> {
    get(v, k)
        .map(|x| x.as_bool().ok_or_else(|| format!("{} is not a boolean", k)))
        .transpose()
}

fn req_u64(v: &Value, k: &str) -> Result<u64, String> {
    get(v, k)
        .ok_or_else(|| format!("{} is missing", k))?
        .as_u64()
        .ok_or_else(|| format!("{} is not a non-negative integer", k))
}

fn b64(k: &str, s: &str) -> Result<Vec<u8>, String> {
    decode_keys_data_field(s).map_err(|e| format!("{}: {}", k, e))
}

fn req_bytes(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    b64(k, req_str(v, k)?)
}

fn opt_bytes(v: &Value, k: &str) -> Result<Option<Vec<u8>>, String> {
    opt_str(v, k)?.map(|s| b64(k, s)).transpose()
}

/// The fold input, adopted.
struct Fold {
    vault_id: String,
    /// The fresh daemon's UIK layer, or its adopt error.
    adopted: Result<Option<KeysetUik>, String>,
    require_signed: bool,
}

impl Fold {
    fn parse(v: &Value) -> Result<Fold, String> {
        let vault_id = req_str(v, "vault_id")?.to_string();
        let require_signed = req_bool(v, "require_signed")?;
        let adopted = match (get(v, "triple"), get(v, "rows")) {
            (Some(triple), _) => fresh_keyset(&vault_id, Served::Membership(triple)),
            (None, Some(rows)) => match serde_json::from_value::<Vec<KeyRow>>(rows.clone()) {
                Ok(rows) => fresh_keyset(&vault_id, Served::KeyRows(&rows)),
                Err(e) => Err(format!("parse keys array: {}", e)),
            },
            (None, None) => Ok(None),
        };
        Ok(Fold {
            vault_id,
            adopted,
            require_signed,
        })
    }

    fn uik(&self) -> Option<&KeysetUik> {
        self.adopted.as_ref().ok().and_then(|u| u.as_ref())
    }

    /// The trust the console acts on: the daemon's, except that a failed
    /// adopt, and no UIK layer on a vault that requires signatures, are
    /// untrusted.
    fn trust(&self) -> MembershipTrust {
        match &self.adopted {
            Err(_) => MembershipTrust::Untrusted,
            Ok(uik) => match resolve_membership_trust(uik.as_ref(), &self.vault_id) {
                MembershipTrust::NoUik if self.require_signed => MembershipTrust::Untrusted,
                t => t,
            },
        }
    }
}

/// `fold(input)`: the fold input and an optional `content_key_b64` (the
/// vault's content key in use). Returns
///
/// ```json
/// { "state": "no_uik" | "verified" | "untrusted", "trusted": bool,
///   "admins": [us_id], "members": [us_id], "role_epoch": n, "root_id": "us_...",
///   "root_pub_b64": "..." | null, "generation": n, "rekey_ok": bool?, "adopt_error": "..."? }
/// ```
///
/// `trusted`: verified, or no UIK layer on a vault that does not require
/// signatures. `members`: everyone the role fold seats, admins included;
/// `admins` and `members` are empty unless verified. `role_epoch`, `root_id`
/// and `root_pub_b64` are the current root's whenever the genesis anchor
/// resolves (`0`, `""` and `null` otherwise). `generation`: the re-key
/// generation the fresh daemon ratcheted to (an unproven bump is not taken).
/// `rekey_ok`, only with a content key: the daemon's re-key check
/// (`verify_rekey_proof`; false on a failed adopt), without which its fold
/// refuses the vault. `adopt_error`, only when the adopt failed.
pub fn fold(input: &str) -> String {
    call(input, fold_value)
}

fn fold_value(v: &Value) -> Out {
    let f = Fold::parse(v)?;
    let content_key = opt_bytes(v, "content_key_b64")?;
    let trust = f.trust();
    let (state, admins, members): (&str, Vec<&String>, Vec<&String>) = match &trust {
        MembershipTrust::NoUik => ("no_uik", Vec::new(), Vec::new()),
        MembershipTrust::Untrusted => ("untrusted", Vec::new(), Vec::new()),
        MembershipTrust::Verified(roles) => (
            "verified",
            roles
                .iter()
                .filter(|(_, r)| r.is_admin())
                .map(|(id, _)| id)
                .collect(),
            roles.keys().collect(),
        ),
    };
    let root = f
        .uik()
        .and_then(|u| rules::resolve_current_root(u, &f.vault_id));
    let mut out = Map::new();
    out.insert("state".into(), json!(state));
    out.insert("trusted".into(), json!(state != "untrusted"));
    out.insert("admins".into(), json!(admins));
    out.insert("members".into(), json!(members));
    out.insert("role_epoch".into(), json!(root.map_or(0, |(_, e)| e)));
    out.insert(
        "root_id".into(),
        json!(root.map_or(String::new(), |(p, _)| derive_id(IdKind::User, &p))),
    );
    out.insert(
        "root_pub_b64".into(),
        json!(root.map(|(p, _)| STANDARD.encode(p))),
    );
    out.insert(
        "generation".into(),
        json!(f.uik().map_or(0, |u| u.generation)),
    );
    if let Some(k) = content_key {
        let ok = match &f.adopted {
            Err(_) => false,
            Ok(uik) => rules::verify_rekey_proof(uik.as_ref(), &trust, &f.vault_id, &k),
        };
        out.insert("rekey_ok".into(), json!(ok));
    }
    if let Err(e) = &f.adopted {
        out.insert("adopt_error".into(), json!(e));
    }
    Ok(Value::Object(out))
}

/// One stored row as the honoring calls read it.
struct Row<'a> {
    item_id: Vec<u8>,
    sig: Option<&'a str>,
    signer: Option<&'a str>,
    ct: Vec<u8>,
    version: u64,
    body: Value,
}

impl<'a> Row<'a> {
    fn parse(v: &'a Value) -> Result<Row<'a>, String> {
        Ok(Row {
            item_id: req_bytes(v, "item_id_b64")?,
            sig: opt_str(v, "sig")?,
            signer: opt_str(v, "signer")?,
            ct: req_bytes(v, "ct_b64")?,
            version: req_u64(v, "version")?,
            body: v.get("body").cloned().unwrap_or(Value::Null),
        })
    }
}

/// `owner_config(input)`: the fold input and one owner-config row,
/// `{item_id_b64, record_type, is_legacy_aux, tombstone, sig?, signer?, ct_b64,
/// version, body}` (`item_id_b64`: the raw blinded id; `record_type`: the
/// sidecar record type; `body`: the opened record's body). Returns `{"honored":
/// bool, "data": ...}`: whether the daemon's fold honors the row, and its data
/// (`null` for a tombstone or a row not honored). As the fold reads it: a native
/// row by `honored_owner_config`; a legacy `aux` row only live, by
/// `fold_owner_config_record`.
pub fn owner_config(input: &str) -> String {
    call(input, owner_config_value)
}

fn owner_config_value(v: &Value) -> Out {
    let f = Fold::parse(v)?;
    let row = Row::parse(v)?;
    let record_type = req_str(v, "record_type")?;
    let is_legacy_aux = req_bool(v, "is_legacy_aux")?;
    let tombstone = req_bool(v, "tombstone")?;
    let honored = if is_legacy_aux && tombstone {
        None
    } else {
        rules::honored_owner_config(
            row.sig,
            row.signer,
            &row.ct,
            row.version,
            f.uik(),
            &f.vault_id,
            &row.item_id,
            is_legacy_aux,
            record_type,
            tombstone,
            row.body,
            &f.trust(),
        )
    };
    Ok(json!({ "honored": honored.is_some(), "data": honored.flatten() }))
}

/// `agent_record(input)`: the fold input and one authorized-agent row, the
/// fields of [`owner_config`] (`record_type` and `is_legacy_aux` are not read:
/// an agent row's record type is `agent`; `tombstone` may be omitted). Returns
/// `{"honored": bool, "data": ...}` by `fold_agent_record`; a tombstone is not
/// honored (the fold reads agent rows only live).
pub fn agent_record(input: &str) -> String {
    call(input, agent_record_value)
}

fn agent_record_value(v: &Value) -> Out {
    let f = Fold::parse(v)?;
    let row = Row::parse(v)?;
    let honored = if opt_bool(v, "tombstone")?.unwrap_or(false) {
        None
    } else {
        rules::fold_agent_record(
            row.sig,
            row.signer,
            &row.ct,
            f.uik(),
            &f.vault_id,
            &row.item_id,
            row.version,
            row.body,
            &f.trust(),
        )
    };
    Ok(json!({ "honored": honored.is_some(), "data": honored }))
}

/// `sidecar_signer(input)`: the fold input and `{record_type, item_id_b64,
/// version, ct_b64, live, sig, signer}`. Returns the signer's `us_...` when the
/// sidecar signature verifies under a member key of the keyset, else `null`
/// (`verify_record_sidecar_sig`). Who the signer is, not whether they may sign.
pub fn sidecar_signer(input: &str) -> String {
    call(input, sidecar_signer_value)
}

fn sidecar_signer_value(v: &Value) -> Out {
    let f = Fold::parse(v)?;
    let record_type = req_str(v, "record_type")?;
    let item_id = req_bytes(v, "item_id_b64")?;
    let version = req_u64(v, "version")?;
    let ct = req_bytes(v, "ct_b64")?;
    let live = req_bool(v, "live")?;
    let sig = req_str(v, "sig")?;
    let signer = req_str(v, "signer")?;
    Ok(json!(rules::verify_record_sidecar_sig(
        &ct,
        f.uik(),
        &f.vault_id,
        &item_id,
        record_type,
        version,
        live,
        sig,
        signer,
    )))
}

/// `approval_authority(input)`: the fold input and `{requester: [us_id],
/// signer}`. Returns `"requester"`, `"admin"` or `"refused"`: the requester
/// always may approve; anyone else only as an admin of a verified fold.
pub fn approval_authority(input: &str) -> String {
    call(input, approval_authority_value)
}

fn approval_authority_value(v: &Value) -> Out {
    let f = Fold::parse(v)?;
    let requester: BTreeSet<String> = match get(v, "requester") {
        None => BTreeSet::new(),
        Some(r) => serde_json::from_value(r.clone())
            .map_err(|_| "requester is not an array of strings".to_string())?,
    };
    let signer = req_str(v, "signer")?;
    let verdict = match rules::approval_authority(f.uik(), &f.vault_id, &requester, signer) {
        ApprovalAuthority::Requester => "requester",
        ApprovalAuthority::Admin => "admin",
        ApprovalAuthority::Refused(_) => "refused",
    };
    Ok(json!(verdict))
}

/// `resolve_current_root(input)`: `{vault_id, genesis_b64, succession?}`
/// (`succession`: the root-succession chain as served, an array of
/// `{old_root_id, new_root_id, new_root_sig_pub, role_epoch, sig}`). Returns
/// `{root_pub_b64, root_id, role_epoch}`, or `null` when the genesis key is
/// not 32 bytes. A certificate that does not chain from the current root is
/// not followed.
pub fn resolve_current_root(input: &str) -> String {
    call(input, resolve_current_root_value)
}

fn resolve_current_root_value(v: &Value) -> Out {
    let vault_id = req_str(v, "vault_id")?;
    let genesis = req_bytes(v, "genesis_b64")?;
    let root_succession = match get(v, "succession") {
        None => Vec::new(),
        Some(s) => {
            serde_json::from_value(s.clone()).map_err(|e| format!("parse succession: {}", e))?
        }
    };
    let uik = KeysetUik {
        creator_sig_pub: genesis,
        root_succession,
        ..KeysetUik::default()
    };
    Ok(match rules::resolve_current_root(&uik, vault_id) {
        None => Value::Null,
        Some((root_pub, role_epoch)) => json!({
            "root_pub_b64": STANDARD.encode(root_pub),
            "root_id": derive_id(IdKind::User, &root_pub),
            "role_epoch": role_epoch,
        }),
    })
}
