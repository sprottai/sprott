//! The JSON API gives the verdicts in `fixtures/cases.json`, which the
//! daemon's test `sync::fresh_keyset_tests` writes from its own adopt.

use serde_json::Value;
use sprott_trust_wasm::api;

fn run(call: &str, input: &str) -> String {
    match call {
        "fold" => api::fold(input),
        "owner_config" => api::owner_config(input),
        "owner_config_row" => api::owner_config_row(input),
        "agent_record" => api::agent_record(input),
        "sidecar_signer" => api::sidecar_signer(input),
        "approval_authority" => api::approval_authority(input),
        "resolve_current_root" => api::resolve_current_root(input),
        other => panic!("unknown call {}", other),
    }
}

#[test]
fn the_api_gives_the_daemon_verdicts() {
    let doc: Value = serde_json::from_str(include_str!("../fixtures/cases.json")).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let out = run(c["call"].as_str().unwrap(), &c["input"].to_string());
        let got: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(got, c["expected"], "{}", c["name"]);
    }
}

/// Input that does not parse, or lacks a field or has the wrong type, comes
/// back as an error.
#[test]
fn bad_input_is_an_error() {
    let calls = [
        "fold",
        "owner_config",
        "owner_config_row",
        "agent_record",
        "sidecar_signer",
        "approval_authority",
        "resolve_current_root",
    ];
    let fold = r#""vault_id": "v", "require_signed": false"#;
    let mut cases: Vec<(&str, String)> = Vec::new();
    for call in calls {
        for input in ["", "not json", "null", "[]", "{}", r#"{"vault_id": 7}"#] {
            cases.push((call, input.to_string()));
        }
    }
    cases.extend([
        ("fold", r#"{"vault_id": "v", "require_signed": "yes"}"#.to_string()),
        ("fold", format!(r#"{{{}, "content_key_b64": "!!"}}"#, fold)),
        ("owner_config", format!(r#"{{{}, "ct_b64": "", "version": 1}}"#, fold)),
        ("agent_record", format!(r#"{{{}, "item_id_b64": "", "ct_b64": "", "version": -1}}"#, fold)),
        ("sidecar_signer", format!(r#"{{{}, "record_type": "policy", "item_id_b64": "", "version": 1, "ct_b64": "", "sig": "", "signer": ""}}"#, fold)),
        ("approval_authority", format!(r#"{{{}, "requester": "us_x", "signer": "us_x"}}"#, fold)),
        ("resolve_current_root", r#"{"vault_id": "v", "genesis_b64": "!!"}"#.to_string()),
        ("resolve_current_root", r#"{"vault_id": "v", "genesis_b64": "", "succession": "x"}"#.to_string()),
    ]);
    for (call, input) in cases {
        let got: Value = serde_json::from_str(&run(call, &input)).unwrap();
        assert!(got["error"].is_string(), "{} {:?}: {}", call, input, got);
    }
}
