//! The vault membership and signature rules of `sprott-trust`, exported to
//! the console as wasm. Every export takes one JSON text and returns one: the
//! result, or `{"error": "..."}` when the input does not parse. The API is in
//! [`api`]; this file only binds it.

use wasm_bindgen::prelude::wasm_bindgen;

pub mod api;

/// The membership a daemon with no prior state folds from the served triple
/// or `/keys` rows ([`api::fold`]).
#[wasm_bindgen]
pub fn fold(input: &str) -> String {
    api::fold(input)
}

/// Whether the daemon's fold honors an owner-config row, and its data
/// ([`api::owner_config`]).
#[wasm_bindgen]
pub fn owner_config(input: &str) -> String {
    api::owner_config(input)
}

/// Whether the daemon's row rule honors an owner-config row, a tombstone
/// included, and its data ([`api::owner_config_row`]).
#[wasm_bindgen]
pub fn owner_config_row(input: &str) -> String {
    api::owner_config_row(input)
}

/// Whether the daemon's fold honors an authorized-agent row, and its data
/// ([`api::agent_record`]).
#[wasm_bindgen]
pub fn agent_record(input: &str) -> String {
    api::agent_record(input)
}

/// The member whose sidecar signature a row carries, if it verifies
/// ([`api::sidecar_signer`]).
#[wasm_bindgen]
pub fn sidecar_signer(input: &str) -> String {
    api::sidecar_signer(input)
}

/// Whether a signer may approve a requester's op ([`api::approval_authority`]).
#[wasm_bindgen]
pub fn approval_authority(input: &str) -> String {
    api::approval_authority(input)
}

/// The current root and role epoch from a genesis key and a succession chain
/// ([`api::resolve_current_root`]).
#[wasm_bindgen]
pub fn resolve_current_root(input: &str) -> String {
    api::resolve_current_root(input)
}
