//! Sealed approval cards (request-model design §5).
//!
//! What an approver reads before approving a brokered call (the bound request
//! values and the consent template) is sealed to the vault's current-generation
//! content key, so the relay and anyone holding only the approve link see the
//! request line, the decision and the rule label, never the content. The op
//! carries `scope.card = {"gen": <generation>, "sealed": "<base64url>"}`; β
//! binds it like the rest of the op. The daemon keeps the plaintext in the op's
//! [`crate::approval::PolicyContext`] (never on the wire).
//!
//! The approver's identity signature covers [`binding_mac`] of the card as
//! opened, keyed from the same content key, so a console that never opened the
//! card can't approve it, and the relay (which can check the signature) can't
//! confirm guesses of its content.
//!
//! Seal: sudp's item record (`seal_record`, XChaCha20-Poly1305 under
//! `HKDF(K, "sudp/v1/item")`) with the context `domain = CARD_DOMAIN`,
//! `vault = vault id`, `id = ""`, `version = generation (u64 big-endian)`. The
//! plaintext is `len (u32 big-endian) ‖ JCS(card) ‖ zero padding` up to a size
//! class (powers of two from 1 KiB), so the length doesn't give away how many
//! digits an amount has. Byte-identical to the console's `openApprovalCard`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sudp::primitives::{Kdf, PrimitiveSuite, StdPrimitives};
use sudp::state::{seal_record, unseal_record, SealCtx};

use crate::error::{AppError, Result};

/// `SealCtx.domain` of an approval card.
pub const CARD_DOMAIN: &str = "sprott/v1/approval-card";

/// HKDF info of the key [`binding_mac`] is keyed by.
pub const CARD_BINDING_INFO: &[u8] = b"sprott card binding v1";

/// The smallest size class a card's plaintext is padded to.
const MIN_CLASS: usize = 1024;

/// The largest card JSON the daemon seals (design §5: the sealed card is
/// base64 inside the op, which is base64 again in the relay's 256 KiB
/// `op_summary`).
pub const MAX_CARD_JSON: usize = 96 * 1024;

/// What the approver reads: the bound `[requests]` values and the consent
/// template they fill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// Sorted `(name, value)` pairs, the exact input of the permit identity.
    pub vars: Vec<(String, String)>,
    pub consent: Option<String>,
}

/// A sealed card as the daemon keeps it beside the op.
#[derive(Clone)]
pub struct SealedCard {
    /// The content-key generation it is sealed under.
    pub gen: u64,
    /// The sealed record, base64url without padding (the op's `scope.card.sealed`).
    pub sealed: String,
    /// [`binding_mac`] of the plaintext: what the approver's signature must cover.
    pub mac: [u8; 32],
    /// SHA-256 of the card JSON: stands for the content in the intent key, so
    /// retries of one request chain although each seal is fresh.
    pub digest: [u8; 32],
    /// The card itself (its `vars` key the permit an approval stores).
    pub card: Card,
}

impl std::fmt::Debug for SealedCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedCard")
            .field("gen", &self.gen)
            .finish_non_exhaustive()
    }
}

impl Card {
    /// Nothing to show: no bound value and no consent template.
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty() && self.consent.is_none()
    }

    /// The card JSON: JCS of `{"v":1,"vars":{…},"consent":"…"}` (`consent`
    /// only when there is a template).
    pub fn json(&self) -> Result<Vec<u8>> {
        let vars: serde_json::Map<String, serde_json::Value> = self
            .vars
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        let mut v = serde_json::json!({ "v": 1, "vars": vars });
        if let Some(c) = &self.consent {
            v["consent"] = serde_json::Value::String(c.clone());
        }
        sudp::canonical::canonicalize_strict(&v)
            .map_err(|e| AppError::Internal(format!("approval card: {e}")))
    }
}

fn ctx<'a>(vault_id: &'a str, version: &'a [u8; 8]) -> SealCtx<'a> {
    SealCtx {
        domain: CARD_DOMAIN,
        vault: vault_id.as_bytes(),
        id: &[],
        version,
    }
}

/// `len ‖ json ‖ zeros`, the total a power of two of at least [`MIN_CLASS`].
fn pad(json: &[u8]) -> Vec<u8> {
    let need = 4 + json.len();
    let class = need.max(MIN_CLASS).next_power_of_two();
    let mut out = Vec::with_capacity(class);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(json);
    out.resize(class, 0);
    out
}

fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let len = u32::from_be_bytes(padded.get(..4)?.try_into().ok()?) as usize;
    padded.get(4..4 + len)
}

/// `HMAC-SHA-256(HKDF-SHA-256(content_key, info = CARD_BINDING_INFO), json)`.
pub fn binding_mac(content_key: &[u8], json: &[u8]) -> [u8; 32] {
    let key = zeroize::Zeroizing::new(
        <StdPrimitives as PrimitiveSuite>::Kdf::derive_32(content_key, &[], CARD_BINDING_INFO)
            .expect("HKDF-SHA-256 expands 32 bytes"),
    );
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key[..]).expect("HMAC takes any key length");
    mac.update(json);
    mac.finalize().into_bytes().into()
}

/// Seal `card` for `vault_id` under the content key of generation `gen`.
pub fn seal(card: Card, content_key: &[u8], vault_id: &str, gen: u64) -> Result<SealedCard> {
    let json = card.json()?;
    if json.len() > MAX_CARD_JSON {
        return Err(AppError::BadRequest(format!(
            "the request's bound values are too large to show for approval ({} bytes, at most {})",
            json.len(),
            MAX_CARD_JSON
        )));
    }
    let version = gen.to_be_bytes();
    let sealed = seal_record::<StdPrimitives>(content_key, &ctx(vault_id, &version), &pad(&json))
        .map_err(|e| AppError::Internal(format!("approval card seal: {e}")))?;
    Ok(SealedCard {
        gen,
        sealed: URL_SAFE_NO_PAD.encode(sealed),
        mac: binding_mac(content_key, &json),
        digest: Sha256::digest(&json).into(),
        card,
    })
}

/// Open a sealed card (the console's side, kept here for tests and the local
/// approval path): the card JSON, or `None` when it doesn't open under this key.
pub fn open(sealed_b64: &str, content_key: &[u8], vault_id: &str, gen: u64) -> Option<Vec<u8>> {
    let sealed = URL_SAFE_NO_PAD.decode(sealed_b64).ok()?;
    let version = gen.to_be_bytes();
    let padded =
        unseal_record::<StdPrimitives>(content_key, &ctx(vault_id, &version), &sealed).ok()?;
    unpad(&padded).map(<[u8]>::to_vec)
}

impl SealedCard {
    /// The op's `scope.card`.
    pub fn scope_value(&self) -> serde_json::Value {
        serde_json::json!({ "gen": self.gen, "sealed": self.sealed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> Card {
        Card {
            vars: vec![
                ("amount".into(), "50.00".into()),
                ("to".into(), "+15550100".into()),
            ],
            consent: Some("Send {{ vars.amount }} to {{ vars.to }}".into()),
        }
    }

    #[test]
    fn a_sealed_card_opens_under_its_key_vault_and_generation_only() {
        let k = [7u8; 32];
        let s = seal(card(), &k, "v1", 3).unwrap();
        let json = open(&s.sealed, &k, "v1", 3).expect("opens");
        assert_eq!(json, card().json().unwrap());
        assert_eq!(s.mac, binding_mac(&k, &json));
        assert!(open(&s.sealed, &[8u8; 32], "v1", 3).is_none(), "another key");
        assert!(open(&s.sealed, &k, "v2", 3).is_none(), "another vault");
        assert!(open(&s.sealed, &k, "v1", 2).is_none(), "another generation");
    }

    #[test]
    fn cards_of_different_lengths_pad_to_the_same_size_class() {
        let k = [1u8; 32];
        let mut short = card();
        short.vars[0].1 = "5".into();
        let mut long = card();
        long.vars[0].1 = "5000000.00".into();
        let a = seal(short, &k, "v", 0).unwrap();
        let b = seal(long, &k, "v", 0).unwrap();
        assert_eq!(a.sealed.len(), b.sealed.len());
        assert_ne!(a.mac, b.mac);
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn each_seal_is_fresh_but_the_mac_and_digest_are_stable() {
        let k = [2u8; 32];
        let a = seal(card(), &k, "v", 0).unwrap();
        let b = seal(card(), &k, "v", 0).unwrap();
        assert_ne!(a.sealed, b.sealed, "a fresh nonce per seal");
        assert_eq!(a.mac, b.mac);
        assert_eq!(a.digest, b.digest);
    }

    #[test]
    fn the_mac_depends_on_the_content_key() {
        let json = card().json().unwrap();
        assert_ne!(binding_mac(&[1u8; 32], &json), binding_mac(&[2u8; 32], &json));
    }

    #[test]
    fn an_oversized_card_is_refused() {
        let big = Card {
            vars: vec![("raw".into(), "x".repeat(MAX_CARD_JSON))],
            consent: None,
        };
        assert!(seal(big, &[0u8; 32], "v", 0).is_err());
    }
}
