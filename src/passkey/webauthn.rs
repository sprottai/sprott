//! WebAuthn assertion verification — thin adapter over
//! `sudp::passkey::WebAuthn` (the SUDP reference implementation of the
//! `Authenticator` trait for ES256/P-256 + PRF).
//!
//! Verification checks (WebAuthn L3 §7.2 plus SUDP channel binding β):
//!   1. Decode `authenticatorData`, `clientDataJSON`, `signature`.
//!   2. `clientDataJSON.type == "webauthn.get"`.
//!   3. `origin` is one the relying party accepts ([`RelyingParty`]).
//!   4. `base64url_decode(challenge) == β` (channel binding).
//!   5. `authenticatorData.rpIdHash == SHA-256(rpId)` for one of the relying
//!      party's RP IDs.
//!   6. User Present flag set.
//!   7. ECDSA-P-256 verify of `authenticatorData ‖ SHA-256(clientDataJSON)`.
//!
//! Adapter responsibilities:
//!   - Bridge sudp's `Error::AuthorizationInvalid` → Sprott's
//!     `AppError::Unauthorized`.
//!   - Adapt the positional API Sprott call sites use (a [`RelyingParty`]:
//!     accepted origins and RP IDs) to sudp's `AuthenticatorContext` (one
//!     origin, one RP ID): the reported origin when it is on the list, and the
//!     listed RP ID the authenticator data names.
//!
//! Sprott currently only verifies `webauthn.get` assertions (registration
//! goes through a separate enrollment path); the historical
//! `AssertionKind::Create` variant was unused and has been removed.

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use sudp::passkey::{WebAuthn, WebAuthnAssertion, WebAuthnPublicKey};
use sudp::primitives::{Authenticator, AuthenticatorContext};

use crate::error::{AppError, Result};

/// The console's root pairs, one per environment (prod, dev): the new root and
/// the legacy root it replaced (`LEGACY_OF` in the rename contract). A root
/// and its pair partner are one console: a passkey made under either RP ID
/// verifies on the origins of both.
pub const LEGACY_OF: [(&str, &str); 2] = [
    ("sprott.ai", "safeclaw.pro"),         // rename:keep
    ("dev.sprott.ai", "dev.safeclaw.pro"), // rename:keep
];

/// Every console RP ID, new and legacy: the same list the console's passkey
/// code uses. Only hosts under these get the console relying party
/// ([`RelyingParty::console`]).
pub const CONSOLE_ROOTS: [&str; 4] = [
    LEGACY_OF[0].0,
    LEGACY_OF[1].0,
    LEGACY_OF[0].1,
    LEGACY_OF[1].1,
];

/// The [`CONSOLE_ROOTS`] entry a host belongs to: the root itself, or the
/// root under a single leading `app.` or `www.` label. `None` for any other
/// host (self-host, localhost).
pub fn console_root_of_host(host: &str) -> Option<&'static str> {
    CONSOLE_ROOTS.iter().copied().find(|root| {
        host == *root
            || ["app.", "www."]
                .iter()
                .any(|label| host.strip_prefix(label) == Some(*root))
    })
}

/// The root pair `(new, legacy)` a [`CONSOLE_ROOTS`] entry belongs to.
fn root_pair(root: &str) -> Option<(&'static str, &'static str)> {
    LEGACY_OF
        .iter()
        .copied()
        .find(|(new, legacy)| root == *new || root == *legacy)
}

/// The new root of the pair a host's console root belongs to: the new root
/// for a host on either root of a pair, `None` for any other host.
pub fn console_new_root_of_host(host: &str) -> Option<&'static str> {
    root_pair(console_root_of_host(host)?).map(|(new, _)| new)
}

/// The [`CONSOLE_ROOTS`] entry of a bare console origin (`https://<host>`, no
/// port, path, query, fragment or userinfo) on one of its hosts. `None` for
/// every other origin.
fn console_root_of_origin(origin: &str) -> Option<&'static str> {
    let url = url::Url::parse(origin).ok()?;
    let bare = url.scheme() == "https"
        && url.port().is_none()
        && matches!(url.path(), "" | "/")
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    let Some(url::Host::Domain(host)) = url.host() else {
        return None;
    };
    if !bare {
        return None;
    }
    console_root_of_host(host)
}

/// Where console pages are linked: `https://app.<new root>` for a console
/// origin on either root of a pair (stored as the root or its `app.` or
/// `www.` host), otherwise the origin as given. A legacy stored origin is
/// mapped here, at read time; the stored config is never rewritten.
pub fn console_link_origin(origin: &str) -> String {
    let origin = origin.trim_end_matches('/');
    match console_root_of_origin(origin).and_then(root_pair) {
        Some((new, _)) => format!("https://app.{}", new),
        None => origin.to_string(),
    }
}

/// Whose assertions the daemon accepts: the RP IDs the authenticator may
/// have signed for (`authenticatorData.rpIdHash` must be the SHA-256 of one
/// of them) and the exact `clientDataJSON.origin` values allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    pub rp_ids: Vec<String>,
    pub origins: Vec<String>,
}

impl RelyingParty {
    /// One origin, matched exactly, under one RP ID: an explicit `--origin` /
    /// `--rp-id`, a self-hosted or localhost daemon.
    pub fn exact(origin: &str, rp_id: &str) -> Self {
        Self {
            rp_ids: vec![rp_id.to_string()],
            origins: vec![origin.trim_end_matches('/').to_string()],
        }
    }

    /// The console's relying party, from the console origin the daemon stored
    /// at pairing (`https://<host>`). Applies only to the console hosts: a
    /// [`CONSOLE_ROOTS`] entry, or one with a single leading `app.` or `www.`
    /// label, so every stored form on either root of a pair gives the same
    /// party. Its RP IDs are the pair's two roots, new first (passkeys are
    /// pinned to a root, and a passkey made on the legacy root keeps
    /// verifying after the move). Its origins are exactly `https://<root>`,
    /// `https://app.<root>` and `https://www.<root>` for both roots: a list,
    /// not every subdomain, so no other host under either root can produce an
    /// approval. `None` for every other origin (a self-hosted console,
    /// localhost, a non-bare URL); the caller then matches that origin
    /// exactly under its own hostname.
    pub fn console(origin: &str) -> Option<Self> {
        let (new, legacy) = root_pair(console_root_of_origin(origin)?)?;
        Some(Self {
            rp_ids: vec![new.to_string(), legacy.to_string()],
            origins: [new, legacy]
                .iter()
                .flat_map(|root| {
                    [
                        format!("https://{}", root),
                        format!("https://app.{}", root),
                        format!("https://www.{}", root),
                    ]
                })
                .collect(),
        })
    }

    /// Is `origin` (as `clientDataJSON` reports it) one this party accepts?
    pub fn allows(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == origin)
    }

    /// The accepted RP ID an assertion was signed for: the one whose SHA-256
    /// is its `authenticatorData.rpIdHash`. `None` when the authenticator
    /// data does not decode or names none of them.
    fn signed_rp_id(&self, assertion: &AssertionData) -> Option<&str> {
        let auth_data = STANDARD.decode(&assertion.authenticator_data).ok()?;
        let rp_id_hash = auth_data.get(..32)?;
        self.rp_ids
            .iter()
            .find(|id| Sha256::digest(id.as_bytes())[..] == *rp_id_hash)
            .map(String::as_str)
    }
}

/// The `origin` an assertion's `clientDataJSON` reports, if it decodes and
/// the ceremony ran in a top-level (same-origin) context: `crossOrigin`
/// absent or `false`. An assertion made inside a cross-origin frame is
/// refused.
fn reported_origin(assertion: &AssertionData) -> Option<String> {
    let raw = STANDARD.decode(&assertion.client_data_json).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    if !matches!(
        json.get("crossOrigin"),
        None | Some(serde_json::Value::Bool(false))
    ) {
        return None;
    }
    json.get("origin")?.as_str().map(str::to_string)
}

/// Assertion data sent by the browser client.
///
/// Re-export of [`sudp::passkey::WebAuthnAssertion`] so Sprott's own call
/// sites and serde shapes remain unchanged.
pub type AssertionData = WebAuthnAssertion;

/// Verify a WebAuthn `webauthn.get` assertion with channel binding.
///
/// Arguments:
/// - `assertion`: the parsed assertion fields (standard base64).
/// - `x_b64`, `y_b64`: the credential's public-key coordinates, standard base64.
/// - `rp`: the relying party: `clientDataJSON.origin` must be one of its
///   origins, and `authenticatorData.rpIdHash` the hash of one of its RP IDs.
/// - `expected_challenge`: 32-byte β the client should have used as the
///   WebAuthn challenge.
///
/// Returns `Ok(())` on success. Failure returns `AppError::Unauthorized` with
/// a generic message (sudp does not distinguish individual check failures to
/// avoid timing side channels).
pub fn verify_assertion(
    assertion: &AssertionData,
    x_b64: &str,
    y_b64: &str,
    rp: &RelyingParty,
    expected_challenge: &[u8; 32],
) -> Result<()> {
    let failed = || AppError::Unauthorized("WebAuthn assertion verification failed".into());
    // The ceremony must be top-level, the reported origin on the list and the
    // signed rpIdHash one of the listed RP IDs; sudp then checks the origin
    // again (exactly), the type, the challenge, rpIdHash against that RP ID,
    // user presence and the signature over all of it.
    let origin = reported_origin(assertion)
        .filter(|o| rp.allows(o))
        .ok_or_else(failed)?;
    let rp_id = rp.signed_rp_id(assertion).ok_or_else(failed)?.to_string();
    let public_key = WebAuthnPublicKey {
        x: x_b64.to_string(),
        y: y_b64.to_string(),
        device_name: String::new(),
    };
    let context = AuthenticatorContext {
        origin,
        rp_id,
        require_uv: false,
    };
    <WebAuthn as Authenticator>::verify_assertion(
        &public_key,
        expected_challenge,
        assertion,
        &context,
    )
    .map_err(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::{Digest, Sha256};

    /// A real ES256 assertion: signed for `rp_id`, reporting `origin`.
    fn assertion(
        key: &SigningKey,
        rp_id: &str,
        origin: &str,
        challenge: &[u8; 32],
    ) -> AssertionData {
        signed(
            key,
            rp_id,
            serde_json::json!({
                "type": "webauthn.get",
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": origin,
            }),
        )
    }

    /// A real ES256 assertion over `client_data`, signed for `rp_id`.
    fn signed(key: &SigningKey, rp_id: &str, client_data: serde_json::Value) -> AssertionData {
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(0x01); // user present
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        let client_data = serde_json::to_vec(&client_data).unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let sig: Signature = key.sign(&signed);
        AssertionData {
            credential_id: None,
            authenticator_data: STANDARD.encode(&auth_data),
            client_data_json: STANDARD.encode(&client_data),
            signature: STANDARD.encode(sig.to_der().as_bytes()),
        }
    }

    fn xy(key: &SigningKey) -> (String, String) {
        let point = key.verifying_key().to_encoded_point(false);
        (
            STANDARD.encode(point.x().unwrap()),
            STANDARD.encode(point.y().unwrap()),
        )
    }

    /// The prod pair's six origins: root, `app.` and `www.` of each root.
    const PROD_ORIGINS: [&str; 6] = [
        "https://sprott.ai",
        "https://app.sprott.ai",
        "https://www.sprott.ai",
        "https://safeclaw.pro",     // rename:keep
        "https://app.safeclaw.pro", // rename:keep
        "https://www.safeclaw.pro", // rename:keep
    ];

    /// The dev pair's six origins.
    const DEV_ORIGINS: [&str; 6] = [
        "https://dev.sprott.ai",
        "https://app.dev.sprott.ai",
        "https://www.dev.sprott.ai",
        "https://dev.safeclaw.pro",     // rename:keep
        "https://app.dev.safeclaw.pro", // rename:keep
        "https://www.dev.safeclaw.pro", // rename:keep
    ];

    /// The prod and dev pairs, `(new, legacy)`.
    const PROD: (&str, &str) = ("sprott.ai", "safeclaw.pro"); // rename:keep
    const DEV: (&str, &str) = ("dev.sprott.ai", "dev.safeclaw.pro"); // rename:keep

    #[test]
    fn the_console_roots_are_both_pairs() {
        assert_eq!(LEGACY_OF, [PROD, DEV]);
        assert_eq!(CONSOLE_ROOTS, [PROD.0, DEV.0, PROD.1, DEV.1]);
        assert_eq!(CONSOLE_ROOTS[..2], ["sprott.ai", "dev.sprott.ai"]);
    }

    #[test]
    fn either_root_of_a_pair_gives_the_pair_party() {
        // Stored forms with a trailing slash or upper case parse to the same
        // host.
        let prod_also = [
            "https://APP.Sprott.ai/",
            "https://App.SafeClaw.pro/", // rename:keep
        ];
        let dev_also = [
            "https://app.DEV.sprott.ai/",
            "https://www.dev.SAFECLAW.pro/", // rename:keep
        ];
        for (origins, also, (new, legacy)) in [
            (PROD_ORIGINS, prod_also, PROD),
            (DEV_ORIGINS, dev_also, DEV),
        ] {
            for stored in origins.iter().chain(also.iter()) {
                let rp = RelyingParty::console(stored).unwrap();
                assert_eq!(rp.rp_ids, vec![new, legacy], "{stored}");
                assert_eq!(rp.origins, origins, "{stored}");
            }
        }
        for not_console in [
            "http://localhost:23293",
            "http://sprott.ai",
            "https://sprott.ai:8443",
            "https://sprott.ai/console",
            "https://sprott.ai/?q",
            "https://evil.com@app.sprott.ai",
            "https://127.0.0.1",
            "not a url",
            // Any other host, self-hosted consoles included: exact matching.
            "https://vault.corp.example",
            "https://app.corp.example",
            "https://www.corp.example",
            "https://app.example",
            "https://evil.sprott.ai",
            "https://evil-sprott.ai",
            "https://notsprott.ai",
            "https://app.app.sprott.ai",
            "https://www.app.sprott.ai",
            "https://staging.dev.sprott.ai",
            "https://sprott.ai.evil.com",
            "https://app.sprott.ai.evil.com",
            "https://dev.sprott.ai.evil.com",
            "https://sprott.ai.",
            "http://safeclaw.pro",              // rename:keep
            "https://safeclaw.pro:8443",        // rename:keep
            "https://evil.safeclaw.pro",        // rename:keep
            "https://evil-safeclaw.pro",        // rename:keep
            "https://app.app.safeclaw.pro",     // rename:keep
            "https://staging.dev.safeclaw.pro", // rename:keep
            "https://safeclaw.pro.evil.com",    // rename:keep
            "https://sprott.ai.safeclaw.pro",   // rename:keep
            "https://safeclaw.pro.sprott.ai",   // rename:keep
            "https://app.safeclaw.pro.",        // rename:keep
        ] {
            assert!(
                RelyingParty::console(not_console).is_none(),
                "{not_console}"
            );
        }
    }

    #[test]
    fn a_cross_origin_ceremony_is_refused() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let (x, y) = xy(&key);
        let challenge = [5u8; 32];
        let rp = RelyingParty::console("https://app.sprott.ai").unwrap();
        let client_data = |cross: Option<serde_json::Value>| {
            let mut c = serde_json::json!({
                "type": "webauthn.get",
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": "https://app.sprott.ai",
            });
            if let Some(v) = cross {
                c["crossOrigin"] = v;
            }
            c
        };
        for rp_id in [PROD.0, PROD.1] {
            for top_level in [None, Some(serde_json::json!(false))] {
                let a = signed(&key, rp_id, client_data(top_level.clone()));
                verify_assertion(&a, &x, &y, &rp, &challenge)
                    .unwrap_or_else(|e| panic!("{rp_id} crossOrigin {top_level:?}: {e:?}"));
            }
            for cross in [
                serde_json::json!(true),
                serde_json::json!("true"),
                serde_json::json!(1),
                serde_json::Value::Null,
            ] {
                let a = signed(&key, rp_id, client_data(Some(cross.clone())));
                assert!(
                    verify_assertion(&a, &x, &y, &rp, &challenge).is_err(),
                    "{rp_id} crossOrigin {cross:?} accepted"
                );
            }
        }
    }

    /// Every stored form of the pair verifies assertions signed for either
    /// RP ID from any of the pair's six origins, and refuses every other
    /// origin, every other RP ID, another challenge and another key.
    fn pair_verifies(
        origins: [&str; 6],
        (new, legacy): (&str, &str),
        bad_origins: &[&str],
        bad_rp_ids: &[&str],
    ) {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let (x, y) = xy(&key);
        let challenge = [7u8; 32];
        for stored in origins {
            let rp = RelyingParty::console(stored).unwrap();
            for origin in origins {
                for rp_id in [new, legacy] {
                    let a = assertion(&key, rp_id, origin, &challenge);
                    verify_assertion(&a, &x, &y, &rp, &challenge)
                        .unwrap_or_else(|e| panic!("{stored}: {rp_id} from {origin}: {e:?}"));
                }
            }
            for origin in bad_origins {
                for rp_id in [new, legacy] {
                    let a = assertion(&key, rp_id, origin, &challenge);
                    assert!(
                        verify_assertion(&a, &x, &y, &rp, &challenge).is_err(),
                        "{stored} accepted {rp_id} from {origin}"
                    );
                }
            }
            for rp_id in bad_rp_ids {
                for origin in origins {
                    let a = assertion(&key, rp_id, origin, &challenge);
                    assert!(
                        verify_assertion(&a, &x, &y, &rp, &challenge).is_err(),
                        "{stored} accepted RP ID {rp_id} from {origin}"
                    );
                }
            }
            for rp_id in [new, legacy] {
                // A different challenge never verifies.
                let a = assertion(&key, rp_id, origins[1], &[8u8; 32]);
                assert!(verify_assertion(&a, &x, &y, &rp, &challenge).is_err());
                // Nor does another key's signature.
                let other = SigningKey::random(&mut rand::rngs::OsRng);
                let a = assertion(&other, rp_id, origins[1], &challenge);
                assert!(verify_assertion(&a, &x, &y, &rp, &challenge).is_err());
            }
        }
    }

    #[test]
    fn prod_accepts_both_rp_ids_from_both_roots_only() {
        pair_verifies(
            PROD_ORIGINS,
            PROD,
            &[
                "https://evil.sprott.ai",
                "https://evil-sprott.ai",
                "https://sprott.ai.evil.com",
                "https://app.app.sprott.ai",
                "https://appsprott.ai",
                "http://sprott.ai",
                "http://app.sprott.ai",
                "https://sprott.ai:8443",
                "https://SPROTT.ai",
                "https://app.sprott.ai/",
                "https://app.dev.sprott.ai",
                "https://evil.safeclaw.pro",     // rename:keep
                "https://evil-safeclaw.pro",     // rename:keep
                "https://safeclaw.pro.evil.com", // rename:keep
                "https://app.app.safeclaw.pro",  // rename:keep
                "http://app.safeclaw.pro",       // rename:keep
                "https://app.dev.safeclaw.pro",  // rename:keep
                "https://nodpay.ai",
                "http://localhost:23293",
            ],
            &[
                "app.sprott.ai",
                "www.sprott.ai",
                "evil-sprott.ai",
                "sprott.ai.evil.com",
                "app.app.sprott.ai",
                "ai",
                "app.safeclaw.pro", // rename:keep
                "pro",
                DEV.0,
                DEV.1,
                "nodpay.ai",
                "localhost",
            ],
        );
    }

    #[test]
    fn dev_accepts_both_rp_ids_from_both_roots_only() {
        pair_verifies(
            DEV_ORIGINS,
            DEV,
            &[
                "https://sprott.ai",
                "https://app.sprott.ai",
                "https://evil.dev.sprott.ai",
                "https://app.app.dev.sprott.ai",
                "https://dev.sprott.ai.evil.com",
                "https://staging.dev.sprott.ai",
                "https://safeclaw.pro",             // rename:keep
                "https://app.safeclaw.pro",         // rename:keep
                "https://staging.dev.safeclaw.pro", // rename:keep
            ],
            &[
                "app.dev.sprott.ai",
                "sprott.ai",
                "app.dev.safeclaw.pro", // rename:keep
                PROD.0,
                PROD.1,
            ],
        );
    }

    #[test]
    fn an_explicit_origin_is_matched_exactly() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let (x, y) = xy(&key);
        let challenge = [3u8; 32];
        let rp = RelyingParty::exact("https://vault.example.com/", "vault.example.com");
        let ok = assertion(
            &key,
            "vault.example.com",
            "https://vault.example.com",
            &challenge,
        );
        assert!(verify_assertion(&ok, &x, &y, &rp, &challenge).is_ok());
        let app = assertion(
            &key,
            "vault.example.com",
            "https://app.vault.example.com",
            &challenge,
        );
        assert!(verify_assertion(&app, &x, &y, &rp, &challenge).is_err());
        let local = RelyingParty::exact("http://localhost:23293", "localhost");
        let a = assertion(&key, "localhost", "http://localhost:23293", &challenge);
        assert!(verify_assertion(&a, &x, &y, &local, &challenge).is_ok());
    }

    #[test]
    fn console_links_go_to_the_app_host_of_the_new_root() {
        let prod_also = [
            "https://app.sprott.ai/",
            "https://app.safeclaw.pro/", // rename:keep
        ];
        let dev_also = [
            "https://dev.sprott.ai/",
            "https://dev.safeclaw.pro/", // rename:keep
        ];
        for (origins, also, link) in [
            (PROD_ORIGINS, prod_also, "https://app.sprott.ai"),
            (DEV_ORIGINS, dev_also, "https://app.dev.sprott.ai"),
        ] {
            for stored in origins.iter().chain(also.iter()) {
                assert_eq!(console_link_origin(stored), link, "{stored}");
            }
        }
        // Any other origin is linked as given (a trailing slash dropped).
        for (stored, link) in [
            ("https://vault.example.com/", "https://vault.example.com"),
            ("http://localhost:23293", "http://localhost:23293"),
            ("https://evil-sprott.ai", "https://evil-sprott.ai"),
            ("https://app.app.sprott.ai", "https://app.app.sprott.ai"),
            ("https://safeclaw.pro:8443", "https://safeclaw.pro:8443"), // rename:keep
            ("https://evil.safeclaw.pro", "https://evil.safeclaw.pro"), // rename:keep
        ] {
            assert_eq!(console_link_origin(stored), link, "{stored}");
        }
        for (host, root, new) in [
            ("app.dev.sprott.ai", Some(DEV.0), Some(DEV.0)),
            ("app.dev.safeclaw.pro", Some(DEV.1), Some(DEV.0)), // rename:keep
            ("dev.safeclaw.pro", Some(DEV.1), Some(DEV.0)),     // rename:keep
            ("sprott.ai", Some(PROD.0), Some(PROD.0)),
            ("www.sprott.ai", Some(PROD.0), Some(PROD.0)),
            ("app.safeclaw.pro", Some(PROD.1), Some(PROD.0)), // rename:keep
            ("app.app.sprott.ai", None, None),
            ("evil-sprott.ai", None, None),
            ("sprott.ai.evil.com", None, None),
            ("evil-safeclaw.pro", None, None), // rename:keep
            ("vault.example.com", None, None),
        ] {
            assert_eq!(console_root_of_host(host), root, "{host}");
            assert_eq!(console_new_root_of_host(host), new, "{host}");
        }
    }
}
