//! Sprott identity & signing layer — Ed25519 principals (UIK / AIK),
//! self-certifying ids, and the canonical signing-input builders that config
//! signatures, re-key events, root succession, and the server-signed sync
//! envelope are all computed over.
//!
//! ## Boundary — why this lives here and NOT in the `sudp` crate
//!
//! sudp core stays a pure symmetric seal / wrap / grant codec: it knows nothing
//! of UIK, roles, or state signatures (design/sudp-identity-signing-revision.md
//! §0 — "SUDP core 只知道 K + 一把包 K 的 wrapping key + 抽象 authenticator +
//! grant/redeem"). Everything in this module is the Sprott-level extension
//! built *on top* of sudp. We reuse sudp's HKDF (so there is exactly one KDF
//! across the system — see [`storage::item`](crate::storage::item)) but keep our
//! own `safeclaw/v1/*` domain labels, pairwise-disjoint from sudp's `sudp/v1/*`
//! set and from the WebAuthn ECDSA-P256 β verification.
//!
//! ## Layering (design/team-shared-vault-security-model.md §5)
//!
//! `custody (passkey PRF / password KDF / HSM) → UIK → K`.
//!
//! - **UIK** = the human principal: signs config / state (no gesture, one per
//!   account, `user_id = derive_id(User, uik_pub)` = the account's cryptographic
//!   primary key). Custody wraps the UIK *private* key; the vault key `K` is
//!   HPKE-sealed to the UIK *public* key. Adding a device = adding one more
//!   custody wrap of the same UIK — it never touches `K`.
//! - **AIK** = an agent principal: one per agent, derived from a single root
//!   seed. The private key is resident in the daemon/`sc` component and NEVER
//!   enters the agent's environment or crosses a machine. `agent_id =
//!   derive_id(Agent, aik_pub)`; the wire bearer is a separate HKDF output so
//!   bearer rotation (epoch bump) is decoupled from identity continuity.
//!
//! This module is the identity half only: keypairs, ids, and the byte-exact
//! signing inputs. The custody→UIK→K wrap graph lives in the vault key layer;
//! the fold/verify *policy* (which pubkeys are owners, when to accept a signed
//! record) lives in the sync/members layer. Those consume the primitives here.
//!
//! ## Cross-language parity
//!
//! Config records are signed in the browser (TS `@sudp-protocol/authorizer` +
//! `lib/vault-grant.ts`) and verified by the daemon (Rust), so [`config_sig_input`]
//! and [`derive_id`] MUST be byte-identical across Rust and TS. The pinned
//! vectors at the bottom of this file are the contract; the TS side pins the
//! same values. Change one side, change both — and never edit an expected value
//! just to make a test pass; find why the two diverged.

use ed25519_dalek::{Signer, SigningKey};
use sudp::primitives::{Kdf, PrimitiveSuite, StdPrimitives};
use zeroize::Zeroizing;

// The domain labels, ids, `verify` and the signing-input builders live in the
// `sprott-trust` crate (pure, no I/O), so the console runs the same code.
pub use sprott_trust::identity::*;

/// HKDF `info` deriving an agent's Ed25519 identity seed from its root seed.
const AIK_IDENTITY_INFO: &[u8] = b"safeclaw/v1/agent-identity";

/// HKDF `info` (prefix, before the big-endian epoch) deriving an agent's wire
/// bearer from its root seed. Pinned label (memory: single-root keyring).
const AIK_BEARER_INFO: &[u8] = b"sc/agent-bearer";

// ── Signing principal (UIK, or a resolved AIK) ─────────────────────────────

/// An Ed25519 signing principal: holds the private key, can sign and expose its
/// public key / id. Used for a UIK (from custody-unwrapped bytes) and for a
/// resolved AIK (see [`AgentRoot::identity`]).
pub struct SigningIdentity {
    key: SigningKey,
}

impl SigningIdentity {
    /// Build from a 32-byte Ed25519 seed (the secret key). Deterministic:
    /// identical seed ⇒ identical public key and identical signatures.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Mint a fresh principal from the OS CSPRNG. (Foundation convenience; the
    /// production UIK is minted in the onboarding ceremony, an AIK from its root.)
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        Self::from_seed(&seed)
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign a message, returning the 64-byte detached signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    /// This principal's self-certifying id under `kind`.
    pub fn id(&self, kind: IdKind) -> String {
        derive_id(kind, &self.public_bytes())
    }

    /// Convenience: the account primary key `us_…` for a UIK.
    pub fn user_id(&self) -> String {
        self.id(IdKind::User)
    }
}

// ── Agent root (AIK single-root derivation) ────────────────────────────────

/// An agent's single root seed. Everything about the agent derives from this one
/// secret: its Ed25519 identity keypair (⇒ `agent_id`) and its per-epoch wire
/// bearer. Storing one root per agent (memory: keyring `{seed, epoch, name}`)
/// keeps identity and bearer rotation independent while sharing no second secret.
pub struct AgentRoot {
    root: Zeroizing<[u8; 32]>,
}

impl AgentRoot {
    /// Adopt an existing 32-byte root seed.
    pub fn from_seed(root: [u8; 32]) -> Self {
        Self {
            root: Zeroizing::new(root),
        }
    }

    /// Mint a fresh agent root from the OS CSPRNG.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut root = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut root);
        Self::from_seed(root)
    }

    fn hkdf(&self, info: &[u8]) -> [u8; 32] {
        <StdPrimitives as PrimitiveSuite>::Kdf::derive_32(&self.root[..], &[], info)
            .expect("HKDF-SHA256 derive_32 is infallible for a 32-byte root")
    }

    /// The agent's Ed25519 identity, derived from the root (domain-separated
    /// from the bearer). The private key stays in this process.
    pub fn identity(&self) -> SigningIdentity {
        let seed = Zeroizing::new(self.hkdf(AIK_IDENTITY_INFO));
        SigningIdentity::from_seed(&seed)
    }

    /// The wire bearer for `epoch`: `HKDF(root, "sc/agent-bearer" ‖ u32_be(epoch))`.
    /// Rotating the bearer = bumping the epoch; the identity (and thus `agent_id`)
    /// is unchanged.
    pub fn bearer(&self, epoch: u32) -> [u8; 32] {
        let mut info = Vec::with_capacity(AIK_BEARER_INFO.len() + 4);
        info.extend_from_slice(AIK_BEARER_INFO);
        info.extend_from_slice(&epoch.to_be_bytes());
        self.hkdf(&info)
    }

    /// The agent's self-certifying id `ag_…`.
    pub fn agent_id(&self) -> String {
        self.identity().id(IdKind::Agent)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    // ── Correctness (no magic values) ──────────────────────────────────────

    #[test]
    fn id_format_and_stability() {
        let uik = SigningIdentity::from_seed(&[0x42; 32]);
        let id = uik.user_id();
        assert!(id.starts_with("us_"), "user id prefix: {id}");
        assert_eq!(id.len(), 3 + 32, "us_ + 32 base32 chars");
        assert_eq!(id, uik.user_id(), "id is deterministic");
        // Agent and user id spaces are prefix-disjoint for the same key.
        assert_ne!(uik.id(IdKind::User), uik.id(IdKind::Agent));
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let uik = SigningIdentity::from_seed(&[7; 32]);
        let pk = uik.public_bytes();
        let msg = b"the owner signs the policy";
        let sig = uik.sign(msg);
        assert!(verify(&pk, msg, &sig));
        // Tampered message fails.
        assert!(!verify(&pk, b"the owner signs the polici", &sig));
        // Wrong key fails.
        let other = SigningIdentity::from_seed(&[8; 32]).public_bytes();
        assert!(!verify(&other, msg, &sig));
        // Tampered signature fails.
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!verify(&pk, msg, &bad));
    }

    #[test]
    fn signatures_are_deterministic() {
        // Ed25519 is deterministic (RFC 8032): same key + msg ⇒ same signature.
        let uik = SigningIdentity::from_seed(&[0x42; 32]);
        let m = b"deterministic?";
        assert_eq!(uik.sign(m), uik.sign(m));
    }

    #[test]
    fn generate_is_random() {
        assert_ne!(
            SigningIdentity::generate().public_bytes(),
            SigningIdentity::generate().public_bytes()
        );
    }

    #[test]
    fn aik_bearer_rotates_identity_stable() {
        let root = AgentRoot::from_seed([0x11; 32]);
        let id0 = root.agent_id();
        assert!(id0.starts_with("ag_"));
        // Identity (hence id) is stable across bearer epochs.
        assert_eq!(id0, root.agent_id());
        // Distinct epochs give distinct bearers; identity unchanged.
        assert_ne!(root.bearer(0), root.bearer(1));
        assert_eq!(root.bearer(3), AgentRoot::from_seed([0x11; 32]).bearer(3));
        // Bearer is domain-separated from the identity seed (no accidental reuse).
        assert_ne!(
            root.bearer(0).to_vec(),
            root.identity().public_bytes().to_vec()
        );
    }

    #[test]
    fn config_sig_input_live_vs_tombstone_differ() {
        let live = config_sig_input("v1", "policy", 3, Some(b"{\"a\":1}"), "us_owner");
        let tomb = config_sig_input("v1", "policy", 3, None, "us_owner");
        assert_ne!(live, tomb, "status byte + body hash separate the two");
    }

    #[test]
    fn config_sig_input_lp_ambiguity_resolved() {
        // Without length prefixes ("ab","c") and ("a","bc") for (vault, ns)
        // would collide; with them the inputs differ.
        let a = config_sig_input("ab", "c", 1, Some(b"x"), "s");
        let b = config_sig_input("a", "bc", 1, Some(b"x"), "s");
        assert_ne!(a, b);
    }

    #[test]
    fn record_signature_input_every_field_binds() {
        let base = record_signature_input("secret", b"\x01\x02", 3, "v1", b"ct", true, "us_a");
        assert_ne!(base, record_signature_input("connection", b"\x01\x02", 3, "v1", b"ct", true, "us_a"), "type binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x03", 3, "v1", b"ct", true, "us_a"), "item_id binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 4, "v1", b"ct", true, "us_a"), "version binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 3, "v2", b"ct", true, "us_a"), "vault binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 3, "v1", b"ct", false, "us_a"), "status (live/tombstone) binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 3, "v1", b"CT", true, "us_a"), "sealed body binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 3, "v1", b"ct", true, "dev_a"), "principal binds");
        assert_eq!(base, record_signature_input("secret", b"\x01\x02", 3, "v1", b"ct", true, "us_a"), "deterministic");
    }

    #[test]
    fn record_signature_input_lp_ambiguity_resolved() {
        // ("ab","c") vs ("a","bc") for (type, item_id) would collide without
        // length prefixes; with them the inputs differ.
        let a = record_signature_input("ab", b"c", 1, "v", b"x", true, "s");
        let b = record_signature_input("a", b"bc", 1, "v", b"x", true, "s");
        assert_ne!(a, b);
    }

    #[test]
    fn record_signature_roundtrip_and_type_tamper() {
        // A principal signs a record; the daemon/server verify over the SAME
        // input (built from the plaintext type + the ciphertext hash). Swapping
        // the plaintext type to bypass the write-gate breaks verification —
        // the signature binds type↔sealed content (A1.3, kills type-class 越权).
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        let input = record_signature_input("agent", b"\xaa\xbb\xcc", 2, "vault-x", b"sealed-ct", true, &uik.user_id());
        let sig = uik.sign(&input);
        assert!(verify(&uik.public_bytes(), &input, &sig), "own signature verifies");
        let swapped = record_signature_input("secret", b"\xaa\xbb\xcc", 2, "vault-x", b"sealed-ct", true, &uik.user_id());
        assert!(!verify(&uik.public_bytes(), &swapped, &sig), "a swapped plaintext type must not verify");
    }

    #[test]
    fn device_request_signature_input_every_field_binds() {
        let base = device_request_signature_input("GET", "/p", 1, b"body", "dev_a");
        assert_ne!(base, device_request_signature_input("PUT", "/p", 1, b"body", "dev_a"), "method binds");
        assert_ne!(base, device_request_signature_input("GET", "/q", 1, b"body", "dev_a"), "path binds");
        assert_ne!(base, device_request_signature_input("GET", "/p", 2, b"body", "dev_a"), "timestamp binds");
        assert_ne!(base, device_request_signature_input("GET", "/p", 1, b"BODY", "dev_a"), "body binds");
        assert_ne!(base, device_request_signature_input("GET", "/p", 1, b"body", "dev_b"), "device_id binds");
        assert_eq!(base, device_request_signature_input("GET", "/p", 1, b"body", "dev_a"), "deterministic");
    }

    #[test]
    fn device_request_signature_input_lp_ambiguity_resolved() {
        // ("GET","/p") vs ("GE","T/p") for (method, path) would collide without
        // length prefixes; with them the inputs differ.
        let a = device_request_signature_input("GET", "/p", 1, b"", "d");
        let b = device_request_signature_input("GE", "T/p", 1, b"", "d");
        assert_ne!(a, b);
    }

    #[test]
    fn device_request_roundtrip_and_path_tamper() {
        // The daemon signs a request with its DIK; the backend verifies over the
        // SAME input rebuilt from the wire (method/path/ts/body/device_id).
        // Replaying the signature onto a different path must fail — the DIK
        // signature binds the request, not just the device.
        let dik = SigningIdentity::from_seed(&UIK_SEED);
        let dev_id = derive_id(IdKind::Device, &dik.public_bytes());
        let input = device_request_signature_input("PUT", "/v/vault-x/membership", 1_700_000_000, b"{}", &dev_id);
        let sig = dik.sign(&input);
        assert!(verify(&dik.public_bytes(), &input, &sig), "own signature verifies");
        let tampered = device_request_signature_input("PUT", "/v/vault-y/membership", 1_700_000_000, b"{}", &dev_id);
        assert!(!verify(&dik.public_bytes(), &tampered, &sig), "a swapped path must not verify");
    }

    #[test]
    fn pinned_device_request_signature_input() {
        // K-vector: GET, path "/api/vault/agents/hashes", ts 1700000000, empty
        // body, device "dev_box". The Node backend mirror pins the same bytes.
        let input = device_request_signature_input("GET", "/api/vault/agents/hashes", 1_700_000_000, b"", "dev_box");
        assert_eq!(hex(&input), "0000001673616665636c61772f76312f6465766963652d72657100000003474554000000182f6170692f7661756c742f6167656e74732f686173686573000000006553f10000000020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855000000076465765f626f78");
    }

    #[test]
    fn agent_proxy_pop_input_every_field_binds() {
        let base = agent_proxy_pop_input("v1", "api.x.com:443", 1, "ag_a");
        assert_ne!(base, agent_proxy_pop_input("v2", "api.x.com:443", 1, "ag_a"), "vault binds");
        assert_ne!(base, agent_proxy_pop_input("v1", "api.y.com:443", 1, "ag_a"), "target binds");
        assert_ne!(base, agent_proxy_pop_input("v1", "api.x.com:443", 2, "ag_a"), "timestamp binds");
        assert_ne!(base, agent_proxy_pop_input("v1", "api.x.com:443", 1, "ag_b"), "agent_id binds");
        assert_eq!(base, agent_proxy_pop_input("v1", "api.x.com:443", 1, "ag_a"), "deterministic");
    }

    #[test]
    fn agent_proxy_pop_roundtrip_and_target_tamper() {
        // The sc transport signs a CONNECT with the AIK; the daemon rebuilds the
        // input from the CONNECT context (vid + target + ts + derived ag_id) and
        // verifies. Replaying the signature onto a different target must fail —
        // the token binds the destination, not just the agent.
        let aik = SigningIdentity::from_seed(&UIK_SEED);
        let ag = derive_id(IdKind::Agent, &aik.public_bytes());
        let input = agent_proxy_pop_input("vault-x", "api.openai.com:443", 1_700_000_000, &ag);
        let sig = aik.sign(&input);
        assert!(verify(&aik.public_bytes(), &input, &sig), "own signature verifies");
        let elsewhere = agent_proxy_pop_input("vault-x", "evil.example:443", 1_700_000_000, &ag);
        assert!(!verify(&aik.public_bytes(), &elsewhere, &sig), "a swapped target must not verify");
    }

    #[test]
    fn pinned_agent_proxy_pop_input() {
        // K-vector: vault "vault-7", target "api.x:443", ts 1700000000, agent "ag_a".
        let input = agent_proxy_pop_input("vault-7", "api.x:443", 1_700_000_000, "ag_a");
        assert_eq!(hex(&input), "0000001b73616665636c61772f76312f6167656e742d70726f78792d706f70000000077661756c742d37000000096170692e783a343433000000006553f1000000000461675f61");
    }

    #[test]
    fn pinned_record_signature_input() {
        // K-vector: type "secret", id 0x0102, version 7, vault "vault-7",
        // sealed body b"ct", live, principal "us_owner". Mirror pins the same.
        let input = record_signature_input("secret", b"\x01\x02", 7, "vault-7", b"ct", true, "us_owner");
        assert_eq!(hex(&input), "00000010737564702f76312f6974656d2d736967000000067365637265740000000201020000000000000007000000077661756c742d370100000020f8dcb34308e5c69f46a33cafa62bd922476b18c78a114eb144e34a5e374f7d600000000875735f6f776e6572");
    }

    // ── Pinned cross-language vectors ───────────────────────────────────────
    // Established first-party here; the TS `@sudp-protocol/authorizer` mirror
    // pins the same values when config-signing lands there. Do NOT edit an
    // expected value to make a test pass — find why Rust ↔ TS diverged.
    // (Filled from the first `cargo test identity` run.)

    const UIK_SEED: [u8; 32] = [0x42; 32];
    const AIK_ROOT: [u8; 32] = [0x11; 32];

    #[test]
    fn pinned_uik_pubkey_and_id() {
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        assert_eq!(
            hex(&uik.public_bytes()),
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        );
        assert_eq!(uik.user_id(), "us_gcl6fxxcznfdjnjyidg3obno24igpq3p");
    }

    #[test]
    fn pinned_config_sig_input() {
        // K-vector: vault "vault-7", ns "policy", version 5, body {"k":"v"},
        // signer "us_owner".
        let input = config_sig_input("vault-7", "policy", 5, Some(b"{\"k\":\"v\"}"), "us_owner");
        assert_eq!(hex(&input), "0000001673616665636c61772f76312f636f6e6669672d736967000000077661756c742d3700000006706f6c69637900000000000000050100000020666c1aa02e8068c6d5cc1d3295009432c16790bec28ec8ce119d0d1a18d613190000000875735f6f776e6572");
    }

    #[test]
    fn pinned_config_signature() {
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        let input = config_sig_input("vault-7", "policy", 5, Some(b"{\"k\":\"v\"}"), "us_owner");
        let sig = uik.sign(&input);
        assert_eq!(hex(&sig), "b6dcc1bd43082cfb16789191d73c65c9213093e2f827ca7e35084cd699668b668b798f97d47c8bb1ca584811f339f3f40430259a192d8c9bcef94a4f4d304304");
        assert!(verify(&uik.public_bytes(), &input, &sig));
    }

    #[test]
    fn pinned_aik_identity_and_bearer() {
        let root = AgentRoot::from_seed(AIK_ROOT);
        assert_eq!(
            hex(&root.identity().public_bytes()),
            "2a25e722dc68abfe33f7d78adc91904ed0c9b7f74b17c52e8338968c87e2357b"
        );
        assert_eq!(root.agent_id(), "ag_n7smudy334mfsttpye6oedc3fqp7pjrf");
        assert_eq!(
            hex(&root.bearer(0)),
            "48922af2f82a4ba05581440fec31d0ef06f22571f0c5f59117d06b656ab6e4b3"
        );
    }

    #[test]
    fn pinned_server_envelope_input() {
        // K-vector: vault "vault-7", kind "shared", format 2, membership_epoch 1,
        // issued_at 1000, nonce = 0xAA*12. The server key signs this exact
        // layout; the Node backend mirror pins the same hex.
        let input = server_envelope_input("vault-7", "shared", 2, 1, 1000, &[0xAA; 12]);
        assert_eq!(hex(&input), "0000001b73616665636c61772f76312f7365727665722d656e76656c6f7065000000077661756c742d37000000067368617265640000000000000002000000000000000100000000000003e80000000caaaaaaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn pinned_contact_token_input() {
        // K-vector: vault "vault-7", account "acc-1", issued_at 1000,
        // nonce = 0xBB*12. Mirrored by the Node backend.
        let input = contact_token_input("vault-7", "acc-1", 1000, &[0xBB; 12]);
        assert_eq!(hex(&input), "0000001973616665636c61772f76312f636f6e746163742d746f6b656e000000077661756c742d37000000056163632d3100000000000003e80000000cbbbbbbbbbbbbbbbbbbbbbbbb");
    }

    #[test]
    fn pinned_rekey_vectors() {
        // DP-S1 re-key golden vectors (Part 2). FIXED inputs:
        //   vault "vault-7", generation 5, content = 0x9a*32, signer "us_owner",
        //   k_commitment = rekey_commitment(content).
        // The browser mirror (lib/uik-crypto.ts) pins the SAME hex in
        // scripts/verify-uik-crypto.mts. Do NOT edit an expected value to make a
        // test pass — find why Rust ↔ TS diverged.
        let content = [0x9au8; 32];
        let commit = crate::storage::sealed_vault::rekey_commitment(&content);
        assert_eq!(
            hex(&commit),
            "9f3fe20e9995e64c9403e734e2a3dce8fd7a8659cc05d9995cbd277c27d6f499"
        );
        // Membership anti-rollback commitment over an EMPTY log prefix (membership_len 0).
        let membership = membership_commitment(&[]);
        assert_eq!(
            hex(&membership),
            "2f12a37c5a33eff8fca2c3623090a825c377cd051cf786dddfc5dd3286d631af"
        );
        // Non-empty prefix (two sigs) — exercises the sig-concat path cross-language.
        let sig_a = [0xAAu8; 64];
        let sig_b = [0xBBu8; 64];
        assert_eq!(
            hex(&membership_commitment(&[&sig_a, &sig_b])),
            "b70c763903e84f63d918943fccb98554f1f384e4a42e0d59c44d54eae0feb3ca"
        );
        let input = rekey_sig_input("vault-7", 5, &commit, "us_owner", 0, &membership);
        assert_eq!(
            hex(&input),
            "0000001173616665636c61772f76312f72656b6579000000077661756c742d370000000000000005000000209f3fe20e9995e64c9403e734e2a3dce8fd7a8659cc05d9995cbd277c27d6f4990000000875735f6f776e65720000000000000000000000202f12a37c5a33eff8fca2c3623090a825c377cd051cf786dddfc5dd3286d631af"
        );
    }

    #[test]
    fn pinned_role_grant_input() {
        // Owner-authority role-grant golden vector (design/identity-uik-aik.md
        // §4.3). FIXED inputs: vault "vault-7", user "us_alice", role "member",
        // generation 3. The browser mirror pins the SAME hex when role-grant
        // signing lands there. Do NOT edit an expected value to make a test pass
        // — find why Rust ↔ TS diverged.
        let input = role_grant_input("vault-7", "us_alice", "member", 3);
        assert_eq!(
            hex(&input),
            "0000001673616665636c61772f76312f726f6c652d6772616e74000000077661756c742d370000000875735f616c696365000000066d656d6265720000000000000003"
        );
        // Role is bound: the same (vault, user, generation) under a different role differs.
        let owner = role_grant_input("vault-7", "us_alice", "owner", 3);
        assert_ne!(input, owner, "role token is part of the signed input");
        // F3-b generation-binding: the SAME (vault, user, role) at a different
        // generation differs, so a stale grant can't be replayed after a re-key.
        let next_gen = role_grant_input("vault-7", "us_alice", "member", 4);
        assert_ne!(input, next_gen, "generation is part of the signed input");
    }

    #[test]
    fn pinned_derive_id() {
        // Cross-language derive_id vector (base32-lower of SHA-256(pubkey)[..20]). The
        // backend + browser mirrors pin the SAME strings so the succession-chain id
        // binding (`new_root_id == derive_id(new_pub)`) agrees byte-for-byte.
        assert_eq!(
            derive_id(IdKind::User, &[0x11u8; 32]),
            "us_alketiy7xmthzdzvf2mwrj46hzp4sxa3"
        );
        assert_eq!(
            derive_id(IdKind::User, &[0x22u8; 32]),
            "us_t5zoudhusu3ohrtmpb7xaumg36neg6ai"
        );
    }

    #[test]
    fn pinned_delegation_event_input() {
        // Delegation-event golden vector (delegation-log-impl-spec.md §1.1). FIXED
        // inputs: vault "vault-7", op "set", subject "us_bob", role "owner", granter
        // "us_alice", seq 5, role_epoch 2. The browser + backend mirrors pin the SAME
        // hex. Do NOT edit an expected value to make a test pass — find why the
        // implementations diverged.
        let input = delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2);
        assert_eq!(
            hex(&input),
            "0000001c73616665636c61772f76312f64656c65676174696f6e2d6576656e74000000077661756c742d37000000037365740000000675735f626f62000000056f776e65720000000875735f616c69636500000000000000050000000000000002"
        );
        // A `remove` carries an EMPTY role token (so the same subject can't be spliced
        // between a set and a remove), and the seq / role_epoch are fixed-width tails.
        let remove = delegation_event_input("vault-7", "remove", "us_bob", "", "us_alice", 6, 2);
        assert_eq!(
            hex(&remove),
            "0000001c73616665636c61772f76312f64656c65676174696f6e2d6576656e74000000077661756c742d370000000672656d6f76650000000675735f626f62000000000000000875735f616c69636500000000000000060000000000000002"
        );
        // seq and role_epoch are both part of the signed input (reorder / replay guard).
        assert_ne!(
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2),
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 6, 2),
            "seq is bound"
        );
        assert_ne!(
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2),
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 3),
            "role_epoch is bound"
        );
    }

    #[test]
    fn pinned_root_succession_input() {
        // Root-succession golden vector (delegation-log-impl-spec.md §1.2). FIXED
        // inputs: vault "vault-7", old_root "us_alice", new_root "us_bob",
        // new_root_sig_pub = 32×0x11, role_epoch 4. Mirrors pin the SAME hex.
        let pub_key = [0x11u8; 32];
        let input = root_succession_input("vault-7", "us_alice", "us_bob", &pub_key, 4);
        assert_eq!(
            hex(&input),
            "0000001b73616665636c61772f76312f726f6f742d73756363657373696f6e000000077661756c742d370000000875735f616c6963650000000675735f626f620000002011111111111111111111111111111111111111111111111111111111111111110000000000000004"
        );
        // The new root's pubkey is bound (a colluding server can't swap in a key it
        // controls) and the epoch is a fixed-width tail (rollback guard).
        assert_ne!(
            input,
            root_succession_input("vault-7", "us_alice", "us_bob", &[0x22u8; 32], 4),
            "new_root_sig_pub is bound"
        );
        assert_ne!(
            input,
            root_succession_input("vault-7", "us_alice", "us_bob", &pub_key, 5),
            "role_epoch is bound"
        );
    }

    #[test]
    fn principal_event_input_every_field_binds() {
        let base = principal_event_input("us_acct", "admit", "dev_box", 5, "us_acct", &[]);
        assert_ne!(base, principal_event_input("us_other", "admit", "dev_box", 5, "us_acct", &[]), "account binds");
        assert_ne!(base, principal_event_input("us_acct", "revoke", "dev_box", 5, "us_acct", &[]), "op binds");
        assert_ne!(base, principal_event_input("us_acct", "admit", "ag_bot", 5, "us_acct", &[]), "principal binds");
        assert_ne!(base, principal_event_input("us_acct", "admit", "dev_box", 6, "us_acct", &[]), "seq binds");
        assert_ne!(base, principal_event_input("us_acct", "admit", "dev_box", 5, "us_other", &[]), "owner binds");
        assert_ne!(base, principal_event_input("us_acct", "admit", "dev_box", 5, "us_acct", &[1u8; 32]), "sc_pk binds");
        assert_eq!(base, principal_event_input("us_acct", "admit", "dev_box", 5, "us_acct", &[]), "deterministic");
    }

    #[test]
    fn principal_event_input_lp_ambiguity_resolved() {
        // ("ab","c") vs ("a","bc") for (account, op) would collide without length
        // prefixes; with them the inputs differ.
        let a = principal_event_input("ab", "c", "d", 1, "s", &[]);
        let b = principal_event_input("a", "bc", "d", 1, "s", &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn principal_event_roundtrip_and_op_tamper() {
        // The account owner signs an admit/revoke with their UIK; the daemon
        // rebuilds the input and verifies against the account anchor (the UIK that
        // self-certifies account_id). Replaying an `admit` signature as a `revoke`
        // (or vice versa) must fail — op is bound.
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        let acct = uik.user_id();
        let input = principal_event_input(&acct, "revoke", "dev_box", 9, &acct, &[]);
        let sig = uik.sign(&input);
        assert!(verify(&uik.public_bytes(), &input, &sig), "own signature verifies");
        let flipped = principal_event_input(&acct, "admit", "dev_box", 9, &acct, &[]);
        assert!(!verify(&uik.public_bytes(), &flipped, &sig), "a swapped op must not verify");
    }

    #[test]
    fn pinned_principal_event_input() {
        // §15 account principal-ledger golden vector. FIXED inputs: account
        // "us_acct", op "revoke", principal "dev_box", seq 7, owner "us_acct".
        // The TS mirror (Phase 3) pins the SAME hex. Do NOT edit an expected value
        // to make a test pass — find why Rust ↔ TS diverged. Contract C1 (grant-v3)
        // appended `lp(sc_pk)`, empty for a revoke: the trailing 00000000.
        let input = principal_event_input("us_acct", "revoke", "dev_box", 7, "us_acct", &[]);
        assert_eq!(hex(&input), "0000001b73616665636c61772f76312f7072696e636970616c2d6576656e740000000775735f61636374000000067265766f6b65000000076465765f626f7800000000000000070000000775735f6163637400000000");
    }

    #[test]
    fn pinned_vault_tombstone_input() {
        // §15 leg-A golden vector. FIXED input: vault "vault-7". The Node (keyset-roles)
        // + TS (uik-crypto) mirrors pin the SAME hex. Do NOT edit an expected value to
        // make a test pass — find why Rust ↔ Node ↔ TS diverged.
        let input = vault_tombstone_input("vault-7");
        assert_eq!(hex(&input), "0000001b73616665636c61772f76312f7661756c742d746f6d6273746f6e65000000077661756c742d37");
    }

    #[test]
    fn vault_tombstone_roundtrip_and_vault_tamper() {
        // The owner signs a tombstone; the daemon rebuilds the input and verifies. A
        // signature over vault A must NOT verify as a tombstone for vault B (vault_id bound).
        let owner = SigningIdentity::from_seed(&UIK_SEED);
        let sig = owner.sign(&vault_tombstone_input("vault-a"));
        assert!(verify(&owner.public_bytes(), &vault_tombstone_input("vault-a"), &sig));
        assert!(!verify(&owner.public_bytes(), &vault_tombstone_input("vault-b"), &sig), "vault_id is bound");
    }
}
