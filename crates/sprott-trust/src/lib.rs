//! The vault membership and signature rules shared by the Sprott daemon and the
//! console: the keyset's UIK layer, the role fold, the honoring rules for signed
//! rows, the signing inputs they are verified over, and the adoption of served
//! membership into a keyset.
//!
//! Pure by construction: no I/O, no async runtime, no daemon state, no
//! randomness. The daemon calls it with its stored keyset; the console (as
//! wasm) calls it with the keyset adopted from the served membership alone.

pub mod adopt;
pub mod identity;
pub mod keyset;
pub mod trust;

pub use keyset::{
    decode_keys_data_field, rekey_commitment, role_sig_tokens, DelegationEvent, KeysFieldError,
    KeysetUik, MemberRole, RekeyProof, RootSuccession, UikCred,
};
pub use trust::{ApprovalAuthority, MembershipTrust};
