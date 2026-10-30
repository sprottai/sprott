//! Two guards for the 2.0 rename.
//!
//! 1. The cryptographic domain strings are frozen. They are inputs to HKDF,
//!    signatures, the WebAuthn PRF and SPAKE2; one changed byte makes existing
//!    vaults, passkey-derived keys, signatures and pairings unreadable. Every
//!    such byte-string literal in `src/` and `crates/` must be exactly the list
//!    below.
//! 2. Shipped text names no pre-2.0 name (`safeclaw`, `__sc__`, `x-sc-device`)
//!    outside the KEEP list: the frozen strings, the OAuth loopback redirect,
//!    the `safeclaw` command link, lines marked `rename:keep`, and the files
//!    that exist to name old things (the move, its tests).

use std::path::{Path, PathBuf};

/// (file, literal as written in the source). Duplicates are real uses.
const FROZEN: &[(&str, &str)] = &[
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/agent-proxy-pop"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/config-sig"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/contact-token"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/delegation-event"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/device-req"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/grant-id"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/membership-commit"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/principal-event"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/principal-head"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/rekey"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/role-grant"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/root-succession"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/server-envelope"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/uik-succession"),
    ("crates/sprott-trust/src/identity.rs", "safeclaw/v1/vault-tombstone"),
    ("crates/sprott-trust/src/identity.rs", "sudp/v1/item-sig"),
    ("crates/sprott-trust/src/keyset.rs", "safeclaw/v1/rekey-kc"),
    ("src/approval/store.rs", "safeclaw/v1/intent"),
    ("src/approval/store.rs", "safeclaw/v1/intent"),
    ("src/cli/webauthn.rs", "safeclaw-prf-v1"),
    ("src/cli/webauthn.rs", "sudp/v1/webauthn-prf-userkey"),
    ("src/crypto/aead.rs", "safeclaw/v1/test"),
    ("src/crypto/batch.rs", "safeclaw/v1/batch-approve"),
    ("src/crypto/binding.rs", "safeclaw/v1/binding"),
    ("src/crypto/binding.rs", "safeclaw/v1/binding-setup"),
    ("src/crypto/envelope.rs", "safeclaw/v1/grant-k-seal"),
    ("src/crypto/envelope.rs", "safeclaw/v1/grant-k-seal"),
    ("src/crypto/envelope.rs", "safeclaw/v1/grant-seal"),
    ("src/crypto/kdf.rs", "safeclaw/v1/userkey\\x00"),
    ("src/crypto/vault_key.rs", "safeclaw/v1/uik-encryption"),
    ("src/crypto/vault_key.rs", "safeclaw/v1/uik-identity"),
    ("src/crypto/vault_key.rs", "safeclaw/v1/uik-kseal"),
    ("src/identity.rs", "safeclaw/v1/agent-identity"),
    ("src/identity.rs", "sc/agent-bearer"),
    ("src/pairing.rs", "safeclaw/v1/pair"),
    ("src/pairing.rs", "safeclaw/v1/pair/keys"),
    ("src/pairing.rs", "safeclaw/v1/pair/keys-set"),
    ("src/pairing.rs", "safeclaw/v1/pair/owner"),
    ("src/state.rs", "safeclaw/v1/op-payload"),
    ("src/storage/item.rs", "safeclaw/item-id/v1"),
];

/// The OAuth loopback redirect registered at providers and stored inside
/// sealed connection records.
const LOOPBACK_REDIRECT: &str = "http://127.0.0.1:8765/safeclaw/oauth/callback";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rel(p: &Path) -> String {
    p.strip_prefix(root()).unwrap_or(p).display().to_string()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn crypto_domain_strings_are_frozen() {
    let lit = regex::Regex::new(r#"b"((?:safeclaw[-/]|sc/agent-bearer|sudp/v1/)[^"]*)""#).unwrap();
    let mut files = Vec::new();
    walk(&root().join("src"), &mut files);
    walk(&root().join("crates"), &mut files);
    let mut found: Vec<(String, String)> = Vec::new();
    for f in files
        .iter()
        .filter(|f| f.extension().is_some_and(|e| e == "rs"))
    {
        let text = std::fs::read_to_string(f).unwrap();
        for c in lit.captures_iter(&text) {
            found.push((rel(f), c[1].to_string()));
        }
    }
    found.sort();
    let mut want: Vec<(String, String)> = FROZEN
        .iter()
        .map(|(f, s)| (f.to_string(), s.to_string()))
        .collect();
    want.sort();
    assert_eq!(
        found, want,
        "a cryptographic domain string changed, moved or appeared"
    );

    // The constants, by value.
    use crate::identity as id;
    for (c, s) in [
        (id::DS_CONFIG_SIG, "safeclaw/v1/config-sig"),
        (id::DS_REKEY, "safeclaw/v1/rekey"),
        (id::DS_ROLE_GRANT, "safeclaw/v1/role-grant"),
        (id::DS_DELEGATION, "safeclaw/v1/delegation-event"),
        (id::DS_ROOT_SUCCESSION, "safeclaw/v1/root-succession"),
        (id::DS_PRINCIPAL_EVENT, "safeclaw/v1/principal-event"),
        (id::DS_VAULT_TOMBSTONE, "safeclaw/v1/vault-tombstone"),
        (id::DS_SUCCESSION, "safeclaw/v1/uik-succession"),
        (id::DS_SERVER_ENVELOPE, "safeclaw/v1/server-envelope"),
        (id::DS_CONTACT_TOKEN, "safeclaw/v1/contact-token"),
        (id::DS_DEVICE_REQ, "safeclaw/v1/device-req"),
        (id::DS_AGENT_PROXY_POP, "safeclaw/v1/agent-proxy-pop"),
        (id::DS_ITEM_SIG, "sudp/v1/item-sig"),
        (id::DS_GRANT_ID, "safeclaw/v1/grant-id"),
        (id::DS_PRINCIPAL_HEAD, "safeclaw/v1/principal-head"),
        (crate::pairing::DS_PAIR, "safeclaw/v1/pair"),
        (crate::pairing::DS_PAIR_KEYS, "safeclaw/v1/pair/keys"),
        (
            crate::pairing::DS_PAIR_KEYS_SET,
            "safeclaw/v1/pair/keys-set",
        ),
        (crate::pairing::DS_PAIR_OWNER, "safeclaw/v1/pair/owner"),
        (crate::approval::store::INTENT_TAG, "safeclaw/v1/intent"),
        (crate::crypto::batch::BATCH_TAG, "safeclaw/v1/batch-approve"),
        (
            crate::crypto::binding::DOMAIN_STANDARD,
            "safeclaw/v1/binding",
        ),
        (
            crate::crypto::binding::DOMAIN_SETUP,
            "safeclaw/v1/binding-setup",
        ),
        (
            crate::crypto::envelope::GRANT_SEAL_INFO_PREFIX,
            "safeclaw/v1/grant-seal",
        ),
        (
            crate::crypto::envelope::GRANT_K_SEAL_INFO_PREFIX,
            "safeclaw/v1/grant-k-seal",
        ),
        (crate::cli::webauthn::PRF_EVAL_SALT, "safeclaw-prf-v1"),
    ] {
        assert_eq!(c, s.as_bytes(), "{s}");
    }

    // The shared batch vectors carry the tag too.
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("crypto/batch_vectors.json")).unwrap();
    assert_eq!(vectors["tag"], "safeclaw/v1/batch-approve");

    // The OAuth loopback redirect, and every compiled service that names one.
    assert_eq!(crate::service::DEFAULT_LOOPBACK_REDIRECT, LOOPBACK_REDIRECT);
    let mut with_redirect = 0;
    for (id, toml) in crate::generated_services::compiled_service_tomls() {
        for line in toml
            .lines()
            .filter(|l| l.trim_start().starts_with("redirect_uri") && l.contains(":8765/"))
        {
            assert!(
                line.contains(&format!("\"{LOOPBACK_REDIRECT}\"")),
                "{id}: {line}"
            );
            with_redirect += 1;
        }
    }
    assert!(
        with_redirect >= 9,
        "the Google services name the loopback redirect"
    );
}

/// Files the binary embeds or the site and installer serve.
fn shipped_files() -> Vec<PathBuf> {
    let r = root();
    let mut out = Vec::new();
    for dir in [
        "src", "crates", "services", "skills", "docs", "static", "demo", "examples", "fuzz",
    ] {
        walk(&r.join(dir), &mut out);
    }
    for f in [
        "install.sh",
        "README.md",
        "Cargo.toml",
        "build.rs",
        ".github/workflows/release.yml",
    ] {
        out.push(r.join(f));
    }
    out.retain(|p| {
        let rel = rel(p);
        let text_like = [
            "rs", "toml", "md", "sh", "yml", "json", "svg", "tape", "txt", "html",
        ]
        .iter()
        .any(|e| p.extension().is_some_and(|x| x == *e))
            || p.file_name().is_some_and(|n| n == "install.sh");
        text_like
            // Not compiled (build.rs skips `_`-prefixed service dirs).
            && !rel.starts_with("services/_")
            // The move from ~/.safeclaw names every old path, by design.
            && !rel.starts_with("src/cli/migrate")
            // A cross-language test vector file, shared with the console.
            && rel != "src/crypto/batch_vectors.json"
            // This file.
            && rel != "src/rename_guard.rs"
            // `#[cfg(test)] mod tests;` files: test code, not shipped.
            && !p.file_name().is_some_and(|n| n == "tests.rs")
    });
    out
}

/// `text` with every `#[cfg(test)] mod ... { ... }` block blanked: test code
/// is not shipped. Braces inside strings, raw strings, chars and comments are
/// skipped while matching.
fn without_test_modules(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    let mut i = 0;
    while i < lines.len() {
        let is_test_mod = lines[i].trim() == "#[cfg(test)]"
            && lines
                .get(i + 1)
                .is_some_and(|l| l.trim_start().contains("mod ") && l.trim_end().ends_with('{'));
        if !is_test_mod {
            i += 1;
            continue;
        }
        let start = i;
        let body: String = lines[i + 1..].join("\n");
        let len = matching_brace_end(&body);
        let blanked_lines = body[..len].matches('\n').count() + 2;
        for line in out.iter_mut().skip(start).take(blanked_lines) {
            line.clear();
        }
        i = start + blanked_lines;
    }
    out.join("\n")
}

/// Byte length of `s` up to and including the `}` that closes its first `{`.
fn matching_brace_end(s: &str) -> usize {
    let b = s.as_bytes();
    let (mut i, mut depth) = (0usize, 0i32);
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b'r' if matches!(b.get(i + 1), Some(b'#') | Some(b'"'))
                && !b
                    .get(i.wrapping_sub(1))
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') =>
            {
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    let close: Vec<u8> = std::iter::once(b'"')
                        .chain(std::iter::repeat(b'#').take(hashes))
                        .collect();
                    j += 1;
                    while j < b.len() && !b[j..].starts_with(&close) {
                        j += 1;
                    }
                    i = j + close.len() - 1;
                }
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'\'' => {
                // A char literal ('x', '\n', '{'), not a lifetime ('a).
                if b.get(i + 1) == Some(&b'\\') {
                    i += 2;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                } else if b.get(i + 2) == Some(&b'\'') {
                    i += 2;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

#[test]
fn test_modules_are_skipped_with_braces_in_strings() {
    let src = "fn a() {}\n#[cfg(test)]\nmod tests {\n    const S: &str = \"{\";\n    const R: &str = r#\"}\"#;\n    const C: char = '}';\n    fn f<'a>(x: &'a str) {} // }\n}\nfn b() {}\n";
    let out = without_test_modules(src);
    assert_eq!(
        out.lines().filter(|l| !l.is_empty()).collect::<Vec<_>>(),
        ["fn a() {}", "fn b() {}"]
    );
}

#[test]
fn shipped_text_names_no_pre_2_0_name() {
    let old = regex::RegexBuilder::new(r"safeclaw|__sc__|x-sc-device")
        .case_insensitive(true)
        .build()
        .unwrap();
    // Spans that may stay, each for a reason.
    let keep = regex::Regex::new(concat!(
        // Frozen cryptographic domain strings (and mentions of their family).
        r"safeclaw/v1/[A-Za-z0-9/_*.\\-]*|safeclaw/item-id/v1|safeclaw-prf-v1",
        r"|safeclaw/batch-approve/test-beta/",
        // The OAuth loopback redirect registered at providers.
        r"|/safeclaw/oauth/callback",
        // `safeclaw` stays a link to the command (install.sh lays it out).
        r"|`safeclaw`|\$\{DEST\}/safeclaw",
        // A frontend file this code mirrors.
        r"|lib/safeclaw-crypto\.ts",
        // Copy that describes the rename or the move.
        r"|Sprott was called SafeClaw before",
        r"|moves `?~/\.safeclaw`? to `?~/\.sprott",
        r"|a phantom from before Sprott 2\.0 \(`__sc__<conn>__`\)",
        // The 1.x `sc upgrade` error, quoted in docs/upgrade.md.
        r"|no checksum for safeclaw-<platform> in the latest release",
    ))
    .unwrap();
    let mut bad = Vec::new();
    for f in shipped_files() {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let text = if f.extension().is_some_and(|e| e == "rs") {
            without_test_modules(&text)
        } else {
            text
        };
        for (i, line) in text.lines().enumerate() {
            if line.contains("rename:keep") || !old.is_match(line) {
                continue;
            }
            if old.is_match(&keep.replace_all(line, "")) {
                bad.push(format!("{}:{}: {}", rel(&f), i + 1, line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "old names in shipped text (rename them, or mark a deliberate one rename:keep):\n{}",
        bad.join("\n")
    );
}
