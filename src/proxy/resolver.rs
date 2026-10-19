//! Phantom parsing, scanning, and substitution (pure string mechanics).
//!
//! A phantom is the ONLY injection trigger: `__sprott__<conn>__` for a
//! connection's sole injectable secret, or `__sprott__<conn>__<role>__` when it
//! exposes several. The prefix is [`crate::names::PHANTOM_PREFIX`].
//! `<conn>`/`<role>` ∈ `[a-z0-9_]` with `__` as the (only) delimiter, so the
//! charset survives env values, URL path/query, JSON, headers, and base64 (Basic
//! auth is decoded before matching). This module finds phantoms at any site and
//! substitutes them given a resolver; it holds no vault or policy knowledge.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::names::PHANTOM_PREFIX;

/// A segment is alnum runs joined by SINGLE underscores, then an optional
/// `__`-delimited second segment, then the closing `__`.
const PHANTOM_BODY_RE: &str = r"[a-z0-9]+(?:_[a-z0-9]+)*(?:__[a-z0-9]+(?:_[a-z0-9]+)*)?__";

/// The phantom grammar as a scanner: the prefix + a segment + an optional
/// `__`-delimited second segment + the closing `__`. A segment is
/// alphanumeric-bounded with internal single underscores (`github_work`), so the
/// `__` delimiter is never ambiguous. Matches ANYWHERE — including glued to a
/// prefix like telegram's `/bot__sprott__telegram__/…` — because a phantom is a
/// value, not necessarily a whole word.
static PHANTOM_RE: Lazy<Regex> = Lazy::new(|| {
    // A segment is alnum runs joined by SINGLE underscores — never `__` (the
    // delimiter) and no leading/trailing `_`. This is what stops the scanner
    // from fusing two directly-adjacent phantoms (`__sprott__a____sprott__b__`)
    // into one over-long match that `parse_phantom` then rejects, silently
    // dropping both.
    Regex::new(&format!("{}{}", regex::escape(PHANTOM_PREFIX), PHANTOM_BODY_RE))
        .expect("phantom regex is valid")
});

/// A parsed phantom. `conn` and `role` are already lowercase (the phantom
/// charset). `role == None` is the sole-secret / oauth-access short form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phantom {
    pub conn: String,
    pub role: Option<String>,
    /// The exact matched token (e.g. `__sprott__github__`) — the de-dup key.
    pub raw: String,
}

/// A body segment (`<conn>` or `<role>`): non-empty, lowercase `[a-z0-9_]`.
fn is_valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Parse a single token as a phantom, or `None`. The token must be EXACTLY the
/// phantom (the scanner feeds it maximal `[A-Za-z0-9_]` runs): start with the prefix,
/// end `__`, a lowercase body split by `__` into one or two segments. `___`
/// (triple underscore) is rejected — the delimiter is exactly `__` and ids never
/// contain it.
pub fn parse_phantom(token: &str) -> Option<Phantom> {
    parse_with(PHANTOM_PREFIX, token)
}

fn parse_with(prefix: &str, token: &str) -> Option<Phantom> {
    let body = token.strip_prefix(prefix)?.strip_suffix("__")?;
    if body.is_empty() || body.contains("___") {
        return None;
    }
    let segs: Vec<&str> = body.split("__").collect();
    match segs.as_slice() {
        [conn] if is_valid_segment(conn) => Some(Phantom {
            conn: (*conn).to_string(),
            role: None,
            raw: token.to_string(),
        }),
        [conn, role] if is_valid_segment(conn) && is_valid_segment(role) => Some(Phantom {
            conn: (*conn).to_string(),
            role: Some((*role).to_string()),
            raw: token.to_string(),
        }),
        _ => None,
    }
}

// ── pre-2.0 phantoms (2.0.x only; delete in 2.1, design/compat-sunset.md) ──

/// The phantom prefix before 2.0. Read only to name its replacement.
const OLD_PHANTOM_PREFIX: &str = "__sc__";

static OLD_PHANTOM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!("{}{}", regex::escape(OLD_PHANTOM_PREFIX), PHANTOM_BODY_RE))
        .expect("old phantom regex is valid")
});

/// The first phantom from before 2.0 in `input` and its 2.0 spelling, e.g.
/// `("__sc__github__", "__sprott__github__")`. The 2.0 scan runs first and
/// every span it matches is masked, so a valid 2.0 phantom that contains an
/// old-looking one (connection `sc`, role `token`: `__sprott__sc__token__`)
/// is never read as old.
pub fn old_phantom(input: &str) -> Option<(String, String)> {
    if !input.contains(OLD_PHANTOM_PREFIX) {
        return None;
    }
    let mut masked = input.as_bytes().to_vec();
    for m in PHANTOM_RE.find_iter(input) {
        // A match is ASCII, so blanking its bytes keeps the text UTF-8.
        masked[m.range()].fill(b' ');
    }
    let masked = String::from_utf8(masked).ok()?;
    OLD_PHANTOM_RE.find_iter(&masked).find_map(|m| {
        let old = parse_with(OLD_PHANTOM_PREFIX, m.as_str())?;
        let new = match &old.role {
            None => format!("{PHANTOM_PREFIX}{}__", old.conn),
            Some(role) => format!("{PHANTOM_PREFIX}{}__{}__", old.conn, role),
        };
        Some((old.raw, new))
    })
}

/// True iff `input` contains at least one phantom. Cheap pre-check that avoids
/// running the full scan on the common (unbrokered) path.
pub fn contains_phantom(input: &str) -> bool {
    input.contains(PHANTOM_PREFIX) && PHANTOM_RE.is_match(input)
}

/// Upper bound on the number of DISTINCT phantoms collected from a single scan
/// site. A legitimate request resolves to ONE connection with a handful of role
/// phantoms (the pipeline rejects multi-connection requests outright), so this
/// ceiling is orders of magnitude above any real payload. Its job is to bound
/// the work an untrusted body can trigger: without it a ~32 MB body of millions
/// of distinct phantoms would allocate a huge `Vec` and (before the HashSet
/// dedup below) run quadratically. Reaching the cap means the caller is
/// pathological, not legitimate; we stop scanning and let the pipeline's
/// single-connection / policy gates reject it.
pub const MAX_PHANTOMS_PER_SITE: usize = 256;

/// Every distinct phantom in `input`, in first-seen order (capped at
/// [`MAX_PHANTOMS_PER_SITE`]). De-duplication is O(1) per match via a seen-set,
/// so a body packed with distinct phantoms can't drive quadratic CPU.
pub fn collect_phantoms(input: &str) -> Vec<Phantom> {
    let mut out: Vec<Phantom> = Vec::new();
    if !input.contains(PHANTOM_PREFIX) {
        return out;
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in PHANTOM_RE.find_iter(input) {
        // parse_phantom is the validator — the regex over-matches `___`, which
        // parse rejects, so a malformed token is skipped, not injected.
        if let Some(ph) = parse_phantom(m.as_str()) {
            if seen.insert(ph.raw.clone()) {
                out.push(ph);
                if out.len() >= MAX_PHANTOMS_PER_SITE {
                    break;
                }
            }
        }
    }
    out
}

/// Substitute every phantom in `input` for which `resolve` returns a value.
/// Returns `(rewritten, substituted_any)`. Phantoms `resolve` declines (returns
/// `None`) are left verbatim — the `__sprott__…__` breadcrumb makes an un-injected
/// phantom recognisable downstream rather than silently dropped.
pub fn substitute<F>(input: &str, resolve: F) -> (String, bool)
where
    F: Fn(&Phantom) -> Option<String>,
{
    if !input.contains(PHANTOM_PREFIX) {
        return (input.to_string(), false);
    }
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut any = false;
    for m in PHANTOM_RE.find_iter(input) {
        if let Some(ph) = parse_phantom(m.as_str()) {
            if let Some(val) = resolve(&ph) {
                out.push_str(&input[last..m.start()]);
                out.push_str(&val);
                last = m.end();
                any = true;
            }
        }
    }
    out.push_str(&input[last..]);
    (out, any)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn p(conn: &str, role: Option<&str>) -> Phantom {
        Phantom {
            conn: conn.to_string(),
            role: role.map(str::to_string),
            raw: match role {
                None => format!("__sprott__{conn}__"),
                Some(r) => format!("__sprott__{conn}__{r}__"),
            },
        }
    }

    // ── parse table ─────────────────────────────────────────────────────────
    #[test]
    fn parse_valid_sole() {
        assert_eq!(parse_phantom("__sprott__github__"), Some(p("github", None)));
    }

    #[test]
    fn parse_valid_conn_with_single_underscore() {
        // A single `_` is part of the id, not a delimiter.
        assert_eq!(
            parse_phantom("__sprott__github_work__"),
            Some(p("github_work", None))
        );
    }

    #[test]
    fn parse_valid_role() {
        assert_eq!(
            parse_phantom("__sprott__bb__username__"),
            Some(p("bb", Some("username")))
        );
        assert_eq!(
            parse_phantom("__sprott__gmail__account_id__"),
            Some(p("gmail", Some("account_id")))
        );
    }

    #[test]
    fn parse_invalid() {
        assert_eq!(parse_phantom("__sprott____"), None); // empty body
        assert_eq!(parse_phantom("__sprott__github"), None); // no trailing __
        assert_eq!(parse_phantom("sprott__github__"), None); // no marker
        assert_eq!(parse_phantom("__sprott__a__b__c__"), None); // 3 segments
        assert_eq!(parse_phantom("__sprott__GitHub__"), None); // uppercase not allowed
        assert_eq!(parse_phantom("__sprott__a___b__"), None); // triple underscore
        assert_eq!(parse_phantom("__sprott__git-hub__"), None); // '-' out of charset
        assert_eq!(parse_phantom("x__sprott__a__"), None); // prefixed → not a phantom
    }

    // ── scan / collect ──────────────────────────────────────────────────────
    #[test]
    fn collect_distinct_in_order() {
        let s = "a=__sprott__github__ b=__sprott__bb__username__ c=__sprott__github__";
        let got = collect_phantoms(s);
        assert_eq!(got, vec![p("github", None), p("bb", Some("username"))]);
    }

    #[test]
    fn collect_caps_distinct_phantoms() {
        // A pathological body of many distinct phantoms is bounded, not
        // collected wholesale (algorithmic-complexity DoS guard). Build well
        // past the cap and confirm we stop at it.
        let mut s = String::new();
        for i in 0..(MAX_PHANTOMS_PER_SITE + 50) {
            s.push_str(&format!("__sprott__c{i}__ "));
        }
        let got = collect_phantoms(&s);
        assert_eq!(got.len(), MAX_PHANTOMS_PER_SITE);
    }

    #[test]
    fn collect_adjacent_phantoms_not_fused() {
        // Two phantoms with no separator must both be found, not swallowed into
        // one over-long match that parse rejects.
        let got = collect_phantoms("__sprott__a____sprott__b__");
        assert_eq!(got, vec![p("a", None), p("b", None)]);
    }

    #[test]
    fn contains_phantom_fastpath() {
        assert!(!contains_phantom("nothing here"));
        assert!(!contains_phantom("Bearer sk-live-realtoken"));
        assert!(contains_phantom("Bearer __sprott__stripe_key__"));
    }

    // ── pre-2.0 phantoms ────────────────────────────────────────────────────
    #[test]
    fn an_old_phantom_is_named_with_its_replacement() {
        assert_eq!(
            old_phantom("https://x:__sc__github__@github.com/o/r"),
            Some(("__sc__github__".to_string(), "__sprott__github__".to_string()))
        );
        assert_eq!(
            old_phantom("Bearer __sc__bb__api_token__"),
            Some((
                "__sc__bb__api_token__".to_string(),
                "__sprott__bb__api_token__".to_string()
            ))
        );
        assert_eq!(old_phantom("Bearer sk-live-real"), None);
        assert_eq!(old_phantom("__sc__GitHub__"), None, "not the grammar");
        // Old phantoms are not phantoms any more.
        assert!(collect_phantoms("Bearer __sc__github__").is_empty());
    }

    #[test]
    fn a_new_phantom_that_contains_an_old_looking_one_is_not_old() {
        // Connection `sc`, role `token`.
        let s = "Bearer __sprott__sc__token__";
        assert_eq!(collect_phantoms(s), vec![p("sc", Some("token"))]);
        assert_eq!(old_phantom(s), None);
        assert_eq!(old_phantom("__sprott__sc__x__:__sprott__sc__"), None);
        // An old one beside a new one is still found.
        assert_eq!(
            old_phantom("__sprott__sc__token__ __sc__github__").map(|(o, _)| o),
            Some("__sc__github__".to_string())
        );
    }

    // ── substitution sites ──────────────────────────────────────────────────
    #[test]
    fn substitute_header_value() {
        let mut m = HashMap::new();
        m.insert("__sprott__stripe_key__".to_string(), "sk-live-REAL".to_string());
        let (out, any) = substitute("Bearer __sprott__stripe_key__", |ph| m.get(&ph.raw).cloned());
        assert!(any);
        assert_eq!(out, "Bearer sk-live-REAL");
    }

    #[test]
    fn substitute_url_path_telegram_shape() {
        // The telegram token lives in the URL PATH, never the authority.
        let mut m = HashMap::new();
        m.insert("__sprott__telegram__".to_string(), "12345:ABCDEF".to_string());
        let (out, any) = substitute("/bot__sprott__telegram__/sendMessage", |ph| {
            m.get(&ph.raw).cloned()
        });
        assert!(any);
        assert_eq!(out, "/bot12345:ABCDEF/sendMessage");
    }

    #[test]
    fn substitute_basic_userinfo_roundtrip() {
        // The git URL-userinfo shape, once base64-decoded, is "user:pass".
        let mut m = HashMap::new();
        m.insert("__sprott__github__".to_string(), "ghp_REALTOKEN".to_string());
        let decoded = "x:__sprott__github__";
        let (out, any) = substitute(decoded, |ph| m.get(&ph.raw).cloned());
        assert!(any);
        assert_eq!(out, "x:ghp_REALTOKEN");
    }

    #[test]
    fn substitute_declined_phantom_left_verbatim() {
        let (out, any) = substitute("Bearer __sprott__unknown__", |_| None);
        assert!(!any);
        assert_eq!(out, "Bearer __sprott__unknown__");
    }

    #[test]
    fn substitute_multiple_roles_one_pass() {
        let mut m = HashMap::new();
        m.insert("__sprott__bb__username__".to_string(), "alice".to_string());
        m.insert("__sprott__bb__api_token__".to_string(), "t0ken".to_string());
        let (out, _) = substitute("__sprott__bb__username__:__sprott__bb__api_token__", |ph| {
            m.get(&ph.raw).cloned()
        });
        assert_eq!(out, "alice:t0ken");
    }
}
