//! The one gate for service definitions.
//!
//! Definition text is untrusted input: it comes from community repositories,
//! local folders, or a team member writing the vault. [`admit`] is the only
//! way to turn it into a [`ServiceDef`] (the type carries a private field, so
//! nothing else can build one, and it has no `Deserialize`): every reader of
//! `aux.services`, of an on-disk service directory and of the compiled-in
//! catalog goes through here, and every consumer holds only what came out
//! ("parse, don't validate"; LangSec full recognition before processing).
//!
//! The gate recognizes the whole definition or rejects the whole definition
//! (CWE-636, no failing open): an unknown field anywhere, an unknown level, a
//! 2.0 `match`, glob, `when`, `vars` or `body` regex, a method that is not a
//! token, a path that is not a URL Pattern pathname, a `condition` that is not
//! CEL over the request, a request path that names nothing, a consent filter
//! the console does not implement, a duplicate rule id, an empty label, a
//! string carrying a control or bidi character, or anything over a limit
//! ([`crate::service::limits`]) rejects it with a precise message. No rule is
//! ever dropped on the way through. Every selector is compiled here, once.
//! What is worth saying about an admitted definition (a condition's member
//! read without a presence guard) comes back as its warnings.
//!
//! Pure and synchronous: no DNS, no network. Hosts and URLs are read with the
//! HTTP client's own URL parser and judged by the address floor in
//! [`crate::core::egress`].

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::core::egress::{check_host_entry, check_url};
use crate::core::policy::{AccessLevel, Condition, Levels, PolicyRule};
use crate::core::request::{BodyFormat, Field, ReadPath, Step};
use crate::core::selector::{
    is_method_token, literal_pattern, path_problem, OneOrMany, PathPattern, Select,
};
use crate::service::limits::*;
use crate::service::{AuthDef, Encoded, RequestShape, ServiceDef, ServiceMeta, ServicePolicy};

/// The filters the console implements for a consent template
/// (`{{ request.<path> | <filter> }}`): `email` renders the bound value as a
/// decoded message card, `graphql` renders a GraphQL request's calls as
/// actions in words (the approval view in the console). A filter outside
/// this set would show the approver nothing, so a definition naming one is
/// rejected.
pub const CONSENT_FILTERS: &[&str] = &["email", "graphql"];

/// Consent-URL query params the OAuth flow itself controls; an
/// `authorize_params` map may never set these (the frontend applies the map
/// first and the protocol params after, so an entry here would silently lose;
/// it is rejected instead).
const RESERVED_AUTHORIZE_PARAMS: &[&str] = &[
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
];

/// Exchange-body params the authorization_code flow itself controls; a
/// `token_params` map may never set these.
const RESERVED_TOKEN_PARAMS: &[&str] = &[
    "grant_type",
    "code",
    "code_verifier",
    "client_id",
    "client_secret",
    "redirect_uri",
];

/// Refresh-body params the flow itself controls; a `refresh_params` map may
/// never set these.
const RESERVED_REFRESH_PARAMS: &[&str] = &[
    "grant_type",
    "refresh_token",
    "client_id",
    "client_secret",
];

// ── Raw (untrusted) shapes: serde targets that only the gate reads ──────────

/// service.toml as written. `deny_unknown_fields` rejects stale v3 sections
/// and any tool-named section (`[git]`, `[docker]`) at parse.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    service: ServiceMeta,
    #[serde(default)]
    auth: Option<AuthDef>,
    #[serde(default)]
    setup: Option<String>,
    #[serde(default)]
    policy: Option<RawInlinePolicy>,
    #[serde(default)]
    requests: HashMap<String, RawRequestShape>,
}

/// A `[requests.<name>]` shape as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequestShape {
    /// The 2.0 `"METHOD /path"` and `vars`: named so they are refused with
    /// the replacement spelled out, not as unknown fields.
    #[serde(default, rename = "match")]
    match_pattern: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    vars: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    method: Option<OneOrMany>,
    #[serde(default)]
    path: Option<OneOrMany>,
    #[serde(default)]
    condition: Option<String>,
    /// The body format: `json`, `form`, `graphql` or `text`.
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    scope: Option<Vec<String>>,
    #[serde(default)]
    consent: Option<String>,
    #[serde(default)]
    encoded: Option<std::collections::BTreeMap<String, RawEncoded>>,
}

/// One `encoded."<request path>"` entry: JSON Schema's content keywords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEncoded {
    #[serde(default, rename = "contentEncoding")]
    content_encoding: Option<String>,
    #[serde(default, rename = "contentMediaType")]
    content_media_type: Option<String>,
}

/// The inline `[policy]` of a service.toml (`[policy.levels]` +
/// `[[policy.rules]]`), the older alternative to a policy.toml.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInlinePolicy {
    #[serde(default)]
    levels: Option<RawLevels>,
    #[serde(default)]
    rules: Vec<RawInlineRule>,
}

/// A read/write floor: `[default]` in policy.toml, `[policy.levels]` inline.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLevels {
    #[serde(default)]
    read: Option<String>,
    #[serde(default)]
    write: Option<String>,
    #[serde(default)]
    ttl: Option<u64>,
}

/// An inline `[[policy.rules]]` entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInlineRule {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path_exact: Option<String>,
    /// Never supported by the matcher; named here so it is rejected with a
    /// precise message instead of a generic unknown-field one.
    #[serde(default)]
    path_suffix: Option<String>,
    level: String,
}

/// policy.toml as written: `[default]` + `[[rule]]`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyFile {
    #[serde(default)]
    default: Option<RawLevels>,
    #[serde(default)]
    rule: Vec<RawRule>,
}

/// A `[[rule]]` in policy.toml.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    label: String,
    /// The 2.0 `"METHOD /path"`: named so it is refused with the replacement
    /// spelled out, not as an unknown field.
    #[serde(default, rename = "match")]
    match_pattern: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    method: Option<OneOrMany>,
    #[serde(default)]
    path: Option<OneOrMany>,
    #[serde(default)]
    condition: Option<String>,
    /// The 2.0 `body` regex and `when`: named so they are refused with the
    /// replacement spelled out.
    #[serde(default)]
    body: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    when: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    ttl: Option<u64>,
}

// ── The gate ─────────────────────────────────────────────────────────────────

/// Turn untrusted definition text into a validated [`ServiceDef`], or reject
/// it whole with every problem found.
///
/// `key` is the name the definition is stored or found under (its
/// `aux.services` key, its service directory name); when given, the declared
/// `[service] id` must equal it. `policy_toml` is the paired policy.toml, if
/// any. The messages carry no control or bidi characters (they quote the
/// definition, and are printed and logged).
pub fn admit(
    key: Option<&str>,
    service_toml: &str,
    policy_toml: Option<&str>,
) -> Result<ServiceDef, Vec<String>> {
    admit_inner(key, service_toml, policy_toml).map_err(|mut errs| {
        if errs.len() > MAX_REPORTED_PROBLEMS {
            let more = errs.len() - MAX_REPORTED_PROBLEMS;
            errs.truncate(MAX_REPORTED_PROBLEMS);
            errs.push(format!("... and {} more problems", more));
        }
        errs.into_iter()
            .map(|e| crate::util::terminal_safe(&e).into_owned())
            .collect()
    })
}

fn admit_inner(
    key: Option<&str>,
    service_toml: &str,
    policy_toml: Option<&str>,
) -> Result<ServiceDef, Vec<String>> {
    // Bytes first: nothing larger than the limit reaches the parser.
    let mut errs = Vec::new();
    check_file_size("service.toml", service_toml, &mut errs);
    if let Some(p) = policy_toml {
        check_file_size("policy.toml", p, &mut errs);
    }
    if !errs.is_empty() {
        return Err(errs);
    }

    // Syntax, then every string and key, before any message quotes a value.
    let service_table = parse_table("service.toml", service_toml)?;
    let policy_table = match policy_toml {
        Some(p) => Some(parse_table("policy.toml", p)?),
        None => None,
    };
    check_strings_in_table(&service_table, "", true, &mut errs);
    if let Some(t) = &policy_table {
        check_strings_in_table(t, "", false, &mut errs);
    }
    if !errs.is_empty() {
        return Err(errs);
    }

    // The schema: an unknown field anywhere is a parse error here.
    let raw: RawService = toml::from_str(service_toml)
        .map_err(|e| vec![toml_problem("service.toml", service_toml, &e, SCHEMA_ERROR)])?;
    let raw_policy: Option<RawPolicyFile> = match policy_toml {
        Some(p) => Some(
            toml::from_str(p)
                .map_err(|e| vec![toml_problem("policy.toml", p, &e, SCHEMA_ERROR)])?,
        ),
        None => None,
    };

    check_service(key, &raw, &mut errs);
    let mut warnings = Vec::new();
    let requests = check_requests(raw.requests, &mut errs, &mut warnings);
    let policy = match (raw_policy, raw.policy.as_ref()) {
        (Some(_), Some(_)) => {
            errs.push(
                "the policy is declared twice (policy.toml and an inline [policy]); keep one"
                    .into(),
            );
            None
        }
        (Some(file), None) => Some(policy_from_file(file, &mut errs, &mut warnings)),
        (None, Some(inline)) => Some(policy_from_inline(inline, &mut errs)),
        (None, None) => None,
    };
    // The rules-against-shapes cross-check (a `when` var a shape had to
    // bind) went with `when`: step 3 covers what a condition reads instead.
    if !errs.is_empty() {
        return Err(errs);
    }
    Ok(ServiceDef {
        service: raw.service,
        auth: raw.auth,
        setup: raw.setup,
        policy,
        requests,
        warnings: warnings
            .into_iter()
            .map(|w| crate::util::terminal_safe(&w).into_owned())
            .collect(),
        _gate: (),
    })
}

fn check_file_size(name: &str, text: &str, errs: &mut Vec<String>) {
    if text.len() > MAX_FILE_BYTES {
        errs.push(format!(
            "{} is {} bytes; the limit is {}",
            name,
            text.len(),
            MAX_FILE_BYTES
        ));
    }
}

fn parse_table(name: &str, text: &str) -> Result<toml::Table, Vec<String>> {
    toml::from_str::<toml::Table>(text)
        .map_err(|e| vec![toml_problem(name, text, &e, SYNTAX_ERROR)])
}

const SYNTAX_ERROR: &str = "syntax error";
const SCHEMA_ERROR: &str = "does not match the definition format";

/// A TOML error as its kind and position only. The parser's own text quotes
/// the offending line and a schema error can quote a key or value; definition
/// text is never echoed, so only a fixed kind and the line and column are
/// reported. `default` is the kind when the error is none of the known ones.
fn toml_problem(name: &str, text: &str, e: &toml::de::Error, default: &str) -> String {
    let kind = toml_error_kind(e.message()).unwrap_or(default);
    match e.span().and_then(|span| line_col(text, span.start)) {
        Some((line, col)) => format!(
            "{}: parse error: {} at line {}, column {}",
            name, kind, line, col
        ),
        None => format!("{}: parse error: {}", name, kind),
    }
}

/// The fixed kind of a TOML error message, from its leading words only.
fn toml_error_kind(message: &str) -> Option<&'static str> {
    const KINDS: [(&str, &str); 8] = [
        ("unknown field", "unknown field"),
        ("missing field", "missing field"),
        ("duplicate field", "duplicate key"),
        ("duplicate key", "duplicate key"),
        ("invalid type", "a value has the wrong type"),
        ("invalid value", "invalid value"),
        ("invalid length", "wrong number of items"),
        ("unknown variant", "unknown value"),
    ];
    let m = message.trim_start();
    KINDS
        .iter()
        .find(|(prefix, _)| m.starts_with(prefix))
        .map(|(_, kind)| *kind)
}

/// 1-based line and column (in characters) of byte offset `at` in `text`.
fn line_col(text: &str, at: usize) -> Option<(usize, usize)> {
    let before = text.get(..at.min(text.len()))?;
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    Some((line, col))
}

// ── Strings: control / bidi characters and lengths, in every value and key ──

/// Walk every string value and key of a parsed file. Only the top-level
/// `setup` of a service.toml is prose: it may carry `\n` and `\t` and the
/// longer prose limit; everything else is a single line.
fn check_strings_in_table(
    table: &toml::Table,
    path: &str,
    service_file: bool,
    errs: &mut Vec<String>,
) {
    for (key, value) in table {
        check_string(&format!("a key in {}", or_root(path)), key, false, errs);
        // A message names the key, shortened: a long key is already an error.
        let mut shown = key.as_str();
        if shown.len() > 64 {
            let mut cut = 64;
            while !shown.is_char_boundary(cut) {
                cut -= 1;
            }
            shown = &shown[..cut];
        }
        let child = if path.is_empty() {
            shown.to_string()
        } else {
            format!("{}.{}", path, shown)
        };
        let prose = service_file && path.is_empty() && key == "setup";
        check_value(value, &child, prose, errs);
    }
}

fn or_root(path: &str) -> &str {
    if path.is_empty() {
        "the file"
    } else {
        path
    }
}

fn check_value(value: &toml::Value, path: &str, prose: bool, errs: &mut Vec<String>) {
    match value {
        toml::Value::String(s) => check_string(path, s, prose, errs),
        toml::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                check_value(item, &format!("{}[{}]", path, i), false, errs);
            }
        }
        toml::Value::Table(t) => check_strings_in_table(t, path, false, errs),
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {}
    }
}

fn check_string(path: &str, s: &str, prose: bool, errs: &mut Vec<String>) {
    let limit = if prose {
        MAX_PROSE_BYTES
    } else {
        MAX_STRING_BYTES
    };
    if s.len() > limit {
        errs.push(format!(
            "{} is {} bytes; the limit is {}",
            path,
            s.len(),
            limit
        ));
        return;
    }
    if let Some(c) = s
        .chars()
        .find(|&c| !(prose && (c == '\n' || c == '\t')) && crate::util::is_unsafe_display_char(c))
    {
        errs.push(format!(
            "{} contains the control or bidi character U+{:04X}{}",
            path,
            c as u32,
            if prose {
                " (only \\n and \\t are allowed)"
            } else {
                ""
            }
        ));
    }
}

// ── [service] and [auth] ─────────────────────────────────────────────────────

/// A service / connection id usable as a phantom `<conn>` segment: `[a-z0-9_]`,
/// no `__` (the phantom delimiter), starting alphanumeric.
fn is_valid_service_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 || s.contains("__") {
        return false;
    }
    s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A secret role key: env-style `[A-Z0-9_]`, starts with a letter, and,
/// because its lowercase becomes a phantom role segment (`__sprott__<conn>__<role>__`),
/// it carries no `__` (the delimiter) and no trailing `_` (which would fuse
/// into the delimiter as `___` and make the advertised phantom unparseable).
fn is_valid_role(s: &str) -> bool {
    if s.is_empty() || s.contains("__") || s.ends_with('_') {
        return false;
    }
    s.starts_with(|c: char| c.is_ascii_uppercase())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A `[requests]` shape name: `[A-Za-z0-9_]+`.
fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Within the limit? Over it, the error is recorded and the caller skips the
/// per-entry checks, so the work done never exceeds the limits.
fn check_count(what: &str, n: usize, limit: usize, errs: &mut Vec<String>) -> bool {
    if n > limit {
        errs.push(format!(
            "{} has {} entries; the limit is {}",
            what, n, limit
        ));
        return false;
    }
    true
}

/// A single host anchor entry: an exact host or a `*.suffix` wildcard
/// (leftmost, single label, over a domain of at least two labels).
/// Authorities only: no scheme, no path, no port, no template.
fn check_host(entry: &str, errs: &mut Vec<String>) {
    if entry.contains("://") || entry.contains('/') || entry.contains("{{") {
        errs.push(format!(
            "host '{}' must be a bare host (no scheme, path or template)",
            entry
        ));
        return;
    }
    if entry.contains(':') {
        errs.push(format!("host '{}' must not carry a port", entry));
        return;
    }
    if entry == "*" {
        errs.push("a bare '*' host is forbidden; anchor to an exact host or a '*.suffix'".into());
        return;
    }
    let base = match entry.strip_prefix("*.") {
        Some(suffix) => {
            if suffix.contains('*') {
                errs.push(format!(
                    "host '{}': '*' is only allowed as the leftmost single label",
                    entry
                ));
                return;
            }
            // A wildcard pins within a domain: never a whole TLD, never an IP.
            let domain = matches!(url::Host::parse(suffix), Ok(url::Host::Domain(_)));
            if !domain || !suffix.trim_end_matches('.').contains('.') {
                errs.push(format!(
                    "host '{}' is too broad; a wildcard needs a domain like *.example.com",
                    entry
                ));
                return;
            }
            suffix
        }
        None => {
            if entry.contains('*') {
                errs.push(format!(
                    "host '{}': '*' is only allowed as the leftmost single label",
                    entry
                ));
                return;
            }
            entry
        }
    };
    if let Err(e) = check_host_entry(base) {
        errs.push(if base == entry {
            e
        } else {
            format!("host '{}': {}", entry, e)
        });
    }
}

fn check_service(key: Option<&str>, raw: &RawService, errs: &mut Vec<String>) {
    let s = &raw.service;
    if !is_valid_service_id(&s.id) {
        errs.push(format!(
            "service id '{}' is not valid (^[a-z0-9][a-z0-9_]* , no '__', at most 64)",
            s.id
        ));
    }
    if let Some(k) = key {
        if k != s.id {
            errs.push(format!(
                "the definition is stored as '{}' but declares id '{}'; they must be the same",
                k, s.id
            ));
        }
    }
    if s.name.trim().is_empty() {
        errs.push("[service] name must not be empty".into());
    }

    // Hosts: non-hidden services must anchor at least one.
    if s.hosts.is_empty() && !s.hidden {
        errs.push("service declares no hosts (an anchor is required)".into());
    }
    if check_count("[service] hosts", s.hosts.len(), MAX_HOSTS, errs) {
        for h in &s.hosts {
            check_host(h, errs);
        }
    }

    // Secrets: env-style role keys, no duplicates.
    let mut seen_secret = HashSet::new();
    let secrets_ok = check_count("[service] secrets", s.secrets.len(), MAX_SECRETS, errs);
    for r in s.secrets.iter().filter(|_| secrets_ok) {
        if !is_valid_role(r) {
            errs.push(format!(
                "secret role '{}' is not a valid env key ([A-Z0-9_])",
                r
            ));
        }
        if !seen_secret.insert(r.to_ascii_uppercase()) {
            errs.push(format!("duplicate secret role '{}'", r));
        }
    }

    // Tags: lowercase-kebab slugs, no duplicates. Free vocabulary; only the
    // shape is enforced so the console can render any tag as a chip.
    let mut seen_tag = HashSet::new();
    let tags_ok = check_count("[service] tags", s.tags.len(), MAX_TAGS, errs);
    for t in s.tags.iter().filter(|_| tags_ok) {
        let kebab = !t.is_empty()
            && t.split('-').all(|seg| {
                !seg.is_empty()
                    && seg
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            });
        if !kebab {
            errs.push(format!(
                "tag '{}' is not lowercase-kebab ([a-z0-9] segments joined by '-')",
                t
            ));
        }
        if !seen_tag.insert(t.as_str()) {
            errs.push(format!("duplicate tag '{}'", t));
        }
    }

    if let Some(g) = &s.group {
        if !is_valid_service_id(g) {
            errs.push(format!("[service] group '{}' is not a service id", g));
        }
    }
    if let Some(a) = &s.activation {
        if a != "auto" {
            errs.push(format!(
                "[service] activation '{}' is unknown (the only value is \"auto\"; omit it otherwise)",
                a
            ));
        }
    }
    // secret_url is a display-only link, rendered as an <a href> by the
    // console: a plain web URL only.
    if let Some(u) = &s.secret_url {
        if let Err(e) = check_url("[service] secret_url", u, &["https", "http"], false) {
            errs.push(e);
        }
    }

    match &raw.auth {
        Some(AuthDef::Snaplii(_)) => {
            // The snaplii exchange input is the first `secrets` role; a def
            // without one can never mint.
            if !s.secrets.iter().any(|r| !r.trim().is_empty()) {
                errs.push(
                    "[auth] type=\"snaplii\" requires a [service] secrets entry (the exchange api key)"
                        .into(),
                );
            }
        }
        Some(AuthDef::Oauth2(o)) => check_oauth2(o, s, &seen_secret, errs),
        None => {}
    }
}

/// The oauth2 section is self-sufficient: the inline fields carry the
/// endpoints and client (there is no template layer; `provider` is a display
/// label only). Endpoints are https to a public host.
fn check_oauth2(
    o: &crate::service::OAuth2Def,
    s: &ServiceMeta,
    seen_secret: &HashSet<String>,
    errs: &mut Vec<String>,
) {
    if !(o.authorization_url.is_some() && o.token_url.is_some() && o.client_id.is_some()) {
        errs.push(
            "[auth] oauth2 must declare authorization_url + token_url + client_id inline".into(),
        );
    }
    if o.provider.as_deref().is_some_and(|p| p.trim().is_empty()) {
        errs.push("[auth] provider (display label) must not be empty (omit it instead)".into());
    }
    if o.client_id.as_deref().is_some_and(|c| c.trim().is_empty()) {
        errs.push("[auth] client_id must not be empty".into());
    }
    if let Some(u) = &o.authorization_url {
        if let Err(e) = check_url("[auth] authorization_url", u, &["https"], true) {
            errs.push(e);
        }
    }
    if let Some(u) = &o.token_url {
        if let Err(e) = check_url("[auth] token_url", u, &["https"], true) {
            errs.push(e);
        }
    }
    // Where the consent lands: not an egress target (a local listener or the
    // provider's own page catches it), so any host is allowed, but only the
    // forms a native or web OAuth client uses. The string checks above
    // already bound its length and characters.
    if let Some(u) = &o.redirect_uri {
        if let Some(problem) = redirect_uri_problem(u) {
            errs.push(format!("[auth] redirect_uri '{}' {}", u, problem));
        }
    }
    if let Some(style) = &o.oauth_style {
        if style != "form" && style != "json" {
            errs.push(format!(
                "[auth] oauth_style '{}' is unknown (\"form\" or \"json\")",
                style
            ));
        }
    }
    if let Some(auth) = &o.token_auth {
        if auth != "post" && auth != "basic" {
            errs.push(format!(
                "[auth] token_auth '{}' is unknown (\"post\" or \"basic\")",
                auth
            ));
        }
    }
    check_count("[auth] scopes", o.scopes.len(), MAX_OAUTH_SCOPES, errs);
    if o.scopes.iter().any(|sc| sc.trim().is_empty()) {
        errs.push("[auth] scopes has an empty entry".into());
    }
    let exposes_ok = check_count("[auth] exposes", o.exposes.len(), MAX_EXPOSES, errs);
    let claims_ok = check_count("[auth.claims]", o.claims.len(), MAX_CLAIMS, errs);
    let mut claim_roles: Vec<&String> = o.claims.keys().filter(|_| claims_ok).collect();
    claim_roles.sort();
    for role in claim_roles {
        let path = &o.claims[role];
        if !o.exposes.iter().any(|e| e == role) {
            errs.push(format!("[auth] claims key '{}' is not in exposes", role));
        }
        check_count(
            &format!("[auth.claims] '{}'", role),
            path.len(),
            MAX_CLAIM_PATH,
            errs,
        );
        if path.is_empty() || path.iter().any(|seg| seg.trim().is_empty()) {
            errs.push(format!(
                "[auth] claims path for '{}' has an empty segment",
                role
            ));
        }
    }
    // authorize_params are ADDITIONS to the consent URL, never overrides of
    // the protocol params the flow itself controls.
    let params_ok = check_count(
        "[auth.authorize_params]",
        o.authorize_params.len(),
        MAX_AUTHORIZE_PARAMS,
        errs,
    );
    let mut params: Vec<&String> = o.authorize_params.keys().filter(|_| params_ok).collect();
    params.sort();
    for k in params {
        if RESERVED_AUTHORIZE_PARAMS.contains(&k.as_str()) {
            errs.push(format!(
                "[auth] authorize_params may not set the reserved param '{}'",
                k
            ));
        }
    }
    // token_params / refresh_params are ADDITIONS to the token-endpoint
    // bodies, same discipline. The one placeholder a token_params value may
    // use is the literal `{state}` (filled at exchange time from the pending
    // connect); any other `{...}` is refused — predictable over clever. A
    // refresh_params value is static: there is no consent state at refresh
    // time.
    check_extra_params(
        "token_params",
        &o.token_params,
        RESERVED_TOKEN_PARAMS,
        true,
        errs,
    );
    check_extra_params(
        "refresh_params",
        &o.refresh_params,
        RESERVED_REFRESH_PARAMS,
        false,
        errs,
    );
    // Durable token slots use RFC 6749 field names; each is a valid env KEY
    // that is ALSO declared in the top-level `secrets` (the uniform
    // durable-credential contract, SERVICES.md §3).
    let declared = |k: &str| s.secrets.iter().any(|r| r.eq_ignore_ascii_case(k));
    if o.refresh_token.trim().is_empty() {
        errs.push("[auth] oauth2 requires a refresh_token (the vault secret KEY the refresh token is stored under)".into());
    } else if !is_valid_role(&o.refresh_token) {
        errs.push(format!(
            "[auth] refresh_token '{}' is not a valid env key ([A-Z0-9_])",
            o.refresh_token
        ));
    } else if !declared(&o.refresh_token) {
        errs.push(format!(
            "[auth] refresh_token '{}' must be listed in the service's top-level secrets",
            o.refresh_token
        ));
    }
    if let Some(idt) = &o.id_token {
        if !is_valid_role(idt) {
            errs.push(format!(
                "[auth] id_token '{}' is not a valid env key ([A-Z0-9_])",
                idt
            ));
        } else if !declared(idt) {
            errs.push(format!(
                "[auth] id_token '{}' must be listed in the service's top-level secrets",
                idt
            ));
        }
    }
    for e in o.exposes.iter().filter(|_| exposes_ok) {
        if !is_valid_service_id(e) {
            errs.push(format!(
                "[auth] exposes entry '{}' is not a valid role ([a-z0-9_])",
                e
            ));
        }
        if seen_secret.contains(&e.to_ascii_uppercase()) {
            errs.push(format!(
                "[auth] exposes entry '{}' collides with a secret role",
                e
            ));
        }
    }
}

/// Check one extra-params map of the token endpoint (`[auth.token_params]` /
/// `[auth.refresh_params]`): the count cap, the flow's `reserved` keys, and
/// the placeholder rule — with `state_ok` a value may use the literal
/// `{state}` (any number of times); everything else between braces, and any
/// stray brace, is refused.
fn check_extra_params(
    which: &str,
    params: &std::collections::HashMap<String, String>,
    reserved: &[&str],
    state_ok: bool,
    errs: &mut Vec<String>,
) {
    let ok = check_count(
        &format!("[auth.{}]", which),
        params.len(),
        MAX_AUTHORIZE_PARAMS,
        errs,
    );
    let mut keys: Vec<&String> = params.keys().filter(|_| ok).collect();
    keys.sort();
    for k in keys {
        if reserved.contains(&k.as_str()) {
            errs.push(format!(
                "[auth] {} may not set the reserved param '{}'",
                which, k
            ));
            continue;
        }
        let v = &params[k];
        let stripped = if state_ok {
            v.replace(crate::auth::oauth2::STATE_PLACEHOLDER, "")
        } else {
            v.clone()
        };
        if stripped.contains('{') || stripped.contains('}') {
            errs.push(if state_ok {
                format!(
                    "[auth] {} '{}' uses a placeholder other than {{state}}",
                    which, k
                )
            } else {
                format!(
                    "[auth] {} '{}' uses a placeholder; refresh values are static",
                    which, k
                )
            });
        }
    }
}

/// The out-of-band redirect: the provider shows the code on its own page.
const OOB_REDIRECT: &str = "urn:ietf:wg:oauth:2.0:oob";

/// Why `uri` is not a redirect an OAuth client uses, or `None`: an `http` or
/// `https` URL (loopback included, RFC 8252 §7.3), [`OOB_REDIRECT`], or a
/// private-use scheme in reverse-domain form (RFC 8252 §7.1: at least two
/// dot-separated labels of letters, digits and `-`, as in
/// `com.example.app:/cb`). Every other scheme is refused.
fn redirect_uri_problem(uri: &str) -> Option<&'static str> {
    let Ok(url) = url::Url::parse(uri) else {
        return Some("is not an absolute URI");
    };
    let scheme = url.scheme();
    let reverse_domain = scheme.contains('.')
        && scheme.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if matches!(scheme, "http" | "https") || uri == OOB_REDIRECT || reverse_domain {
        None
    } else {
        Some(
            "must be an http(s) URL, urn:ietf:wg:oauth:2.0:oob, or a reverse-domain app scheme (com.example.app:/cb)",
        )
    }
}

// ── [requests] ───────────────────────────────────────────────────────────────

/// The refusal of a 2.0 `match`, with its replacement spelled out.
const MATCH_REPLACEMENT: &str = "`match` is not read; use method = \"DELETE\" and path = \"/v1/x/:id\" (a URL Pattern pathname: `:name` is one segment, a final `/*` the rest of the path)";

/// The refusal of a 2.0 `when`, with its replacement spelled out.
const WHEN_REPLACEMENT: &str = "`when` is not read; use condition = \"request.body.amount > 80\" (CEL over the request; guard a value a request may leave out with has(request.body.amount) && …)";

/// The refusal of a 2.0 rule `body` regex, with its replacement spelled out.
const BODY_REPLACEMENT: &str = "`body` (a regex) is not read; use condition = \"request.body.amount > 80\" (CEL over the request)";

/// The refusal of a 2.0 `vars`, with its replacement spelled out.
const VARS_REPLACEMENT: &str = "`vars` is not read; name each value by its request path in `scope`, `consent` and `condition` (\"request.body.amount\", \"request.query.force\", \"request.graphql.fields\"), and set the body format with body = \"json\" | \"form\" | \"graphql\" | \"text\"";

/// The `contentEncoding` values a definition may declare (JSON Schema
/// 2020-12 §8.3: RFC 4648's encodings and RFC 2045's).
const CONTENT_ENCODINGS: &[&str] = &[
    "base16",
    "base32",
    "base32hex",
    "base64",
    "base64url",
    "quoted-printable",
    "7bit",
    "8bit",
    "binary",
];

/// A rule's or a shape's `method` and `path` as written, checked and compiled.
/// `None` when it has a problem (recorded). A 2.0 `match` is refused with the
/// replacement spelled out. The count limit applies to the method × path
/// pairs and is checked before anything is compiled.
fn check_selector(
    what: &str,
    legacy: bool,
    method: Option<OneOrMany>,
    path: Option<OneOrMany>,
    errs: &mut Vec<String>,
) -> Option<Select> {
    if legacy {
        errs.push(format!("{}: {}", what, MATCH_REPLACEMENT));
        return None;
    }
    let methods = method.map(OneOrMany::into_vec);
    let paths = path.map(OneOrMany::into_vec);
    let pairs = methods
        .as_ref()
        .map_or(1, |m| m.len().max(1))
        .saturating_mul(paths.as_ref().map_or(1, |p| p.len().max(1)));
    if pairs > MAX_MATCH_PATTERNS {
        errs.push(format!(
            "{} has {} method × path pairs; the limit is {}",
            what, pairs, MAX_MATCH_PATTERNS
        ));
        return None;
    }
    let mut ok = true;
    if methods.as_ref().is_some_and(Vec::is_empty) {
        errs.push(format!(
            "{}: `method = []` lists no method; omit `method` for any method",
            what
        ));
        ok = false;
    }
    if paths.as_ref().is_some_and(Vec::is_empty) {
        errs.push(format!(
            "{}: `path = []` lists no path; omit `path` for any path",
            what
        ));
        ok = false;
    }
    for m in methods.iter().flatten().filter(|m| !is_method_token(m)) {
        errs.push(format!(
            "{}: method '{}' is not an HTTP method token (RFC 9110)",
            what, m
        ));
        ok = false;
    }
    let mut compiled = Vec::new();
    for p in paths.iter().flatten() {
        if let Some(problem) = path_problem(p) {
            errs.push(format!("{}: path '{}' {}", what, p, problem));
            ok = false;
            continue;
        }
        match PathPattern::compile(p) {
            Ok(c) => compiled.push(c),
            Err(e) => {
                errs.push(format!("{}: path '{}' {}", what, p, e));
                ok = false;
            }
        }
    }
    ok.then(|| Select::new(methods.unwrap_or_default(), compiled))
}

/// Whose condition is checked, for the warning that says what an unguarded
/// read means.
enum Decides {
    /// A rule at this level.
    Rule(Option<AccessLevel>),
    /// A `[requests]` shape.
    Shape,
}

/// Compile a `condition`, recording why it is refused, and a warning for each
/// member read no presence test guards (what a request without the value
/// gets, and the guard to write).
fn check_condition(
    what: &str,
    source: &str,
    decides: Decides,
    errs: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Option<Condition> {
    let condition = match Condition::compile(source) {
        Ok(c) => c,
        Err(why) => {
            errs.push(format!(
                "{}: condition = \"{}\" is not valid: {}",
                what, source, why
            ));
            return None;
        }
    };
    if matches!(decides, Decides::Shape)
        && condition.reads().iter().any(|r| r.path.field == Field::Graphql)
    {
        errs.push(format!(
            "{}: a [requests] condition can't read request.graphql (it is read once a shape has matched); read request.body",
            what
        ));
        return None;
    }
    for path in condition.unguarded() {
        let means = match &decides {
            Decides::Shape => "a request without it doesn't match this shape".to_string(),
            Decides::Rule(Some(AccessLevel::Allow) | None) => {
                "this rule doesn't allow a request without it".to_string()
            }
            Decides::Rule(Some(AccessLevel::Deny)) => {
                "a request without it is denied by this rule too".to_string()
            }
            Decides::Rule(Some(level)) => {
                format!("a request without it is decided {} by this rule too", level)
            }
        };
        warnings.push(format!(
            "{}: the condition reads {} with no presence test: {}; guard it with {} && …",
            what,
            path,
            means,
            path.guard()
        ));
    }
    Some(condition)
}

/// A request path a shape reads (`scope`, `consent`, an `encoded` key): a
/// path into `request` with at least one field, `request.graphql` only in
/// the `graphql` body format.
fn check_path(what: &str, text: &str, format: BodyFormat, errs: &mut Vec<String>) -> Option<ReadPath> {
    match ReadPath::parse(text) {
        Ok(p) if p.field == Field::Graphql && format != BodyFormat::Graphql => {
            errs.push(format!(
                "{}: {} is read only with body = \"graphql\"",
                what, p
            ));
            None
        }
        Ok(p) => Some(p),
        Err(e) => {
            errs.push(format!("{}: {}", what, e));
            None
        }
    }
}

/// Check every `[requests]` shape and compile it. The shapes that pass;
/// every problem is recorded.
fn check_requests(
    requests: HashMap<String, RawRequestShape>,
    errs: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> HashMap<String, RequestShape> {
    let mut out = HashMap::new();
    if !check_count("[requests]", requests.len(), MAX_REQUESTS, errs) {
        return out;
    }
    let mut shapes: Vec<(String, RawRequestShape)> = requests.into_iter().collect();
    shapes.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, shape) in shapes {
        let what = format!("[requests.{}]", name);
        let before = errs.len();
        if !is_ident(&name) {
            errs.push(format!(
                "{} is not a valid request name ([A-Za-z0-9_])",
                what
            ));
        }
        if shape.vars.is_some() {
            errs.push(format!("{}: {}", what, VARS_REPLACEMENT));
        }
        let select = check_selector(
            &what,
            shape.match_pattern.is_some(),
            shape.method,
            shape.path,
            errs,
        );
        if select.as_ref().is_some_and(Select::is_every) {
            errs.push(format!(
                "{} selects every request; declare its `method` and `path`",
                what
            ));
        }
        let format = match shape.body.as_deref() {
            None => BodyFormat::Json,
            Some(f) => BodyFormat::parse(f).unwrap_or_else(|| {
                errs.push(format!(
                    "{}: body = \"{}\" is not a body format ({})",
                    what,
                    f,
                    BodyFormat::NAMES.join(", ")
                ));
                BodyFormat::Json
            }),
        };
        let condition = shape
            .condition
            .as_deref()
            .and_then(|c| check_condition(&what, c, Decides::Shape, errs, warnings));

        // scope: request paths, each once.
        let scope = shape.scope.map(|entries| {
            if !check_count(&format!("{} scope", what), entries.len(), MAX_SCOPE, errs) {
                return Vec::new();
            }
            let mut paths: Vec<ReadPath> = Vec::new();
            for entry in &entries {
                if let Some(p) = check_path(&format!("{} scope", what), entry, format, errs) {
                    if paths.contains(&p) {
                        errs.push(format!("{} scope lists {} more than once", what, p));
                    } else {
                        paths.push(p);
                    }
                }
            }
            paths
        });

        let consent_reads = match &shape.consent {
            Some(consent) => check_consent(&what, consent, format, errs),
            None => Vec::new(),
        };

        let mut encoded = std::collections::BTreeMap::new();
        if let Some(entries) = shape.encoded {
            if check_count(&format!("{} encoded", what), entries.len(), MAX_SCOPE, errs) {
                for (key, e) in entries {
                    let at = format!("{} encoded.\"{}\"", what, key);
                    let Some(path) = check_path(&format!("{} encoded", what), &key, format, errs)
                    else {
                        continue;
                    };
                    if path.steps.is_empty() && path.field != Field::Body {
                        errs.push(format!("{}: names no value that carries media", at));
                    }
                    if e.content_encoding.is_none() && e.content_media_type.is_none() {
                        errs.push(format!(
                            "{}: declares neither contentEncoding nor contentMediaType",
                            at
                        ));
                    }
                    if let Some(enc) = &e.content_encoding {
                        if !CONTENT_ENCODINGS.contains(&enc.as_str()) {
                            errs.push(format!(
                                "{}: contentEncoding \"{}\" is unknown ({})",
                                at,
                                enc,
                                CONTENT_ENCODINGS.join(", ")
                            ));
                        }
                    }
                    if let Some(media) = &e.content_media_type {
                        if media.parse::<mime::Mime>().is_err() {
                            errs.push(format!(
                                "{}: contentMediaType \"{}\" is not a media type",
                                at, media
                            ));
                        }
                    }
                    encoded.insert(
                        path.to_string(),
                        Encoded {
                            content_encoding: e.content_encoding,
                            content_media_type: e.content_media_type,
                        },
                    );
                }
            }
        }

        if let (Some(select), true) = (select, errs.len() == before) {
            out.insert(
                name,
                RequestShape {
                    select,
                    condition,
                    format,
                    scope,
                    consent: shape.consent,
                    consent_reads,
                    encoded,
                },
            );
        }
    }
    out
}

/// A consent template is literal text and `{{ request.<path> }}` or
/// `{{ request.<path> | <filter> }}` tokens, nothing else. Every filter is one
/// the console implements ([`CONSENT_FILTERS`]); `graphql` reads only
/// `request.graphql.calls`. The paths it reads, which an approval binds.
fn check_consent(
    what: &str,
    template: &str,
    format: BodyFormat,
    errs: &mut Vec<String>,
) -> Vec<ReadPath> {
    let refs = match crate::service::consent_refs(template) {
        Ok(refs) => refs,
        Err(e) => {
            errs.push(format!("{} consent has {}", what, e));
            return Vec::new();
        }
    };
    let calls = ReadPath::new(Field::Graphql, vec![Step::Key("calls".into())]);
    let mut paths = Vec::new();
    for r in refs {
        let Some(path) = check_path(&format!("{} consent", what), &r.path, format, errs) else {
            continue;
        };
        if let Some(f) = r.filter.as_deref() {
            if !CONSENT_FILTERS.contains(&f) {
                errs.push(format!(
                    "{} consent filter '{}' is unknown (known: {})",
                    what,
                    f,
                    CONSENT_FILTERS.join(", ")
                ));
            }
            // `graphql` shows a list of calls, so it reads only the calls a
            // GraphQL request makes, never a field the agent writes freely.
            if f == "graphql" && path != calls {
                errs.push(format!(
                    "{} consent filter 'graphql' reads only {}",
                    what, calls
                ));
            }
        }
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

// ── Policy ───────────────────────────────────────────────────────────────────

fn parse_level(what: &str, s: &str, errs: &mut Vec<String>) -> Option<AccessLevel> {
    let level = AccessLevel::parse(s);
    if level.is_none() {
        errs.push(format!(
            "{}: level '{}' is unknown (allow, ask, ask-always or deny)",
            what, s
        ));
    }
    level
}

/// A `ttl` from a definition may not exceed [`MAX_TTL_SECONDS`]; over it the
/// definition is refused, never clamped.
fn check_ttl(what: &str, ttl: Option<u64>, errs: &mut Vec<String>) {
    if let Some(t) = ttl.filter(|t| *t > MAX_TTL_SECONDS) {
        errs.push(format!(
            "{}: ttl = {} is over the limit of {} seconds (one year)",
            what, t, MAX_TTL_SECONDS
        ));
    }
}

fn levels_from(what: &str, raw: &RawLevels, errs: &mut Vec<String>) -> Levels {
    check_ttl(what, raw.ttl, errs);
    Levels {
        read: raw
            .read
            .as_deref()
            .and_then(|l| parse_level(&format!("{} read", what), l, errs)),
        write: raw
            .write
            .as_deref()
            .and_then(|l| parse_level(&format!("{} write", what), l, errs)),
        ttl: raw.ttl,
    }
}

/// A rule id: the key a user edit names it by. `[a-z0-9][a-z0-9_-]*`.
fn is_valid_rule_id(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn policy_from_file(
    file: RawPolicyFile,
    errs: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> ServicePolicy {
    let defaults = file
        .default
        .as_ref()
        .map(|d| levels_from("policy.toml [default]", d, errs));
    if !check_count("policy.toml rules", file.rule.len(), MAX_RULES, errs) {
        return ServicePolicy {
            defaults,
            rules: Vec::new(),
        };
    }
    let mut seen_ids = HashSet::new();
    let mut rules = Vec::with_capacity(file.rule.len());
    for r in file.rule {
        let what = format!("rule '{}'", r.id);
        if !is_valid_rule_id(&r.id) {
            errs.push(format!("{}: the id must be [a-z0-9][a-z0-9_-]*", what));
        }
        if !seen_ids.insert(r.id.clone()) {
            errs.push(format!("{}: the id is used by more than one rule", what));
        }
        if r.label.trim().is_empty() {
            errs.push(format!("{}: the label must not be empty", what));
        }
        let select = check_selector(
            &what,
            r.match_pattern.is_some(),
            r.method,
            r.path,
            errs,
        );
        if r.when.is_some() {
            errs.push(format!("{}: {}", what, WHEN_REPLACEMENT));
        }
        if r.body.is_some() {
            errs.push(format!("{}: {}", what, BODY_REPLACEMENT));
        }
        if select.as_ref().is_some_and(Select::is_every) && r.condition.is_none() {
            errs.push(format!(
                "{}: with no `method`, `path` or `condition`, it matches every request; list what it matches (a level for every request is [default])",
                what
            ));
        }
        check_ttl(&what, r.ttl, errs);
        let level = match r.level.as_deref() {
            Some(l) => parse_level(&what, l, errs),
            None => {
                errs.push(format!(
                    "{}: declares no level (allow, ask, ask-always or deny)",
                    what
                ));
                None
            }
        };
        let condition = r
            .condition
            .as_deref()
            .and_then(|c| check_condition(&what, c, Decides::Rule(level), errs, warnings));
        rules.push(PolicyRule {
            id: Some(r.id),
            label: Some(r.label),
            select: select.unwrap_or_default(),
            condition,
            level,
            ttl: r.ttl,
        });
    }
    ServicePolicy { defaults, rules }
}

fn policy_from_inline(inline: &RawInlinePolicy, errs: &mut Vec<String>) -> ServicePolicy {
    let defaults = inline
        .levels
        .as_ref()
        .map(|l| levels_from("[policy.levels]", l, errs));
    if !check_count("[[policy.rules]]", inline.rules.len(), MAX_RULES, errs) {
        return ServicePolicy {
            defaults,
            rules: Vec::new(),
        };
    }
    let mut rules = Vec::with_capacity(inline.rules.len());
    for (i, r) in inline.rules.iter().enumerate() {
        let what = format!("[[policy.rules]] #{}", i + 1);
        if r.path_suffix.is_some() {
            errs.push(format!(
                "{}: path_suffix is not supported; write the path in path_exact",
                what
            ));
        }
        let Some(path) = &r.path_exact else {
            errs.push(format!("{}: declares no path_exact", what));
            continue;
        };
        if r.method
            .as_deref()
            .is_some_and(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphabetic()))
        {
            errs.push(format!("{}: method must be letters (e.g. DELETE)", what));
        }
        // `path_exact` is that one path: a literal pattern, without the
        // trailing `/` no request path keeps.
        let exact = match path.trim_end_matches('/') {
            "" => "/",
            trimmed => trimmed,
        };
        let select = match PathPattern::compile(&literal_pattern(exact)) {
            Ok(p) => Select::new(r.method.iter().cloned().collect(), vec![p]),
            Err(e) => {
                errs.push(format!("{}: path_exact '{}' {}", what, path, e));
                Select::every()
            }
        };
        let level = parse_level(&what, &r.level, errs);
        rules.push(PolicyRule {
            id: None,
            label: None,
            select,
            condition: None,
            level,
            ttl: None,
        });
    }
    ServicePolicy { defaults, rules }
}

#[cfg(test)]
mod tests;

/// Test fixtures: admit a service.toml with no storage key and no policy.
#[cfg(test)]
pub(crate) fn admit_toml(service_toml: &str) -> Result<ServiceDef, Vec<String>> {
    admit(None, service_toml, None)
}
