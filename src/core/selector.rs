//! Which requests a rule or a `[requests]` shape selects: `method` and `path`.
//!
//! - `method`: RFC 9110 token(s), a string or a list (any of), stored and
//!   compared uppercase. Absent: any method.
//! - `path`: WHATWG URL Pattern pathname(s) (`urlpattern`, the crate Deno's
//!   `URLPattern` is built on), a string or a list (any of). `:name` is one
//!   non-empty segment, `*` any characters including `/`. Absent: any path.
//!
//! The keys AND together. A pattern is matched against the request path as
//! the proxy normalized it ([`crate::core::path`]), without its query and with
//! one trailing `/` removed (the root `/` stays). Named groups are the match's
//! params. Every pattern is compiled once, when its rule or shape is loaded.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The named groups of a matched `path` pattern.
pub type Params = BTreeMap<String, String>;

// ── Matching target ──────────────────────────────────────────────────────────

/// The part of a request path a pattern is matched against: the query cut
/// off, then one trailing `/` removed unless the path is `/`.
pub fn match_target(path: &str) -> &str {
    let path = path.split('?').next().unwrap_or(path);
    match path.strip_suffix('/') {
        Some(rest) if !rest.is_empty() => rest,
        _ => path,
    }
}

// ── Methods ──────────────────────────────────────────────────────────────────

/// An RFC 9110 method token (§5.6.2 `token`, `1*tchar`).
pub fn is_method_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

// ── Path patterns ────────────────────────────────────────────────────────────

/// The regex engine URL Pattern runs on here: the regex crate under explicit
/// limits (its "Untrusted input" guidance), compiled when first needed. URL
/// Pattern builds a regex for each of a URL's eight components; only the
/// pathname's matcher is ever run, so the other seven are never compiled.
///
/// It matches bytes, without Unicode tables: a normalized request path is
/// ASCII ([`crate::core::path`] percent-encodes every other byte), so the
/// result is the same, and a pattern compiles in a fraction of the time.
#[derive(Debug)]
pub struct PathRegex {
    source: String,
    compiled: OnceLock<Result<regex::bytes::Regex, String>>,
}

impl PathRegex {
    fn compiled(&self) -> Result<&regex::bytes::Regex, &str> {
        use crate::service::limits::{
            PATH_REGEX_DFA_SIZE_LIMIT, PATH_REGEX_NEST_LIMIT, PATH_REGEX_SIZE_LIMIT,
        };
        self.compiled
            .get_or_init(|| {
                regex::bytes::RegexBuilder::new(&self.source)
                    .unicode(false)
                    .size_limit(PATH_REGEX_SIZE_LIMIT)
                    .dfa_size_limit(PATH_REGEX_DFA_SIZE_LIMIT)
                    .nest_limit(PATH_REGEX_NEST_LIMIT)
                    .build()
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(String::as_str)
    }
}

impl urlpattern::regexp::RegExp for PathRegex {
    fn syntax() -> urlpattern::RegexSyntax {
        urlpattern::RegexSyntax::Rust
    }

    fn parse(pattern: &str, _flags: &str, _force_eval: bool) -> Result<Self, ()> {
        Ok(PathRegex {
            source: pattern.to_string(),
            compiled: OnceLock::new(),
        })
    }

    /// The groups, each a whole `str` slice; a match that would split a
    /// character (only possible on a non-ASCII input) is no match.
    fn matches<'a>(&self, text: &'a str) -> Option<Vec<Option<&'a str>>> {
        let captures = self.compiled().ok()?.captures(text.as_bytes())?;
        captures
            .iter()
            .skip(1)
            .map(|c| match c {
                Some(m) => text.get(m.range()).map(Some),
                None => Some(None),
            })
            .collect()
    }

    fn pattern_string(&self) -> &str {
        &self.source
    }
}

type Compiled = urlpattern::UrlPattern<PathRegex>;

/// A `path` pattern, compiled once. Matching runs only its pathname matcher,
/// over the path as normalized (see the module docs).
#[derive(Clone)]
pub struct PathPattern {
    source: String,
    /// `Err` only for a stored user rule whose pattern does not compile
    /// ([`PathPattern::lenient`]); the gate refuses a definition with one.
    compiled: Result<Arc<Compiled>, String>,
}

impl PathPattern {
    /// Compile `source`, or say why it is not a path pattern: it must start
    /// with `/` and parse as a URL Pattern pathname, and any regex group in it
    /// must compile under the limits.
    pub fn compile(source: &str) -> Result<PathPattern, String> {
        if !source.starts_with('/') {
            return Err("must start with '/'".into());
        }
        let init = urlpattern::UrlPatternInit {
            pathname: Some(source.to_string()),
            ..Default::default()
        };
        // The parser reads untrusted definition text: a panic in it is a
        // refusal, never a crash.
        let parsed = std::panic::catch_unwind(|| Compiled::parse(init, Default::default()))
            .map_err(|_| "is not a URL Pattern pathname".to_string())?
            .map_err(|e| format!("is not a URL Pattern pathname: {}", e))?;
        // Compile the one regex matching runs now, so a pattern is either
        // whole at load or refused there.
        if let urlpattern::matcher::InnerMatcher::RegExp { regexp } =
            &parsed.pathname.matcher.inner
        {
            match regexp {
                Ok(r) => {
                    r.compiled().map_err(|e| {
                        format!("has a regex group that does not compile: {}", e)
                    })?;
                }
                Err(e) => return Err(format!("is not a URL Pattern pathname: {}", e)),
            }
        }
        Ok(PathPattern {
            source: source.to_string(),
            compiled: Ok(Arc::new(parsed)),
        })
    }

    /// A stored user rule's pattern: compiled now; one that does not compile
    /// is kept as unreadable rather than failing the whole sealed policy.
    pub fn lenient(source: &str) -> PathPattern {
        Self::compile(source).unwrap_or_else(|e| PathPattern {
            source: source.to_string(),
            compiled: Err(e),
        })
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Why the pattern does not compile, when it does not.
    pub fn error(&self) -> Option<&str> {
        self.compiled.as_ref().err().map(String::as_str)
    }

    /// The named groups when the pattern matches `target` (a
    /// [`match_target`]); `None` when it doesn't or can't be read.
    fn exec(&self, target: &str) -> Option<Params> {
        let pattern = self.compiled.as_ref().ok()?;
        let pathname = &pattern.pathname;
        let groups = pathname.matcher.matches(target)?;
        Some(
            pathname
                .group_name_list
                .iter()
                .zip(groups)
                .filter_map(|(name, value)| Some((name.clone(), value?.to_string())))
                .collect(),
        )
    }
}

impl std::fmt::Debug for PathPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PathPattern({:?})", self.source)
    }
}

impl Serialize for PathPattern {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.source.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PathPattern {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(PathPattern::lenient(&String::deserialize(d)?))
    }
}

/// `path` as a pattern that matches exactly that path: every character URL
/// Pattern reads as syntax escaped. For the inline `[[policy.rules]]`
/// `path_exact`.
pub fn literal_pattern(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(c, ':' | '(' | ')' | '{' | '}' | '+' | '?' | '*' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The `/`-separated segments of a pattern, split outside regex groups (a
/// group like `([^/]+)` holds a `/`), escapes kept. `None` when a group or an
/// escape is left open.
fn raw_segments(pattern: &str) -> Option<Vec<String>> {
    let body = pattern.strip_prefix('/')?;
    let mut raw: Vec<String> = vec![String::new()];
    let (mut depth, mut class, mut escaped) = (0usize, false, false);
    for c in body.chars() {
        let cur = raw.last_mut()?;
        if escaped {
            escaped = false;
            cur.push(c);
            continue;
        }
        match c {
            '\\' => escaped = true,
            '[' if depth > 0 => class = true,
            ']' if depth > 0 => class = false,
            '(' if !class => depth += 1,
            ')' if !class => depth = depth.checked_sub(1)?,
            '/' if depth == 0 => {
                raw.push(String::new());
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    (depth == 0 && !escaped).then_some(raw)
}

/// Why a `path` is refused before it is compiled, or `None`: it carries 2.0
/// glob syntax ([`glob_problem`]), or ends with a `/` no request path keeps
/// ([`match_target`]). The same check for a definition and a stored rule.
pub fn path_problem(pattern: &str) -> Option<String> {
    if let Some(problem) = glob_problem(pattern) {
        return Some(problem);
    }
    (pattern.len() > 1 && pattern.ends_with('/')).then(|| {
        "ends with '/', which no request path does (one trailing '/' is removed before matching); drop it"
            .into()
    })
}

/// Why a `path` carries 2.0 glob syntax, or `None`: `**`, or `*` as a whole
/// segment before the last (2.0's one-segment `*`, which in a URL Pattern
/// matches any characters, `/` included). A final `/*` is the rest of the
/// path.
pub fn glob_problem(pattern: &str) -> Option<String> {
    let segments = raw_segments(pattern)?;
    let doubled = segments.iter().any(|s| {
        let mut escaped = false;
        let mut star = false;
        for c in s.chars() {
            if escaped {
                escaped = false;
                star = false;
                continue;
            }
            match c {
                '\\' => escaped = true,
                '*' if star => return true,
                '*' => {
                    star = true;
                    continue;
                }
                _ => {}
            }
            star = false;
        }
        false
    });
    if doubled {
        return Some(
            "has '**', a 2.0 glob; a final '/*' matches the rest of the path".into(),
        );
    }
    if let Some((_, init)) = segments.split_last() {
        if init.iter().any(|s| s == "*") {
            return Some(
                "has '*' as a whole segment, which matches any characters, '/' included; write ':name' for one segment"
                    .into(),
            );
        }
    }
    None
}

// ── Selections ───────────────────────────────────────────────────────────────

/// What a rule or a shape selects: `method` AND `path`, each a list read as
/// any of, an empty one no restriction.
#[derive(Clone, Debug, Default)]
pub struct Select {
    /// Uppercase method tokens.
    methods: Vec<String>,
    paths: Vec<PathPattern>,
    /// Why a stored user rule's selection is refused (it selects nothing).
    problem: Option<String>,
}

impl Select {
    /// Every request.
    pub fn every() -> Select {
        Select::default()
    }

    /// These methods (uppercased) AND these paths.
    pub fn new(methods: Vec<String>, paths: Vec<PathPattern>) -> Select {
        Select {
            methods: methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
            paths,
            problem: None,
        }
    }

    /// A stored user rule's selection the daemon refuses, and why.
    pub fn refused(why: String) -> Select {
        Select {
            methods: Vec::new(),
            paths: Vec::new(),
            problem: Some(why),
        }
    }

    /// Why this selection is refused, when it is.
    pub fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    /// Whether it selects every request.
    pub fn is_every(&self) -> bool {
        self.problem.is_none() && self.methods.is_empty() && self.paths.is_empty()
    }

    /// The `method` list, uppercase; empty for any method.
    pub fn methods(&self) -> &[String] {
        &self.methods
    }

    /// The `path` list as written; empty for any path.
    pub fn paths(&self) -> Vec<String> {
        self.paths.iter().map(|p| p.as_str().to_string()).collect()
    }

    /// The params when it selects `method` on `path` (a request path as
    /// normalized; [`match_target`] is applied here). The method compares
    /// ignoring ASCII case: the proxy uppercases it at ingress, and a caller
    /// that did not still meets the rule it names. A refused selection
    /// selects nothing.
    pub fn exec(&self, method: &str, path: &str) -> Option<Params> {
        if self.problem.is_some() {
            return None;
        }
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return None;
        }
        if self.paths.is_empty() {
            return Some(Params::new());
        }
        let target = match_target(path);
        self.paths.iter().find_map(|p| p.exec(target))
    }

    /// What it selects as text to show: each method × path as
    /// `"METHOD path"` (a method alone when no path, a path alone when no
    /// method).
    pub fn display(&self) -> Vec<String> {
        match (self.methods.is_empty(), self.paths.is_empty()) {
            (true, true) => Vec::new(),
            (false, true) => self.methods.clone(),
            (true, false) => self.paths(),
            (false, false) => self
                .methods
                .iter()
                .flat_map(|m| self.paths.iter().map(move |p| format!("{} {}", m, p.as_str())))
                .collect(),
        }
    }

    /// Could one request be selected by both? See [`paths_overlap`].
    pub fn overlaps(&self, other: &Select) -> bool {
        if self.problem.is_some() || other.problem.is_some() {
            return false;
        }
        let methods = self.methods.is_empty()
            || other.methods.is_empty()
            || self
                .methods
                .iter()
                .any(|m| other.methods.iter().any(|n| m.eq_ignore_ascii_case(n)));
        let paths = self.paths.is_empty()
            || other.paths.is_empty()
            || self
                .paths
                .iter()
                .any(|p| other.paths.iter().any(|q| paths_overlap(p, q)));
        methods && paths
    }
}

/// Written as its keys: `method` and `path`, each omitted when empty (and
/// `problem` when refused).
impl Serialize for Select {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(None)?;
        if !self.methods.is_empty() {
            map.serialize_entry("method", &self.methods)?;
        }
        if !self.paths.is_empty() {
            map.serialize_entry("path", &self.paths)?;
        }
        if let Some(p) = &self.problem {
            map.serialize_entry("problem", p)?;
        }
        map.end()
    }
}

// ── Overlap (the gate's shape-vs-rule check) ─────────────────────────────────

/// One segment of a pattern in the form the overlap check reads exactly.
#[derive(Debug, PartialEq)]
enum Seg {
    /// Literal text, unescaped.
    Literal(String),
    /// `:name`: any non-empty segment.
    Any,
    /// `:name(a|b|c)`: one of these literal words.
    OneOf(BTreeSet<String>),
    /// `:name(<another regex>)`: read as possibly any segment.
    Regex,
}

/// The characters a literal segment may hold for the overlap check to compare
/// it as text (RFC 3986 unreserved, sub-delims, `:` and `@`): canonicalization
/// leaves these alone, so equal text is the only way two literals agree.
fn plain_literal(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-._~!$&'*+,;=:@".contains(c))
}

/// `pattern` as segments plus whether it ends in `/*` (any rest, `/`
/// included), when it uses only literal segments, `:name`, `:name(regex)` and
/// a final `*`; `None` for any other form.
fn overlap_form(pattern: &str) -> Option<(Vec<Seg>, bool)> {
    let mut raw = raw_segments(pattern)?;
    let rest = raw.last().is_some_and(|s| s == "*");
    if rest {
        raw.pop();
    }
    let segs = raw.iter().map(|s| segment_form(s)).collect::<Option<Vec<Seg>>>()?;
    Some((segs, rest))
}

fn segment_form(s: &str) -> Option<Seg> {
    if let Some(named) = s.strip_prefix(':') {
        let name_len = named
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '$'))
            .map_or(named.len(), |(i, _)| i);
        if name_len == 0 {
            return None;
        }
        let rest = &named[name_len..];
        if rest.is_empty() {
            return Some(Seg::Any);
        }
        let regex = rest.strip_prefix('(')?.strip_suffix(')')?;
        let words: Option<BTreeSet<String>> = regex
            .split('|')
            .map(|w| {
                (!w.is_empty()
                    && w.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                .then(|| w.to_string())
            })
            .collect();
        return Some(words.map_or(Seg::Regex, Seg::OneOf));
    }
    let mut text = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => text.push(chars.next()?),
            ':' | '(' | ')' | '{' | '}' | '*' | '+' | '?' => return None,
            c => text.push(c),
        }
    }
    plain_literal(&text).then_some(Seg::Literal(text))
}

fn segments_overlap(a: &Seg, b: &Seg) -> bool {
    use Seg::*;
    match (a, b) {
        (Literal(x), Literal(y)) => x == y,
        (Literal(x), Any) | (Any, Literal(x)) => !x.is_empty(),
        (OneOf(set), Literal(x)) | (Literal(x), OneOf(set)) => set.contains(x),
        (OneOf(x), OneOf(y)) => !x.is_disjoint(y),
        _ => true,
    }
}

/// Could one request path match both patterns? Exact for the forms the
/// compiled definitions use (literal segments, `:name`, `:name(a|b|…)`, and a
/// final `*`); any other form counts as overlapping. A path-level check for
/// the gate: does a rule apply on a path a `[requests]` shape covers.
pub fn paths_overlap(a: &PathPattern, b: &PathPattern) -> bool {
    let (Some((sa, ra)), Some((sb, rb))) = (overlap_form(a.as_str()), overlap_form(b.as_str()))
    else {
        return true;
    };
    let common = sa.len().min(sb.len());
    if !sa
        .iter()
        .zip(sb.iter())
        .take(common)
        .all(|(x, y)| segments_overlap(x, y))
    {
        return false;
    }
    match (ra, rb) {
        // Fixed lengths must agree.
        (false, false) => sa.len() == sb.len(),
        // `a/*` needs a segment past its prefix; a fixed `b` supplies it.
        (true, false) => sb.len() > sa.len(),
        (false, true) => sa.len() > sb.len(),
        // Both open-ended: a path long enough for both exists.
        (true, true) => true,
    }
}

// ── Serde ────────────────────────────────────────────────────────────────────

/// One string or a list of them, as a selector key is written.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub(crate) fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

/// A list written as one string when it holds one, else as a list.
pub(crate) fn serialize_one_or_many<S: Serializer, T: Serialize>(
    v: &[T],
    s: S,
) -> Result<S::Ok, S::Error> {
    if v.len() == 1 {
        v[0].serialize(s)
    } else {
        v.serialize(s)
    }
}

/// `Option<Vec<String>>` read from one string or a list, uppercased (a
/// stored rule's `method`).
pub(crate) mod methods_opt {
    use super::OneOrMany;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
        Ok(Some(
            OneOrMany::deserialize(d)?
                .into_vec()
                .into_iter()
                .map(|m| m.to_ascii_uppercase())
                .collect(),
        ))
    }

    pub fn serialize<S: Serializer>(v: &Option<Vec<String>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => super::serialize_one_or_many(v, s),
            None => s.serialize_none(),
        }
    }
}

/// `Option<Vec<PathPattern>>` read from one string or a list, each compiled
/// leniently (a stored rule's `path`).
pub(crate) mod paths_opt {
    use super::{OneOrMany, PathPattern};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<PathPattern>>, D::Error> {
        Ok(Some(
            OneOrMany::deserialize(d)?
                .into_vec()
                .iter()
                .map(|p| PathPattern::lenient(p))
                .collect(),
        ))
    }

    pub fn serialize<S: Serializer>(v: &Option<Vec<PathPattern>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => super::serialize_one_or_many(v, s),
            None => s.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select(methods: &[&str], paths: &[&str]) -> Select {
        Select::new(
            methods.iter().map(|s| s.to_string()).collect(),
            paths
                .iter()
                .map(|s| PathPattern::compile(s).unwrap_or_else(|e| panic!("{s}: {e}")))
                .collect(),
        )
    }

    /// Normalize a request path the way the proxy does, then select.
    fn selects(select: &Select, method: &str, path: &str) -> bool {
        let normalized = crate::core::path::normalize(path).expect("a valid path");
        select.exec(method, &normalized).is_some()
    }

    #[test]
    fn method_and_path_and_together_and_absent_keys_select_any() {
        let s = select(
            &["delete", "PATCH"],
            &["/zones/:zone/dns_records/:record", "/zones/:zone"],
        );
        assert_eq!(s.methods(), ["DELETE", "PATCH"]);
        let params = s.exec("DELETE", "/zones/z1/dns_records/r1/").unwrap();
        assert_eq!(params.get("zone").map(String::as_str), Some("z1"));
        assert_eq!(params.get("record").map(String::as_str), Some("r1"));
        assert!(s.exec("patch", "/zones/z1").is_some());
        assert!(s.exec("PUT", "/zones/z1").is_none());
        assert!(s.exec("DELETE", "/zones/z1/dns_records").is_none());
        // `:name` is one non-empty segment.
        assert!(s.exec("DELETE", "/zones//dns_records/r1").is_none());
        assert!(s.exec("DELETE", "/zones/a/b/dns_records/r1").is_none());
        assert_eq!(
            s.display(),
            [
                "DELETE /zones/:zone/dns_records/:record",
                "DELETE /zones/:zone",
                "PATCH /zones/:zone/dns_records/:record",
                "PATCH /zones/:zone",
            ]
        );
        // `*` crosses `/`, and needs the `/` before it.
        let s = select(&[], &["/batch/*"]);
        assert!(s.exec("POST", "/batch/storage/v1").is_some());
        assert!(s.exec("POST", "/batch").is_none());
        assert!(s.exec("POST", "/batch/").is_none());
        // No keys: every request. Method only: any path.
        assert!(Select::new(vec![], vec![]).is_every());
        let s = select(&["POST"], &[]);
        assert!(s.exec("POST", "/anything/at/all").is_some());
        assert!(s.exec("GET", "/").is_none());
        // The query is never part of the match.
        assert!(select(&[], &["/x"]).exec("GET", "/x?a=1").is_some());
        // A refused selection selects nothing.
        assert!(Select::refused("why".into()).exec("GET", "/x").is_none());
    }

    /// The normalized path is what is matched: a `:` stays a literal, an
    /// escaped slash stays inside its segment, a merged `//` is one `/`.
    #[test]
    fn patterns_match_the_normalized_path() {
        let s = select(&["POST"], &["/v1/projects/:project\\:getIamPolicy"]);
        assert!(selects(&s, "POST", "/v1/projects/p:getIamPolicy"));
        assert!(!selects(&s, "POST", "/v1/projects/p"));
        let s = select(&["DELETE"], &["/repos/:owner/:repo"]);
        assert!(selects(&s, "DELETE", "/repos/o/r/"));
        assert!(selects(&s, "DELETE", "/repos/o%2fx/r"));
        assert!(selects(&s, "DELETE", "//repos//o/r"));
        assert!(!selects(&s, "DELETE", "/repos/o//"));
        let s = select(&["GET"], &["/tasks/v1/users/@me/lists/:list", "/api/v1.1/me"]);
        assert!(selects(&s, "GET", "/tasks/v1/users/@me/lists/l1"));
        assert!(selects(&s, "GET", "/api/v1.1/me"));
        assert!(!selects(&s, "GET", "/api/v1x1/me"));
        // Optional groups: a slug of one to three segments.
        let s = select(&["POST"], &["/project/:vcs{/:org}?{/:repo}?/pipeline"]);
        for p in ["/project/gh%2Fo%2Fr/pipeline", "/project/gh/o%2Fr/pipeline", "/project/gh/o/r/pipeline"] {
            assert!(selects(&s, "POST", p), "{p}");
        }
        assert!(!selects(&s, "POST", "/project/gh/o/r/x/pipeline"));
        assert!(!selects(&s, "POST", "/project/pipeline"));
    }

    #[test]
    fn match_target_strips_the_query_and_one_trailing_slash() {
        assert_eq!(match_target("/"), "/");
        assert_eq!(match_target("/a/"), "/a");
        assert_eq!(match_target("/a//"), "/a/");
        assert_eq!(match_target("/a?b=/"), "/a");
        assert_eq!(match_target("/?q"), "/");
    }

    #[test]
    fn what_is_not_a_path_pattern_or_a_method_is_named() {
        for good in [
            "/",
            "/x",
            "/repos/:owner/:repo",
            "/orgs/:org/:access(memberships|members)/:username",
            "/batch/*",
            "/books{/:id}?",
            "/contents/设计.md",
        ] {
            assert!(PathPattern::compile(good).is_ok(), "{good}");
        }
        for bad in [
            "x",
            "",
            "*",
            "/a/:",
            "/a/:x(",
            "/a/:x((y))",
            "/a/?",
            "/:a/:a",
            "/x/:y(a{2,1})",
            "/x/:y((?:\\w{100}){100})",
        ] {
            assert!(PathPattern::compile(bad).is_err(), "{bad}");
        }
        let lenient = PathPattern::lenient("/a/:");
        assert!(lenient.error().is_some());
        assert!(lenient.exec("/a/x").is_none());
        for m in ["GET", "M-SEARCH", "PROPFIND", "x!#$%&'*+-.^_`|~"] {
            assert!(is_method_token(m), "{m}");
        }
        for m in ["", "GE T", "GET/", "G\u{e9}T", "(GET)"] {
            assert!(!is_method_token(m), "{m}");
        }
    }

    #[test]
    fn glob_syntax_is_named() {
        assert!(path_problem("/a/").is_some());
        assert!(path_problem("/a/*/b").is_some());
        assert_eq!(path_problem("/"), None);
        assert_eq!(path_problem("/a/:b/*"), None);
        for glob in ["/repos/*/issues", "/a/**", "/a/**/b", "/a**", "/*/projects/:id"] {
            assert!(glob_problem(glob).is_some(), "{glob}");
        }
        for fine in ["/a/*", "/*", "/files/*.json", "/a/\\*/b", "/a/\\*\\*", "/x/:y([^/]*)/z"] {
            assert_eq!(glob_problem(fine), None, "{fine}");
        }
    }

    #[test]
    fn a_literal_pattern_matches_only_its_path() {
        let p = PathPattern::compile(&literal_pattern("/v1/a:b/(c)/{d}/e+f/g*")).unwrap();
        let s = Select::new(vec![], vec![p]);
        assert!(selects(&s, "GET", "/v1/a:b/(c)/{d}/e+f/g*"));
        assert!(!selects(&s, "GET", "/v1/a"));
        assert!(!selects(&s, "GET", "/v1/a:b/(c)/{d}/eef/gx"));
    }

    #[test]
    fn overlap_is_exact_on_the_corpus_forms_and_conservative_elsewhere() {
        let buy = select(&["POST"], &["/buy"]);
        assert!(buy.overlaps(&buy));
        assert!(select(&[], &["/buy"]).overlaps(&buy));
        assert!(select(&["post"], &["/buy"]).overlaps(&buy));
        assert!(select(&["POST"], &["/:x"]).overlaps(&buy));
        assert!(select(&[], &["/*"]).overlaps(&select(&["POST"], &["/a/b"])));
        assert!(select(&[], &["/a/*"]).overlaps(&select(&[], &["/a/:x/c"])));
        assert!(select(&[], &["/a/*"]).overlaps(&select(&[], &["/:x/b/*"])));
        assert!(!select(&["GET"], &["/buy"]).overlaps(&buy));
        assert!(!buy.overlaps(&select(&["POST"], &["/refund"])));
        assert!(!select(&[], &["/a/:x"]).overlaps(&select(&[], &["/a/b/c"])));
        assert!(!select(&[], &["/a/*"]).overlaps(&select(&[], &["/a"])));
        assert!(!select(&[], &["/a/b/*"]).overlaps(&select(&[], &["/a/c/d"])));
        let repo = select(&["PATCH", "POST"], &["/repos/:owner/:repo", "/repositories/:id"]);
        assert!(repo.overlaps(&select(&["POST"], &["/repos/acme/app"])));
        assert!(!repo.overlaps(&select(&["POST"], &["/graphql"])));
        assert!(!repo.overlaps(&select(&["GET"], &["/repos/:o/:r"])));
        let words = select(&[], &["/orgs/:org/:access(memberships|members)/:user"]);
        assert!(words.overlaps(&select(&[], &["/orgs/acme/members/bob"])));
        assert!(words.overlaps(&select(&[], &["/orgs/:o/:k(members|teams)/:id"])));
        assert!(!words.overlaps(&select(&[], &["/orgs/acme/hooks/1"])));
        assert!(!words.overlaps(&select(&[], &["/orgs/:o/:k(hooks|teams)/:id"])));
        // `:name` is never empty.
        assert!(!select(&[], &["/a/:x/b"]).overlaps(&select(&[], &["/a//b"])));
        // Anything else counts as overlapping.
        assert!(select(&[], &["/books{/:id}?"]).overlaps(&select(&[], &["/authors"])));
        assert!(select(&[], &["/:x(\\d+)"]).overlaps(&select(&[], &["/abc"])));
        // No keys overlaps everything.
        assert!(Select::every().overlaps(&select(&["GET"], &["/x"])));
    }

    #[test]
    fn a_stored_pattern_reads_back_as_written() {
        let p: PathPattern = serde_json::from_value(serde_json::json!("/a/:")).unwrap();
        assert!(p.error().is_some());
        assert_eq!(serde_json::to_value(&p).unwrap(), serde_json::json!("/a/:"));
        let s = select(&["post"], &["/a", "/b/:id"]);
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            serde_json::json!({"method": ["POST"], "path": ["/a", "/b/:id"]})
        );
    }
}
