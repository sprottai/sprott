//! Policy engine — path-matched rules → access decisions.
//!
//! **One vocabulary**: [`AccessLevel`] (`allow | ask | ask-always | deny`) — the
//! access DECISION. It is what a rule declares, what the read/write floor
//! declares, and what evaluation returns. (An earlier revision split an
//! author-assigned `risk` CLASSIFICATION from the resolved `level`, bridged by a
//! per-vault risk→level map. That indirection is gone: a rule states its
//! decision directly, and the recipe author writes `allow`/`ask` on the action
//! instead of a `low`/`high` label.)
//!
//! Resolution order (PROTOCOL.md §6.4): most-restrictive matching rule
//! (deny-override / fail-safe) → connection default → tag default →
//! global default → floor (`ask-always`).
//!
//! A rule selects requests by `method` and `path` (a URL Pattern pathname),
//! [`crate::core::selector`].
//! - `body`: regex matched against request body text (optional), compiled once
//!   when its rule is loaded ([`BodyPattern`])
use crate::core::selector::{PathPattern, Select};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

// ── Body patterns ──────────────────────────────────────────────────────────────

/// A rule's `body` predicate, compiled once when the rule is loaded (a
/// definition at the gate, a user edit when the sealed policy is read) and
/// matched with `is_match` only, so no request ever compiles a regex. The
/// builder limits follow the regex crate's "Untrusted input" guidance: a
/// bounded pattern length and an explicit compiled-size limit.
#[derive(Clone)]
pub struct BodyPattern {
    source: String,
    /// `Err` only for a user edit (`aux.policy`) whose pattern does not
    /// compile; a definition carrying one is rejected at the gate. See
    /// `matches_rule` for how such a rule decides. Shared, so the copies a
    /// per-request rule merge makes reuse one compiled program and its cache.
    compiled: Result<std::sync::Arc<Regex>, String>,
}

impl BodyPattern {
    /// Compile `source` under the definition limits, or say why it cannot be.
    pub fn compile(source: &str) -> Result<BodyPattern, String> {
        use crate::service::limits::{
            BODY_REGEX_DFA_SIZE_LIMIT, BODY_REGEX_NEST_LIMIT, BODY_REGEX_SIZE_LIMIT,
            MAX_BODY_PATTERN_BYTES,
        };
        if source.len() > MAX_BODY_PATTERN_BYTES {
            return Err(format!(
                "is {} bytes; the limit is {}",
                source.len(),
                MAX_BODY_PATTERN_BYTES
            ));
        }
        RegexBuilder::new(source)
            .size_limit(BODY_REGEX_SIZE_LIMIT)
            .dfa_size_limit(BODY_REGEX_DFA_SIZE_LIMIT)
            .nest_limit(BODY_REGEX_NEST_LIMIT)
            .build()
            .map(|re| BodyPattern {
                source: source.to_string(),
                compiled: Ok(std::sync::Arc::new(re)),
            })
            .map_err(|e| e.to_string())
    }

    /// A user edit's pattern: compiled now; one that does not compile is kept
    /// as unreadable rather than failing the whole sealed policy.
    pub fn lenient(source: &str) -> BodyPattern {
        Self::compile(source).unwrap_or_else(|e| BodyPattern {
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

    /// Does the pattern match `text`? `None` when it is unreadable.
    fn is_match(&self, text: &str) -> Option<bool> {
        self.compiled.as_ref().ok().map(|re| re.is_match(text))
    }
}

impl std::fmt::Debug for BodyPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BodyPattern({:?})", self.source)
    }
}

impl Serialize for BodyPattern {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.source.serialize(s)
    }
}

impl<'de> Deserialize<'de> for BodyPattern {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(BodyPattern::lenient(&String::deserialize(d)?))
    }
}

// ── Access Level ───────────────────────────────────────────────────────────────

/// The access DECISION for a request.
///
/// - `Allow`: pass through immediately, no approval
/// - `Ask`: approve once; the approval holds for the rule's / floor's `ttl`
///   (what it covers: `crate::approval::reuse`)
/// - `AskAlways`: approve every request, never cache
/// - `Deny`: block unconditionally
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessLevel {
    Allow,
    Ask,
    AskAlways,
    Deny,
}

impl std::fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessLevel::Allow => write!(f, "allow"),
            AccessLevel::Ask => write!(f, "ask"),
            AccessLevel::AskAlways => write!(f, "ask-always"),
            AccessLevel::Deny => write!(f, "deny"),
        }
    }
}

impl AccessLevel {
    /// Parse a kebab-case level name. `None` for anything else.
    pub fn parse(s: &str) -> Option<AccessLevel> {
        match s {
            "allow" => Some(AccessLevel::Allow),
            "ask" => Some(AccessLevel::Ask),
            "ask-always" => Some(AccessLevel::AskAlways),
            "deny" => Some(AccessLevel::Deny),
            _ => None,
        }
    }

    /// Restrictiveness rank — higher = stricter. Used to resolve overlapping
    /// rules by "most restrictive wins" (deny-override / fail-safe, à la AWS
    /// IAM / Cedar). PROTOCOL.md §6.4.
    pub fn restrictiveness(&self) -> u8 {
        match self {
            AccessLevel::Allow => 0,
            AccessLevel::Ask => 1,
            AccessLevel::AskAlways => 2,
            AccessLevel::Deny => 3,
        }
    }
}

// ── Rules ───────────────────────────────────────────────────────────────────────

/// A fully-formed policy rule — from a service's `policy.toml`, or the merged
/// result after user edits. A matched rule decides the request via its `level`.
/// `level` hangs on the *rule* (matcher + optional `body` predicate), so future
/// predicate rules (`amount > $100`) decide the same way. A rule with no `level`
/// is malformed — it can never decide — and is skipped at evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyRule {
    /// Unique id (e.g. "send-email"). The key for user edits / the ask-cache scope.
    pub id: Option<String>,
    /// Human-readable label for the console.
    pub label: Option<String>,
    /// Which requests it decides: `method` AND `path`, each a list read as
    /// any of (one logical operation exposed at several endpoints), absent =
    /// no restriction ([`crate::core::selector`]). Compiled when the rule is
    /// loaded. A refused stored user rule carries a refused selection
    /// ([`evaluate_decision`] says how it decides).
    #[serde(flatten)]
    pub select: Select,
    /// Regex matched against request body text. Omit to skip body matching.
    pub body: Option<BodyPattern>,
    /// A structured field condition, AND-combined with the selector and `body`:
    /// `"vars.<name> <op> <literal>"`, e.g. `"vars.amount > 80"`. The var is
    /// resolved from the request's matching `[requests]` shape (service.toml);
    /// an UNDEFINED var makes the condition — and so the rule — not match
    /// (policy is an explicit contract, we never fabricate a decision). See
    /// [`Condition`] and design/request-scope.md.
    pub when: Option<String>,
    /// The access decision when this rule matches.
    pub level: Option<AccessLevel>,
    /// Cache TTL (seconds) after an `ask` approval, scoped to this rule
    /// (PROTOCOL.md §6.1 `policy.rules[].ttl`).
    pub ttl: Option<u64>,
}

impl PolicyRule {
    /// The access decision for this rule. `None` only if the rule declares no
    /// `level` (malformed) → caller falls through to defaults.
    pub fn effective_level(&self) -> Option<AccessLevel> {
        self.level
    }
}

/// Read/write access levels — a floor DECISION for when no rule matches. Used at
/// the connection, tag, and global layers. The read/write split is the
/// method-derived base: `is_write_method` picks `write` for mutating methods,
/// `read` otherwise.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Levels {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<AccessLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<AccessLevel>,
    /// `ask`-cache TTL when the floor decision is `ask`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

/// A sparse user edit to one rule, keyed by rule id in `aux.policy.connections.
/// <id>.rules`. Two modes:
///   - **override** an existing built-in rule (set `level` and/or `ttl`; the id
///     matches a built-in),
///   - **add** a new rule (carries its own selector, `method` and / or
///     `path`: having one is what makes it a new rule rather than an
///     override).
///
/// Each selector key is read (and its patterns compiled) once, when the
/// sealed policy is read, and written back as it was stored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleConfig {
    /// A 2.0 rule's `"METHOD /path"`. Not read: an entry that carries one is
    /// a refused rule ([`RuleConfig::select`]); kept so the record reads back
    /// as stored.
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_pattern: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::core::selector::methods_opt"
    )]
    pub method: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::core::selector::paths_opt"
    )]
    pub path: Option<Vec<PathPattern>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyPattern>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<AccessLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

impl RuleConfig {
    /// What an added rule selects; `None` for an override (no selector key).
    /// A rule the daemon refuses (DESIGN.md §2) gets a
    /// [`Select::refused`] selection: one in the 2.0 `match` syntax, or whose
    /// selector can't be read (a pattern that doesn't compile, a method that
    /// isn't a token, an empty list). [`evaluate_decision`] says how a
    /// refused rule decides.
    pub fn select(&self) -> Option<Select> {
        if self.match_pattern.is_some() {
            return Some(Select::refused(
                "it is in the 2.0 `match` syntax; write `method` and `path`".into(),
            ));
        }
        if self.method.is_none() && self.path.is_none() {
            return None;
        }
        let methods = self.method.clone().unwrap_or_default();
        let paths = self.path.clone().unwrap_or_default();
        if self.method.as_ref().is_some_and(Vec::is_empty)
            || self.path.as_ref().is_some_and(Vec::is_empty)
        {
            return Some(Select::refused("an empty `method` or `path` list".into()));
        }
        if let Some(m) = methods
            .iter()
            .find(|m| !crate::core::selector::is_method_token(m))
        {
            return Some(Select::refused(format!("method '{}' is not a method token", m)));
        }
        if let Some((p, e)) = paths.iter().find_map(|p| {
            let problem = crate::core::selector::path_problem(p.as_str())
                .or_else(|| p.error().map(str::to_string))?;
            Some((p.as_str(), problem))
        }) {
            return Some(Select::refused(format!("path '{}' {}", p, e)));
        }
        Some(Select::new(methods, paths))
    }

    /// Test fixture: an entry selecting `"METHOD /path"` or `"/path"`.
    #[cfg(test)]
    pub(crate) fn selecting(spec: &str) -> RuleConfig {
        let (method, path) = match spec.split_once(' ') {
            Some((m, p)) => (Some(vec![m.to_ascii_uppercase()]), p),
            None => (None, spec),
        };
        RuleConfig {
            method,
            path: Some(vec![PathPattern::lenient(path)]),
            ..Default::default()
        }
    }
}

// ── Per-connection + global policy (sealed in `aux.policy`) ──────────────────────

/// A connection's user policy layer (PROTOCOL.md `M.policy.connections.<id>`).
/// Sparse — present only for connections the user actually customised. The
/// built-in rule set comes from the connection's *service* definition; this adds a
/// per-connection default override and per-rule edits/additions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionPolicy {
    /// Override this connection's default read/write floor (over the service's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Levels>,
    /// Per-rule edits (override built-in by id) and additions (new id + match).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rules: HashMap<String, RuleConfig>,
}

/// The whole policy tree (`aux.policy`, PROTOCOL.md §5.2 / §6.4 `M.policy`).
/// Replaces the old split `policy_defaults` + `service_state`. Sparse: a fresh
/// vault has none and the daemon uses [`Policy::default`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Approval hold timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Global default floor (when no rule and no more-specific default match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Levels>,
    /// Per-tag default floor, keyed by service tag (e.g. "ai", "messaging").
    /// Beats `default`. Serde name stays `categories` — the map is sealed in
    /// `aux.policy`, and its KEYS are data, so the tags cutover needed no
    /// schema change (stale old-name keys simply never match).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub categories: HashMap<String, Levels>,
    /// Per-connection user policy, keyed by `connection_id`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub connections: HashMap<String, ConnectionPolicy>,
    /// The owner's switch for installed services (definitions stored with a
    /// source): off (absent) = the vault neither loads nor adds them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_installed_services: bool,
}

impl Default for Policy {
    fn default() -> Self {
        // Design stance: Sprott is *first* a credential-separating proxy —
        // the agent never holds the secret, the daemon injects it — and only
        // *secondly* an approval gate for risky operations. So the baseline
        // floor is `allow` (inject + forward, no per-call friction); services
        // tighten genuinely sensitive paths with a stricter `level` on rules.
        // (ai/messaging are redundant with the global default but kept
        // explicit so a future stricter global default doesn't silently
        // re-gate them.)
        let allow_rw = || Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Allow),
            ttl: None,
        };
        let mut categories = HashMap::new();
        categories.insert("ai".into(), allow_rw());
        categories.insert("messaging".into(), allow_rw());
        Self {
            // ONE approval window (SSOT, user decision 2026-07-14): every
            // pending-op surface derives from this — broker asks, CLI
            // ceremonies (op.rs stamps it), the value stash, the relay poll
            // budget, and the grant-page countdown.
            timeout: Some(1800),
            default: Some(allow_rw()),
            categories,
            connections: HashMap::new(),
            allow_installed_services: false,
        }
    }
}

impl Policy {
    /// Overlay a user's sparse `aux.policy` onto the compiled defaults so unset
    /// parts (global floor, tag defaults) keep safe values. Called at
    /// unlock/refresh to produce the effective policy the evaluator reads.
    pub fn effective(user: Option<&Policy>) -> Policy {
        let mut p = Policy::default();
        if let Some(u) = user {
            if u.timeout.is_some() {
                p.timeout = u.timeout;
            }
            if u.default.is_some() {
                p.default = u.default.clone();
            }
            for (k, v) in &u.categories {
                p.categories.insert(k.clone(), v.clone());
            }
            p.connections = u.connections.clone();
            p.allow_installed_services = u.allow_installed_services;
        }
        p
    }
}

// ── Merge ─────────────────────────────────────────────────────────────────────

/// Field-wise merge of two [`Levels`] with user > built-in precedence. Each field
/// independently takes the user's value when set, else the built-in's.
pub fn merge_levels(user: Option<&Levels>, built_in: Option<&Levels>) -> Option<Levels> {
    match (user, built_in) {
        (None, None) => None,
        (Some(u), None) => Some(u.clone()),
        (None, Some(r)) => Some(r.clone()),
        (Some(u), Some(r)) => Some(Levels {
            read: u.read.or(r.read),
            write: u.write.or(r.write),
            ttl: u.ttl.or(r.ttl),
        }),
    }
}

/// Merge a connection's user [`RuleConfig`] edits onto a service's built-in
/// rules. By id: an edit overrides `level` / `ttl` (and `label`/`body` if given)
/// of the matching built-in, in its place; an entry with a selector whose id is
/// *not* built-in is appended as a new rule, in id order (the declaration
/// order a tie between equally strict rules goes to). An entry in the 2.0
/// `match` syntax is appended as a refused rule, whatever its id, and
/// overrides nothing. PROTOCOL.md §6.4 `M.policy` (logical merged view).
pub fn merge_rules(built_in: &[PolicyRule], user: &HashMap<String, RuleConfig>) -> Vec<PolicyRule> {
    let mut out: Vec<PolicyRule> = built_in
        .iter()
        .map(|rule| {
            let edit = rule
                .id
                .as_ref()
                .and_then(|id| user.get(id))
                .filter(|e| e.match_pattern.is_none());
            match edit {
                Some(e) => PolicyRule {
                    level: e.level.or(rule.level),
                    ttl: e.ttl.or(rule.ttl),
                    label: e.label.clone().or_else(|| rule.label.clone()),
                    body: e.body.clone().or_else(|| rule.body.clone()),
                    when: e.when.clone().or_else(|| rule.when.clone()),
                    ..rule.clone()
                },
                None => rule.clone(),
            }
        })
        .collect();
    // New rules: user entries with a selector and an id not present in
    // built-ins, and refused entries, in id order.
    let built_in_ids: std::collections::HashSet<&str> =
        built_in.iter().filter_map(|r| r.id.as_deref()).collect();
    let mut added: Vec<(&String, &RuleConfig)> = user
        .iter()
        .filter(|(id, e)| !built_in_ids.contains(id.as_str()) || e.match_pattern.is_some())
        .collect();
    added.sort_by_key(|(id, _)| *id);
    for (id, e) in added {
        if let Some(select) = e.select() {
            out.push(PolicyRule {
                id: Some(id.clone()),
                label: e.label.clone(),
                select,
                body: e.body.clone(),
                when: e.when.clone(),
                level: e.level,
                ttl: e.ttl,
            });
        }
    }
    out
}

/// A connection's own rule edit that cannot be enforced as written on a
/// scoped request (the service declares a `[requests]` shape for its path),
/// with the reason; `None` when every edit covering the request is
/// enforceable.
///
/// An approval on a scoped path binds only the matched shape's `scope`
/// values, so a rule whose decision depends on anything else could be
/// approved for one request and then decide a different request the approval
/// still matches. The same invariant the compiled policies are held to (the
/// gate, `service::gate`: a deciding field must be bound), applied per
/// request to the user's edits:
///   - a `when` on a var the matched shape declares but does not bind;
///   - a `body` regex (the body is never bound).
///
/// Each edit is judged as the rule it produces: the MERGED rule
/// ([`merge_rules`]), so an edit of only `level` on a built-in rule that has
/// a `body` decides on that body and is judged so. Only rules a user edit
/// touches (`aux.policy.connections.<id>.rules`) are checked, only those that
/// decide `ask` or `ask-always` (an `allow` or `deny` mints no approval and
/// is re-decided on every request), and only those whose selector covers this
/// request. A `when` naming a var this shape does not declare never fires
/// here (P3) and is not refused.
/// `shape` / `declared` / `binds` describe the matched shape
/// (`crate::service::RequestScope`).
pub fn unenforceable_user_rule(
    built_in: &[PolicyRule],
    user: &HashMap<String, RuleConfig>,
    method: &str,
    path: &str,
    shape: &str,
    declared: &[String],
    binds: &[String],
) -> Option<String> {
    let merged = merge_rules(built_in, user);
    let mut edited: Vec<(&str, &PolicyRule)> = merged
        .iter()
        .filter_map(|r| {
            let id = r.id.as_deref()?;
            user.contains_key(id).then_some((id, r))
        })
        .collect();
    edited.sort_by_key(|(id, _)| *id);
    for (id, rule) in edited {
        // Only an ask decision mints an approval this could ride: `allow` and
        // `deny` (or no level) are re-decided on every request.
        if !matches!(rule.level, Some(AccessLevel::Ask | AccessLevel::AskAlways)) {
            continue;
        }
        if rule.select.exec(method, path).is_none() {
            continue;
        }
        if rule.body.is_some() {
            return Some(format!(
                "this connection's policy rule '{}' decides on the request body, which an approval \
                 on this path does not bind (it binds only the [requests.{}] scope fields); remove \
                 the rule's body match, or gate it with `when` on a bound field",
                id, shape
            ));
        }
        let Some(cond) = rule.when.as_deref().and_then(compiled_condition) else {
            continue; // an unparseable `when` never matches (P3)
        };
        for var in cond.var_names() {
            // The declared fields the `when` can resolve to, by the same lookup
            // evaluation uses (`extract_request_scope` inserts each var as
            // `name` and as `<shape>.name`). None: it never resolves here.
            let qualified = format!("{}.", shape);
            let fields: Vec<&str> = [Some(var.as_str()), var.strip_prefix(qualified.as_str())]
                .into_iter()
                .flatten()
                .filter(|f| declared.iter().any(|d| d == f))
                .collect();
            if fields.iter().any(|f| !binds.iter().any(|b| b == f)) {
                return Some(format!(
                    "this connection's policy rule '{}' gates on `vars.{}`, which the [requests.{}] \
                     shape does not bind, so an approval could not hold it fixed; gate the rule on a \
                     bound field instead",
                    id, var, shape
                ));
            }
        }
    }
    None
}


// ── `when` field conditions ──────────────────────────────────────────────────

/// Extracted request variables, `var-name → value` (the JSON value as read: a
/// body field keeps its JSON type, a query param is a string, a GraphQL
/// request's `fields` is a list of names). Produced by the service layer from
/// the matching `[requests]` shape (service.toml); consumed here to evaluate a
/// rule's `when`. Both the bare name (`amount`) and, for a matched shape, the
/// qualified name (`purchase.amount`) are inserted so a rule spanning several
/// shapes can disambiguate. Empty when a request matched no shape.
pub type VarMap = std::collections::HashMap<String, serde_json::Value>;

/// A parsed `when` predicate: a CEL expression (the Common Expression
/// Language, via cel-rust: the rule language of Kubernetes admission policies,
/// Envoy RBAC and Google IAM conditions) over `vars`, e.g.
/// `vars.amount > 100` or `vars.fields.exists(f, f in ["serviceDelete"])`. A
/// var is `vars.<name>`, or `vars.<shape>.<name>` for one shape's var.
///
/// It decides a request only when it evaluates to `true`. Anything else (a
/// var the request left undefined, a type that doesn't compare, a non-bool
/// result) means the rule does not match (P3: the engine invents no
/// decision). CEL's `||` and `&&` absorb an error the other side decides, so
/// `vars.a == 1 || vars.b == 2` still fires on `b` when `a` is undefined.
#[derive(Clone)]
pub struct Condition {
    program: std::sync::Arc<cel::Program>,
    vars: Vec<String>,
}

impl std::fmt::Debug for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Condition").field("vars", &self.vars).finish()
    }
}

impl Condition {
    /// Compile `s`. `Err` says why it is not a condition: CEL that doesn't
    /// parse, no `vars.<name>` in it, or a name other than `vars` (a bare
    /// word is a name in CEL; a string literal is quoted).
    pub fn compile(s: &str) -> Result<Condition, String> {
        let program = cel::Program::compile(s).map_err(|e| e.to_string())?;
        let mut vars = Vec::new();
        let mut unknown = Vec::new();
        let mut calls = Vec::new();
        walk_names(program.expression(), &mut Vec::new(), &mut vars, &mut unknown, &mut calls);
        if let Some(name) = unknown.first() {
            return Err(format!(
                "`{name}` is not a known name (a var is `vars.<name>`; quote a string literal)"
            ));
        }
        // A function this build doesn't provide would error on every request
        // and the rule would never fire: refused here instead.
        calls.sort();
        calls.dedup();
        if let Some(f) = calls.iter().find(|f| !function_exists(f)) {
            return Err(format!("`{f}()` is not a function this policy engine provides"));
        }
        if vars.is_empty() {
            return Err("it reads no `vars.<name>`".into());
        }
        vars.sort();
        vars.dedup();
        Ok(Condition {
            program: std::sync::Arc::new(program),
            vars,
        })
    }

    /// [`Self::compile`], for callers that only need to know it compiles.
    pub fn parse(s: &str) -> Option<Condition> {
        Condition::compile(s).ok()
    }

    /// The vars it reads (`vars.` stripped; may be qualified `shape.name`).
    /// Used by build-time verification to check membership in the service's
    /// declared `[requests]` vars.
    pub fn var_names(&self) -> &[String] {
        &self.vars
    }

    /// Evaluate against the request vars: `true` only for a CEL `true`.
    pub fn eval(&self, vars: &VarMap) -> bool {
        // Only the vars this condition reads go into its context (a GraphQL
        // `request` can be large). `vars.<shape>.<name>` reads a nested map,
        // so a qualified key nests.
        let reads = |k: &str| {
            self.vars.iter().any(|v| {
                v == k
                    || v.strip_prefix(k).is_some_and(|r| r.starts_with('.'))
                    || k.strip_prefix(v.as_str()).is_some_and(|r| r.starts_with('.'))
            })
        };
        let mut tree = serde_json::Map::new();
        let mut keys: Vec<&String> = vars.keys().filter(|k| reads(k)).collect();
        keys.sort();
        for k in keys {
            match k.split_once('.') {
                None => {
                    tree.entry(k.clone()).or_insert_with(|| vars[k].clone());
                }
                Some((shape, name)) => {
                    let slot = tree
                        .entry(shape.to_string())
                        .or_insert_with(|| serde_json::Value::Object(Default::default()));
                    if !slot.is_object() {
                        *slot = serde_json::Value::Object(Default::default());
                    }
                    if let Some(obj) = slot.as_object_mut() {
                        obj.insert(name.to_string(), vars[k].clone());
                    }
                }
            }
        }
        let mut ctx = cel::Context::default();
        if ctx.add_variable("vars", serde_json::Value::Object(tree)).is_err() {
            return false;
        }
        matches!(self.program.execute(&ctx), Ok(cel::Value::Bool(true)))
    }
}

/// Whether the engine provides a function of this name: called as a plain
/// function and as a method, with no arguments, it answers "undeclared" in
/// both forms only when it doesn't exist (a wrong arity or receiver is a
/// different error).
fn function_exists(name: &str) -> bool {
    [format!("{name}()"), format!("''.{name}()")].iter().any(|src| {
        cel::Program::compile(src).is_ok_and(|probe| {
            !matches!(
                probe.execute(&cel::Context::default()),
                Err(cel::ExecutionError::UndeclaredReference(_))
            )
        })
    })
}

/// Collect the `vars.<a>[.<b>]` a CEL expression reads, any other free name
/// (a comprehension's own variables are bound inside it), and the functions
/// it calls (operators and macros have non-identifier names and are skipped).
fn walk_names(
    e: &cel::IdedExpr,
    bound: &mut Vec<String>,
    vars: &mut Vec<String>,
    unknown: &mut Vec<String>,
    calls: &mut Vec<String>,
) {
    use cel::common::ast::{EntryExpr, Expr};
    let vars_path = |e: &cel::IdedExpr| -> Option<String> {
        let Expr::Select(outer) = &e.expr else { return None };
        match &outer.operand.expr {
            Expr::Ident(id) if id == "vars" => Some(outer.field.clone()),
            Expr::Select(inner) => match &inner.operand.expr {
                Expr::Ident(id) if id == "vars" => Some(format!("{}.{}", inner.field, outer.field)),
                _ => None,
            },
            _ => None,
        }
    };
    if let Some(path) = vars_path(e) {
        vars.push(path);
        return;
    }
    // CEL's type denotations (`type(x) == string`) are names too.
    const TYPES: &[&str] = &[
        "int", "uint", "double", "bool", "string", "bytes", "list", "map", "null_type", "type",
    ];
    match &e.expr {
        Expr::Ident(name) => {
            if name != "vars" && !bound.contains(name) && !TYPES.contains(&name.as_str()) {
                unknown.push(name.clone());
            }
        }
        // `vars["x"]` reads a var the checks can't name: only `vars.x` is.
        Expr::Call(c)
            if (c.func_name == "_[_]" || c.func_name == "_[?_]")
                && c.args.first().is_some_and(|a| match &a.expr {
                    Expr::Ident(id) => id == "vars",
                    Expr::Select(sel) => matches!(&sel.operand.expr, Expr::Ident(id) if id == "vars"),
                    _ => false,
                }) =>
        {
            unknown.push("vars[…]".into());
        }
        Expr::Select(s) => walk_names(&s.operand, bound, vars, unknown, calls),
        Expr::Call(c) => {
            let is_ident = |n: &str| {
                n.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                    && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            };
            if is_ident(&c.func_name) {
                calls.push(c.func_name.clone());
            }
            if let Some(t) = &c.target {
                walk_names(t, bound, vars, unknown, calls);
            }
            for a in &c.args {
                walk_names(a, bound, vars, unknown, calls);
            }
        }
        Expr::Comprehension(c) => {
            walk_names(&c.iter_range, bound, vars, unknown, calls);
            let n = bound.len();
            bound.push(c.iter_var.clone());
            bound.extend(c.iter_var2.clone());
            bound.push(c.accu_var.clone());
            for x in [&c.accu_init, &c.loop_cond, &c.loop_step, &c.result] {
                walk_names(x, bound, vars, unknown, calls);
            }
            bound.truncate(n);
        }
        Expr::List(l) => {
            for x in &l.elements {
                walk_names(x, bound, vars, unknown, calls);
            }
        }
        Expr::Map(m) => {
            for entry in &m.entries {
                if let EntryExpr::MapEntry(me) = &entry.expr {
                    walk_names(&me.key, bound, vars, unknown, calls);
                    walk_names(&me.value, bound, vars, unknown, calls);
                }
            }
        }
        Expr::Struct(st) => {
            for entry in &st.entries {
                if let EntryExpr::StructField(f) = &entry.expr {
                    walk_names(&f.value, bound, vars, unknown, calls);
                }
            }
        }
        Expr::Literal(_) | Expr::Unspecified => {}
    }
}

/// The text a rule's `body` regex is matched against: the body as sent, and,
/// when it is JSON, also its decoded form (parsed and written back out), on a
/// line of its own. A JSON string can spell any character as an escape, and
/// the upstream acts on the decoded value, so a rule must see that value too.
/// A rule fires when either form matches.
pub fn policy_body_view(raw: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    // Only `\uXXXX` and `\/` can spell a character a rule's pattern names;
    // the other escapes (`\n`, `\"`, `\\`…) can't hide one.
    if !raw.contains("\\u") && !raw.contains("\\/") {
        return Cow::Borrowed(raw);
    }
    match serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| serde_json::to_string(&v).ok())
    {
        Some(decoded) if decoded != raw => Cow::Owned(format!("{raw}\n{decoded}")),
        _ => Cow::Borrowed(raw),
    }
}

/// Check if a single rule matches the given request.
fn matches_rule(
    rule: &PolicyRule,
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
) -> bool {
    if rule.select.exec(method, path).is_none() {
        return false;
    }
    if let Some(ref pattern) = rule.body {
        match pattern.is_match(body.unwrap_or("")) {
            Some(true) => {}
            Some(false) => return false,
            // An unreadable pattern (only a user edit can carry one; the gate
            // rejects a definition with one) never loosens a decision: the
            // rule matches wherever it would restrict, and never where it
            // would allow.
            None => {
                if !matches!(
                    rule.level,
                    Some(AccessLevel::Ask | AccessLevel::AskAlways | AccessLevel::Deny)
                ) {
                    return false;
                }
            }
        }
    }
    // `when` field condition: an unparseable predicate or an undefined/failing
    // var means the rule does NOT match (P3 — never fabricate a decision).
    if let Some(ref cond) = rule.when {
        match compiled_condition(cond) {
            Some(c) if c.eval(vars) => {}
            _ => return false,
        }
    }
    true
}

/// A `when` compiled once per distinct text: a policy's rules are few and
/// change rarely, and every brokered request evaluates them.
fn compiled_condition(text: &str) -> Option<Condition> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Condition>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().ok().and_then(|c| c.get(text).cloned()) {
        return hit;
    }
    let compiled = Condition::parse(text);
    if let Ok(mut c) = cache.lock() {
        c.insert(text.to_string(), compiled.clone());
    }
    compiled
}

// ── Policy Evaluation ──────────────────────────────────────────────────────────

/// The read/write split the default floors and the reuse classes use. Fails
/// closed: only `GET`, `HEAD` and `OPTIONS` (any case) are reads; every other
/// method, including extension methods (`MOVE`, `PROPPATCH`, …), is a write.
pub(crate) fn is_write_method(method: &str) -> bool {
    !["GET", "HEAD", "OPTIONS"]
        .iter()
        .any(|read| read.eq_ignore_ascii_case(method))
}

/// Determine the access level for a request. See [`evaluate_with_match`].
pub fn evaluate(
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> AccessLevel {
    evaluate_with_match(
        method,
        path,
        body,
        vars,
        rules,
        connection_levels,
        policy,
        tags,
    )
    .0
}

/// What decided a request: a matched rule, or a default floor (connection,
/// tag, global, or the safe floor). The unit an `ask` approval is reused by
/// (`crate::approval::Reuse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidedBy {
    /// A rule matched; its `id` and `label` as declared.
    Rule {
        id: Option<String>,
        label: Option<String>,
    },
    /// No rule matched.
    Floor,
}

/// Resolve the access decision for a request, returning `(level,
/// matched_rule_id, ttl)`. See [`evaluate_decision`], which also says what
/// decided it.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_match(
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> (AccessLevel, Option<String>, Option<u64>) {
    let (level, by, ttl) = evaluate_decision(
        method,
        path,
        body,
        vars,
        rules,
        connection_levels,
        policy,
        tags,
    );
    let id = match by {
        DecidedBy::Rule { id, .. } => id,
        DecidedBy::Floor => None,
    };
    (level, id, ttl)
}

/// The stricter of two decisions for one request: `overlay` only where it is
/// more restrictive than `base`, a tie keeps `base`. How a policy that may
/// only tighten (a vault definition's) joins the decision made without it.
pub fn stricter(
    base: (AccessLevel, DecidedBy, Option<u64>),
    overlay: (AccessLevel, DecidedBy, Option<u64>),
) -> (AccessLevel, DecidedBy, Option<u64>) {
    if overlay.0.restrictiveness() > base.0.restrictiveness() {
        overlay
    } else {
        base
    }
}

/// Resolve the access decision for a request, returning `(level, what decided
/// it, ttl)`.
///
/// Resolution (PROTOCOL.md §6.4):
///   1. Among ALL matching rules, the **most restrictive** effective level wins
///      (deny-override / fail-safe). A tie goes to the first in declaration
///      order (the definition's rules in file order, then the user's added
///      rules, [`merge_rules`]), so the ask-cache scope is deterministic.
///   2. else connection default (read/write floor),
///   3. else tag default (the service's tags matched against the
///      `Policy.categories` floor map; several hits → most restrictive wins),
///   4. else global default,
///   5. else `ask-always` (safe floor).
///
/// [`DecidedBy::Rule`] when a rule decided (step 1), else
/// [`DecidedBy::Floor`].
///
/// A refused rule (a stored user rule the daemon can't read, DESIGN.md §2)
/// decides every request on its connection: a refused `deny` denies it, any
/// other makes it the stricter of `ask-always` and the decision without the
/// refused rules. A refused rule never loosens a decision.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_decision(
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> (AccessLevel, DecidedBy, Option<u64>) {
    let without = decide_readable(
        method,
        path,
        body,
        vars,
        rules,
        connection_levels,
        policy,
        tags,
    );
    let mut refused = rules
        .into_iter()
        .flatten()
        .filter(|r| r.select.problem().is_some());
    let Some(first) = refused.next() else {
        return without;
    };
    let by = |r: &PolicyRule| DecidedBy::Rule {
        id: r.id.clone(),
        label: r.label.clone(),
    };
    if let Some(deny) = std::iter::once(first)
        .chain(refused)
        .find(|r| r.level == Some(AccessLevel::Deny))
    {
        return (AccessLevel::Deny, by(deny), None);
    }
    stricter(without, (AccessLevel::AskAlways, by(first), None))
}

/// [`evaluate_decision`] over the rules that can be read.
#[allow(clippy::too_many_arguments)]
fn decide_readable(
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> (AccessLevel, DecidedBy, Option<u64>) {
    // The `ask`-cache window a matched rule inherits when it pins no `ttl` of
    // its own: the ttl of the most-specific floor (connection → tag → global),
    // the SAME precedence as the read/write floor decision below. Direction-
    // independent (Levels.ttl is a single value). Resolved up front because a
    // rule decision returns early; consumed only by an `ask` rule (a floor
    // decision returns its own floor's ttl), and a final constant fills in
    // when nothing pins a window at all.
    let floor_ttl = connection_levels
        .and_then(|lv| lv.ttl)
        .or_else(|| {
            tags.iter()
                .filter_map(|t| policy.categories.get(t))
                .find_map(|lv| lv.ttl)
        })
        .or_else(|| policy.default.as_ref().and_then(|lv| lv.ttl));

    // 1. Rules — most-restrictive matching wins (deny-override).
    if let Some(rules) = rules {
        let mut best: Option<(&PolicyRule, AccessLevel)> = None;
        for rule in rules {
            if !matches_rule(rule, method, path, body, vars) {
                continue;
            }
            let Some(level) = rule.effective_level() else {
                continue; // rule declares no level → no decision; skip.
            };
            // Strictly stricter only: the first of equally strict rules stands.
            if best.is_none_or(|(_, b)| level.restrictiveness() > b.restrictiveness()) {
                best = Some((rule, level));
            }
        }
        if let Some((rule, level)) = best {
            // The rule's own ttl wins; else it inherits the default-floor window.
            let by = DecidedBy::Rule {
                id: rule.id.clone(),
                label: rule.label.clone(),
            };
            return (level, by, rule.ttl.or(floor_ttl));
        }
    }

    // 2-4. Default floor: connection → tag → global. Read/write split.
    let pick = |lv: &Levels| -> Option<(AccessLevel, Option<u64>)> {
        let l = if is_write_method(method) {
            lv.write
        } else {
            lv.read
        };
        l.map(|l| (l, lv.ttl))
    };
    if let Some(lv) = connection_levels {
        if let Some((l, ttl)) = pick(lv) {
            return (l, DecidedBy::Floor, ttl);
        }
    }
    // A service may carry several tags; if more than one hits a floor that
    // decides this method, the most restrictive wins (fail-closed, mirrors
    // the rule-layer deny-override above).
    let tag_hit = tags
        .iter()
        .filter_map(|t| policy.categories.get(t))
        .filter_map(|lv| pick(lv))
        .max_by_key(|(l, _)| l.restrictiveness());
    if let Some((l, ttl)) = tag_hit {
        return (l, DecidedBy::Floor, ttl);
    }
    if let Some(lv) = policy.default.as_ref() {
        if let Some((l, ttl)) = pick(lv) {
            return (l, DecidedBy::Floor, ttl);
        }
    }

    // 5. Safe floor.
    (AccessLevel::AskAlways, DecidedBy::Floor, None)
}

// ── Unit Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::default()
    }

    fn rule(id: &str, pat: &str, level: AccessLevel) -> PolicyRule {
        PolicyRule {
            id: Some(id.into()),
            label: None,
            select: sel(pat),
            body: None,
            when: None,
            level: Some(level),
            ttl: None,
        }
    }

    /// `"METHOD /path"` or `"/path"` (2.1 syntax) as a selection.
    fn sel(spec: &str) -> Select {
        let (methods, path) = match spec.split_once(' ') {
            Some((m, p)) => (vec![m.to_string()], p),
            None => (vec![], spec),
        };
        Select::new(methods, vec![PathPattern::compile(path).unwrap()])
    }

    // ── ask-once window (ttl) resolution ─────────────────────────────────────
    #[test]
    fn ask_rule_without_ttl_inherits_floor_window() {
        let rules = vec![rule("del", "DELETE /x", AccessLevel::Ask)]; // ttl: None
        let conn = Levels {
            read: None,
            write: None,
            ttl: Some(1234),
        };

        // A matched ask rule that pins no ttl inherits the connection-floor window.
        let (_l, id, ttl) = evaluate_with_match(
            "DELETE",
            "/x",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&rules),
            Some(&conn),
            &policy(),
            &[],
        );
        assert_eq!(id.as_deref(), Some("del"));
        assert_eq!(ttl, Some(1234));

        // The rule's own ttl wins over the floor window.
        let mut pinned = rules.clone();
        pinned[0].ttl = Some(60);
        let (_l2, _id2, ttl2) = evaluate_with_match(
            "DELETE",
            "/x",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&pinned),
            Some(&conn),
            &policy(),
            &[],
        );
        assert_eq!(ttl2, Some(60));

        // No ttl anywhere in the floors → None (the proxy applies its constant).
        let bare = Levels::default();
        let (_l3, _id3, ttl3) = evaluate_with_match(
            "DELETE",
            "/x",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&rules),
            Some(&bare),
            &policy(),
            &[],
        );
        assert_eq!(ttl3, None);
    }

    // ── AccessLevel ──────────────────────────────────────────────────────────
    #[test]
    fn access_level_parses_and_ranks() {
        assert_eq!(
            AccessLevel::parse("ask-always"),
            Some(AccessLevel::AskAlways)
        );
        assert_eq!(AccessLevel::parse("nope"), None);
        assert!(AccessLevel::Deny.restrictiveness() > AccessLevel::Allow.restrictiveness());
    }

    // ── Connection rule edits on scoped paths ────────────────────────────────
    #[test]
    fn user_rule_on_a_scoped_path_must_decide_on_bound_fields() {
        let built_in = vec![rule("pay", "POST /pay", AccessLevel::Ask)];
        let declared = vec!["amount".to_string(), "memo".to_string()];
        let binds = vec!["amount".to_string()];
        let check = |user: &HashMap<String, RuleConfig>, m: &str, p: &str| {
            unenforceable_user_rule(&built_in, user, m, p, "purchase", &declared, &binds)
        };
        let add = |pat: Option<&str>, when: Option<&str>, body: Option<&str>| RuleConfig {
            when: when.map(str::to_string),
            body: body.map(BodyPattern::lenient),
            level: Some(AccessLevel::AskAlways),
            ..pat.map(RuleConfig::selecting).unwrap_or_default()
        };
        let mut user = HashMap::new();
        // Gating on a bound field is enforceable.
        user.insert(
            "big".to_string(),
            add(Some("POST /pay"), Some("vars.amount > 100"), None),
        );
        assert_eq!(check(&user, "POST", "/pay"), None);

        // A declared but unbound field decides: refused, by rule and field.
        user.insert(
            "memo".to_string(),
            add(Some("POST /pay"), Some("vars.memo == \"x\""), None),
        );
        let e = check(&user, "post", "/pay").expect("refused");
        assert!(e.contains("'memo'") && e.contains("vars.memo"), "{e}");
        assert!(!e.contains('\u{2014}'), "no em dash in copy");
        // Only where the rule's match covers the request.
        assert_eq!(check(&user, "POST", "/other"), None);
        user.remove("memo");

        // Qualified by this shape: the same field; by another shape: never
        // resolves here, so not refused. An undeclared var never fires.
        user.insert(
            "q".to_string(),
            add(Some("POST /pay"), Some("vars.purchase.memo == 1"), None),
        );
        assert!(check(&user, "POST", "/pay").is_some());
        user.insert(
            "q".to_string(),
            add(Some("POST /pay"), Some("vars.refund.memo == 1"), None),
        );
        assert_eq!(check(&user, "POST", "/pay"), None);
        user.insert(
            "q".to_string(),
            add(Some("POST /pay"), Some("vars.nope == 1"), None),
        );
        assert_eq!(check(&user, "POST", "/pay"), None);
        user.remove("q");

        // An override of a built-in rule by id is checked on the built-in's
        // match, with the built-in's level.
        user.insert(
            "pay".to_string(),
            RuleConfig {
                when: Some("vars.memo == 1".into()),
                ..Default::default()
            },
        );
        assert!(check(&user, "POST", "/pay").unwrap().contains("'pay'"));
        user.remove("pay");

        // A body match on a covered scoped path: refused (the body is never bound).
        user.insert("b".to_string(), add(Some("/pay"), None, Some("refund")));
        let e = check(&user, "POST", "/pay").expect("refused");
        assert!(e.contains("'b'") && e.contains("body"), "{e}");
        assert_eq!(check(&user, "POST", "/elsewhere"), None);
        user.remove("b");

        // `allow` / `deny` edits mint no approval: never refused.
        for level in [AccessLevel::Allow, AccessLevel::Deny] {
            let mut only = HashMap::new();
            only.insert(
                "protect".to_string(),
                RuleConfig {
                    level: Some(level),
                    ..add(Some("POST /pay"), Some("vars.memo == 1"), Some("bitcoin"))
                },
            );
            assert_eq!(check(&only, "POST", "/pay"), None, "{level:?}");
        }

        // A declared var whose own name has a dot resolves verbatim, as at
        // evaluation.
        let dotted = vec!["a.b".to_string(), "amount".to_string()];
        let mut only = HashMap::new();
        only.insert(
            "d".to_string(),
            add(Some("POST /pay"), Some("vars.a.b == 1"), None),
        );
        assert!(unenforceable_user_rule(
            &built_in, &only, "POST", "/pay", "purchase", &dotted, &binds
        )
        .is_some());
    }

    #[test]
    fn scoped_check_judges_the_merged_rule() {
        // A built-in `deny` that decides on the body; an edit of only its
        // level to `ask` produces an ask that decides on the body, which an
        // approval on this scoped path does not bind: refused.
        let built_in = vec![PolicyRule {
            body: Some(BodyPattern::compile("gift").unwrap()),
            ..rule("gifts", "POST /pay", AccessLevel::Deny)
        }];
        let declared = vec!["amount".to_string()];
        let binds = vec!["amount".to_string()];
        let check = |user: &HashMap<String, RuleConfig>| {
            unenforceable_user_rule(
                &built_in, user, "POST", "/pay", "purchase", &declared, &binds,
            )
        };
        let mut user = HashMap::new();
        assert_eq!(check(&user), None, "the built-in deny mints no approval");
        user.insert(
            "gifts".to_string(),
            RuleConfig {
                level: Some(AccessLevel::Ask),
                ..Default::default()
            },
        );
        let e = check(&user).expect("level-only edit on a body rule");
        assert!(e.contains("'gifts'") && e.contains("body"), "{e}");
        // A `ttl`-only edit keeps the deny: nothing to refuse.
        user.insert(
            "gifts".to_string(),
            RuleConfig {
                ttl: Some(60),
                ..Default::default()
            },
        );
        assert_eq!(check(&user), None);
        // A built-in ask gated on a field this shape does not bind, edited
        // only in ttl: the merged rule still decides on that field.
        let built_in = vec![PolicyRule {
            when: Some("vars.memo == 1".into()),
            ..rule("memo", "POST /pay", AccessLevel::Ask)
        }];
        let declared = vec!["amount".to_string(), "memo".to_string()];
        let mut user = HashMap::new();
        user.insert(
            "memo".to_string(),
            RuleConfig {
                ttl: Some(60),
                ..Default::default()
            },
        );
        assert!(unenforceable_user_rule(
            &built_in, &user, "POST", "/pay", "purchase", &declared, &binds
        )
        .is_some());
    }

    /// A stored user rule in the 2.0 `match` syntax is refused (DESIGN.md
    /// §2): a refused `deny` denies the whole connection, any other refused
    /// rule makes every request on it ask every time, unless the decision
    /// without it is stricter. It overrides no built-in rule.
    #[test]
    fn a_stored_2_0_rule_is_refused() {
        let floor = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Deny),
            ttl: None,
        };
        let built_in = vec![rule("read", "GET /x", AccessLevel::Ask)];
        let decide = |user: &HashMap<String, RuleConfig>, m: &str, p: &str| {
            let rules = merge_rules(&built_in, user);
            evaluate_decision(m, p, None, &VarMap::new(), Some(&rules), Some(&floor), &policy(), &[])
        };
        let old = |level: AccessLevel| RuleConfig {
            match_pattern: Some("delete /repos/*/*".into()),
            level: Some(level),
            ..Default::default()
        };
        let mut user = HashMap::new();
        user.insert("del".to_string(), old(AccessLevel::Deny));
        for (m, p) in [("GET", "/x"), ("GET", "/elsewhere"), ("DELETE", "/repos/o/r")] {
            let (level, by, _) = decide(&user, m, p);
            assert_eq!(level, AccessLevel::Deny, "{m} {p}");
            assert!(matches!(by, DecidedBy::Rule { id: Some(ref id), .. } if id == "del"));
        }
        for level in [AccessLevel::Allow, AccessLevel::Ask, AccessLevel::AskAlways] {
            user.insert("del".to_string(), old(level));
            assert_eq!(decide(&user, "GET", "/elsewhere").0, AccessLevel::AskAlways, "{level:?}");
            assert_eq!(decide(&user, "GET", "/x").0, AccessLevel::AskAlways, "{level:?}");
            // Stricter without it: that stands.
            assert_eq!(decide(&user, "POST", "/elsewhere").0, AccessLevel::Deny, "{level:?}");
        }
        // On a built-in id it overrides nothing, and is refused too.
        let mut user = HashMap::new();
        user.insert(
            "read".to_string(),
            RuleConfig {
                match_pattern: Some("GET /x".into()),
                level: Some(AccessLevel::Allow),
                ..Default::default()
            },
        );
        let merged = merge_rules(&built_in, &user);
        assert_eq!(merged[0].level, Some(AccessLevel::Ask));
        assert_eq!(decide(&user, "GET", "/x").0, AccessLevel::AskAlways);
        // A 2.1 `method` is stored uppercase and selects.
        let edit: RuleConfig = serde_json::from_value(
            serde_json::json!({"method": "delete", "path": "/repos/:owner/:repo", "level": "deny"}),
        )
        .unwrap();
        assert_eq!(edit.method.as_deref(), Some(&["DELETE".to_string()][..]));
        let mut user = HashMap::new();
        user.insert("del".to_string(), edit);
        let rules = merge_rules(&[], &user);
        assert_eq!(rules[0].select.exec("DELETE", "/repos/o/r").map(|p| p.len()), Some(2));
        assert_eq!(decide(&user, "DELETE", "/repos/o/r").0, AccessLevel::Deny);
        assert_eq!(decide(&user, "GET", "/elsewhere").0, AccessLevel::Allow);
    }

    #[test]
    fn body_patterns_compile_once_and_unreadable_ones_never_loosen() {
        let p = BodyPattern::compile("gift|card").unwrap();
        assert_eq!(p.is_match("a gift"), Some(true));
        assert_eq!(p.is_match("cash"), Some(false));
        assert!(BodyPattern::compile("(unclosed").is_err());
        assert!(BodyPattern::compile(&"a".repeat(2000)).is_err());
        // Serde: a sealed user edit with a bad pattern still loads.
        let edit: RuleConfig = serde_json::from_value(
            serde_json::json!({"method": "POST", "path": "/x", "body": "(", "level": "deny"}),
        )
        .unwrap();
        let body = edit.body.as_ref().unwrap();
        assert!(body.error().is_some());
        assert_eq!(serde_json::to_value(body).unwrap(), serde_json::json!("("));
        // The rule that carries it restricts everywhere its match covers, and
        // never allows.
        let with = |level| {
            vec![PolicyRule {
                body: Some(BodyPattern::lenient("(")),
                ..rule("r", "POST /x", level)
            }]
        };
        let floor = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Ask),
            ttl: None,
        };
        let decide = |rules: &Vec<PolicyRule>| {
            evaluate(
                "POST",
                "/x",
                Some("anything"),
                &VarMap::new(),
                Some(rules),
                Some(&floor),
                &policy(),
                &[],
            )
        };
        assert_eq!(decide(&with(AccessLevel::Deny)), AccessLevel::Deny);
        assert_eq!(
            decide(&with(AccessLevel::AskAlways)),
            AccessLevel::AskAlways
        );
        assert_eq!(
            decide(&with(AccessLevel::Allow)),
            AccessLevel::Ask,
            "falls to the floor"
        );
    }

    // ── Method normalization (fail closed) ───────────────────────────────────
    #[test]
    fn only_get_head_options_are_reads() {
        for m in ["GET", "HEAD", "OPTIONS", "get", "Head", "options"] {
            assert!(!is_write_method(m), "{m} is a read");
        }
        for m in [
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "delete",
            "MOVE",
            "PROPPATCH",
            "COPY",
            "MKCOL",
            "TRACE",
            "",
        ] {
            assert!(is_write_method(m), "{m} is a write");
        }
    }

    #[test]
    fn rule_method_matches_case_insensitively() {
        let rules = vec![rule("del", "DELETE /x", AccessLevel::Deny)];
        let floor = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Ask),
            ttl: None,
        };
        let decide = |m: &str| {
            evaluate_decision(
                m,
                "/x",
                None,
                &VarMap::new(),
                Some(&rules),
                Some(&floor),
                &policy(),
                &[],
            )
        };
        // A lowercase `delete` hits the DELETE rule, never a floor.
        let (level, by, _) = decide("delete");
        assert_eq!(level, AccessLevel::Deny);
        assert!(matches!(by, DecidedBy::Rule { id: Some(ref id), .. } if id == "del"));
        // An extension method falls to the WRITE floor, not the read one.
        for m in ["MOVE", "PROPPATCH", "propfind"] {
            let (level, by, _) = decide(m);
            assert_eq!(by, DecidedBy::Floor);
            assert_eq!(level, AccessLevel::Ask, "{m} takes the write floor");
        }
        assert_eq!(decide("GET").0, AccessLevel::Allow);
    }

    // ── Path matching ────────────────────────────────────────────────────────
    fn path_matches(pattern: &str, path: &str) -> bool {
        sel(pattern).exec("GET", path).is_some()
    }

    #[test]
    fn a_named_group_matches_one_segment() {
        assert!(path_matches("/repos/:owner/issues", "/repos/r/issues"));
        assert!(!path_matches("/repos/:owner", "/repos/o/r"));
    }

    #[test]
    fn a_final_wildcard_matches_variable_depth() {
        // One rule covers any-depth refs (heads/main, heads/feature/x, tags/v1).
        let p = "/repos/:owner/:repo/git/refs/*";
        assert!(path_matches(p, "/repos/o/r/git/refs/heads/main"));
        assert!(path_matches(p, "/repos/o/r/git/refs/heads/feature/x"));
        assert!(path_matches(p, "/repos/o/r/git/refs/tags/v1"));
        // `/*` requires at least one more segment — the bare prefix does not match.
        assert!(!path_matches(p, "/repos/o/r/git/refs"));
        assert!(!path_matches(p, "/repos/o/r/git/refs/"));
        // Fixed prefix still has to line up.
        assert!(!path_matches(p, "/repos/o/r/git/blobs/abc"));
        // A named group is still exactly one segment (no accidental widening).
        assert!(!path_matches(
            "/repos/:owner/:repo/git/refs/:ref",
            "/repos/o/r/git/refs/heads/main"
        ));
    }

    /// Equally strict rules: the first in declaration order decides (the
    /// definition's rules in file order, then added user rules by id), never
    /// the more specific one.
    #[test]
    fn a_tie_goes_to_declaration_order() {
        let decide = |rules: &Vec<PolicyRule>| {
            evaluate_with_match("POST", "/m/send", None, &VarMap::new(), Some(rules), None, &policy(), &[]).1
        };
        let rules = vec![
            rule("broad", "POST /m/:id", AccessLevel::Ask),
            rule("narrow", "POST /m/send", AccessLevel::Ask),
        ];
        assert_eq!(decide(&rules).as_deref(), Some("broad"));
        let rules = vec![
            rule("narrow", "POST /m/send", AccessLevel::Ask),
            rule("broad", "POST /m/:id", AccessLevel::Ask),
        ];
        assert_eq!(decide(&rules).as_deref(), Some("narrow"));
        // A stricter rule still wins wherever it is.
        let rules = vec![
            rule("broad", "POST /m/:id", AccessLevel::Ask),
            rule("narrow", "POST /m/send", AccessLevel::AskAlways),
        ];
        assert_eq!(decide(&rules).as_deref(), Some("narrow"));
        // Added user rules follow the definition's, in id order.
        let mut user = HashMap::new();
        for id in ["b-user", "a-user"] {
            user.insert(
                id.to_string(),
                RuleConfig {
                    level: Some(AccessLevel::Ask),
                    ..RuleConfig::selecting("POST /m/send")
                },
            );
        }
        let merged = merge_rules(&[], &user);
        assert_eq!(decide(&merged).as_deref(), Some("a-user"));
        let merged = merge_rules(&[rule("built-in", "POST /m/:id", AccessLevel::Ask)], &user);
        assert_eq!(decide(&merged).as_deref(), Some("built-in"));
    }

    // ── Level resolution ─────────────────────────────────────────────────────
    #[test]
    fn level_on_rule_decides() {
        // The headline: list (allow) + read (ask) = read an email in ONE
        // approval, not two.
        let low = vec![rule("list", "GET /m", AccessLevel::Allow)];
        assert_eq!(
            evaluate(
                "GET",
                "/m",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&low),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Allow
        );
        let med = vec![rule("read", "GET /m/:id", AccessLevel::Ask)];
        assert_eq!(
            evaluate(
                "GET",
                "/m/1",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&med),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Ask
        );
        let high = vec![rule("send", "POST /m/send", AccessLevel::AskAlways)];
        assert_eq!(
            evaluate(
                "POST",
                "/m/send",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&high),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::AskAlways
        );
        let del = vec![rule("del", "DELETE /m/:id", AccessLevel::Deny)];
        assert_eq!(
            evaluate(
                "DELETE",
                "/m/1",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&del),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Deny
        );
    }

    #[test]
    fn match_list_is_an_or_across_patterns() {
        // One rule, two endpoints (different method AND path depth) for the same
        // logical operation — both fire it, unrelated requests don't.
        let rules = vec![PolicyRule {
            id: Some("open-network".into()),
            label: None,
            select: Select::new(
                vec!["POST".into(), "PATCH".into()],
                vec![
                    PathPattern::compile("/v1/projects/:ref/network-restrictions/apply").unwrap(),
                    PathPattern::compile("/v1/projects/:ref/network-restrictions").unwrap(),
                ],
            ),
            body: None,
            when: None,
            level: Some(AccessLevel::AskAlways),
            ttl: None,
        }];
        let ev = |m: &str, p: &str| {
            evaluate(
                m,
                p,
                None,
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                None,
                &policy(),
                &[],
            )
        };
        assert_eq!(
            ev("POST", "/v1/projects/abc/network-restrictions/apply"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            ev("PATCH", "/v1/projects/abc/network-restrictions"),
            AccessLevel::AskAlways
        );
        // Wrong method on the PATCH path, or an unrelated path → no match → floor.
        assert_eq!(
            ev("GET", "/v1/projects/abc/network-restrictions"),
            AccessLevel::Allow
        );
        assert_eq!(
            ev("POST", "/v1/projects/abc/database/query"),
            AccessLevel::Allow
        );
    }

    #[test]
    fn a_stored_rule_reads_back_as_it_was_written() {
        // `method` and `path` keep one string as a string and a list as a
        // list.
        for stored in [
            serde_json::json!({"method": "POST", "path": "/a/:id", "level": "ask"}),
            serde_json::json!({"method": ["POST", "PATCH"], "path": ["/a", "/b/*"], "level": "ask"}),
        ] {
            let edit: RuleConfig = serde_json::from_value(stored.clone()).unwrap();
            assert!(edit.select().is_some_and(|s| s.problem().is_none()), "{stored}");
            assert_eq!(serde_json::to_value(&edit).unwrap(), stored);
        }
        // An override carries no selector.
        let edit: RuleConfig = serde_json::from_value(serde_json::json!({"level": "allow"})).unwrap();
        assert!(edit.select().is_none());
        // One the daemon refuses is kept as stored, and marked so.
        for bad in [
            serde_json::json!({"match": "delete /x/*", "level": "deny"}),
            serde_json::json!({"path": "/a/:", "level": "deny"}),
            serde_json::json!({"path": "/repos/*/issues", "level": "deny"}),
            serde_json::json!({"method": "GE T", "level": "deny"}),
            serde_json::json!({"method": [], "level": "deny"}),
            serde_json::json!({"match": "POST /a", "path": "/a", "level": "deny"}),
        ] {
            let edit: RuleConfig = serde_json::from_value(bad.clone()).unwrap();
            assert!(edit.select().unwrap().problem().is_some(), "{bad}");
            assert_eq!(serde_json::to_value(&edit).unwrap(), bad);
        }
    }

    /// A stored user rule whose selector can't be read is refused like one in
    /// the 2.0 syntax: it never loosens a decision.
    #[test]
    fn an_unreadable_selector_is_a_refused_rule() {
        let floor = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Ask),
            ttl: None,
        };
        let decide = |level: AccessLevel| {
            let mut user = HashMap::new();
            user.insert(
                "r".to_string(),
                RuleConfig {
                    path: Some(vec![PathPattern::lenient("/a/:")]),
                    level: Some(level),
                    ..Default::default()
                },
            );
            let rules = merge_rules(&[], &user);
            evaluate("GET", "/elsewhere", None, &VarMap::new(), Some(&rules), Some(&floor), &policy(), &[])
        };
        assert_eq!(decide(AccessLevel::Deny), AccessLevel::Deny);
        assert_eq!(decide(AccessLevel::AskAlways), AccessLevel::AskAlways);
        assert_eq!(decide(AccessLevel::Allow), AccessLevel::AskAlways);
    }

    #[test]
    fn rule_with_no_level_is_skipped() {
        // A malformed rule (no level) can never decide → falls through to the
        // global default (allow).
        let bad = vec![PolicyRule {
            id: Some("bad".into()),
            label: None,
            select: sel("GET /x"),
            body: None,
            when: None,
            level: None,
            ttl: None,
        }];
        assert_eq!(
            evaluate(
                "GET",
                "/x",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&bad),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Allow
        );
    }

    // ── Conflict resolution: deny-override / most-restrictive ─────────────────
    #[test]
    fn most_restrictive_matching_rule_wins() {
        // Two rules match the same request; the stricter (deny) wins even though
        // it's less specific — fail-safe, not most-specific.
        let rules = vec![
            rule("broad", "DELETE /m/:id", AccessLevel::Deny), // less specific, stricter
            rule("narrow", "DELETE /m/safe", AccessLevel::Allow), // more specific, looser
        ];
        assert_eq!(
            evaluate(
                "DELETE",
                "/m/safe",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Deny
        );
    }

    // ── Default floor chain ──────────────────────────────────────────────────
    #[test]
    fn no_rule_falls_through_to_connection_then_tag_then_global() {
        // No matching rule → connection floor wins when set.
        let conn = Levels {
            read: Some(AccessLevel::Ask),
            write: None,
            ttl: None,
        };
        assert_eq!(
            evaluate(
                "GET",
                "/unmatched",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&vec![]),
                Some(&conn),
                &policy(),
                &[]
            ),
            AccessLevel::Ask
        );
        // No connection floor → tag floor (ai = allow).
        assert_eq!(
            evaluate(
                "POST",
                "/v1/chat",
                None,
                &crate::core::policy::VarMap::new(),
                None,
                None,
                &policy(),
                &["ai".into()]
            ),
            AccessLevel::Allow
        );
        // No tag match → global default (allow).
        assert_eq!(
            evaluate(
                "GET",
                "/x",
                None,
                &crate::core::policy::VarMap::new(),
                None,
                None,
                &policy(),
                &["unknown".into()]
            ),
            AccessLevel::Allow
        );
    }

    #[test]
    fn multiple_tag_floors_most_restrictive_wins() {
        let mut p = policy();
        p.categories.insert(
            "wallet".into(),
            Levels {
                read: Some(AccessLevel::AskAlways),
                write: Some(AccessLevel::Deny),
                ttl: None,
            },
        );
        // ai says allow, wallet says ask-always/deny → the stricter floor wins.
        let tags = vec!["ai".to_string(), "wallet".to_string()];
        assert_eq!(
            evaluate(
                "GET",
                "/x",
                None,
                &crate::core::policy::VarMap::new(),
                None,
                None,
                &p,
                &tags
            ),
            AccessLevel::AskAlways
        );
        assert_eq!(
            evaluate(
                "POST",
                "/x",
                None,
                &crate::core::policy::VarMap::new(),
                None,
                None,
                &p,
                &tags
            ),
            AccessLevel::Deny
        );
    }

    // ── Merge: override by id + add new rule ──────────────────────────────────
    #[test]
    fn merge_overrides_level_by_id() {
        let built_in = vec![rule("read", "GET /m/:id", AccessLevel::Ask)];
        let mut user = HashMap::new();
        user.insert(
            "read".into(),
            RuleConfig {
                level: Some(AccessLevel::Allow),
                ..Default::default()
            },
        );
        let merged = merge_rules(&built_in, &user);
        assert_eq!(merged[0].level, Some(AccessLevel::Allow));
        assert_eq!(merged[0].select.display(), ["GET /m/:id"]); // preserved
    }

    #[test]
    fn merge_lets_user_tighten_a_rule_to_deny() {
        let built_in = vec![rule("del", "DELETE /m/:id", AccessLevel::AskAlways)];
        let mut user = HashMap::new();
        user.insert(
            "del".into(),
            RuleConfig {
                level: Some(AccessLevel::Deny),
                ..Default::default()
            },
        );
        let merged = merge_rules(&built_in, &user);
        assert_eq!(
            evaluate(
                "DELETE",
                "/m/1",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&merged),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Deny
        );
    }

    #[test]
    fn merge_adds_new_rule_with_match() {
        let built_in = vec![rule("send", "POST /m/send", AccessLevel::AskAlways)];
        let mut user = HashMap::new();
        user.insert(
            "vip".into(),
            RuleConfig {
                level: Some(AccessLevel::Allow),
                ..RuleConfig::selecting("POST /m/vip")
            },
        );
        let merged = merge_rules(&built_in, &user);
        assert_eq!(merged.len(), 2);
        assert!(merged
            .iter()
            .any(|r| r.id.as_deref() == Some("vip") && r.level == Some(AccessLevel::Allow)));
    }

    #[test]
    fn merge_levels_user_wins_fieldwise() {
        let u = Levels {
            read: Some(AccessLevel::Allow),
            write: None,
            ttl: None,
        };
        let r = Levels {
            read: Some(AccessLevel::Ask),
            write: Some(AccessLevel::Deny),
            ttl: Some(30),
        };
        let m = merge_levels(Some(&u), Some(&r)).unwrap();
        assert_eq!(m.read, Some(AccessLevel::Allow)); // user
        assert_eq!(m.write, Some(AccessLevel::Deny)); // recipe
        assert_eq!(m.ttl, Some(30));
    }

    // ── ask-cache scope: method is part of the key (regression) ──────────────
    #[test]
    fn matched_rule_id_and_ttl_returned_for_ask_cache() {
        let mut rules = vec![rule("read", "GET /x", AccessLevel::Ask)];
        rules[0].ttl = Some(60);
        let (lvl, id, ttl) = evaluate_with_match(
            "GET",
            "/x",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&rules),
            None,
            &policy(),
            &[],
        );
        assert_eq!(lvl, AccessLevel::Ask);
        assert_eq!(id.as_deref(), Some("read"));
        assert_eq!(ttl, Some(60));
    }

    // ── `when` field conditions (Phase 2) ────────────────────────────────────
    #[test]
    fn condition_parses_and_evaluates() {
        use serde_json::json;
        let mut vars = VarMap::new();
        vars.insert("amount".into(), json!(100));
        vars.insert("merchant".into(), json!("acme"));
        let eval = |w: &str, v: &VarMap| Condition::parse(w).unwrap().eval(v);

        assert!(eval("vars.amount > 80", &vars));
        assert!(!eval("vars.amount > 200", &vars));
        assert!(eval("vars.amount >= 100", &vars));
        assert!(eval("vars.amount <= 100", &vars));
        assert!(eval(r#"vars.merchant == "acme""#, &vars));
        assert!(eval("vars.merchant != 'evil'", &vars));
        // Undefined var → false (P3), never a panic.
        assert!(!eval("vars.missing > 0", &vars));
        // `||` still decides on the side it can read.
        assert!(eval("vars.missing > 0 || vars.amount > 80", &vars));
        // A type that doesn't compare → false, not an error.
        assert!(!eval("vars.merchant > 0", &vars));
        // double() reads a number sent as a string.
        let mut text = VarMap::new();
        text.insert("amount".into(), json!("150"));
        assert!(!eval("vars.amount > 100", &text));
        assert!(eval("double(vars.amount) > 100.0", &text));
        // A qualified var reads one shape's value.
        let mut q = VarMap::new();
        q.insert("purchase.amount".into(), json!(5));
        q.insert("amount".into(), json!(5));
        assert!(eval("vars.purchase.amount == 5", &q));
        // Malformed or not about vars → no condition (build-time rejects;
        // runtime treats it as a non-match).
        assert!(Condition::parse("amount > 80").is_none());
        assert!(Condition::parse("vars.amount ~ 80").is_none());
        assert!(Condition::parse("1 == 1").is_none());
        assert!(Condition::parse("vars.amount == bare").is_none());
        assert!(Condition::parse("vars['amount'] > 1").is_none());
        // A function this build lacks is refused, not left to fail on every request.
        assert!(Condition::compile("vars.model.startswith('o3')").is_err());
        assert!(Condition::compile("vars.model.lowerAscii() == 'o3'").is_err());
        // `matches` is CEL's standard RE2 function (cel's `regex` feature).
        assert!(Condition::compile("vars.model.matches('^o3')").is_ok());
        assert!(Condition::compile("vars.model.startsWith('o3')").is_ok());
        assert!(Condition::compile("size(vars.fields) > 0 && vars.fields.exists(f, f == 'a')").is_ok());
        // A type test, and a number sent as text read either way.
        let c = Condition::parse("!(type(vars.amount) in [int, uint, double]) || vars.amount > 100").unwrap();
        assert!(c.eval(&text));
        let mut padded = VarMap::new();
        padded.insert("amount".into(), json!(" 500"));
        assert!(c.eval(&padded));
        let mut listed = VarMap::new();
        listed.insert("amount".into(), json!([500]));
        assert!(c.eval(&listed));
        assert!(!c.eval(&vars), "the number 100 is not over 100");
    }

    #[test]
    fn when_composes_with_most_restrictive_wins() {
        // The snaplii shape: a base `ask` on every purchase, and an
        // `ask-always` refinement for amount > 80. Most-restrictive-wins picks
        // ask-always when both match, ask when only the base does.
        let rules = vec![
            PolicyRule {
                id: Some("p".into()),
                label: None,
                select: sel("POST /buy"),
                body: None,
                when: None,
                level: Some(AccessLevel::Ask),
                ttl: None,
            },
            PolicyRule {
                id: Some("pl".into()),
                label: None,
                select: sel("POST /buy"),
                body: None,
                when: Some("vars.amount > 80".into()),
                level: Some(AccessLevel::AskAlways),
                ttl: None,
            },
        ];
        let mut big = VarMap::new();
        big.insert("amount".into(), serde_json::json!(100));
        let mut small = VarMap::new();
        small.insert("amount".into(), serde_json::json!(50));

        assert_eq!(
            evaluate(
                "POST",
                "/buy",
                None,
                &big,
                Some(&rules),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::AskAlways
        );
        assert_eq!(
            evaluate(
                "POST",
                "/buy",
                None,
                &small,
                Some(&rules),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Ask
        );
        // Amount undefined (no shape matched / field absent) → the `when` rule
        // doesn't fire, the base `ask` still gates the spend (never a bypass).
        assert_eq!(
            evaluate(
                "POST",
                "/buy",
                None,
                &VarMap::new(),
                Some(&rules),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Ask
        );
    }

    #[test]
    fn body_rules_also_see_the_decoded_json() {
        let view = policy_body_view(r#"{"query":"mutation { service\u0044elete(id: \"x\") }"}"#);
        let p = BodyPattern::compile("serviceDelete").unwrap();
        assert_eq!(p.is_match(&view), Some(true));
        let gh = BodyPattern::compile(r#""private"\s*:\s*false"#).unwrap();
        assert_eq!(gh.is_match(&policy_body_view(r#"{"priv\u0061te": false}"#)), Some(true));
        // Plain JSON and non-JSON pass through unchanged.
        assert!(matches!(policy_body_view(r#"{"a":1}"#), std::borrow::Cow::Borrowed(_)));
        assert!(matches!(policy_body_view("not json"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn when_tests_a_list_var_with_cel_macros() {
        let c = Condition::parse("vars.fields.exists(f, f in ['serviceDelete', 'projectDelete'])").unwrap();
        let mut vars = VarMap::new();
        vars.insert("fields".into(), serde_json::json!(["serviceInstanceRedeploy", "projectDelete"]));
        assert!(c.eval(&vars));
        vars.insert("fields".into(), serde_json::json!(["serviceDeleteX", "variableUpsert"]));
        assert!(!c.eval(&vars));
        assert!(!c.eval(&VarMap::new()), "undefined var: no match");
        // The macro's own variable is not a free name.
        assert!(Condition::parse("vars.fields.exists(f, f == g)").is_none());
    }
}
