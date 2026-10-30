//! Policy engine — selected rules → access decisions.
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
//! A rule selects requests by `method` and `path` (a URL Pattern pathname,
//! [`crate::core::selector`]) and an optional `condition`: one CEL expression
//! over the request object ([`crate::core::request`]), compiled once when its
//! rule is loaded ([`Condition`]). A condition that errors never loosens a
//! decision ([`evaluate_decision`]).
use crate::core::request::{chain, Field, Read, ReadPath, Request, Step, Unreadable};
use crate::core::selector::{PathPattern, Select};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::sync::Arc;

// ── Conditions ─────────────────────────────────────────────────────────────────

/// A rule's or a `[requests]` shape's `condition`: one CEL expression (the
/// Common Expression Language, via cel-rust: the rule language of Kubernetes
/// admission policies, Envoy RBAC and Google IAM conditions) over `request`,
/// e.g. `has(request.body.amount) && request.body.amount > 100`. Compiled
/// once, when its rule or shape is loaded, with the paths it reads.
///
/// It may not read `request.method`, `request.path` or `request.params`
/// (`method` and `path` select those), read `request` whole, index with
/// anything but a constant, call a function this engine doesn't provide, or
/// read `request.body` whole and a member of it at once. A whole map or
/// subtree used as a value is read whole; `'<name>' in request.headers` (or
/// `request.query`) reads only that name's presence, as `has()` does.
#[derive(Clone)]
pub struct Condition {
    source: String,
    /// `Err` only for a stored user rule's condition that does not compile
    /// ([`Condition::lenient`]): such a rule is refused (DESIGN §2); a
    /// definition carrying one is rejected at the gate.
    compiled: Result<Arc<CompiledCondition>, String>,
}

struct CompiledCondition {
    program: cel::Program,
    /// Every read, sorted, each once.
    reads: Vec<Read>,
    /// The member reads not guarded by a presence test (verify warnings).
    unguarded: Vec<ReadPath>,
}

impl std::fmt::Debug for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Condition({:?})", self.source)
    }
}

impl Serialize for Condition {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.source.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Condition::lenient(&String::deserialize(d)?))
    }
}

/// CEL's type denotations (`type(x) == string`) are names too.
const CEL_TYPES: &[&str] = &[
    "int", "uint", "double", "bool", "string", "bytes", "list", "map", "null_type", "type",
];

impl Condition {
    /// Compile `source`, or say why it is not a condition.
    pub fn compile(source: &str) -> Result<Condition, String> {
        let program = cel::Program::compile(source).map_err(|e| e.to_string())?;
        let mut walk = Walk::default();
        walk.walk(program.expression(), &mut Vec::new());
        if let Some(p) = walk.problems.first() {
            return Err(p.clone());
        }
        if let Some(name) = walk.unknown.first() {
            return Err(format!(
                "`{name}` is not a known name (read the request as `request.<field>`; quote a string literal)"
            ));
        }
        // A function this build doesn't provide would error on every request:
        // refused here instead.
        walk.calls.sort();
        walk.calls.dedup();
        if let Some(f) = walk.calls.iter().find(|f| !function_exists(f)) {
            return Err(format!("`{f}()` is not a function this policy engine provides"));
        }
        let mut reads = walk.reads;
        reads.sort();
        reads.dedup();
        let body_whole = reads
            .iter()
            .any(|r| r.path.field == Field::Body && r.path.steps.is_empty() && !r.presence);
        let body_member = reads
            .iter()
            .any(|r| r.path.field == Field::Body && !r.path.steps.is_empty());
        if body_whole && body_member {
            return Err(
                "it reads request.body whole (its text) and a member of it; read one or the other"
                    .into(),
            );
        }
        let mut unguarded = Vec::new();
        guard_walk(program.expression(), &[], &mut unguarded);
        unguarded.sort();
        unguarded.dedup();
        Ok(Condition {
            source: source.to_string(),
            compiled: Ok(Arc::new(CompiledCondition {
                program,
                reads,
                unguarded,
            })),
        })
    }

    /// A stored user rule's condition: compiled now; one that does not
    /// compile is kept as unreadable rather than failing the whole sealed
    /// policy.
    pub fn lenient(source: &str) -> Condition {
        Self::compile(source).unwrap_or_else(|e| Condition {
            source: source.to_string(),
            compiled: Err(e),
        })
    }

    /// The condition as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Why it does not compile, when it does not.
    pub fn error(&self) -> Option<&str> {
        self.compiled.as_ref().err().map(String::as_str)
    }

    /// What it reads (nothing when it does not compile). Step 3 covers these
    /// in an approval.
    pub fn reads(&self) -> &[Read] {
        self.compiled.as_ref().map(|c| c.reads.as_slice()).unwrap_or(&[])
    }

    /// The member reads (below `request.body`, `request.query`,
    /// `request.headers`) not guarded by `has()` or `'<name>' in …` in the
    /// same `&&` chain (or by its negation in the same `||` chain): a request
    /// without the value makes the condition an error.
    pub fn unguarded(&self) -> &[ReadPath] {
        self.compiled.as_ref().map(|c| c.unguarded.as_slice()).unwrap_or(&[])
    }

    /// Evaluate over `request`: `Some` when it is a bool, `None` for an error
    /// (an absent value, a type mismatch) or any other result. A value it
    /// reads that can't be read refuses the request (`Err`).
    pub fn eval(&self, request: &Request<'_>) -> Result<Option<bool>, Unreadable> {
        let Ok(c) = &self.compiled else {
            return Ok(None);
        };
        let object = request.object(&c.reads)?;
        let mut ctx = cel::Context::default();
        if ctx.add_variable("request", object).is_err() {
            return Ok(None);
        }
        Ok(match c.program.execute(&ctx) {
            Ok(cel::Value::Bool(b)) => Some(b),
            _ => None,
        })
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

/// What a condition's expression reads and calls, and what it may not do.
#[derive(Default)]
struct Walk {
    reads: Vec<Read>,
    unknown: Vec<String>,
    calls: Vec<String>,
    problems: Vec<String>,
}

impl Walk {
    fn read(&mut self, path: Result<ReadPath, String>, presence: bool) {
        let path = path.and_then(|p| p.check().map(|_| p));
        match path {
            Ok(p) => match p.field {
                Field::Method => self.problems.push(
                    "it reads request.method; select the method with `method = \"…\"`".into(),
                ),
                Field::Path => self
                    .problems
                    .push("it reads request.path; select the path with `path = \"…\"`".into()),
                Field::Params => self.problems.push(
                    "it reads request.params; name the segment in `path` (\"/repos/:owner/:repo\") and select it there"
                        .into(),
                ),
                _ => self.reads.push(Read { path: p, presence }),
            },
            Err(e) => self.problems.push(e),
        }
    }

    fn walk(&mut self, e: &cel::IdedExpr, bound: &mut Vec<String>) {
        use cel::common::ast::{EntryExpr, Expr, LiteralValue};
        if let Some(path) = chain(e) {
            self.read(path, false);
            return;
        }
        match &e.expr {
            // has(<operand>.<field>): the presence of that member.
            Expr::Select(s) if s.test => {
                if matches!(&s.operand.expr, Expr::Ident(id) if id == "request") {
                    match crate::core::request::ReadPath::parse(&format!("request.{}", s.field)) {
                        Ok(p) => self.read(Ok(p), true),
                        Err(e) => self.problems.push(e),
                    }
                    return;
                }
                match chain(&s.operand) {
                    Some(Ok(mut p)) => {
                        p.steps.push(Step::Key(s.field.clone()));
                        self.read(Ok(p), true);
                    }
                    Some(Err(e)) => self.problems.push(e),
                    None => self.walk(&s.operand, bound),
                }
            }
            Expr::Select(s) => self.walk(&s.operand, bound),
            Expr::Ident(name) => {
                if name == "request" {
                    self.problems.push(
                        "`request` is read whole; read its fields (request.body.<name>, request.headers['<name>'], …)"
                            .into(),
                    );
                } else if !bound.contains(name) && !CEL_TYPES.contains(&name.as_str()) {
                    self.unknown.push(name.clone());
                }
            }
            // '<name>' in request.query / request.headers: that name's presence.
            Expr::Call(c) if c.func_name == "@in" && c.args.len() == 2 => {
                if let Expr::Literal(LiteralValue::String(k)) = &c.args[0].expr {
                    if let Some(Ok(mut p)) = chain(&c.args[1]) {
                        if matches!(p.field, Field::Query | Field::Headers) && p.steps.is_empty() {
                            p.steps.push(Step::Key(k.inner().to_string()));
                            self.read(Ok(p), true);
                            return;
                        }
                    }
                }
                self.walk(&c.args[0], bound);
                self.walk(&c.args[1], bound);
            }
            Expr::Call(c) => {
                let is_ident = |n: &str| {
                    n.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                };
                if is_ident(&c.func_name) {
                    self.calls.push(c.func_name.clone());
                }
                if let Some(t) = &c.target {
                    self.walk(t, bound);
                }
                for a in &c.args {
                    self.walk(a, bound);
                }
            }
            Expr::Comprehension(c) => {
                self.walk(&c.iter_range, bound);
                let n = bound.len();
                bound.push(c.iter_var.clone());
                bound.extend(c.iter_var2.clone());
                bound.push(c.accu_var.clone());
                for x in [&c.accu_init, &c.loop_cond, &c.loop_step, &c.result] {
                    self.walk(x, bound);
                }
                bound.truncate(n);
            }
            Expr::List(l) => {
                for x in &l.elements {
                    self.walk(x, bound);
                }
            }
            Expr::Map(m) => {
                for entry in &m.entries {
                    if let EntryExpr::MapEntry(me) = &entry.expr {
                        self.walk(&me.key, bound);
                        self.walk(&me.value, bound);
                    }
                }
            }
            Expr::Struct(st) => {
                for entry in &st.entries {
                    if let EntryExpr::StructField(f) = &entry.expr {
                        self.walk(&f.value, bound);
                    }
                }
            }
            Expr::Literal(_) | Expr::Unspecified => {}
        }
    }
}

/// The member paths a presence test `e` establishes when it is true:
/// `has(P)`, `'<name>' in Q`, and the conjuncts of an `&&`.
fn presence_facts(e: &cel::IdedExpr) -> Vec<ReadPath> {
    use cel::common::ast::{Expr, LiteralValue};
    match &e.expr {
        Expr::Select(s) if s.test => match chain(&s.operand) {
            Some(Ok(mut p)) => {
                p.steps.push(Step::Key(s.field.clone()));
                vec![p]
            }
            _ => Vec::new(),
        },
        Expr::Call(c) if c.func_name == "@in" && c.args.len() == 2 => {
            match (&c.args[0].expr, chain(&c.args[1])) {
                (Expr::Literal(LiteralValue::String(k)), Some(Ok(mut p))) => {
                    p.steps.push(Step::Key(k.inner().to_string()));
                    vec![p]
                }
                _ => Vec::new(),
            }
        }
        Expr::Call(c) if c.func_name == "_&&_" => c.args.iter().flat_map(presence_facts).collect(),
        _ => Vec::new(),
    }
}

/// The member paths present when `e` is false: `!has(P)`, and the
/// disjuncts of an `||`.
fn absence_facts(e: &cel::IdedExpr) -> Vec<ReadPath> {
    use cel::common::ast::Expr;
    match &e.expr {
        Expr::Call(c) if c.func_name == "!_" && c.args.len() == 1 => presence_facts(&c.args[0]),
        Expr::Call(c) if c.func_name == "_||_" => c.args.iter().flat_map(absence_facts).collect(),
        _ => Vec::new(),
    }
}

/// The operands of a chain of one logical operator.
fn flatten<'e>(e: &'e cel::IdedExpr, op: &str, out: &mut Vec<&'e cel::IdedExpr>) {
    match &e.expr {
        cel::common::ast::Expr::Call(c) if c.func_name == op => {
            for a in &c.args {
                flatten(a, op, out);
            }
        }
        _ => out.push(e),
    }
}

/// Collect the member reads in `e` that no presence test guards: one in the
/// same `&&` chain (`has(P) && …P…`), or its negation in the same `||` chain
/// (`!has(P) || …P…`), or a `?:` condition. A guard on a path guards every
/// path above it too.
fn guard_walk(e: &cel::IdedExpr, guards: &[ReadPath], out: &mut Vec<ReadPath>) {
    use cel::common::ast::{EntryExpr, Expr};
    let need = |p: ReadPath, out: &mut Vec<ReadPath>| {
        if p.is_member() && !guards.iter().any(|g| p.is_prefix_of(g)) {
            out.push(p);
        }
    };
    if let Some(Ok(p)) = chain(e) {
        need(p, out);
        return;
    }
    match &e.expr {
        Expr::Call(c) if c.func_name == "_&&_" || c.func_name == "_||_" => {
            let mut parts = Vec::new();
            flatten(e, &c.func_name, &mut parts);
            for (i, part) in parts.iter().enumerate() {
                let mut g = guards.to_vec();
                for (j, other) in parts.iter().enumerate() {
                    if i != j {
                        g.extend(if c.func_name == "_&&_" {
                            presence_facts(other)
                        } else {
                            absence_facts(other)
                        });
                    }
                }
                guard_walk(part, &g, out);
            }
        }
        Expr::Call(c) if c.func_name == "_?_:_" && c.args.len() == 3 => {
            guard_walk(&c.args[0], guards, out);
            let mut then = guards.to_vec();
            then.extend(presence_facts(&c.args[0]));
            guard_walk(&c.args[1], &then, out);
            let mut otherwise = guards.to_vec();
            otherwise.extend(absence_facts(&c.args[0]));
            guard_walk(&c.args[2], &otherwise, out);
        }
        // has(P): P itself needs no guard, the member it is under does.
        Expr::Select(s) if s.test => match chain(&s.operand) {
            Some(Ok(p)) => need(p, out),
            Some(Err(_)) => {}
            None => guard_walk(&s.operand, guards, out),
        },
        Expr::Select(s) => guard_walk(&s.operand, guards, out),
        Expr::Call(c) => {
            if let Some(t) = &c.target {
                guard_walk(t, guards, out);
            }
            for a in &c.args {
                guard_walk(a, guards, out);
            }
        }
        Expr::Comprehension(c) => {
            for x in [&c.iter_range, &c.accu_init, &c.loop_cond, &c.loop_step, &c.result] {
                guard_walk(x, guards, out);
            }
        }
        Expr::List(l) => {
            for x in &l.elements {
                guard_walk(x, guards, out);
            }
        }
        Expr::Map(m) => {
            for entry in &m.entries {
                if let EntryExpr::MapEntry(me) = &entry.expr {
                    guard_walk(&me.key, guards, out);
                    guard_walk(&me.value, guards, out);
                }
            }
        }
        Expr::Struct(st) => {
            for entry in &st.entries {
                if let EntryExpr::StructField(f) = &entry.expr {
                    guard_walk(&f.value, guards, out);
                }
            }
        }
        Expr::Ident(_) | Expr::Literal(_) | Expr::Unspecified => {}
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
/// A rule with no `level` is malformed — it can never decide — and is skipped
/// at evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyRule {
    /// Unique id (e.g. "send-email"). The key for user edits / the ask-cache scope.
    pub id: Option<String>,
    /// Human-readable label for the console.
    pub label: Option<String>,
    /// The label in Chinese (the `_zh` convention of acts.toml).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_zh: Option<String>,
    /// What an approval card says a request this rule decides does.
    #[serde(skip)]
    pub consent: Option<RuleConsent>,
    /// Which requests it decides: `method` AND `path`, each a list read as
    /// any of (one logical operation exposed at several endpoints), absent =
    /// no restriction ([`crate::core::selector`]). Compiled when the rule is
    /// loaded. A refused stored user rule carries a refused selection
    /// ([`evaluate_decision`] says how it decides).
    #[serde(flatten)]
    pub select: Select,
    /// AND-combined with the selector: a CEL condition over `request`
    /// ([`Condition`]). How one that errors decides: [`evaluate_decision`].
    pub condition: Option<Condition>,
    /// The access decision when this rule matches.
    pub level: Option<AccessLevel>,
    /// Cache TTL (seconds) after an `ask` approval, scoped to this rule
    /// (PROTOCOL.md §6.1 `policy.rules[].ttl`).
    pub ttl: Option<u64>,
}

/// The sentence an approval card shows for a request a rule decides: a
/// template over `request` in the grammar of a `[requests]` shape's
/// `consent` (`{{ request.body.type }}`), in English and optionally Chinese,
/// and the values the templates read, which an approval covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleConsent {
    pub en: String,
    pub zh: Option<String>,
    pub reads: Vec<crate::core::request::ReadPath>,
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

/// The fields of a user rule the user added ([`UserRule`]): its selector
/// (`method`, `path`, `condition`), `label`, `level` and `ttl`. A 2.0 entry's
/// `match`, `when` and `body` are kept so the record reads back as stored;
/// an entry that carries one is refused ([`RuleConfig::select`]).
///
/// Each selector key is read (its patterns and condition compiled) once, when
/// the sealed policy is read, and written back as it was stored.
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
    pub condition: Option<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// A 2.0 `body` regex. Not read, like `match`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// A 2.0 `when` (CEL over `vars`). Not read, like `match`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<AccessLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

impl RuleConfig {
    /// Why an entry in 2.0 syntax is refused, with what to write instead.
    pub fn legacy(&self) -> Option<&'static str> {
        if self.match_pattern.is_some() {
            Some("it is in the 2.0 `match` syntax; write `method` and `path`")
        } else if self.when.is_some() {
            Some("it has a 2.0 `when`; write `condition`, CEL over the request (\"request.body.amount > 80\")")
        } else if self.body.is_some() {
            Some("it has a 2.0 `body` regex; write `condition`, CEL over the request (\"request.body.amount > 80\")")
        } else {
            None
        }
    }

    /// What an added rule selects; `None` for an override (no selector key).
    /// A rule the daemon refuses (DESIGN.md §2) gets a [`Select::refused`]
    /// selection: one in 2.0 syntax (`match`, `when`, `body`), or whose
    /// selector can't be read (a pattern that doesn't compile, a method that
    /// isn't a token, an empty list, a condition that doesn't compile).
    /// [`evaluate_decision`] says how a refused rule decides.
    pub fn select(&self) -> Option<Select> {
        if let Some(why) = self.legacy() {
            return Some(Select::refused(why.into()));
        }
        if let Some(e) = self.condition.as_ref().and_then(Condition::error) {
            return Some(Select::refused(format!("its condition is not valid: {}", e)));
        }
        if self.method.is_none() && self.path.is_none() && self.condition.is_none() {
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
    /// The user's rules on this connection, in order ([`UserRules`]).
    #[serde(default, skip_serializing_if = "UserRules::is_empty")]
    pub rules: UserRules,
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


// ── User rules ───────────────────────────────────────────────────────────────

/// A connection's user rules (DESIGN §2): an ordered list, each entry an
/// override of one of the definition's rules (`{"override": "<id>", "level",
/// "ttl"}`) or a rule of the user's own under a stable id (`{"id": "<id>",
/// "label", "method", "path", "condition", "level", "ttl"}`; no selector key:
/// every request on the connection). Rules of the same level tie in the order
/// the definition's rules, then this list.
///
/// A 2.0 record (a map by id) is read as such a list in id order (the order
/// 2.0 broke ties in): an entry with a selector key, or in 2.0 syntax, is an
/// added rule; any other overrides the rule of that id. Either form is
/// written back as it was stored. An entry that can't be read is kept as
/// stored and refused ([`UserRules::resolve`]).
#[derive(Debug, Clone, Default)]
pub struct UserRules {
    entries: Vec<UserRule>,
    /// Read from a 2.0 map by id, and written back as one.
    by_id: bool,
}

/// One stored user rule: as stored, and as read.
#[derive(Debug, Clone)]
struct UserRule {
    /// The entry as stored: a list entry, or a 2.0 map entry's value.
    raw: serde_json::Value,
    /// A 2.0 map entry's key.
    key: Option<String>,
    entry: Result<UserEntry, String>,
}

/// What a user rule says.
#[derive(Debug, Clone)]
pub enum UserEntry {
    /// The `level` and `ttl` of the definition's rule `id`.
    Override {
        id: String,
        level: Option<AccessLevel>,
        ttl: Option<u64>,
    },
    /// A rule of the user's own; windows key on its `id`.
    Added { id: String, rule: RuleConfig },
}

/// A 2.1 list entry as stored.
#[derive(Deserialize)]
struct ListEntry {
    #[serde(default, rename = "override")]
    target: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(flatten)]
    rule: RuleConfig,
}

impl RuleConfig {
    /// It has a selector key, or 2.0 syntax: a rule of its own.
    fn selects(&self) -> bool {
        self.method.is_some()
            || self.path.is_some()
            || self.condition.is_some()
            || self.legacy().is_some()
    }
}

impl UserEntry {
    fn read_list(v: &serde_json::Value) -> Result<UserEntry, String> {
        let e: ListEntry = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
        match (e.target, e.id) {
            (Some(id), None) => {
                if e.rule.selects() || e.rule.label.is_some() {
                    return Err(format!(
                        "an override of '{id}' sets only `level` and `ttl`"
                    ));
                }
                Ok(UserEntry::Override {
                    id,
                    level: e.rule.level,
                    ttl: e.rule.ttl,
                })
            }
            (None, Some(id)) if !id.is_empty() => Ok(UserEntry::Added { id, rule: e.rule }),
            _ => Err("an entry has an `id`, or the `override` of a rule".into()),
        }
    }

    fn read_by_id(id: &str, v: &serde_json::Value) -> Result<UserEntry, String> {
        let rule: RuleConfig = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
        Ok(if rule.selects() {
            UserEntry::Added {
                id: id.to_string(),
                rule,
            }
        } else {
            UserEntry::Override {
                id: id.to_string(),
                level: rule.level,
                ttl: rule.ttl,
            }
        })
    }

    fn to_list_value(&self) -> serde_json::Value {
        match self {
            UserEntry::Override { id, level, ttl } => {
                let mut v = serde_json::json!({ "override": id });
                if let Some(l) = level {
                    v["level"] = serde_json::json!(l);
                }
                if let Some(t) = ttl {
                    v["ttl"] = serde_json::json!(t);
                }
                v
            }
            UserEntry::Added { id, rule } => {
                let mut v = serde_json::to_value(rule).unwrap_or_else(|_| serde_json::json!({}));
                v["id"] = serde_json::json!(id);
                v
            }
        }
    }
}

impl UserRules {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append an entry (to a 2.0 record: under its id).
    pub fn push(&mut self, entry: UserEntry) {
        let (raw, key) = if self.by_id {
            let (id, rule) = match &entry {
                UserEntry::Override { id, level, ttl } => (
                    id.clone(),
                    RuleConfig {
                        level: *level,
                        ttl: *ttl,
                        ..Default::default()
                    },
                ),
                UserEntry::Added { id, rule } => (id.clone(), rule.clone()),
            };
            self.entries.retain(|e| e.key.as_deref() != Some(id.as_str()));
            let raw = serde_json::to_value(rule).unwrap_or_else(|_| serde_json::json!({}));
            (raw, Some(id))
        } else {
            (entry.to_list_value(), None)
        };
        self.entries.push(UserRule {
            raw,
            key,
            entry: Ok(entry),
        });
        if self.by_id {
            self.entries.sort_by(|a, b| a.key.cmp(&b.key));
        }
    }

    /// Every entry as read: `Err` with why for one that can't be read.
    pub fn entries(&self) -> impl Iterator<Item = Result<&UserEntry, &str>> {
        self.entries
            .iter()
            .map(|e| e.entry.as_ref().map_err(String::as_str))
    }

    /// What each entry is on a connection whose definition has the rules
    /// `defined` (DESIGN §2), in order:
    ///   - an override of one of them sets its `level` and `ttl`; the first
    ///     override of an id counts, a later one is refused;
    ///   - an override of an id the definition doesn't have is refused when
    ///     it tightens (`deny`, `ask-always`) and dropped otherwise;
    ///   - an added rule is a rule, or refused when its selector or condition
    ///     can't be read, it is in 2.0 syntax, or its id is taken (by one of
    ///     the definition's rules or an earlier added rule);
    ///   - an entry that can't be read is refused.
    pub fn resolve(&self, defined: &[PolicyRule]) -> Vec<Resolved<'_>> {
        let defined: std::collections::HashSet<&str> =
            defined.iter().filter_map(|r| r.id.as_deref()).collect();
        let mut overridden = std::collections::HashSet::new();
        let mut added = std::collections::HashSet::new();
        let mut out = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            let refused = |id: Option<String>, level: Option<AccessLevel>, why: String| {
                Resolved::Refused(PolicyRule {
                    id,
                    label: None,
                    label_zh: None,
                    consent: None,
                    select: Select::refused(why),
                    condition: None,
                    level,
                    ttl: None,
                })
            };
            out.push(match &e.entry {
                Err(why) => {
                    let id = e.key.clone().or_else(|| {
                        ["id", "override"]
                            .iter()
                            .find_map(|k| e.raw.get(*k).and_then(|v| v.as_str()))
                            .map(str::to_string)
                    });
                    let level = e
                        .raw
                        .get("level")
                        .and_then(|v| v.as_str())
                        .and_then(AccessLevel::parse);
                    refused(id, level, format!("it can't be read: {}", why))
                }
                Ok(UserEntry::Override { id, level, ttl }) => {
                    if !defined.contains(id.as_str()) {
                        let why = format!("it overrides '{}', a rule this service doesn't have", id);
                        match level {
                            Some(AccessLevel::Deny | AccessLevel::AskAlways) => {
                                refused(Some(id.clone()), *level, why)
                            }
                            _ => Resolved::Dropped {
                                id,
                                why: format!("{why}; it is not applied"),
                            },
                        }
                    } else if !overridden.insert(id.as_str()) {
                        refused(Some(id.clone()), *level, format!("'{}' is overridden twice", id))
                    } else {
                        Resolved::Override {
                            id,
                            level: *level,
                            ttl: *ttl,
                        }
                    }
                }
                Ok(UserEntry::Added { id, rule }) => {
                    let taken = if defined.contains(id.as_str()) {
                        Some(format!("its id '{}' is a rule of this service's", id))
                    } else if !added.insert(id.as_str()) {
                        Some(format!("its id '{}' is used by an earlier rule", id))
                    } else {
                        None
                    };
                    let select = match taken {
                        Some(why) => Select::refused(why),
                        None => rule.select().unwrap_or_else(Select::every),
                    };
                    let rule = PolicyRule {
                        id: Some(id.clone()),
                        label: rule.label.clone(),
                        label_zh: None,
                        consent: None,
                        condition: rule.condition.clone().filter(|c| c.error().is_none()),
                        select,
                        level: rule.level,
                        ttl: rule.ttl,
                    };
                    if rule.select.problem().is_some() {
                        Resolved::Refused(rule)
                    } else {
                        Resolved::Rule(rule)
                    }
                }
            });
        }
        out
    }

    /// The entries refused or dropped on a connection whose definition has
    /// the rules `defined`, with why: what the console shows.
    pub fn notes(&self, defined: &[PolicyRule]) -> Vec<RuleNote> {
        self.resolve(defined)
            .into_iter()
            .filter_map(|r| match r {
                Resolved::Refused(rule) => Some(RuleNote {
                    rule: rule.id.clone(),
                    level: rule.level,
                    refused: true,
                    why: rule.select.problem().unwrap_or_default().to_string(),
                }),
                Resolved::Dropped { id, why } => Some(RuleNote {
                    rule: Some(id.to_string()),
                    level: None,
                    refused: false,
                    why,
                }),
                _ => None,
            })
            .collect()
    }
}

/// A 2.0 map by id ([`UserRules`]), in id order.
impl From<HashMap<String, RuleConfig>> for UserRules {
    fn from(map: HashMap<String, RuleConfig>) -> UserRules {
        let mut rules = UserRules {
            entries: Vec::new(),
            by_id: true,
        };
        let mut ids: Vec<_> = map.into_iter().collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0));
        for (id, rule) in ids {
            let raw = serde_json::to_value(&rule).unwrap_or_else(|_| serde_json::json!({}));
            let entry = UserEntry::read_by_id(&id, &raw);
            rules.entries.push(UserRule {
                raw,
                key: Some(id),
                entry,
            });
        }
        rules
    }
}

impl Serialize for UserRules {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.by_id {
            let map: serde_json::Map<String, serde_json::Value> = self
                .entries
                .iter()
                .map(|e| (e.key.clone().unwrap_or_default(), e.raw.clone()))
                .collect();
            map.serialize(s)
        } else {
            let list: Vec<&serde_json::Value> = self.entries.iter().map(|e| &e.raw).collect();
            list.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for UserRules {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<UserRules, D::Error> {
        Ok(match serde_json::Value::deserialize(d)? {
            serde_json::Value::Null => UserRules::default(),
            serde_json::Value::Array(list) => UserRules {
                entries: list
                    .into_iter()
                    .map(|raw| UserRule {
                        entry: UserEntry::read_list(&raw),
                        raw,
                        key: None,
                    })
                    .collect(),
                by_id: false,
            },
            serde_json::Value::Object(map) => {
                let mut entries: Vec<UserRule> = map
                    .into_iter()
                    .map(|(key, raw)| UserRule {
                        entry: UserEntry::read_by_id(&key, &raw),
                        raw,
                        key: Some(key),
                    })
                    .collect();
                entries.sort_by(|a, b| a.key.cmp(&b.key));
                UserRules {
                    entries,
                    by_id: true,
                }
            }
            other => {
                return Err(serde::de::Error::custom(format!(
                    "rules: a list of rules, not {}",
                    other
                )))
            }
        })
    }
}

/// A user rule as a connection reads it ([`UserRules::resolve`]).
#[derive(Debug, Clone)]
pub enum Resolved<'u> {
    Override {
        id: &'u str,
        level: Option<AccessLevel>,
        ttl: Option<u64>,
    },
    /// An added rule.
    Rule(PolicyRule),
    /// A rule the daemon refuses: it selects nothing, and decides how
    /// [`evaluate_decision`] says.
    Refused(PolicyRule),
    /// An override of a rule the definition doesn't have that would not
    /// tighten: not applied.
    Dropped { id: &'u str, why: String },
}

/// A user rule the daemon refuses or doesn't apply, and why (the console
/// shows it on the connection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleNote {
    /// Its id, or the id it overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<AccessLevel>,
    /// Refused: its connection asks every time (a refused `deny` denies
    /// it). Otherwise it is only not applied.
    pub refused: bool,
    pub why: String,
}

/// A connection's rules for one pass: the definition rules `built_in` in
/// file order with the user's overrides applied, then the user's added and
/// refused rules in list order (DESIGN §2). PROTOCOL.md §6.4 `M.policy`
/// (logical merged view).
pub fn merge_rules(built_in: &[PolicyRule], user: &UserRules) -> Vec<PolicyRule> {
    merge_rules_over(built_in, user, built_in)
}

/// [`merge_rules`] for a pass that leaves out some of the connection's
/// definition rules: `defined` is all of them, so an override of one this
/// pass leaves out applies to nothing, and is no override of a missing rule.
pub fn merge_rules_over(
    built_in: &[PolicyRule],
    user: &UserRules,
    defined: &[PolicyRule],
) -> Vec<PolicyRule> {
    let resolved = user.resolve(defined);
    let mut out: Vec<PolicyRule> = built_in
        .iter()
        .map(|rule| {
            let edit = resolved.iter().find_map(|r| match r {
                Resolved::Override { id, level, ttl } if rule.id.as_deref() == Some(*id) => {
                    Some((*level, *ttl))
                }
                _ => None,
            });
            match edit {
                Some((level, ttl)) => PolicyRule {
                    level: level.or(rule.level),
                    ttl: ttl.or(rule.ttl),
                    ..rule.clone()
                },
                None => rule.clone(),
            }
        })
        .collect();
    for r in resolved {
        if let Resolved::Rule(rule) | Resolved::Refused(rule) = r {
            out.push(rule);
        }
    }
    out
}

// `unenforceable_user_rule` (a user `when` or `body` an approval on a scoped
// path could not bind) is gone with `when` and `body`: step 3 covers what a
// condition reads instead.

// ── Policy Evaluation ──────────────────────────────────────────────────────────

/// The read/write split the default floors and the reuse classes use. Fails
/// closed: only `GET`, `HEAD` and `OPTIONS` (any case) are reads; every other
/// method, including extension methods (`MOVE`, `PROPPATCH`, …), is a write.
pub(crate) fn is_write_method(method: &str) -> bool {
    !["GET", "HEAD", "OPTIONS"]
        .iter()
        .any(|read| read.eq_ignore_ascii_case(method))
}

/// A decision: the level, what decided it, and the `ask` window (seconds).
pub type Decision = (AccessLevel, DecidedBy, Option<u64>);

/// Determine the access level for a request. See [`evaluate_decision`].
pub fn evaluate(
    request: &Request<'_>,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> Result<AccessLevel, Unreadable> {
    evaluate_decision(request, rules, connection_levels, policy, tags).map(|d| d.0)
}

/// What decided a request: a matched rule, or a default floor (connection,
/// tag, global, or the safe floor). The unit an `ask` approval is reused by
/// (`crate::approval::Reuse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidedBy {
    /// A rule matched; its `id` and `label` as declared, and what an
    /// approval card shows for it.
    Rule {
        id: Option<String>,
        label: Option<String>,
        label_zh: Option<String>,
        consent: Option<RuleConsent>,
    },
    /// No rule matched.
    Floor,
}

impl DecidedBy {
    /// What deciding by `rule` records.
    pub fn of(rule: &PolicyRule) -> DecidedBy {
        DecidedBy::Rule {
            id: rule.id.clone(),
            label: rule.label.clone(),
            label_zh: rule.label_zh.clone(),
            consent: rule.consent.clone(),
        }
    }
}

/// Resolve the access decision for a request, returning `(level,
/// matched_rule_id, ttl)`. See [`evaluate_decision`], which also says what
/// decided it.
pub fn evaluate_with_match(
    request: &Request<'_>,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> Result<(AccessLevel, Option<String>, Option<u64>), Unreadable> {
    let (level, by, ttl) = evaluate_decision(request, rules, connection_levels, policy, tags)?;
    let id = match by {
        DecidedBy::Rule { id, .. } => id,
        DecidedBy::Floor => None,
    };
    Ok((level, id, ttl))
}

/// The stricter of two decisions for one request: `overlay` only where it is
/// more restrictive than `base`, a tie keeps `base`. How a policy that may
/// only tighten (a vault definition's) joins the decision made without it,
/// and how a rule matched only through an erroring condition does.
pub fn stricter(base: Decision, overlay: Decision) -> Decision {
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
/// An error never loosens a decision (DESIGN §1): a condition that errors or
/// isn't a bool matches for a `deny`, `ask-always` or `ask` rule and doesn't
/// for an `allow` rule; a rule matched only so counts only where it makes the
/// decision stricter (decided with and without those rules, the stricter
/// kept, a tie to the decision without them).
///
/// A refused rule (a stored user rule the daemon can't read, DESIGN.md §2)
/// decides every request on its connection: a refused `deny` denies it, any
/// other makes it the stricter of `ask-always` and the decision without the
/// refused rules. A refused rule never loosens a decision.
///
/// A value a condition reads that can't be read refuses the request (`Err`).
pub fn evaluate_decision(
    request: &Request<'_>,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> Result<Decision, Unreadable> {
    let without = decide_readable(request, rules, connection_levels, policy, tags)?;
    let mut refused = rules
        .into_iter()
        .flatten()
        .filter(|r| r.select.problem().is_some());
    let Some(first) = refused.next() else {
        return Ok(without);
    };
    let by = DecidedBy::of;
    if let Some(deny) = std::iter::once(first)
        .chain(refused)
        .find(|r| r.level == Some(AccessLevel::Deny))
    {
        return Ok((AccessLevel::Deny, by(deny), None));
    }
    Ok(stricter(without, (AccessLevel::AskAlways, by(first), None)))
}

/// How a rule meets a request: not, cleanly, or only through a condition that
/// errored (counted where it is stricter, [`evaluate_decision`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Met {
    No,
    Yes,
    ByError,
}

fn meets(rule: &PolicyRule, request: &Request<'_>) -> Result<Met, Unreadable> {
    if rule.select.exec(request.method(), request.path()).is_none() {
        return Ok(Met::No);
    }
    let Some(condition) = &rule.condition else {
        return Ok(Met::Yes);
    };
    Ok(match condition.eval(request)? {
        Some(true) => Met::Yes,
        Some(false) => Met::No,
        None if matches!(
            rule.level,
            Some(AccessLevel::Ask | AccessLevel::AskAlways | AccessLevel::Deny)
        ) =>
        {
            Met::ByError
        }
        None => Met::No,
    })
}

/// The condition and consent reads of every rule in `rules` that matches
/// `request` at `level` (cleanly or through an error): what an approval of a request
/// decided at `level` covers besides its scope (DESIGN §4).
pub fn matched_reads(
    request: &Request<'_>,
    rules: &[PolicyRule],
    level: AccessLevel,
) -> Result<Vec<Read>, Unreadable> {
    let mut out = Vec::new();
    for rule in rules.iter().filter(|r| r.level == Some(level)) {
        if rule.condition.is_none() && rule.consent.is_none() {
            continue;
        }
        if meets(rule, request)? != Met::No {
            if let Some(condition) = &rule.condition {
                out.extend(condition.reads().iter().cloned());
            }
            if let Some(consent) = &rule.consent {
                out.extend(consent.reads.iter().map(|p| Read {
                    path: p.clone(),
                    presence: false,
                }));
            }
        }
    }
    Ok(out)
}

/// [`evaluate_decision`] over the rules that can be read.
fn decide_readable(
    request: &Request<'_>,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> Result<Decision, Unreadable> {
    // The `ask`-cache window a matched rule inherits when it pins no `ttl` of
    // its own: the ttl of the most-specific floor (connection → tag → global),
    // the SAME precedence as the read/write floor decision below. Direction-
    // independent (Levels.ttl is a single value). Consumed only by an `ask`
    // rule (a floor decision returns its own floor's ttl), and a final
    // constant fills in when nothing pins a window at all.
    let floor_ttl = connection_levels
        .and_then(|lv| lv.ttl)
        .or_else(|| {
            tags.iter()
                .filter_map(|t| policy.categories.get(t))
                .find_map(|lv| lv.ttl)
        })
        .or_else(|| policy.default.as_ref().and_then(|lv| lv.ttl));

    // 1. Rules — most-restrictive matching wins (deny-override). Each rule's
    // condition is evaluated once.
    let mut met: Vec<(&PolicyRule, AccessLevel, bool)> = Vec::new();
    for rule in rules.into_iter().flatten() {
        let m = meets(rule, request)?;
        if m == Met::No {
            continue;
        }
        let Some(level) = rule.effective_level() else {
            continue; // rule declares no level → no decision; skip.
        };
        met.push((rule, level, m == Met::ByError));
    }
    let decide = |with_errors: bool| -> Decision {
        let mut best: Option<(&PolicyRule, AccessLevel)> = None;
        for (rule, level, by_error) in &met {
            if *by_error && !with_errors {
                continue;
            }
            // Strictly stricter only: the first of equally strict rules stands.
            if best.is_none_or(|(_, b)| level.restrictiveness() > b.restrictiveness()) {
                best = Some((rule, *level));
            }
        }
        match best {
            Some((rule, level)) => {
                let by = DecidedBy::of(rule);
                // The rule's own ttl wins; else it inherits the default-floor window.
                (level, by, rule.ttl.or(floor_ttl))
            }
            None => floor_decision(request.method(), connection_levels, policy, tags),
        }
    };
    let without = decide(false);
    Ok(if met.iter().any(|(_, _, by_error)| *by_error) {
        stricter(without, decide(true))
    } else {
        without
    })
}

/// Steps 2-5: the default floor, connection → tag → global, read/write split,
/// else `ask-always`.
fn floor_decision(
    method: &str,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> Decision {
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
    use crate::core::request::{BodyFormat, RequestInput};

    fn policy() -> Policy {
        Policy::default()
    }

    fn rule(id: &str, pat: &str, level: AccessLevel) -> PolicyRule {
        PolicyRule {
            id: Some(id.into()),
            label: None,
            label_zh: None,
            consent: None,
            select: sel(pat),
            condition: None,
            level: Some(level),
            ttl: None,
        }
    }

    fn when(id: &str, pat: &str, condition: &str, level: AccessLevel) -> PolicyRule {
        PolicyRule {
            condition: Some(Condition::compile(condition).unwrap_or_else(|e| panic!("{condition}: {e}"))),
            ..rule(id, pat, level)
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

    /// A request with a body and no headers (no Content-Type).
    fn req<'a>(method: &'a str, path: &'a str, body: &'a str) -> Request<'a> {
        Request::new(
            RequestInput {
                method,
                path,
                body: Some(body.as_bytes()),
                ..Default::default()
            },
            BodyFormat::Json,
            Default::default(),
        )
    }

    fn level(r: &Request<'_>, rules: &Vec<PolicyRule>, floor: Option<&Levels>) -> AccessLevel {
        evaluate(r, Some(rules), floor, &policy(), &[]).unwrap()
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
        let r = Request::bare("DELETE", "/x");
        // A matched ask rule that pins no ttl inherits the connection-floor window.
        let (_l, id, ttl) = evaluate_with_match(&r, Some(&rules), Some(&conn), &policy(), &[]).unwrap();
        assert_eq!(id.as_deref(), Some("del"));
        assert_eq!(ttl, Some(1234));

        // The rule's own ttl wins over the floor window.
        let mut pinned = rules.clone();
        pinned[0].ttl = Some(60);
        let (_l2, _id2, ttl2) =
            evaluate_with_match(&r, Some(&pinned), Some(&conn), &policy(), &[]).unwrap();
        assert_eq!(ttl2, Some(60));

        // No ttl anywhere in the floors → None (the proxy applies its constant).
        let bare = Levels::default();
        let (_l3, _id3, ttl3) = evaluate_with_match(&r, Some(&rules), Some(&bare), &policy(), &[]).unwrap();
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

    /// A stored user rule in 2.0 syntax (`match`, `when`, a `body` regex) is
    /// refused (DESIGN.md §2): a refused `deny` denies the whole connection,
    /// any other refused rule makes every request on it ask every time,
    /// unless the decision without it is stricter. It overrides no built-in
    /// rule.
    #[test]
    fn a_stored_2_0_rule_is_refused() {
        let floor = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Deny),
            ttl: None,
        };
        let built_in = vec![rule("read", "GET /x", AccessLevel::Ask)];
        let decide = |user: &HashMap<String, RuleConfig>, m: &str, p: &str| {
            let rules = merge_rules(&built_in, &user.clone().into());
            evaluate_decision(&Request::bare(m, p), Some(&rules), Some(&floor), &policy(), &[]).unwrap()
        };
        let olds = |level: AccessLevel| {
            [
                RuleConfig {
                    match_pattern: Some("delete /repos/*/*".into()),
                    level: Some(level),
                    ..Default::default()
                },
                RuleConfig {
                    when: Some("vars.amount > 1".into()),
                    level: Some(level),
                    ..RuleConfig::selecting("DELETE /repos/:o/:r")
                },
                RuleConfig {
                    body: Some("gift".into()),
                    level: Some(level),
                    ..RuleConfig::selecting("DELETE /repos/:o/:r")
                },
            ]
        };
        for (i, old) in olds(AccessLevel::Deny).into_iter().enumerate() {
            let mut user = HashMap::new();
            user.insert("del".to_string(), old);
            for (m, p) in [("GET", "/x"), ("GET", "/elsewhere"), ("DELETE", "/repos/o/r")] {
                let (level, by, _) = decide(&user, m, p);
                assert_eq!(level, AccessLevel::Deny, "#{i} {m} {p}");
                assert!(matches!(by, DecidedBy::Rule { id: Some(ref id), .. } if id == "del"));
            }
        }
        for level in [AccessLevel::Allow, AccessLevel::Ask, AccessLevel::AskAlways] {
            for old in olds(level) {
                let mut user = HashMap::new();
                user.insert("del".to_string(), old);
                assert_eq!(decide(&user, "GET", "/elsewhere").0, AccessLevel::AskAlways, "{level:?}");
                assert_eq!(decide(&user, "GET", "/x").0, AccessLevel::AskAlways, "{level:?}");
                // Stricter without it: that stands.
                assert_eq!(decide(&user, "POST", "/elsewhere").0, AccessLevel::Deny, "{level:?}");
            }
        }
        // On a built-in id it overrides nothing, and is refused too.
        for edit in [
            RuleConfig {
                match_pattern: Some("GET /x".into()),
                level: Some(AccessLevel::Allow),
                ..Default::default()
            },
            RuleConfig {
                when: Some("vars.a == 1".into()),
                level: Some(AccessLevel::Allow),
                ..Default::default()
            },
        ] {
            let mut user = HashMap::new();
            user.insert("read".to_string(), edit);
            let merged = merge_rules(&built_in, &user.clone().into());
            assert_eq!(merged[0].level, Some(AccessLevel::Ask));
            assert_eq!(decide(&user, "GET", "/x").0, AccessLevel::AskAlways);
        }
        // A 2.1 `method` is stored uppercase and selects.
        let edit: RuleConfig = serde_json::from_value(
            serde_json::json!({"method": "delete", "path": "/repos/:owner/:repo", "level": "deny"}),
        )
        .unwrap();
        assert_eq!(edit.method.as_deref(), Some(&["DELETE".to_string()][..]));
        let mut user = HashMap::new();
        user.insert("del".to_string(), edit);
        let rules = merge_rules(&[], &user.clone().into());
        assert_eq!(rules[0].select.exec("DELETE", "/repos/o/r").map(|p| p.len()), Some(2));
        assert_eq!(decide(&user, "DELETE", "/repos/o/r").0, AccessLevel::Deny);
        assert_eq!(decide(&user, "GET", "/elsewhere").0, AccessLevel::Allow);
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
            evaluate_decision(&Request::bare(m, "/x"), Some(&rules), Some(&floor), &policy(), &[]).unwrap()
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
            evaluate_with_match(&Request::bare("POST", "/m/send"), Some(rules), None, &policy(), &[])
                .unwrap()
                .1
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
        let merged = merge_rules(&[], &user.clone().into());
        assert_eq!(decide(&merged).as_deref(), Some("a-user"));
        let merged = merge_rules(&[rule("built-in", "POST /m/:id", AccessLevel::Ask)], &user.clone().into());
        assert_eq!(decide(&merged).as_deref(), Some("built-in"));
    }

    // ── Level resolution ─────────────────────────────────────────────────────
    #[test]
    fn level_on_rule_decides() {
        // The headline: list (allow) + read (ask) = read an email in ONE
        // approval, not two.
        let low = vec![rule("list", "GET /m", AccessLevel::Allow)];
        assert_eq!(level(&Request::bare("GET", "/m"), &low, None), AccessLevel::Allow);
        let med = vec![rule("read", "GET /m/:id", AccessLevel::Ask)];
        assert_eq!(level(&Request::bare("GET", "/m/1"), &med, None), AccessLevel::Ask);
        let high = vec![rule("send", "POST /m/send", AccessLevel::AskAlways)];
        assert_eq!(level(&Request::bare("POST", "/m/send"), &high, None), AccessLevel::AskAlways);
        let del = vec![rule("del", "DELETE /m/:id", AccessLevel::Deny)];
        assert_eq!(level(&Request::bare("DELETE", "/m/1"), &del, None), AccessLevel::Deny);
    }

    #[test]
    fn match_list_is_an_or_across_patterns() {
        // One rule, two endpoints (different method AND path depth) for the same
        // logical operation — both fire it, unrelated requests don't.
        let rules = vec![PolicyRule {
            id: Some("open-network".into()),
            label: None,
            label_zh: None,
            consent: None,
            select: Select::new(
                vec!["POST".into(), "PATCH".into()],
                vec![
                    PathPattern::compile("/v1/projects/:ref/network-restrictions/apply").unwrap(),
                    PathPattern::compile("/v1/projects/:ref/network-restrictions").unwrap(),
                ],
            ),
            condition: None,
            level: Some(AccessLevel::AskAlways),
            ttl: None,
        }];
        let ev = |m: &str, p: &str| level(&Request::bare(m, p), &rules, None);
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
            serde_json::json!({"path": "/a", "condition": "request.body.amount > 1", "level": "deny"}),
            serde_json::json!({"condition": "request.query.force == '1'", "level": "deny"}),
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
            serde_json::json!({"path": "/a", "when": "vars.amount > 1", "level": "deny"}),
            serde_json::json!({"path": "/a", "body": "(", "level": "deny"}),
            serde_json::json!({"path": "/a", "condition": "request.path == '/a'", "level": "deny"}),
            serde_json::json!({"path": "/a", "condition": "request.body.amount >", "level": "deny"}),
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
        let decide = |edit: RuleConfig, level: AccessLevel| {
            let mut user = HashMap::new();
            user.insert("r".to_string(), RuleConfig { level: Some(level), ..edit });
            let rules = merge_rules(&[], &user.clone().into());
            evaluate(&Request::bare("GET", "/elsewhere"), Some(&rules), Some(&floor), &policy(), &[]).unwrap()
        };
        for edit in [
            RuleConfig {
                path: Some(vec![PathPattern::lenient("/a/:")]),
                ..Default::default()
            },
            RuleConfig {
                condition: Some(Condition::lenient("request.method == 'GET'")),
                ..Default::default()
            },
        ] {
            assert_eq!(decide(edit.clone(), AccessLevel::Deny), AccessLevel::Deny);
            assert_eq!(decide(edit.clone(), AccessLevel::AskAlways), AccessLevel::AskAlways);
            assert_eq!(decide(edit, AccessLevel::Allow), AccessLevel::AskAlways);
        }
        // A 2.0 entry on a built-in id with a condition that can't be read is
        // a refused rule beside the built-in one.
        let built_in = vec![rule("read", "GET /x", AccessLevel::Allow)];
        let mut user = HashMap::new();
        user.insert(
            "read".to_string(),
            RuleConfig {
                condition: Some(Condition::lenient("nope(")),
                ..Default::default()
            },
        );
        let rules = merge_rules(&built_in, &user.clone().into());
        assert!(rules[1].select.problem().is_some());
        assert_eq!(
            evaluate(&Request::bare("GET", "/x"), Some(&rules), Some(&floor), &policy(), &[]).unwrap(),
            AccessLevel::AskAlways
        );
    }

    #[test]
    fn rule_with_no_level_is_skipped() {
        // A malformed rule (no level) can never decide → falls through to the
        // global default (allow).
        let bad = vec![PolicyRule {
            level: None,
            ..rule("bad", "GET /x", AccessLevel::Deny)
        }];
        assert_eq!(level(&Request::bare("GET", "/x"), &bad, None), AccessLevel::Allow);
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
        assert_eq!(level(&Request::bare("DELETE", "/m/safe"), &rules, None), AccessLevel::Deny);
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
            level(&Request::bare("GET", "/unmatched"), &vec![], Some(&conn)),
            AccessLevel::Ask
        );
        // No connection floor → tag floor (ai = allow).
        assert_eq!(
            evaluate(&Request::bare("POST", "/v1/chat"), None, None, &policy(), &["ai".into()]).unwrap(),
            AccessLevel::Allow
        );
        // No tag match → global default (allow).
        assert_eq!(
            evaluate(&Request::bare("GET", "/x"), None, None, &policy(), &["unknown".into()]).unwrap(),
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
            evaluate(&Request::bare("GET", "/x"), None, None, &p, &tags).unwrap(),
            AccessLevel::AskAlways
        );
        assert_eq!(
            evaluate(&Request::bare("POST", "/x"), None, None, &p, &tags).unwrap(),
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
        let merged = merge_rules(&built_in, &user.clone().into());
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
        let merged = merge_rules(&built_in, &user.clone().into());
        assert_eq!(level(&Request::bare("DELETE", "/m/1"), &merged, None), AccessLevel::Deny);
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
        let merged = merge_rules(&built_in, &user.clone().into());
        assert_eq!(merged.len(), 2);
        assert!(merged
            .iter()
            .any(|r| r.id.as_deref() == Some("vip") && r.level == Some(AccessLevel::Allow)));
    }

    // ── User rules: the ordered list (DESIGN §2) ─────────────────────────────

    fn user_rules(v: serde_json::Value) -> UserRules {
        serde_json::from_value(v).unwrap()
    }

    /// A list and a 2.0 map are each read, and written back as stored; an
    /// entry that can't be read is kept as stored.
    #[test]
    fn user_rules_read_a_list_and_a_2_0_map_and_write_each_back_as_stored() {
        let list = serde_json::json!([
            {"override": "read", "level": "allow", "ttl": 60},
            {"id": "vip", "method": ["POST"], "path": ["/m/vip"], "level": "deny"},
            {"id": "all", "level": "ask"},
            {"id": "odd", "level": "sometimes", "future": 1}
        ]);
        let rules = user_rules(list.clone());
        assert_eq!(serde_json::to_value(&rules).unwrap(), list);
        let read: Vec<_> = rules.entries().collect();
        assert!(matches!(read[0], Ok(UserEntry::Override { id, level: Some(AccessLevel::Allow), ttl: Some(60) }) if id == "read"));
        assert!(matches!(read[1], Ok(UserEntry::Added { id, .. }) if id == "vip"));
        assert!(matches!(read[2], Ok(UserEntry::Added { id, .. }) if id == "all"));
        assert!(read[3].is_err());

        // A 2.0 map: an entry with a selector (or 2.0 syntax) is an added
        // rule, any other an override; read in id order.
        let map = serde_json::json!({
            "vip": {"method": ["POST"], "path": ["/m/vip"], "level": "deny"},
            "read": {"level": "allow"},
            "old": {"match": "GET /x", "level": "deny"}
        });
        let rules = user_rules(map.clone());
        assert_eq!(serde_json::to_value(&rules).unwrap(), map);
        let ids: Vec<String> = rules
            .entries()
            .map(|e| match e.unwrap() {
                UserEntry::Override { id, .. } => format!("override {id}"),
                UserEntry::Added { id, .. } => format!("added {id}"),
            })
            .collect();
        assert_eq!(ids, ["added old", "override read", "added vip"]);

        // In a connection's policy record, both ways.
        for rules in [list, map] {
            let cp = serde_json::json!({"default": {"write": "ask"}, "rules": rules});
            let read: ConnectionPolicy = serde_json::from_value(cp.clone()).unwrap();
            assert_eq!(serde_json::to_value(&read).unwrap(), cp);
        }
        let empty: ConnectionPolicy = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(empty.rules.is_empty());
        assert_eq!(serde_json::to_value(&empty).unwrap(), serde_json::json!({}));
    }

    /// Equally strict rules tie in order: the definition's rules, then the
    /// user's in list order (not id order). An added rule with no selector
    /// key matches every request.
    #[test]
    fn user_rules_tie_in_list_order_after_the_definitions() {
        let first = |rules: &[PolicyRule], m: &str, p: &str| {
            match evaluate_decision(&Request::bare(m, p), Some(&rules.to_vec()), None, &policy(), &[])
                .unwrap()
                .1
            {
                DecidedBy::Rule { id, .. } => id,
                DecidedBy::Floor => None,
            }
        };
        let user = user_rules(serde_json::json!([
            {"id": "b-user", "method": "POST", "path": "/m/send", "level": "ask"},
            {"id": "a-user", "method": "POST", "path": "/m/send", "level": "ask"},
            {"id": "everything", "level": "ask"}
        ]));
        let merged = merge_rules(&[], &user);
        assert_eq!(first(&merged, "POST", "/m/send").as_deref(), Some("b-user"));
        assert_eq!(first(&merged, "GET", "/anything").as_deref(), Some("everything"));
        let merged = merge_rules(&[rule("built-in", "POST /m/:id", AccessLevel::Ask)], &user);
        assert_eq!(first(&merged, "POST", "/m/send").as_deref(), Some("built-in"));
    }

    /// An override sets a rule's `level` and `ttl`, and nothing else; the
    /// rest the daemon refuses: an override with other keys, a second
    /// override of one rule, an added rule under a taken id.
    #[test]
    fn an_override_sets_level_and_ttl_and_the_rest_is_refused() {
        let built_in = vec![rule("del", "DELETE /m/:id", AccessLevel::AskAlways)];
        let decide = |user: serde_json::Value, m: &str, p: &str| {
            let rules = merge_rules(&built_in, &user_rules(user));
            evaluate_decision(&Request::bare(m, p), Some(&rules), None, &policy(), &[]).unwrap()
        };
        let (level, by, ttl) = decide(serde_json::json!([{"override": "del", "level": "ask", "ttl": 90}]), "DELETE", "/m/1");
        assert_eq!((level, ttl), (AccessLevel::Ask, Some(90)));
        assert!(matches!(by, DecidedBy::Rule { id: Some(ref id), .. } if id == "del"));
        assert_eq!(decide(serde_json::json!([{"override": "del", "level": "deny"}]), "DELETE", "/m/1").0, AccessLevel::Deny);
        for refused in [
            serde_json::json!([{"override": "del", "level": "allow", "path": "/other"}]),
            serde_json::json!([{"override": "del", "level": "ask"}, {"override": "del", "level": "allow"}]),
            serde_json::json!([{"id": "del", "method": "GET", "path": "/x", "level": "allow"}]),
            serde_json::json!([{"id": "x", "path": "/x", "level": "allow"}, {"id": "x", "path": "/y", "level": "allow"}]),
            serde_json::json!([{"id": "x", "override": "del", "level": "allow"}]),
            serde_json::json!([{"level": "allow"}]),
        ] {
            assert_eq!(decide(refused.clone(), "GET", "/elsewhere").0, AccessLevel::AskAlways, "{refused}");
            let notes = user_rules(refused.clone()).notes(&built_in);
            assert!(notes.iter().any(|n| n.refused && !n.why.is_empty()), "{refused}: {notes:?}");
        }
    }

    /// An override of a rule the definition no longer has: one that tightens
    /// is refused (`deny` denies the connection, `ask-always` asks every
    /// time); any other is dropped, with a note.
    #[test]
    fn an_override_of_a_rule_the_service_lacks() {
        let built_in = vec![rule("del", "DELETE /m/:id", AccessLevel::AskAlways)];
        let floor = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Allow),
            ttl: None,
        };
        let decide = |user: &UserRules, m: &str, p: &str| {
            let rules = merge_rules(&built_in, user);
            evaluate_decision(&Request::bare(m, p), Some(&rules), Some(&floor), &policy(), &[]).unwrap().0
        };
        let gone = |level: &str| user_rules(serde_json::json!([{"override": "batch", "level": level}]));
        assert_eq!(decide(&gone("deny"), "GET", "/m"), AccessLevel::Deny);
        assert_eq!(decide(&gone("ask-always"), "GET", "/m"), AccessLevel::AskAlways);
        for loosens in ["allow", "ask"] {
            assert_eq!(decide(&gone(loosens), "GET", "/m"), AccessLevel::Allow);
            assert_eq!(decide(&gone(loosens), "DELETE", "/m/1"), AccessLevel::AskAlways);
            let notes = gone(loosens).notes(&built_in);
            assert_eq!(notes.len(), 1);
            assert!(!notes[0].refused && notes[0].why.contains("'batch'"), "{notes:?}");
        }
        let ttl_only = user_rules(serde_json::json!({"batch": {"ttl": 60}}));
        assert_eq!(decide(&ttl_only, "GET", "/m"), AccessLevel::Allow);
        let notes = gone("deny").notes(&built_in);
        assert_eq!(notes, [RuleNote {
            rule: Some("batch".into()),
            level: Some(AccessLevel::Deny),
            refused: true,
            why: "it overrides 'batch', a rule this service doesn't have".into(),
        }]);
        // A pass that leaves the rule out applies the override to nothing.
        let kept = user_rules(serde_json::json!([{"override": "del", "level": "deny"}]));
        let rules = merge_rules_over(&[], &kept, &built_in);
        assert!(rules.is_empty());
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
        let (lvl, id, ttl) =
            evaluate_with_match(&Request::bare("GET", "/x"), Some(&rules), None, &policy(), &[]).unwrap();
        assert_eq!(lvl, AccessLevel::Ask);
        assert_eq!(id.as_deref(), Some("read"));
        assert_eq!(ttl, Some(60));
    }

    // ── conditions ───────────────────────────────────────────────────────────
    #[test]
    fn a_condition_is_cel_over_the_request() {
        let eval = |c: &str, body: &str| {
            Condition::compile(c)
                .unwrap_or_else(|e| panic!("{c}: {e}"))
                .eval(&req("POST", "/x", body))
                .unwrap()
        };
        let body = r#"{"amount": 100, "merchant": "acme", "fields": ["a", "b"]}"#;
        assert_eq!(eval("request.body.amount > 80", body), Some(true));
        assert_eq!(eval("request.body.amount > 200", body), Some(false));
        assert_eq!(eval("request.body.merchant == 'acme'", body), Some(true));
        assert_eq!(eval("request.body.fields.exists(f, f in ['b'])", body), Some(true));
        // An absent value, a type that doesn't compare: an error (None).
        assert_eq!(eval("request.body.missing > 0", body), None);
        assert_eq!(eval("request.body.merchant > 0", body), None);
        assert_eq!(eval("has(request.body.missing) && request.body.missing > 0", body), Some(false));
        // `||` decides on the side it can read.
        assert_eq!(eval("request.body.missing > 0 || request.body.amount > 80", body), Some(true));
        // A non-bool result is not a match.
        assert_eq!(eval("request.body.amount", body), None);
        // The query and headers are read too.
        let headers = vec![("x-account".to_string(), b"prod".to_vec())];
        let r = Request::new(
            RequestInput {
                method: "POST",
                path: "/x",
                query: Some("force=1"),
                headers: &headers,
                ..Default::default()
            },
            BodyFormat::Json,
            Default::default(),
        );
        let c = |s: &str| Condition::compile(s).unwrap().eval(&r).unwrap();
        assert_eq!(c("request.query.force == '1'"), Some(true));
        assert_eq!(c("'x-account' in request.headers && request.headers['x-account'] == 'prod'"), Some(true));
        assert_eq!(c("'x-other' in request.headers"), Some(false));
    }

    #[test]
    fn what_a_condition_may_not_read_is_refused_by_name() {
        for (bad, why) in [
            ("request.path == '/x'", "select the path with `path"),
            ("request.method == 'GET'", "select the method with `method"),
            ("request.params.owner == 'o'", "name the segment in `path`"),
            ("request == {}", "`request` is read whole"),
            ("request.nope == 1", "request has no field 'nope'"),
            ("request.headers[request.query.h] == 'x'", "must be a constant"),
            ("request.headers['X-Account'] == 'x'", "header names are lowercase"),
            ("request.query.a.b == 'x'", "takes one name"),
            ("amount > 80", "`amount` is not a known name"),
            ("request.body.model.startswith('o3')", "`startswith()` is not a function"),
            ("request.body.amount > ", ""),
            ("request.body.contains('x') && request.body.a == 1", "whole (its text) and a member"),
        ] {
            let e = Condition::compile(bad).expect_err(bad);
            assert!(e.contains(why), "{bad}: {e}");
        }
        for ok in [
            "request.body.model.matches('^o3')",
            "size(request.graphql.fields) > 0 && request.graphql.fields.exists(f, f == 'a')",
            "!(type(request.body.amount) in [int, uint, double]) || request.body.amount > 100",
            "request.host == 'api.x.com'",
            "request.body.contains('refund')",
            "true",
        ] {
            assert!(Condition::compile(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn a_condition_names_what_it_reads_and_presence_tests_read_only_presence() {
        let reads = |c: &str| -> Vec<(String, bool)> {
            Condition::compile(c)
                .unwrap()
                .reads()
                .iter()
                .map(|r| (r.path.to_string(), r.presence))
                .collect()
        };
        assert_eq!(
            reads("'x-account' in request.headers && request.headers['x-account'] == 'prod'"),
            [
                ("request.headers['x-account']".to_string(), false),
                ("request.headers['x-account']".to_string(), true)
            ]
        );
        assert_eq!(reads("'x-account' in request.headers"), [("request.headers['x-account']".to_string(), true)]);
        assert_eq!(
            reads("has(request.body.amount) && request.body.amount > 1"),
            [("request.body.amount".to_string(), false), ("request.body.amount".to_string(), true)]
        );
        assert_eq!(reads("size(request.query) > 0"), [("request.query".to_string(), false)]);
    }

    #[test]
    fn unguarded_member_reads_are_named() {
        let unguarded = |c: &str| -> Vec<String> {
            Condition::compile(c).unwrap().unguarded().iter().map(|p| p.to_string()).collect()
        };
        assert_eq!(unguarded("request.body.amount > 1000"), ["request.body.amount"]);
        assert!(unguarded("has(request.body.amount) && request.body.amount > 1000").is_empty());
        assert!(unguarded("request.body.amount > 1000 && has(request.body.amount)").is_empty());
        assert!(unguarded("!has(request.body.amount) || request.body.amount > 1000").is_empty());
        assert_eq!(
            unguarded("has(request.body.a) || request.body.a > 1"),
            ["request.body.a"]
        );
        assert_eq!(unguarded("has(request.body.o.price)"), ["request.body.o"]);
        assert!(unguarded("has(request.body.o) && has(request.body.o.price)").is_empty());
        assert!(unguarded("'x-a' in request.headers && request.headers['x-a'] == 'p'").is_empty());
        assert_eq!(unguarded("request.headers['x-a'] == 'p'"), ["request.headers['x-a']"]);
        assert!(unguarded("request.graphql.fields.exists(f, f == 'a')").is_empty());
        assert!(unguarded("has(request.body.a) ? request.body.a > 1 : false").is_empty());
    }

    /// An error never loosens a decision (DESIGN §1).
    #[test]
    fn an_error_never_loosens_a_decision() {
        let unguarded = || vec![when("big", "POST /pay", "request.body.amount > 1000", AccessLevel::Deny)];
        // Fires on a string amount (a type error) and on an absent one.
        assert_eq!(level(&req("POST", "/pay", r#"{"amount":"5000"}"#), &unguarded(), None), AccessLevel::Deny);
        assert_eq!(level(&req("POST", "/pay", "{}"), &unguarded(), None), AccessLevel::Deny);
        assert_eq!(level(&req("POST", "/pay", r#"{"amount":5}"#), &unguarded(), None), AccessLevel::Allow);
        // With `has()`, an absent amount doesn't.
        let guarded = vec![when(
            "big",
            "POST /pay",
            "has(request.body.amount) && request.body.amount > 1000",
            AccessLevel::Deny,
        )];
        assert_eq!(level(&req("POST", "/pay", "{}"), &guarded, None), AccessLevel::Allow);
        assert_eq!(level(&req("POST", "/pay", r#"{"amount":5000}"#), &guarded, None), AccessLevel::Deny);
        // Two reads: an absent fee doesn't hide a string amount.
        let either = vec![when(
            "big",
            "POST /pay",
            "request.body.amount > 1000 || request.body.fee > 50",
            AccessLevel::Deny,
        )];
        assert_eq!(level(&req("POST", "/pay", r#"{"amount":"5000"}"#), &either, None), AccessLevel::Deny);
        // An allow rule that errors doesn't allow.
        let floor = Levels {
            read: Some(AccessLevel::Ask),
            write: Some(AccessLevel::Ask),
            ttl: None,
        };
        let allow = vec![when("ok", "POST /pay", "request.body.amount < 10", AccessLevel::Allow)];
        assert_eq!(level(&req("POST", "/pay", r#"{"amount":5}"#), &allow, Some(&floor)), AccessLevel::Allow);
        assert_eq!(level(&req("POST", "/pay", "{}"), &allow, Some(&floor)), AccessLevel::Ask);
        assert_eq!(level(&req("POST", "/pay", r#"{"amount":"5"}"#), &allow, Some(&floor)), AccessLevel::Ask);
        // An allow rule on request.body.model allows.
        let model = vec![when("cheap", "POST /chat", "request.body.model == 'gpt-4o-mini'", AccessLevel::Allow)];
        assert_eq!(
            level(&req("POST", "/chat", r#"{"model":"gpt-4o-mini"}"#), &model, Some(&floor)),
            AccessLevel::Allow
        );
        // An `ask` rule matched only through an error doesn't replace a
        // stricter fallback: an ask-always write floor stands.
        let strict = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::AskAlways),
            ttl: None,
        };
        let ask = vec![when("pay", "POST /pay", "request.body.amount > 1", AccessLevel::Ask)];
        let (l, by, _) = evaluate_decision(&req("POST", "/pay", "{}"), Some(&ask), Some(&strict), &policy(), &[]).unwrap();
        assert_eq!((l, by), (AccessLevel::AskAlways, DecidedBy::Floor));
        // Where it is stricter, it decides.
        let (l, by, _) = evaluate_decision(&req("POST", "/pay", "{}"), Some(&ask), Some(&floor), &policy(), &[]).unwrap();
        assert_eq!(l, AccessLevel::Ask);
        assert_eq!(by, DecidedBy::Floor, "a tie keeps the decision without it");
        let lax = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Allow),
            ttl: None,
        };
        let (l, by, _) = evaluate_decision(&req("POST", "/pay", "{}"), Some(&ask), Some(&lax), &policy(), &[]).unwrap();
        assert_eq!(l, AccessLevel::Ask);
        assert!(matches!(by, DecidedBy::Rule { id: Some(ref id), .. } if id == "pay"));
    }

    #[test]
    fn conditions_compose_with_most_restrictive_wins() {
        // The snaplii shape: a base `ask` on every purchase, and an
        // `ask-always` refinement for amount > 80.
        let rules = vec![
            rule("p", "POST /buy", AccessLevel::Ask),
            when(
                "pl",
                "POST /buy",
                "!has(request.body.amount) || request.body.amount > 80",
                AccessLevel::AskAlways,
            ),
        ];
        assert_eq!(level(&req("POST", "/buy", r#"{"amount":100}"#), &rules, None), AccessLevel::AskAlways);
        assert_eq!(level(&req("POST", "/buy", r#"{"amount":50}"#), &rules, None), AccessLevel::Ask);
        assert_eq!(level(&req("POST", "/buy", "{}"), &rules, None), AccessLevel::AskAlways);
    }

    /// A value a condition reads that can't be read refuses the request; one
    /// nothing reads is not checked.
    #[test]
    fn a_body_a_condition_cannot_read_refuses_the_request() {
        let rules = vec![when(
            "big",
            "POST /pay",
            "has(request.body.amount) && request.body.amount > 1000",
            AccessLevel::Deny,
        )];
        for body in [
            r#"{"amount":1,"amount":5000}"#,
            r#"{"amount":1,"AMOUNT":5000}"#,
            r#"{"Amount":5000}"#,
            r#"{"amount": NaN}"#,
            "\u{feff}{\"amount\":1}",
            r#"{"amount":1,"note":"&amount=5000"}"#,
        ] {
            let e = evaluate(&req("POST", "/pay", body), Some(&rules), None, &policy(), &[]).unwrap_err();
            assert_eq!(e.status, 422, "{body}");
        }
        // Another path: nothing reads the body.
        assert_eq!(level(&req("POST", "/other", r#"{"Amount":5000}"#), &rules, None), AccessLevel::Allow);
        // A form body is read as a form.
        assert_eq!(level(&req("POST", "/pay", "amount=5000"), &rules, None), AccessLevel::Deny);
    }
}
