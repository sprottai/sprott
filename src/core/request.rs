//! The request object (request-model design §1): the one `request` that a
//! rule's or a `[requests]` shape's `condition`, a shape's `scope` and its
//! `consent` read.
//!
//! | Field | Content |
//! |---|---|
//! | `request.method` | the method, uppercase |
//! | `request.host` | the host, lowercase, with the port when it isn't the scheme's default |
//! | `request.path` | the path as normalized at ingress |
//! | `request.params` | the named groups of the matched `path` pattern |
//! | `request.query` | the query as sent, WHATWG-parsed to a map |
//! | `request.headers` | the headers as forwarded, by lowercase name |
//! | `request.body` | the body after its content codings are undone |
//! | `request.graphql` | `{calls, fields, request}` when the body format is `graphql` |
//!
//! A value is read only when something reads it, and the way its standard
//! says a server reads it. A read value that can't be read so refuses the
//! request (400 `request_unreadable`, 422 `request_invalid`): a repeated or
//! non-UTF-8 query parameter, header or form field, a body that looks like
//! JSON but isn't strict JSON, readings that disagree. A value nothing reads
//! is never checked.
//!
//! The body has readings, since a server may pick its parser by
//! Content-Type, by sniffing, or not at all: strict JSON (RFC 8259, I-JSON)
//! where the body parses as JSON, and WHATWG form unless exactly one
//! Content-Type source says the body is something else (the declared format
//! `form` always takes it; a multipart body never). Every path below
//! `request.body` that is read gets the one value every reading that defines
//! it agrees on. Whenever anything is read below `request.body`, the reading
//! profile refuses the ways common servers read a field differently: a
//! byte-order mark or a NUL byte, a JSON-looking or JSON-typed body that isn't
//! strict JSON, member names along a read path (or inside a value read whole)
//! that are equal under Unicode case folding, an integer beyond ±2^53 where it
//! is read. Multipart is not read.

use std::cell::OnceCell;
use std::fmt;

use serde::Serialize;
use serde_json::{Map, Value as Json};

use crate::core::selector::Params;
use crate::service::{graphql, strict_json};

// ── Refusal ──────────────────────────────────────────────────────────────────

/// Why a request can't be read the way a condition, `scope` or `consent`
/// needs: the HTTP status (400 unreadable, 415 a content coding that can't be
/// undone, 422 invalid) and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Unreadable {
    pub status: u16,
    pub message: String,
}

impl Unreadable {
    pub fn unreadable(message: impl Into<String>) -> Self {
        Unreadable {
            status: 400,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Unreadable {
            status: 422,
            message: message.into(),
        }
    }
}

impl From<graphql::Refusal> for Unreadable {
    fn from(r: graphql::Refusal) -> Self {
        Unreadable {
            status: r.status,
            message: r.message,
        }
    }
}

// ── Body format ──────────────────────────────────────────────────────────────

/// The body format a `[requests]` shape declares (`body = "…"`): the server's,
/// never the caller's Content-Type. Absent: `json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyFormat {
    #[default]
    Json,
    Form,
    Graphql,
    Text,
}

impl BodyFormat {
    pub const NAMES: &'static [&'static str] = &["json", "form", "graphql", "text"];

    pub fn parse(s: &str) -> Option<BodyFormat> {
        match s {
            "json" => Some(BodyFormat::Json),
            "form" => Some(BodyFormat::Form),
            "graphql" => Some(BodyFormat::Graphql),
            "text" => Some(BodyFormat::Text),
            _ => None,
        }
    }
}

// ── Paths into `request` ─────────────────────────────────────────────────────

/// A top-level field of `request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field {
    Method,
    Host,
    Path,
    Params,
    Query,
    Headers,
    Body,
    Graphql,
}

impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Field::Method => "method",
            Field::Host => "host",
            Field::Path => "path",
            Field::Params => "params",
            Field::Query => "query",
            Field::Headers => "headers",
            Field::Body => "body",
            Field::Graphql => "graphql",
        }
    }

    fn parse(s: &str) -> Option<Field> {
        Some(match s {
            "method" => Field::Method,
            "host" => Field::Host,
            "path" => Field::Path,
            "params" => Field::Params,
            "query" => Field::Query,
            "headers" => Field::Headers,
            "body" => Field::Body,
            "graphql" => Field::Graphql,
            _ => return None,
        })
    }
}

/// One step below a field: a member name or a list index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    Key(String),
    Index(u64),
}

/// A path into `request`: `request.body.raw`, `request.headers['x-account']`.
/// Written and parsed as the CEL select / index chain it is; its text
/// ([`fmt::Display`]) is canonical (a name that is a CEL identifier as
/// `.name`, any other as `['name']`) and keys the values an approval binds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadPath {
    pub field: Field,
    pub steps: Vec<Step>,
}

/// One read a condition makes: a path, and whether only its presence is read
/// (`has(request.body.a)`, `'k' in request.headers`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Read {
    pub path: ReadPath,
    pub presence: bool,
}

const CEL_RESERVED: &[&str] = &[
    "true", "false", "null", "in", "as", "break", "const", "continue", "else", "for",
    "function", "if", "import", "let", "loop", "package", "namespace", "return", "var",
    "void", "while",
];

fn is_cel_ident(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !CEL_RESERVED.contains(&s)
}

impl fmt::Display for ReadPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "request.{}", self.field.name())?;
        for s in &self.steps {
            match s {
                Step::Key(k) if is_cel_ident(k) => write!(f, ".{k}")?,
                Step::Key(k) => write!(f, "['{}']", k.replace('\\', "\\\\").replace('\'', "\\'"))?,
                Step::Index(i) => write!(f, "[{i}]")?,
            }
        }
        Ok(())
    }
}

impl ReadPath {
    pub fn new(field: Field, steps: Vec<Step>) -> ReadPath {
        ReadPath { field, steps }
    }

    /// Parse a path written in a `scope`, a `consent` token or an `encoded`
    /// key: a CEL select / index chain rooted at `request`, with constant
    /// indexes, that [`Self::check`] accepts.
    pub fn parse(text: &str) -> Result<ReadPath, String> {
        let not_a_path = || {
            format!(
                "'{}' is not a request path (request.body.<name>, request.query.<name>, request.headers['<name>'])",
                text
            )
        };
        let program = cel::Program::compile(text.trim()).map_err(|_| not_a_path())?;
        let path = match chain(program.expression()) {
            Some(Ok(p)) => p,
            Some(Err(e)) => return Err(format!("'{}': {}", text, e)),
            None => return Err(not_a_path()),
        };
        path.check().map_err(|e| format!("'{}': {}", text, e))?;
        Ok(path)
    }

    /// Whether `self` is `other` or a path above it.
    pub fn is_prefix_of(&self, other: &ReadPath) -> bool {
        self.field == other.field && other.steps.starts_with(&self.steps)
    }

    /// The path one step up, `None` at a field.
    pub fn parent(&self) -> Option<ReadPath> {
        let (_, init) = self.steps.split_last()?;
        Some(ReadPath::new(self.field, init.to_vec()))
    }

    /// What a field takes below it: `method`, `host` and `path` nothing;
    /// `params`, `query` and `headers` one name (a header name lowercase, as
    /// `request.headers` holds them); `body` and `graphql` any path.
    pub fn check(&self) -> Result<(), String> {
        match self.field {
            Field::Method | Field::Host | Field::Path if !self.steps.is_empty() => Err(format!(
                "request.{} is a string; it has no members",
                self.field.name()
            )),
            Field::Params | Field::Query | Field::Headers => match self.steps.as_slice() {
                [] => Ok(()),
                [Step::Key(k)] if self.field == Field::Headers && k.chars().any(|c| c.is_ascii_uppercase()) => {
                    Err(format!(
                        "header names are lowercase in request.headers: write '{}'",
                        k.to_ascii_lowercase()
                    ))
                }
                [Step::Key(_)] => Ok(()),
                _ => Err(format!(
                    "request.{} takes one name: request.{}['<name>']",
                    self.field.name(),
                    self.field.name()
                )),
            },
            _ => Ok(()),
        }
    }

    /// Whether this path reads below `request.body`, `request.query` or
    /// `request.headers`: a value a request may leave out.
    pub fn is_member(&self) -> bool {
        matches!(self.field, Field::Body | Field::Query | Field::Headers) && !self.steps.is_empty()
    }

    /// The presence test that guards this path: `has(<path>)`, or
    /// `'<name>' in <parent>` for a name `has()` can't select.
    pub fn guard(&self) -> String {
        match (self.steps.last(), self.parent()) {
            (Some(Step::Key(k)), _) if is_cel_ident(k) => format!("has({})", self),
            (Some(Step::Key(k)), Some(parent)) => format!(
                "'{}' in {}",
                k.replace('\\', "\\\\").replace('\'', "\\'"),
                parent
            ),
            (Some(Step::Index(i)), Some(parent)) => format!("size({}) > {}", parent, i),
            _ => format!("has({})", self),
        }
    }
}

/// Whether `e` is a select / index chain rooted at the name `request`.
fn rooted(e: &cel::IdedExpr) -> bool {
    use cel::common::ast::Expr;
    match &e.expr {
        Expr::Ident(id) => id == "request",
        Expr::Select(s) if !s.test => rooted(&s.operand),
        Expr::Call(c) if (c.func_name == "_[_]" || c.func_name == "_[?_]") && c.args.len() == 2 => {
            rooted(&c.args[0])
        }
        _ => false,
    }
}

/// The path `e` spells when it is a select / index chain rooted at
/// `request`: `None` when it isn't one, `Some(Err)` when it is one that names
/// no readable path (`request` whole, an unknown field, an index that isn't a
/// constant).
pub(crate) fn chain(e: &cel::IdedExpr) -> Option<Result<ReadPath, String>> {
    use cel::common::ast::{Expr, LiteralValue};
    let mut steps: Vec<Step> = Vec::new();
    let mut cur = e;
    loop {
        match &cur.expr {
            Expr::Select(s) if !s.test => {
                steps.push(Step::Key(s.field.clone()));
                cur = &s.operand;
            }
            Expr::Call(c) if c.func_name == "_[_]" && c.target.is_none() && c.args.len() == 2 => {
                let step = match &c.args[1].expr {
                    Expr::Literal(LiteralValue::String(s)) => Some(Step::Key(s.inner().to_string())),
                    Expr::Literal(LiteralValue::Int(i)) if *i.inner() >= 0 => {
                        Some(Step::Index(*i.inner() as u64))
                    }
                    Expr::Literal(LiteralValue::UInt(u)) => Some(Step::Index(*u.inner())),
                    _ => None,
                };
                match step {
                    Some(s) => {
                        steps.push(s);
                        cur = &c.args[0];
                    }
                    None => {
                        return rooted(&c.args[0]).then(|| {
                            Err("an index into request must be a constant ('name' or a number)".into())
                        })
                    }
                }
            }
            Expr::Call(c) if c.func_name == "_[?_]" && c.args.len() == 2 => {
                return rooted(&c.args[0])
                    .then(|| Err("an optional index (`[?…]`) into request is not read".into()));
            }
            Expr::Ident(id) if id == "request" => break,
            _ => return None,
        }
    }
    steps.reverse();
    let mut steps = steps.into_iter();
    let field = match steps.next() {
        None => {
            return Some(Err(
                "`request` is read whole; read its fields (request.body.<name>, request.headers['<name>'], …)".into(),
            ))
        }
        Some(Step::Key(k)) => match Field::parse(&k) {
            Some(f) => f,
            None => {
                return Some(Err(format!(
                    "request has no field '{}' (method, host, path, params, query, headers, body, graphql)",
                    k
                )))
            }
        },
        Some(Step::Index(_)) => {
            return Some(Err("request is read by field name, not by index".into()))
        }
    };
    Some(Ok(ReadPath::new(field, steps.collect())))
}

// ── Method readings ─────────────────────────────────────────────────────────

/// The headers some servers read a request's method from instead of its
/// request line (the convention Google's and other HTTP APIs document).
pub const METHOD_OVERRIDES: &[&str] = &["x-http-method-override", "x-http-method", "x-method-override"];

/// The methods a request may be read as (DESIGN §6): its request line, and
/// each method-override header it is forwarded with, each uppercase, each
/// once. A reading must be exactly one RFC 9110 method token after trimming
/// whitespace; anything else (a list, a control character, a header given
/// twice) is refused with why. A `_method` parameter is not read (a
/// framework convention whose parsers differ).
pub fn method_readings(line: &str, headers: &[(String, Vec<u8>)]) -> Result<Vec<String>, String> {
    let mut out = vec![line.to_ascii_uppercase()];
    for name in METHOD_OVERRIDES {
        let values: Vec<&[u8]> = headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_slice())
            .collect();
        match values.as_slice() {
            [] => {}
            [one] => {
                let reading = std::str::from_utf8(one)
                    .ok()
                    .map(str::trim)
                    .filter(|m| crate::core::selector::is_method_token(m))
                    .ok_or_else(|| format!("the {name} header is not one HTTP method"))?;
                let reading = reading.to_ascii_uppercase();
                if !out.contains(&reading) {
                    out.push(reading);
                }
            }
            _ => return Err(format!("the {name} header is given more than once")),
        }
    }
    Ok(out)
}

// ── Input ────────────────────────────────────────────────────────────────────

/// What the proxy has of a request, as it is decided and forwarded.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestInput<'a> {
    /// Uppercase.
    pub method: &'a str,
    /// Lowercase, with `:port` when it isn't the scheme's default.
    pub host: &'a str,
    /// As normalized at ingress (a reading of it, for an encoded slash).
    pub path: &'a str,
    /// The query string as sent, without its `?`.
    pub query: Option<&'a str>,
    /// The headers as forwarded: lowercase names, in order, a repeated
    /// header once per value.
    pub headers: &'a [(String, Vec<u8>)],
    /// The body after its content codings are undone.
    pub body: Option<&'a [u8]>,
    /// Why the body can't be read (a content coding that can't be undone):
    /// every read of it is refused with this.
    pub body_error: Option<&'a Unreadable>,
}

// ── The request object ───────────────────────────────────────────────────────

/// One request as a definition reads it: in a body format, with the params
/// of the `path` pattern it matched. Every source is parsed at most once.
pub struct Request<'a> {
    input: RequestInput<'a>,
    format: BodyFormat,
    params: Params,
    json: OnceCell<Result<Option<Json>, Unreadable>>,
    form: OnceCell<Option<Vec<(String, Vec<u8>)>>>,
    query: OnceCell<Vec<(String, Vec<u8>)>>,
    graphql: OnceCell<Result<Json, Unreadable>>,
}

impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.input.method)
            .field("path", &self.input.path)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

/// The JSON whitespace (RFC 8259 §2).
fn is_json_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// WHATWG `application/x-www-form-urlencoded` parsing, keeping each value's
/// bytes (a value read must be UTF-8; a name is decoded the WHATWG way).
fn urlencoded(input: &[u8]) -> Vec<(String, Vec<u8>)> {
    let decode = |s: &[u8]| -> Vec<u8> {
        let plus: Vec<u8> = s.iter().map(|&b| if b == b'+' { b' ' } else { b }).collect();
        percent_encoding::percent_decode(&plus).collect()
    };
    input
        .split(|&b| b == b'&')
        .filter(|seq| !seq.is_empty())
        .map(|seq| {
            let (name, value) = match seq.iter().position(|&b| b == b'=') {
                Some(i) => (&seq[..i], &seq[i + 1..]),
                None => (seq, &[][..]),
            };
            (String::from_utf8_lossy(&decode(name)).into_owned(), decode(value))
        })
        .collect()
}

/// The one value `name` has in `pairs` (`what` names the source in a
/// refusal): absent, or refused when given twice or not UTF-8.
fn single(pairs: &[(String, Vec<u8>)], name: &str, what: &str) -> Result<Option<String>, Unreadable> {
    let mut found = pairs.iter().filter(|(k, _)| k == name);
    let Some((_, first)) = found.next() else {
        return Ok(None);
    };
    if found.next().is_some() {
        return Err(Unreadable::unreadable(format!("the {} {} is given more than once", what, name)));
    }
    String::from_utf8(first.clone())
        .map(Some)
        .map_err(|_| Unreadable::unreadable(format!("the {} {} is not UTF-8", what, name)))
}

/// Every pair of `pairs` as a map, refused when a name is given twice or a
/// value is not UTF-8 (the whole map is read).
fn whole(pairs: &[(String, Vec<u8>)], what: &str) -> Result<Json, Unreadable> {
    let mut map = Map::new();
    for (k, _) in pairs {
        if !map.contains_key(k) {
            let v = single(pairs, k, what)?.unwrap_or_default();
            map.insert(k.clone(), Json::String(v));
        }
    }
    Ok(Json::Object(map))
}

/// A character's Unicode simple case fold, as an equivalence: two characters
/// fold alike when servers that match names case-insensitively (Go's
/// `EqualFold`, .NET's ordinal ignore-case) could take one for the other.
/// Uppercase then lowercase, one character each way; a character whose
/// mapping is several characters stays itself. A superset of simple case
/// folding (`ı` folds with `i` here, as in .NET), which only refuses more.
fn fold_char(c: char) -> char {
    fn one(mut it: impl Iterator<Item = char>) -> Option<char> {
        let first = it.next()?;
        it.next().is_none().then_some(first)
    }
    let upper = one(c.to_uppercase()).unwrap_or(c);
    one(upper.to_lowercase())
        .or_else(|| one(c.to_lowercase()))
        .unwrap_or(c)
}

fn fold(s: &str) -> String {
    s.chars().map(fold_char).collect()
}

/// A member name a server matching names case-insensitively could take for
/// `name`: the first that folds like it but isn't it.
fn case_twin<'k>(mut names: impl Iterator<Item = &'k String>, name: &str) -> Option<&'k String> {
    let f = fold(name);
    names.find(|m| m.as_str() != name && fold(m) == f)
}

fn twin_refusal(path: &str, twin: &str) -> Unreadable {
    Unreadable::invalid(format!(
        "the request body has a member \"{}\" beside {}; a server that matches names case-insensitively may read either",
        crate::util::terminal_safe(twin),
        path
    ))
}

/// Refuse a value read whole that a server could read another way: two
/// members of one object equal under case folding, or an integer beyond
/// ±2^53 (I-JSON).
fn check_read_value(v: &Json, path: &str) -> Result<(), Unreadable> {
    match v {
        Json::Object(m) => {
            let mut seen: std::collections::HashMap<String, &String> = std::collections::HashMap::new();
            for (k, inner) in m {
                if let Some(other) = seen.insert(fold(k), k) {
                    return Err(Unreadable::invalid(format!(
                        "the request body has members \"{}\" and \"{}\" under {}; a server that matches names case-insensitively may read either",
                        crate::util::terminal_safe(other),
                        crate::util::terminal_safe(k),
                        path
                    )));
                }
                check_read_value(inner, path)?;
            }
            Ok(())
        }
        Json::Array(a) => a.iter().try_for_each(|x| check_read_value(x, path)),
        Json::Number(n) => {
            let beyond = match (n.as_i64(), n.as_u64()) {
                (Some(i), _) => i.unsigned_abs() > (1u64 << 53),
                (None, Some(u)) => u > (1u64 << 53),
                _ => false,
            };
            if beyond {
                Err(Unreadable::invalid(format!(
                    "the request body has an integer beyond 2^53 at {}, which a server may read rounded",
                    path
                )))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

/// How the JSON reading reaches a path.
enum JsonAt<'j> {
    Value(&'j Json),
    /// A member is absent, or a step is `null` (F-49: absent, not refused).
    Absent,
}

/// Walk the JSON reading along `steps`, checking each object on the way for a
/// member that folds like the next name. A step that meets a string, number,
/// bool, or an array where it isn't an index is refused (422): the server
/// reads that body in a way the path can't see.
fn walk_json<'j>(root: &'j Json, steps: &[Step], path: &str) -> Result<JsonAt<'j>, Unreadable> {
    let mut cur = root;
    for step in steps {
        cur = match (cur, step) {
            (Json::Object(m), Step::Key(k)) => {
                if let Some(twin) = case_twin(m.keys(), k) {
                    return Err(twin_refusal(path, twin));
                }
                match m.get(k) {
                    Some(v) => v,
                    None => return Ok(JsonAt::Absent),
                }
            }
            (Json::Array(a), Step::Index(i)) => match a.get(*i as usize) {
                Some(v) => v,
                None => return Ok(JsonAt::Absent),
            },
            (Json::Null, _) => return Ok(JsonAt::Absent),
            _ => {
                return Err(Unreadable::invalid(format!(
                    "the request body can't be read at {}: it has no member there (not a JSON object)",
                    path
                )))
            }
        };
    }
    Ok(JsonAt::Value(cur))
}

/// The text a value has when a form field carries it: a string is itself,
/// anything else its JCS text (`true`, `5000`).
fn as_text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        other => String::from_utf8(sudp::canonical::canonicalize(other)).unwrap_or_default(),
    }
}

/// `node` with only the parts the reads at it need: everything for a value
/// read whole, the members along each path for the others. An array is kept
/// whole (its indexes would move otherwise).
fn prune(node: &Json, reads: &[(&[Step], bool)]) -> Json {
    if reads.iter().any(|(steps, presence)| steps.is_empty() && !presence) {
        return node.clone();
    }
    match node {
        Json::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                let below: Vec<(&[Step], bool)> = reads
                    .iter()
                    .filter_map(|(steps, presence)| match steps.split_first() {
                        Some((Step::Key(s), rest)) if s == k => Some((rest, *presence)),
                        _ => None,
                    })
                    .collect();
                if !below.is_empty() {
                    out.insert(k.clone(), prune(v, &below));
                }
            }
            Json::Object(out)
        }
        other => other.clone(),
    }
}

/// The media type a Content-Type source names, read two ways: strict RFC
/// 9110 parsing (`mime`), and the token before the first `;`, `,` or
/// whitespace (how Rails, Rack and PHP cut it).
fn media_types(source: &str) -> (Option<String>, String) {
    let strict = source
        .trim()
        .parse::<mime::Mime>()
        .ok()
        .map(|m| m.essence_str().to_ascii_lowercase());
    let loose = source
        .trim_start()
        .split(|c: char| c == ';' || c == ',' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    (strict, loose)
}

const FORM: &str = "application/x-www-form-urlencoded";

fn is_json_type(t: &str) -> bool {
    t == "application/json" || (t.starts_with("application/") && t.ends_with("+json"))
}

impl<'a> Request<'a> {
    pub fn new(input: RequestInput<'a>, format: BodyFormat, params: Params) -> Request<'a> {
        Request {
            input,
            format,
            params,
            json: OnceCell::new(),
            form: OnceCell::new(),
            query: OnceCell::new(),
            graphql: OnceCell::new(),
        }
    }

    /// A request with only a method and a path (tests, the floor probe).
    pub fn bare(method: &'a str, path: &'a str) -> Request<'a> {
        Request::new(
            RequestInput {
                method,
                path,
                ..Default::default()
            },
            BodyFormat::Json,
            Params::new(),
        )
    }

    pub fn input(&self) -> RequestInput<'a> {
        self.input
    }

    pub fn method(&self) -> &'a str {
        self.input.method
    }

    pub fn path(&self) -> &'a str {
        self.input.path
    }

    pub fn format(&self) -> BodyFormat {
        self.format
    }

    fn query_pairs(&self) -> &[(String, Vec<u8>)] {
        self.query
            .get_or_init(|| urlencoded(self.input.query.unwrap_or("").as_bytes()))
    }

    fn header_pairs(&self) -> &[(String, Vec<u8>)] {
        self.input.headers
    }

    fn body_bytes(&self) -> Result<&'a [u8], Unreadable> {
        if let Some(e) = self.input.body_error {
            return Err(e.clone());
        }
        Ok(self.input.body.unwrap_or(&[]))
    }

    fn blank(body: &[u8]) -> bool {
        body.iter().all(|&b| is_json_ws(b))
    }

    /// Every non-empty Content-Type source: each `content-type` header, and a
    /// `$ct` query parameter (Google's API front end reads one).
    fn content_types(&self) -> Vec<String> {
        self.header_pairs()
            .iter()
            .filter(|(k, _)| k == "content-type")
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .chain(
                self.query_pairs()
                    .iter()
                    .filter(|(k, _)| k == "$ct")
                    .map(|(_, v)| String::from_utf8_lossy(v).into_owned()),
            )
            .filter(|s| !s.trim().is_empty())
            .collect()
    }

    /// The strict JSON reading: the body as RFC 8259 / I-JSON, `None` when it
    /// doesn't parse (or is blank). A body that is JSON by its Content-Type or
    /// starts like JSON (`{`, `[`) but isn't strict JSON is refused, and so is
    /// any body with a byte-order mark or a NUL byte: refused only when
    /// something reads below `request.body`.
    fn json_reading(&self) -> Result<Option<&Json>, Unreadable> {
        let read = self.json.get_or_init(|| {
            let body = self.body_bytes()?;
            if body.starts_with(&[0xEF, 0xBB, 0xBF])
                || body.starts_with(&[0xFE, 0xFF])
                || body.starts_with(&[0xFF, 0xFE])
            {
                return Err(Unreadable::invalid("the request body starts with a byte-order mark"));
            }
            if body.contains(&0) {
                return Err(Unreadable::invalid("the request body has a NUL byte"));
            }
            if Self::blank(body) {
                return Ok(None);
            }
            match strict_json::parse(body) {
                Ok(v) => Ok(Some(v)),
                Err(e) => {
                    let looks = body
                        .iter()
                        .find(|&&b| !is_json_ws(b))
                        .is_some_and(|&b| b == b'{' || b == b'[');
                    let typed = self.content_types().iter().any(|ct| {
                        let (strict, loose) = media_types(ct);
                        strict.as_deref().is_some_and(is_json_type) || is_json_type(&loose)
                    });
                    if looks || typed {
                        Err(Unreadable::invalid(format!(
                            "the request body looks like JSON but isn't strict JSON (RFC 8259, I-JSON): {}",
                            e
                        )))
                    } else {
                        Ok(None)
                    }
                }
            }
        });
        read.as_ref().map(Option::as_ref).map_err(Clone::clone)
    }

    /// The WHATWG form reading, when it is taken: always for a declared
    /// `form`, else unless exactly one Content-Type source names a type other
    /// than `application/x-www-form-urlencoded` both ways it is read; never
    /// on a multipart body.
    fn form_reading(&self) -> Option<&[(String, Vec<u8>)]> {
        self.form
            .get_or_init(|| {
                let sources = self.content_types();
                let types: Vec<(Option<String>, String)> =
                    sources.iter().map(|s| media_types(s)).collect();
                let multipart = |(strict, loose): &(Option<String>, String)| {
                    strict.as_deref().is_some_and(|t| t.starts_with("multipart/"))
                        || loose.starts_with("multipart/")
                };
                if !types.is_empty() && types.iter().all(multipart) {
                    return None;
                }
                let other_type = types.len() == 1
                    && types[0].0.as_deref() != Some(FORM)
                    && types[0].1 != FORM;
                if self.format != BodyFormat::Form && other_type {
                    return None;
                }
                let body = self.input.body.unwrap_or(&[]);
                Some(urlencoded(body))
            })
            .as_deref()
    }

    /// The one value every body reading that defines the path at `steps`
    /// agrees on (`None`: no reading defines it), with the reading profile's
    /// refusals. `value` is a read of the value (not only its presence).
    fn body_value(&self, steps: &[Step], value: bool) -> Result<Option<Json>, Unreadable> {
        let shown = ReadPath::new(Field::Body, steps.to_vec()).to_string();
        let mut defined: Vec<Json> = Vec::new();
        if let Some(json) = self.json_reading()? {
            if let JsonAt::Value(v) = walk_json(json, steps, &shown)? {
                if value {
                    check_read_value(v, &shown)?;
                }
                defined.push(v.clone());
            }
        }
        if let Some(form) = self.form_reading() {
            match steps {
                [Step::Key(k), rest @ ..] => {
                    if let Some(twin) = case_twin(form.iter().map(|(n, _)| n), k) {
                        return Err(twin_refusal(&shown, twin));
                    }
                    let found = form.iter().any(|(n, _)| n == k);
                    if found && !rest.is_empty() {
                        return Err(Unreadable::invalid(format!(
                            "the request body read as a form has a string at request.body.{}, so {} can't be read",
                            k, shown
                        )));
                    }
                    if found {
                        let s = single(form, k, "form field")?.unwrap_or_default();
                        defined.push(Json::String(s));
                    }
                }
                _ => {}
            }
        }
        let Some((first, rest)) = defined.split_first() else {
            return Ok(None);
        };
        if rest.iter().any(|v| as_text(v) != as_text(first)) {
            return Err(Unreadable::invalid(format!(
                "the request body reads one way as JSON and another as a form at {}",
                shown
            )));
        }
        Ok(Some(first.clone()))
    }

    /// The body read whole: its text.
    fn body_text(&self) -> Result<String, Unreadable> {
        let body = self.body_bytes()?;
        String::from_utf8(body.to_vec())
            .map_err(|_| Unreadable::unreadable("the request body is not UTF-8 text"))
    }

    /// `request.graphql`, when the body format is `graphql`: the operation a
    /// server would run (graphql.rs), refused with the status a GraphQL server
    /// gives. A blank body makes no call.
    fn graphql_value(&self) -> Result<Option<&Json>, Unreadable> {
        if self.format != BodyFormat::Graphql {
            return Ok(None);
        }
        let read = self.graphql.get_or_init(|| {
            let body = self.body_bytes()?;
            let op = if Self::blank(body) {
                graphql::Operation {
                    calls: Vec::new(),
                    variables: Map::new(),
                }
            } else {
                let json = strict_json::parse(body).map_err(|e| {
                    Unreadable::unreadable(format!("the request body is not valid JSON: {e}"))
                })?;
                graphql::read(&json)?
            };
            let mut obj = Map::new();
            obj.insert(
                "calls".into(),
                Json::String(op.calls_var(crate::service::BOUND_VALUE_CAP)),
            );
            obj.insert("fields".into(), Json::from(op.fields()));
            obj.insert("request".into(), Json::String(op.request_var()));
            Ok(Json::Object(obj))
        });
        read.as_ref().map(Some).map_err(Clone::clone)
    }

    /// The value at `path` (`None`: absent), read as a `scope`, a `consent`
    /// or a condition reads it.
    pub fn value(&self, path: &ReadPath) -> Result<Option<Json>, Unreadable> {
        let one = |pairs: &[(String, Vec<u8>)], what: &str| -> Result<Option<Json>, Unreadable> {
            match path.steps.as_slice() {
                [] => whole(pairs, what).map(Some),
                [Step::Key(k)] => Ok(single(pairs, k, what)?.map(Json::String)),
                _ => Ok(None),
            }
        };
        match path.field {
            Field::Method => Ok(Some(Json::String(self.input.method.to_string()))),
            Field::Host => Ok(Some(Json::String(self.input.host.to_string()))),
            Field::Path => Ok(Some(Json::String(self.input.path.to_string()))),
            Field::Params => Ok(match path.steps.as_slice() {
                [] => Some(Json::Object(
                    self.params
                        .iter()
                        .map(|(k, v)| (k.clone(), Json::String(v.clone())))
                        .collect(),
                )),
                [Step::Key(k)] => self.params.get(k).map(|v| Json::String(v.clone())),
                _ => None,
            }),
            Field::Query => one(self.query_pairs(), "query parameter"),
            Field::Headers => one(self.header_pairs(), "header"),
            Field::Body if path.steps.is_empty() => self.body_text().map(|t| Some(Json::String(t))),
            Field::Body => self.body_value(&path.steps, true),
            Field::Graphql => {
                let Some(g) = self.graphql_value()? else {
                    return Ok(None);
                };
                let mut cur = g;
                for step in &path.steps {
                    let next = match (cur, step) {
                        (Json::Object(m), Step::Key(k)) => m.get(k),
                        (Json::Array(a), Step::Index(i)) => a.get(*i as usize),
                        _ => None,
                    };
                    match next {
                        Some(v) => cur = v,
                        None => return Ok(None),
                    }
                }
                Ok(Some(cur.clone()))
            }
        }
    }

    /// The `request` object a condition evaluates, holding only what `reads`
    /// read: a presence read puts in no value a condition could use, a body
    /// read keeps the body's own structure along its path (so `has()` and a
    /// step through `null` behave as on the body itself).
    pub fn object(&self, reads: &[Read]) -> Result<Json, Unreadable> {
        let mut obj = Map::new();
        for field in [Field::Method, Field::Host, Field::Path, Field::Params, Field::Graphql] {
            if reads.iter().any(|r| r.path.field == field) {
                if let Some(v) = self.value(&ReadPath::new(field, Vec::new()))? {
                    obj.insert(field.name().into(), v);
                }
            }
        }
        for (field, what) in [(Field::Query, "query parameter"), (Field::Headers, "header")] {
            let at: Vec<&Read> = reads.iter().filter(|r| r.path.field == field).collect();
            if at.is_empty() {
                continue;
            }
            if at.iter().any(|r| r.path.steps.is_empty() && !r.presence) {
                let pairs = if field == Field::Query {
                    self.query_pairs()
                } else {
                    self.header_pairs()
                };
                obj.insert(field.name().into(), whole(pairs, what)?);
                continue;
            }
            let mut map = Map::new();
            for r in &at {
                let [Step::Key(k)] = r.path.steps.as_slice() else {
                    continue;
                };
                if r.presence {
                    let pairs = if field == Field::Query {
                        self.query_pairs()
                    } else {
                        self.header_pairs()
                    };
                    if pairs.iter().any(|(n, _)| n == k) {
                        map.entry(k.clone()).or_insert(Json::Null);
                    }
                } else if let Some(v) = self.value(&r.path)? {
                    map.insert(k.clone(), v);
                }
            }
            obj.insert(field.name().into(), Json::Object(map));
        }
        let body: Vec<&Read> = reads.iter().filter(|r| r.path.field == Field::Body).collect();
        if !body.is_empty() {
            let value = if body.iter().any(|r| r.path.steps.is_empty() && !r.presence) {
                Json::String(self.body_text()?)
            } else {
                self.body_tree(&body)?
            };
            obj.insert("body".into(), value);
        }
        Ok(Json::Object(obj))
    }

    /// `request.body` for member reads: the JSON reading pruned to the read
    /// paths, with the values only the form reading defines put in.
    fn body_tree(&self, reads: &[&Read]) -> Result<Json, Unreadable> {
        let mut agreed: Vec<(&Read, Option<Json>)> = Vec::new();
        for &r in reads {
            if r.path.steps.is_empty() {
                continue; // `has()` on the body itself: always present
            }
            agreed.push((r, self.body_value(&r.path.steps, !r.presence)?));
        }
        let mut tree = match self.json_reading()? {
            Some(json) => {
                let paths: Vec<(&[Step], bool)> = agreed
                    .iter()
                    .map(|(r, _)| (r.path.steps.as_slice(), r.presence))
                    .collect();
                prune(json, &paths)
            }
            None => Json::Object(Map::new()),
        };
        if let Json::Object(m) = &mut tree {
            for (r, v) in &agreed {
                if let ([Step::Key(k)], Some(v)) = (r.path.steps.as_slice(), v) {
                    m.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn path(s: &str) -> ReadPath {
        ReadPath::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    fn with<'a>(
        headers: &'a [(String, Vec<u8>)],
        query: Option<&'a str>,
        body: &'a str,
        format: BodyFormat,
    ) -> Request<'a> {
        Request::new(
            RequestInput {
                method: "POST",
                host: "api.x.com",
                path: "/x",
                query,
                headers,
                body: Some(body.as_bytes()),
                body_error: None,
            },
            format,
            Params::new(),
        )
    }

    fn ct(v: &str) -> Vec<(String, Vec<u8>)> {
        vec![("content-type".to_string(), v.as_bytes().to_vec())]
    }

    #[test]
    fn paths_parse_to_their_canonical_text() {
        for (written, canonical) in [
            ("request.body.raw", "request.body.raw"),
            ("request.body['raw']", "request.body.raw"),
            ("request.headers['x-account']", "request.headers['x-account']"),
            ("request.query.addParents", "request.query.addParents"),
            ("request.body.items[0].id", "request.body.items[0].id"),
            ("request.body['in']", "request.body['in']"),
            ("request.graphql.calls", "request.graphql.calls"),
            ("request.params.zone", "request.params.zone"),
            ("request.body", "request.body"),
        ] {
            assert_eq!(path(written).to_string(), canonical, "{written}");
            assert_eq!(path(canonical), path(written));
        }
        for bad in [
            "request",
            "request.nope",
            "request.method.x",
            "request.headers['X-Account']",
            "request.query.a.b",
            "body.raw",
            "request.body.raw + 1",
            "request.headers[name]",
            "",
        ] {
            assert!(ReadPath::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(path("request.headers['x-account']").guard(), "'x-account' in request.headers");
        assert_eq!(path("request.body.amount").guard(), "has(request.body.amount)");
    }

    #[test]
    fn query_and_headers_refuse_only_what_is_read_twice() {
        let headers = vec![
            ("x-a".to_string(), b"1".to_vec()),
            ("x-a".to_string(), b"2".to_vec()),
            ("x-b".to_string(), b"3".to_vec()),
            ("x-c".to_string(), vec![0xff]),
        ];
        let r = with(&headers, Some("a=1&a=2&b=%20x+y&c=%FF"), "", BodyFormat::Json);
        assert_eq!(r.value(&path("request.query.b")).unwrap(), Some(json!(" x y")));
        assert_eq!(r.value(&path("request.query.zz")).unwrap(), None);
        assert_eq!(r.value(&path("request.query.a")).unwrap_err().status, 400);
        assert_eq!(r.value(&path("request.query.c")).unwrap_err().status, 400);
        assert_eq!(r.value(&path("request.query")).unwrap_err().status, 400);
        assert_eq!(r.value(&path("request.headers['x-b']")).unwrap(), Some(json!("3")));
        assert_eq!(r.value(&path("request.headers['x-a']")).unwrap_err().status, 400);
        assert_eq!(r.value(&path("request.headers['x-c']")).unwrap_err().status, 400);
        // A presence read reads no value: a repeat is not refused.
        let reads = [Read {
            path: path("request.headers['x-a']"),
            presence: true,
        }];
        assert_eq!(r.object(&reads).unwrap(), json!({"headers": {"x-a": null}}));
    }

    #[test]
    fn the_body_is_read_as_json_and_as_a_form_where_a_server_may() {
        let amount = path("request.body.amount");
        let read = |headers: &[(String, Vec<u8>)], body: &str, format| {
            with(headers, None, body, format).value(&amount)
        };
        // JSON, with or without its Content-Type.
        assert_eq!(read(&[], r#"{"amount":5000}"#, BodyFormat::Json).unwrap(), Some(json!(5000)));
        assert_eq!(read(&ct("text/plain"), r#"{"amount":5000}"#, BodyFormat::Text).unwrap(), Some(json!(5000)));
        // A form, whatever the declared format, unless the type says otherwise.
        assert_eq!(read(&[], "amount=5000", BodyFormat::Json).unwrap(), Some(json!("5000")));
        assert_eq!(read(&ct("text/plain"), "amount=5000", BodyFormat::Json).unwrap(), None);
        assert_eq!(read(&ct("text/plain"), "amount=5000", BodyFormat::Form).unwrap(), Some(json!("5000")));
        assert_eq!(read(&ct(""), "amount=5000", BodyFormat::Json).unwrap(), Some(json!("5000")));
        assert_eq!(
            read(&ct("application/x-www-form-urlencoded, application/json"), "amount=5000", BodyFormat::Json).unwrap(),
            Some(json!("5000"))
        );
        assert_eq!(read(&ct("multipart/form-data; boundary=b"), "amount=5000", BodyFormat::Form).unwrap(), None);
        let two = vec![
            ("content-type".to_string(), b"text/plain".to_vec()),
            ("content-type".to_string(), FORM.as_bytes().to_vec()),
        ];
        assert_eq!(read(&two, "amount=5000", BodyFormat::Json).unwrap(), Some(json!("5000")));
        let typed = vec![
            ("content-type".to_string(), b"text/plain".to_vec()),
            ("content-type".to_string(), b"application/json".to_vec()),
        ];
        assert_eq!(read(&typed, "amount=5000", BodyFormat::Json).unwrap_err().status, 422);
        // A polyglot whose readings disagree is refused; a JSON chat body sent
        // as JSON whose text holds a form spelling is not.
        assert_eq!(read(&[], r#"{"amount":1,"x":"&amount=5000"}"#, BodyFormat::Json).unwrap_err().status, 422);
        let chat = r#"{"model":"gpt-4o","messages":[{"content":"a&model=civic"}]}"#;
        let model = path("request.body.model");
        let json_type = ct("application/json");
        let r = with(&json_type, None, chat, BodyFormat::Json);
        assert_eq!(r.value(&model).unwrap(), Some(json!("gpt-4o")));
        // A repeated form field that is read.
        assert_eq!(read(&[], "amount=1&amount=2", BodyFormat::Form).unwrap_err().status, 400);
    }

    #[test]
    fn the_reading_profile_refuses_what_servers_read_differently() {
        let amount = path("request.body.amount");
        let refused = |body: &str| with(&[], None, body, BodyFormat::Text).value(&amount).map_err(|e| e.status);
        for body in [
            r#"{"amount":1,"amount":2}"#,
            r#"{"amount":1,"AMOUNT":5000}"#,
            r#"{"Amount":5000}"#,
            r#"{"amount": NaN}"#,
            "\u{feff}{\"amount\":1}",
            "  {\"amount\":1,}",
            "{\"amount\":1}\u{0}",
            r#"{"amount":9007199254740993}"#,
            r#"[{"amount":1}]"#,
            "Amount=5",
        ] {
            assert_eq!(refused(body), Err(422), "{body}");
        }
        // Objects nothing reads aren't checked.
        let tool = r#"{"amount":1,"tools":[{"parameters":{"ID":1,"id":2}}],"seed":9007199254740993}"#;
        assert_eq!(refused(tool), Ok(Some(json!(1))));
        // A JSON-typed body that isn't JSON at all is refused too; a blank one
        // reads nothing.
        let json_type = ct("application/json");
        let r = with(&json_type, None, "amount=1", BodyFormat::Json);
        assert_eq!(r.value(&amount).unwrap_err().status, 422);
        let r = with(&json_type, None, "  ", BodyFormat::Json);
        assert_eq!(r.value(&amount).unwrap(), None);
        // A step through a non-object is refused; through null it is absent.
        let deep = path("request.body.a.b");
        for (body, out) in [(r#"{"a":"x"}"#, Err(422)), (r#"{"a":null}"#, Ok(None)), (r#"{"a":{}}"#, Ok(None))] {
            assert_eq!(with(&[], None, body, BodyFormat::Json).value(&deep).map_err(|e| e.status), out, "{body}");
        }
    }

    #[test]
    fn a_condition_sees_the_body_structure_along_its_reads() {
        let r = with(&[], None, r#"{"o":{"item":{"price":"40","sku":"x"},"note":"n"},"z":1}"#, BodyFormat::Json);
        let reads = [
            Read { path: path("request.body.o"), presence: true },
            Read { path: path("request.body.o.item.price"), presence: false },
            Read { path: path("request.body.missing"), presence: true },
        ];
        assert_eq!(r.object(&reads).unwrap(), json!({"body": {"o": {"item": {"price": "40"}}}}));
        let r = with(&[], None, r#"{"o":null}"#, BodyFormat::Json);
        let reads = [Read { path: path("request.body.o.item"), presence: true }];
        assert_eq!(r.object(&reads).unwrap(), json!({"body": {"o": null}}));
        // The form reading's values join the JSON reading's.
        let r = with(&[], None, "amount=5000", BodyFormat::Json);
        let reads = [Read { path: path("request.body.amount"), presence: false }];
        assert_eq!(r.object(&reads).unwrap(), json!({"body": {"amount": "5000"}}));
    }

    #[test]
    fn graphql_reads_the_operation_and_a_blank_body_makes_no_call() {
        let r = with(&[], None, r#"{"query":"mutation { a(id: 1) }"}"#, BodyFormat::Graphql);
        assert_eq!(r.value(&path("request.graphql.fields")).unwrap(), Some(json!(["a"])));
        let r = with(&[], None, "", BodyFormat::Graphql);
        assert_eq!(r.value(&path("request.graphql.fields")).unwrap(), Some(json!([])));
        let r = with(&[], None, "not json", BodyFormat::Graphql);
        assert_eq!(r.value(&path("request.graphql.fields")).unwrap_err().status, 400);
        let r = with(&[], None, r#"{"query":"mutation { a }"}"#, BodyFormat::Json);
        assert_eq!(r.value(&path("request.graphql.fields")).unwrap(), None);
    }

    #[test]
    fn a_method_is_read_from_the_line_and_each_override() {
        let h = |pairs: &[(&str, &str)]| -> Vec<(String, Vec<u8>)> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.as_bytes().to_vec())).collect()
        };
        assert_eq!(method_readings("post", &[]).unwrap(), ["POST"]);
        assert_eq!(
            method_readings("POST", &h(&[("x-http-method-override", " delete ")])).unwrap(),
            ["POST", "DELETE"]
        );
        assert_eq!(
            method_readings("POST", &h(&[("x-http-method", "GET"), ("x-method-override", "POST")])).unwrap(),
            ["POST", "GET"]
        );
        for bad in [
            h(&[("x-http-method-override", "DELETE, GET")]),
            h(&[("x-http-method-override", "")]),
            h(&[("x-method-override", "DEL ETE")]),
            h(&[("x-http-method", "GET"), ("x-http-method", "GET")]),
        ] {
            assert!(method_readings("POST", &bad).is_err(), "{bad:?}");
        }
        assert!(method_readings("POST", &[("x-http-method".into(), b"DELETE\0".to_vec())]).is_err());
    }

    #[test]
    fn names_fold_as_case_insensitive_servers_match_them() {
        for (a, b) in [("amount", "AMOUNT"), ("k", "\u{212a}"), ("s", "\u{17f}"), ("σ", "ς"), ("i", "ı")] {
            assert_eq!(fold(a), fold(b), "{a} {b}");
        }
        assert_ne!(fold("amount"), fold("amounts"));
        assert_eq!(fold("ß"), "ß");
    }
}
