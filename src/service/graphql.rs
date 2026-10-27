//! Reading a GraphQL request for policy and consent: the top-level calls of the
//! operation a server will execute, with every argument resolved.
//!
//! A `[requests]` var `{ in = "graphql", at = "request" | "calls" | "fields" }`
//! reads the body as a GraphQL-over-HTTP JSON request (`query`, optional
//! `operationName` and `variables`; other keys are ignored, as that spec
//! requires of a server). Policy decides on `fields`, the approval binds
//! `request` and shows `calls`.
//!
//! Parsing and validation are apollo-compiler's (the parser Apollo Router builds
//! on), without a schema. What this file adds are the spec's own steps for
//! "which calls run" (GraphQL, September 2025): GetOperation (§6.1),
//! CollectFields at the root with fragments expanded and `@skip`/`@include`
//! applied (§6.3.2), and variable values with their defaults (§6.1.2). A
//! request the spec has a server refuse is refused here, with the status
//! GraphQL over HTTP gives it: 400 when it is not a readable GraphQL request,
//! 422 when its document fails validation.

use apollo_compiler::ast;
use serde_json::{Map, Value as Json};

/// Parse bounds: a document past them is refused, never read partially.
const TOKEN_LIMIT: usize = 100_000;
const RECURSION_LIMIT: usize = 128;

/// A string argument longer than this is shown shortened in `calls`.
const SHOW_STRING_MAX: usize = 200;
/// How much of a shortened string `calls` keeps.
const SHOW_STRING_KEEP: usize = 120;

/// One top-level call: the field the server resolves (alias removed), its
/// arguments as JSON (the spec's mapping: an enum is its name as a string, an
/// argument whose variable was not provided is absent), and any directive on
/// it other than `@skip`/`@include` (those decide whether it is a call at all).
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub field: String,
    pub args: Map<String, Json>,
    pub directives: Vec<(String, Map<String, Json>)>,
}

/// The calls a request makes, in execution order (a mutation's root fields
/// run serially in this order, so the order is part of the action).
#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    pub calls: Vec<Call>,
}

/// Why a request was refused: the HTTP status and the reason, as a GraphQL
/// server would give them.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub status: u16,
    pub message: String,
}

fn bad_request(message: impl Into<String>) -> Refusal {
    Refusal {
        status: 400,
        message: message.into(),
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal {
        status: 422,
        message: message.into(),
    }
}

impl Operation {
    /// The `request` var: every call in full, as canonical JSON (keys sorted,
    /// so argument order, which the spec says carries no meaning, doesn't
    /// change it). What an approval binds.
    pub fn request_var(&self) -> String {
        canonical(&Json::Array(
            self.calls.iter().map(|c| call_json(c, &|s| s)).collect(),
        ))
    }

    /// The `calls` var: the same calls for a person to read, within `budget`
    /// bytes. A long string is always shortened to its start and length. Past
    /// the budget, in turn: the biggest argument values become their size,
    /// biggest first, until it fits (the short ids and names that say what a
    /// call acts on go last); identical calls fold into one with a `count`;
    /// arguments go and a field's calls fold into one with a `count`; calls
    /// past the budget become a final `{"more": N}`. Each stage costs one pass.
    pub fn calls_var(&self, budget: usize) -> String {
        let mut shown: Vec<Json> = self.calls.iter().map(|c| call_json(c, &shorten)).collect();
        let fits = |list: &[Json]| array_len(list) <= budget;
        if fits(&shown) {
            return canonical(&Json::Array(shown));
        }
        summarize_biggest(&mut shown, budget);
        if fits(&shown) {
            return canonical(&Json::Array(shown));
        }
        let folded = fold(shown, |c| canonical(c));
        if fits(&folded) {
            return canonical(&Json::Array(folded));
        }
        let names: Vec<Json> = self
            .calls
            .iter()
            .map(|c| serde_json::json!({ "field": c.field }))
            .collect();
        let names = fold(names, |c| c["field"].as_str().unwrap_or_default().to_string());
        if fits(&names) {
            return canonical(&Json::Array(names));
        }
        // As many names as fit beside the `more` entry that counts the rest.
        let mut kept: Vec<Json> = Vec::new();
        let mut len = 2; // `[` `]`
        for (i, name) in names.iter().enumerate() {
            let item = canonical(name).len() + 1;
            let more = canonical(&serde_json::json!({ "more": names.len() - i - 1 })).len() + 1;
            if len + item + more > budget {
                kept.push(serde_json::json!({ "more": names.len() - i }));
                return canonical(&Json::Array(kept));
            }
            len += item;
            kept.push(name.clone());
        }
        canonical(&Json::Array(kept))
    }

    /// The `fields` var: the called field names, each once, in order of first
    /// call.
    pub fn fields(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.calls
            .iter()
            .filter(|c| seen.insert(c.field.as_str()))
            .map(|c| c.field.clone())
            .collect()
    }
}

fn canonical(v: &Json) -> String {
    String::from_utf8(sudp::canonical::canonicalize(v)).unwrap_or_default()
}

fn call_json(c: &Call, strings: &dyn Fn(String) -> String) -> Json {
    let mut obj = Map::new();
    obj.insert("field".into(), Json::String(c.field.clone()));
    if !c.args.is_empty() {
        obj.insert(
            "args".into(),
            map_strings(Json::Object(c.args.clone()), strings),
        );
    }
    if !c.directives.is_empty() {
        let dirs = c
            .directives
            .iter()
            .map(|(name, args)| {
                let mut d = Map::new();
                d.insert("name".into(), Json::String(name.clone()));
                if !args.is_empty() {
                    d.insert(
                        "args".into(),
                        map_strings(Json::Object(args.clone()), strings),
                    );
                }
                Json::Object(d)
            })
            .collect();
        obj.insert("directives".into(), Json::Array(dirs));
    }
    Json::Object(obj)
}

fn map_strings(v: Json, f: &dyn Fn(String) -> String) -> Json {
    match v {
        Json::String(s) => Json::String(f(s)),
        Json::Array(a) => Json::Array(a.into_iter().map(|x| map_strings(x, f)).collect()),
        Json::Object(o) => {
            Json::Object(o.into_iter().map(|(k, x)| (k, map_strings(x, f))).collect())
        }
        other => other,
    }
}

/// An argument value whose JSON is longer than this shows as its size when
/// the calls don't fit.
const SHOW_VALUE_MAX: usize = 160;

/// The canonical length of a JSON array of these items.
fn array_len(items: &[Json]) -> usize {
    2 + items.iter().map(|i| canonical(i).len()).sum::<usize>() + items.len().saturating_sub(1)
}

/// Replace argument values (of calls and of their directives) with their
/// size, biggest first, until the list fits `budget` or none is left over
/// [`SHOW_VALUE_MAX`].
fn summarize_biggest(calls: &mut [Json], budget: usize) {
    // (size, call, directive, argument)
    let mut big: Vec<(usize, usize, Option<usize>, String)> = Vec::new();
    for (ci, call) in calls.iter().enumerate() {
        let mut add = |args: Option<&Json>, di: Option<usize>| {
            for (k, v) in args.and_then(Json::as_object).into_iter().flatten() {
                let n = canonical(v).len();
                if n > SHOW_VALUE_MAX {
                    big.push((n, ci, di, k.clone()));
                }
            }
        };
        add(call.get("args"), None);
        if let Some(Json::Array(dirs)) = call.get("directives") {
            for (di, d) in dirs.iter().enumerate() {
                add(d.get("args"), Some(di));
            }
        }
    }
    big.sort_by(|a, b| b.0.cmp(&a.0));
    let mut len = array_len(calls);
    for (n, ci, di, key) in big {
        if len <= budget {
            return;
        }
        let size = Json::String(format!("… ({n} bytes)"));
        len = len - n + canonical(&size).len();
        let call = &mut calls[ci];
        let args = match di {
            None => call.get_mut("args"),
            Some(di) => call
                .get_mut("directives")
                .and_then(|d| d.get_mut(di))
                .and_then(|d| d.get_mut("args")),
        };
        if let Some(v) = args.and_then(|a| a.get_mut(&key)) {
            *v = size;
        }
    }
}

/// Calls with the same `key` folded into the first, with how many there were.
fn fold(calls: Vec<Json>, key: impl Fn(&Json) -> String) -> Vec<Json> {
    let mut out: Vec<Json> = Vec::new();
    let mut counts: Vec<u64> = Vec::new();
    let mut at: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for c in calls {
        match at.entry(key(&c)) {
            std::collections::hash_map::Entry::Occupied(e) => counts[*e.get()] += 1,
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(out.len());
                out.push(c);
                counts.push(1);
            }
        }
    }
    for (c, n) in out.iter_mut().zip(counts) {
        if n > 1 {
            c["count"] = Json::from(n);
        }
    }
    out
}

fn shorten(s: String) -> String {
    let n = s.chars().count();
    if n <= SHOW_STRING_MAX {
        return s;
    }
    let start: String = s.chars().take(SHOW_STRING_KEEP).collect();
    format!("{start}… ({n} chars)")
}

/// Read a parsed JSON body as the GraphQL operation a server would execute.
pub fn read(body: &Json) -> Result<Operation, Refusal> {
    let obj = body.as_object().ok_or_else(|| {
        bad_request("the body is not a GraphQL request (a JSON object with a query)")
    })?;
    let query = match obj.get("query") {
        Some(Json::String(q)) => q,
        _ => return Err(bad_request("the GraphQL request has no query string")),
    };
    let op_name = match obj.get("operationName") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) => Some(s.as_str()),
        Some(_) => return Err(bad_request("operationName must be a string")),
    };
    let empty = Map::new();
    let provided = match obj.get("variables") {
        None | Some(Json::Null) => &empty,
        Some(Json::Object(m)) => m,
        Some(_) => return Err(bad_request("variables must be an object")),
    };

    let doc = ast::Document::parser()
        .token_limit(TOKEN_LIMIT)
        .recursion_limit(RECURSION_LIMIT)
        .parse_ast(query.as_str(), "query.graphql")
        .map_err(|e| {
            bad_request(format!(
                "the GraphQL query does not parse: {}",
                brief(e.errors.iter())
            ))
        })?;
    if let Err(errors) = doc.validate_standalone_executable() {
        // Which directives exist is the schema's to say (`@skip` and
        // `@include` always do), so without one an unknown directive is not
        // an error here; the server still checks its own.
        let real: Vec<_> = errors
            .iter()
            .filter(|d| d.error.unstable_error_name() != Some("UndefinedDirective"))
            .collect();
        if !real.is_empty() {
            return Err(invalid(format!(
                "the GraphQL query is not valid: {}",
                brief(real)
            )));
        }
    }

    let op = get_operation(&doc, op_name)?;
    let vars = variable_values(op, provided)?;
    let fragments: std::collections::HashMap<&str, &ast::FragmentDefinition> = doc
        .definitions
        .iter()
        .filter_map(|d| match d {
            ast::Definition::FragmentDefinition(f) => Some((f.name.as_str(), &**f)),
            _ => None,
        })
        .collect();

    let mut grouped = Collected::default();
    let mut visited = std::collections::HashSet::new();
    collect_fields(
        &op.selection_set,
        &fragments,
        &vars,
        &mut visited,
        &mut grouped,
    )?;

    let mut calls = Vec::new();
    for field in grouped.fields {
        if field.name == "__typename" {
            continue; // a meta field: names a type, does nothing
        }
        calls.push(Call {
            field: field.name.to_string(),
            args: arguments(&field.arguments, &vars)?,
            directives: field
                .directives
                .0
                .iter()
                .filter(|d| d.name != "skip" && d.name != "include")
                .map(|d| Ok((d.name.to_string(), arguments(&d.arguments, &vars)?)))
                .collect::<Result<_, Refusal>>()?,
        });
    }
    Ok(Operation { calls })
}

/// The diagnostics as a GraphQL server reports them: each message with the
/// line and column it points at.
fn brief<'a>(
    errors: impl IntoIterator<
        Item = apollo_compiler::diagnostic::Diagnostic<
            'a,
            apollo_compiler::validation::DiagnosticData,
        >,
    >,
) -> String {
    errors
        .into_iter()
        .map(|d| {
            let e = d.to_json();
            match e.locations.first() {
                Some(at) => format!("{} (line {}, column {})", e.message, at.line, at.column),
                None => e.message,
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// GetOperation (§6.1): the named operation, or the only one.
fn get_operation<'d>(
    doc: &'d ast::Document,
    name: Option<&str>,
) -> Result<&'d ast::OperationDefinition, Refusal> {
    let mut ops = doc.definitions.iter().filter_map(|d| match d {
        ast::Definition::OperationDefinition(o) => Some(&**o),
        _ => None,
    });
    match name {
        Some(n) => ops
            .find(|o| o.name.as_ref().is_some_and(|x| x == n))
            .ok_or_else(|| bad_request(format!("the query has no operation named {n}"))),
        None => {
            let first = ops
                .next()
                .ok_or_else(|| bad_request("the query has no operation"))?;
            if ops.next().is_some() {
                return Err(bad_request(
                    "the query has several operations; name one in operationName",
                ));
            }
            Ok(first)
        }
    }
}

/// The operation's variables: the ones it declares, and the values it runs
/// with.
#[derive(Default)]
struct Vars {
    declared: std::collections::HashSet<String>,
    values: Map<String, Json>,
}

/// The variable values the operation runs with (§6.1.2): the provided value,
/// else the declared default, else absent. Values the client sent for
/// variables the operation doesn't declare are ignored.
fn variable_values(
    op: &ast::OperationDefinition,
    provided: &Map<String, Json>,
) -> Result<Vars, Refusal> {
    let mut vars = Vars::default();
    for def in &op.variables {
        let name = def.name.as_str();
        vars.declared.insert(name.to_string());
        if let Some(v) = provided.get(name) {
            vars.values.insert(name.to_string(), v.clone());
        } else if let Some(default) = &def.default_value {
            if let Some(v) = value(default, &Vars::default())? {
                vars.values.insert(name.to_string(), v);
            }
        }
    }
    Ok(vars)
}

/// CollectFields (§6.3.2) on the root selection set: fields grouped by
/// response key in order, fragment spreads and inline fragments expanded,
/// `@skip`/`@include` applied. A fragment's type condition is not checked
/// (that needs the schema): every fragment counts, so a call is never missed.
/// Fields sharing a response key run once, so they must be the same call.
/// The root fields in execution order, one per response key.
#[derive(Default)]
struct Collected<'d> {
    fields: Vec<&'d ast::Field>,
    by_key: std::collections::HashMap<&'d str, usize>,
}

fn collect_fields<'d>(
    selections: &'d [ast::Selection],
    fragments: &std::collections::HashMap<&str, &'d ast::FragmentDefinition>,
    vars: &Vars,
    visited: &mut std::collections::HashSet<&'d str>,
    out: &mut Collected<'d>,
) -> Result<(), Refusal> {
    for selection in selections {
        let directives = match selection {
            ast::Selection::Field(f) => &f.directives,
            ast::Selection::FragmentSpread(f) => &f.directives,
            ast::Selection::InlineFragment(f) => &f.directives,
        };
        if !included(directives, vars)? {
            continue;
        }
        match selection {
            ast::Selection::Field(field) => {
                let key = field.alias.as_ref().unwrap_or(&field.name).as_str();
                match out.by_key.get(key) {
                    Some(&i) => {
                        let first = out.fields[i];
                        if first.name != field.name || first.arguments != field.arguments {
                            return Err(invalid(format!(
                                "the fields answering as {key} are different calls and can't be merged"
                            )));
                        }
                    }
                    None => {
                        out.by_key.insert(key, out.fields.len());
                        out.fields.push(field);
                    }
                }
            }
            ast::Selection::FragmentSpread(spread) => {
                let name = spread.fragment_name.as_str();
                if !visited.insert(name) {
                    continue;
                }
                let fragment = fragments.get(name).ok_or_else(|| {
                    invalid(format!("the query uses an undefined fragment {name}"))
                })?;
                collect_fields(&fragment.selection_set, fragments, vars, visited, out)?;
            }
            ast::Selection::InlineFragment(inline) => {
                collect_fields(&inline.selection_set, fragments, vars, visited, out)?;
            }
        }
    }
    Ok(())
}

/// `@skip(if:)` / `@include(if:)` (§3.13), with the `if` argument a Boolean
/// literal or a Boolean variable.
fn included(directives: &ast::DirectiveList, vars: &Vars) -> Result<bool, Refusal> {
    for d in &directives.0 {
        let want = match d.name.as_str() {
            "skip" => false,
            "include" => true,
            _ => continue,
        };
        let cond = d
            .arguments
            .iter()
            .find(|a| a.name == "if")
            .map(|a| value(&a.value, vars))
            .transpose()?
            .flatten();
        match cond {
            Some(Json::Bool(b)) if b != want => return Ok(false),
            Some(Json::Bool(_)) => {}
            _ => return Err(invalid(format!("@{} needs a Boolean if argument", d.name))),
        }
    }
    Ok(true)
}

fn arguments(
    args: &[apollo_compiler::Node<ast::Argument>],
    vars: &Vars,
) -> Result<Map<String, Json>, Refusal> {
    let mut out = Map::new();
    for a in args {
        if let Some(v) = value(&a.value, vars)? {
            out.insert(a.name.to_string(), v);
        }
    }
    Ok(out)
}

/// A literal as JSON, with variables substituted. `None` = absent (a variable
/// with no value): an argument or object field it fills is left out, a list
/// item becomes null. A number past what JSON carries exactly is refused.
fn value(v: &ast::Value, vars: &Vars) -> Result<Option<Json>, Refusal> {
    Ok(Some(match v {
        ast::Value::Null => Json::Null,
        ast::Value::Enum(name) => Json::String(name.to_string()),
        // All Variable Uses Defined (§5.8.3).
        ast::Value::Variable(name) if !vars.declared.contains(name.as_str()) => {
            return Err(invalid(format!(
                "the query uses ${name}, which its operation doesn't declare"
            )))
        }
        ast::Value::Variable(name) => return Ok(vars.values.get(name.as_str()).cloned()),
        ast::Value::String(s) => Json::String(s.clone()),
        ast::Value::Boolean(b) => Json::Bool(*b),
        ast::Value::Int(i) => {
            let n: i64 = i
                .as_str()
                .parse()
                .map_err(|_| bad_request(format!("the integer {} is out of range", i.as_str())))?;
            if n.unsigned_abs() > (1u64 << 53) {
                return Err(bad_request(format!("the integer {n} is out of range")));
            }
            Json::from(n)
        }
        ast::Value::Float(f) => f
            .try_to_f64()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Json::Number)
            .ok_or_else(|| bad_request(format!("the number {} is out of range", f.as_str())))?,
        ast::Value::List(items) => Json::Array(
            items
                .iter()
                .map(|x| Ok(value(x, vars)?.unwrap_or(Json::Null)))
                .collect::<Result<_, Refusal>>()?,
        ),
        ast::Value::Object(fields) => {
            let mut obj = Map::new();
            for (k, x) in fields {
                if let Some(x) = value(x, vars)? {
                    obj.insert(k.to_string(), x);
                }
            }
            Json::Object(obj)
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn calls(body: Json) -> String {
        read(&body).unwrap().calls_var(8 * 1024)
    }

    fn refused(body: Json) -> u16 {
        read(&body).unwrap_err().status
    }

    #[test]
    fn a_plain_mutation_reads_its_call() {
        let op = read(&json!({"query": "mutation { serviceDelete(id: \"abc\") }"})).unwrap();
        assert_eq!(
            op.calls_var(8192),
            r#"[{"args":{"id":"abc"},"field":"serviceDelete"}]"#
        );
        assert_eq!(op.request_var(), op.calls_var(8192));
        assert_eq!(op.fields().join("\n"), "serviceDelete");
    }

    #[test]
    fn variables_and_defaults_follow_the_spec() {
        let q = "mutation Del($id: String!, $env: String = \"prod\") { serviceDelete(id: $id, environmentId: $env) }";
        assert_eq!(
            calls(json!({"query": q, "variables": {"id": "x1"}})),
            r#"[{"args":{"environmentId":"prod","id":"x1"},"field":"serviceDelete"}]"#
        );
        // Not provided and no default: the argument is absent, not null.
        let q2 = "mutation($id: String) { serviceDelete(id: $id) }";
        assert_eq!(
            calls(json!({"query": q2})),
            r#"[{"field":"serviceDelete"}]"#
        );
        // Provided as null: null.
        assert_eq!(
            calls(json!({"query": q2, "variables": {"id": null}})),
            r#"[{"args":{"id":null},"field":"serviceDelete"}]"#
        );
        // Values for undeclared variables are ignored.
        assert_eq!(
            calls(json!({"query": q2, "variables": {"other": 1}})),
            r#"[{"field":"serviceDelete"}]"#
        );
    }

    #[test]
    fn aliases_and_fragments_resolve_to_the_real_fields() {
        let q = "mutation { a: serviceInstanceRedeploy(serviceId: \"s\") ...F ... on Mutation { volumeDelete(volumeId: \"v\") } } fragment F on Mutation { b: serviceDelete(id: \"x\") }";
        assert_eq!(
            read(&json!({"query": q})).unwrap().fields().join("\n"),
            "serviceInstanceRedeploy\nserviceDelete\nvolumeDelete"
        );
    }

    #[test]
    fn skip_and_include_decide_which_calls_run() {
        let q = "mutation($s: Boolean!) { serviceDelete(id: \"x\") @skip(if: $s) volumeDelete(volumeId: \"v\") @include(if: true) }";
        assert_eq!(
            read(&json!({"query": q, "variables": {"s": true}}))
                .unwrap()
                .fields()
                .join("\n"),
            "volumeDelete"
        );
        assert_eq!(
            read(&json!({"query": q, "variables": {"s": false}}))
                .unwrap()
                .fields()
                .join("\n"),
            "serviceDelete\nvolumeDelete"
        );
        let frag = "mutation { ...F @include(if: false) } fragment F on Mutation { serviceDelete(id: \"x\") }";
        assert_eq!(
            read(&json!({"query": frag})).unwrap().fields().join("\n"),
            ""
        );
    }

    #[test]
    fn two_requests_that_differ_bind_differently() {
        // An object key the agent controls can't pass itself off as another
        // argument or another call: keys and strings stay JSON strings.
        let q = "mutation($v: JSON) { variableCollectionUpsert(input: {variables: $v}) }";
        let a = read(&json!({"query": q, "variables": {"v": {"A": "1", "B": "2"}}})).unwrap();
        let b = read(&json!({"query": q, "variables": {"v": {"A: \"1\", B": "2"}}})).unwrap();
        let c =
            read(&json!({"query": q, "variables": {"v": {"A\nserviceDelete(id: \"x\")": "1"}}}))
                .unwrap();
        assert_ne!(a.request_var(), b.request_var());
        assert!(!c.calls_var(8192).contains('\n'));
        // Argument order carries no meaning; call order does.
        let x = read(&json!({"query": "mutation { a(p: 1, q: 2) b }"})).unwrap();
        let y = read(&json!({"query": "mutation { a(q: 2, p: 1) b }"})).unwrap();
        let z = read(&json!({"query": "mutation { b a(p: 1, q: 2) }"})).unwrap();
        assert_eq!(x.request_var(), y.request_var());
        assert_ne!(x.request_var(), z.request_var());
    }

    #[test]
    fn long_values_are_shortened_for_show_never_for_binding() {
        let pad = "a".repeat(9000);
        let q = "mutation($v: String!) { serviceDelete(id: \"prod-svc\") variableUpsert(input: {name: \"PAD\", value: $v}) }";
        let op = read(&json!({"query": q, "variables": {"v": pad}})).unwrap();
        let shown = op.calls_var(8192);
        assert!(shown.contains(r#""id":"prod-svc""#), "{shown}");
        assert!(shown.contains("(9000 chars)"));
        assert!(op.request_var().contains(&"a".repeat(9000)));
        // Bulky values go before the short ones that name the target.
        let bulk: serde_json::Map<String, Json> =
            (0..400).map(|i| (format!("K{i}"), json!("v".repeat(20)))).collect();
        let q = "mutation($v: JSON) { variableCollectionUpsert(input: {variables: $v}) serviceDelete(id: \"prod-db\") }";
        let shown = read(&json!({"query": q, "variables": {"v": bulk}}))
            .unwrap()
            .calls_var(8192);
        assert!(shown.contains(r#""id":"prod-db""#), "{shown}");
        assert!(shown.contains("bytes)"), "{shown}");
        // Different targets never fold into one shown target.
        let many: String = (0..300)
            .map(|i| format!("d{i}: serviceDelete(id: \"svc-{i}\") "))
            .collect();
        let shown = read(&json!({"query": format!("mutation {{ {many} }}")}))
            .unwrap()
            .calls_var(8192);
        assert!(!shown.contains("svc-0") || shown.contains("svc-299"), "{shown}");
        assert!(shown.contains(r#""count":300"#) || shown.contains("svc-299"), "{shown}");
        // A large pile of distinct field names stays quick.
        let wide: String = (0..20_000).map(|i| format!("f{i} ")).collect();
        let started = std::time::Instant::now();
        let op = read(&json!({"query": format!("mutation {{ {wide} }}")})).unwrap();
        assert!(op.calls_var(8192).len() <= 8192);
        assert_eq!(op.fields().len(), 20_000);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
        // Identical padding calls fold into a count; the delete keeps its target.
        let pad: String = (0..400)
            .map(|i| format!("p{i}: serviceInstanceRedeploy(serviceId: \"same\") "))
            .collect();
        let q = format!("mutation {{ {pad} serviceDelete(id: \"prod-db\") }}");
        let shown = read(&json!({"query": q})).unwrap().calls_var(8192);
        assert!(shown.contains(r#""count":400"#), "{shown}");
        assert!(shown.contains(r#""id":"prod-db""#), "{shown}");
        // A huge batch of distinct fields keeps every name it can, then counts the rest.
        let many: String = (0..2000)
            .map(|i| format!("f{i}(id: \"{i}\") "))
            .collect();
        let shown = read(&json!({"query": format!("mutation {{ {many} }}")}))
            .unwrap()
            .calls_var(8192);
        assert!(shown.len() <= 8192);
        assert!(shown.contains(r#""more":"#), "{shown}");
    }

    #[test]
    fn escapes_are_decoded_before_reading() {
        let body: Json =
            serde_json::from_str(r#"{"query":"mutation { service\u0044elete(id: \"x\") }"}"#).unwrap();
        assert_eq!(read(&body).unwrap().fields().join("\n"), "serviceDelete");
        let s = calls(json!({"query": "mutation { serviceDelete(id: \"\\u0078\\u{79}\") }"}));
        assert_eq!(s, r#"[{"args":{"id":"xy"},"field":"serviceDelete"}]"#);
    }

    #[test]
    fn enums_lists_objects_and_typename() {
        let q = "# serviceDelete\nmutation {\n __typename,\n variableUpsert(input: {flags: [1, 2.5, true, null], kind: SHARED}) # serviceDelete\n}";
        assert_eq!(
            calls(json!({"query": q})),
            r#"[{"args":{"input":{"flags":[1,2.5,true,null],"kind":"SHARED"}},"field":"variableUpsert"}]"#
        );
    }

    #[test]
    fn operation_name_selects_one_of_several() {
        let q = "query A { me { name } } mutation B { serviceDelete(id: \"x\") }";
        assert_eq!(
            read(&json!({"query": q, "operationName": "B"}))
                .unwrap()
                .fields()
                .join("\n"),
            "serviceDelete"
        );
        assert_eq!(
            read(&json!({"query": q, "operationName": "A"}))
                .unwrap()
                .fields()
                .join("\n"),
            "me"
        );
        assert_eq!(refused(json!({"query": q})), 400);
        assert_eq!(refused(json!({"query": q, "operationName": "C"})), 400);
    }

    #[test]
    fn requests_a_server_would_refuse_are_refused_with_its_status() {
        for body in [
            json!([{"query": "mutation { serviceDelete(id: \"x\") }"}]), // batch
            json!({"query": "mutation { serviceDelete(id: \"x\") "}),    // unclosed
            json!({"query": 5}),
            json!({"query": "mutation { a }", "variables": [1]}),
            json!({"query": "{ }"}),
            json!({"query": "mutation { a(n: 99999999999999999999) }"}),
        ] {
            assert_eq!(refused(body.clone()), 400, "{body}");
        }
        for body in [
            json!({"query": "mutation { ...Missing }"}),
            json!({"query": "mutation { ...F } fragment F on Mutation { ...F }"}), // cycle
            json!({"query": "mutation { serviceDelete(id: $nope) }"}),             // undeclared
            json!({"query": "mutation { serviceDelete(id: \"x\", id: \"y\") }"}),  // repeated arg
            json!({"query": "type Q { a: Int }"}),
            json!({"query": "mutation B { a } mutation B { serviceDelete(id: \"x\") }", "operationName": "B"}),
            json!({"query": "mutation { x: a(id: 1) x: serviceDelete(id: 1) }"}),
        ] {
            assert_eq!(refused(body.clone()), 422, "{body}");
        }
    }

    #[test]
    fn unknown_request_keys_are_ignored() {
        let body = json!({"query": "mutation { serviceDelete(id: \"x\") }", "extensions": {"persistedQuery": {"version": 1}}, "documentId": "abc"});
        assert_eq!(read(&body).unwrap().fields().join("\n"), "serviceDelete");
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let deep = format!(
            "mutation {{ a(x: {}1{}) }}",
            "[".repeat(500),
            "]".repeat(500)
        );
        assert!(read(&json!({"query": deep})).is_err());
    }
}
