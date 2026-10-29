//! What an approval covers (request-model design §4), and the permit
//! identity that keys it.
//!
//! An approval covers the method, host and path, plus:
//!   - the whole request, when no `[requests]` shape matched or the matched
//!     one lists no `scope` (or lists the token `request`): the query string
//!     as sent, the headers whose meaning HTTP itself defines for a request
//!     ([`COVERED_HEADERS`]) and every header carrying a phantom, as `name:
//!     value` lines, and the body covered by its content;
//!   - the values a shape's `scope` lists;
//!   - always, the values read by the condition of every rule that matched at
//!     the winning level and every value the shape's `consent` reads.
//!
//! A body covered by content leaves out what its media type's standard makes
//! per message, so a re-run that differs only there redeems: a multipart
//! body's boundary and its parts' `Content-ID` (RFC 2046, RFC 2045 §7), an
//! embedded request's headers outside the named list (a Google batch part),
//! an email's `Date` and `Message-ID` (RFC 5322 §3.6). Structure is taken only
//! when it is unambiguous (one Content-Type source with one valid boundary,
//! one structural line ending taken from the first delimiter, every
//! dash-boundary at a structural line start and followed by the line ending
//! or `--`, a close delimiter last, an embedded request `httparse` accepts
//! whole); else the body or part is covered as its bytes. A JSON body for
//! which a compiled-in definition declares `encoded` values is covered as its
//! JCS text with each such value covered by its content.
//!
//! The permit identity is an HMAC-SHA-256 over the covered components, each
//! tagged by its name, under HKDF-SHA-256 of the vault's current-generation
//! content key ([`IDENTITY_INFO`]): the relay, which carries the op, never
//! sees it, and nobody without the key can confirm a guess of a value.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

use crate::core::request::{Field, Read, ReadPath, Request, Step, Unreadable};
use crate::service::Encoded;

/// The request headers covered with the whole request: those whose meaning
/// HTTP itself defines for a request (RFC 9110), the WebDAV headers that
/// define what a method does (RFC 4918), and `prefer` (RFC 7240; PostgREST
/// turns an insert into an upsert under `resolution=merge-duplicates`).
pub const COVERED_HEADERS: &[&str] = &[
    "content-type",
    "content-language",
    "content-location",
    "content-range",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
    "if-range",
    "destination",
    "overwrite",
    "depth",
    "prefer",
];

/// HKDF info of the permit identity key.
pub const IDENTITY_INFO: &[u8] = b"sprott permit identity v1";

/// Multipart nesting is read this deep, and this many parts in all; past
/// either, the rest is covered as bytes.
const MAX_NESTING: usize = 8;
const MAX_PARTS: usize = 1000;

/// What an approval of one request covers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Covered {
    /// The covered components, `(name, bytes)`, sorted by name: what the
    /// permit identity is an HMAC of.
    pub components: Vec<(String, Vec<u8>)>,
    /// Finer components that only name what a re-run changed (a JSON
    /// body's top-level members, when the body is covered as its bytes).
    pub detail: Vec<(String, Vec<u8>)>,
    /// What the approval card shows: `(request path, text)`.
    pub shown: Vec<(String, String)>,
}

impl Covered {
    /// Both coverages: on a tie between path readings, an approval covers
    /// what either reading covers (DESIGN §4).
    pub fn union(mut self, other: Covered) -> Covered {
        self.components.extend(other.components);
        self.components.sort();
        self.components.dedup();
        self.detail.extend(other.detail);
        self.detail.sort();
        self.detail.dedup();
        for (label, text) in other.shown {
            if !self.shown.iter().any(|(l, _)| *l == label) {
                self.shown.push((label, text));
            }
        }
        self
    }
}

/// What [`cover`] covers of a request.
pub struct Scope<'s> {
    /// The path the request is decided on and forwarded with.
    pub path: &'s str,
    /// The whole request.
    pub whole: bool,
    /// The values a shape's `scope` lists.
    pub listed: &'s [ReadPath],
    /// The values the winning rules' conditions and the consent read.
    pub reads: &'s [Read],
    /// A compiled-in definition's `encoded` values, by path text (empty for
    /// a vault definition, whose `encoded` is for display only).
    pub encoded: &'s BTreeMap<String, Encoded>,
}

/// The name a listed or read value's component has: the path below
/// `request`, members joined with `.` (`body.amount`, `headers.x-account`),
/// in the namespace `read:` so it never shares a name with a whole-request
/// component.
fn read_name(path: &ReadPath) -> String {
    let mut name = format!("read:{}", path.field.name());
    for step in &path.steps {
        match step {
            Step::Key(k) => {
                name.push('.');
                name.push_str(k);
            }
            Step::Index(i) => name.push_str(&format!("[{i}]")),
        }
    }
    name
}

/// JCS text (RFC 8785).
fn jcs(v: &Json) -> Vec<u8> {
    sudp::canonical::canonicalize(v)
}

/// A value as the card shows it: a string is itself, anything else its JCS
/// text.
fn shown_text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        other => String::from_utf8(jcs(other)).unwrap_or_default(),
    }
}

/// Bytes as the card shows them: the text when it is UTF-8, else their size
/// and SHA-256.
fn shown_bytes(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => crate::approval::card::summary(b),
    }
}

/// Cover `request` as `scope` says.
pub fn cover(request: &Request<'_>, scope: &Scope<'_>) -> Result<Covered, Unreadable> {
    let input = request.input();
    let mut c = Covered::default();
    c.components
        .push(("method".into(), input.method.as_bytes().to_vec()));
    c.components.push(("host".into(), input.host.as_bytes().to_vec()));
    c.components.push(("path".into(), scope.path.as_bytes().to_vec()));
    if scope.whole {
        whole(request, scope, &mut c);
    }
    for path in scope.listed {
        value(request, path, scope, &mut c)?;
    }
    for read in scope.reads {
        if read.presence {
            let present = request.value(&read.path)?.is_some();
            c.components.push((
                format!("{}?", read_name(&read.path)),
                vec![present as u8],
            ));
        } else {
            value(request, &read.path, scope, &mut c)?;
        }
    }
    c.components.sort();
    c.components.dedup();
    c.detail.sort();
    c.detail.dedup();
    let mut seen = BTreeSet::new();
    c.shown.retain(|(label, _)| seen.insert(label.clone()));
    Ok(c)
}

/// One listed or read value: absent is covered as absent, distinct from
/// `null`; a value is covered as its JCS text, or by its content when a
/// compiled-in definition declares it `encoded`.
fn value(
    request: &Request<'_>,
    path: &ReadPath,
    scope: &Scope<'_>,
    c: &mut Covered,
) -> Result<(), Unreadable> {
    let name = read_name(path);
    let Some(v) = request.value(path)? else {
        c.components.push((name, vec![0]));
        return Ok(());
    };
    c.shown.push((path.to_string(), shown_text(&v)));
    if let (Some(enc), Json::String(s)) = (scope.encoded.get(&path.to_string()), &v) {
        if let Some(decoded) = decode_encoded(s, enc) {
            let prefix = name.trim_start_matches("read:").to_string();
            let media = enc.content_media_type.as_deref().map(str::as_bytes);
            Walker::default().entity(&prefix, media, &decoded, 0, &mut c.components);
            return Ok(());
        }
    }
    let mut bytes = vec![1];
    bytes.extend(jcs(&v));
    c.components.push((name, bytes));
    Ok(())
}

/// A declared `encoded` string's bytes. Base64 is read the way Google reads
/// a protobuf `bytes` field in JSON: standard or URL-safe alphabet, padding
/// optional (strings that decode to the same bytes are the same message to
/// the server). `None` for one that doesn't decode, or another encoding.
fn decode_encoded(s: &str, enc: &Encoded) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
    use base64::engine::DecodePaddingMode;
    use base64::Engine;
    match enc.content_encoding.as_deref() {
        Some("base64" | "base64url") => {
            let normalized: String = s
                .trim_end_matches('=')
                .chars()
                .map(|c| match c {
                    '-' => '+',
                    '_' => '/',
                    c => c,
                })
                .collect();
            let engine = GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                GeneralPurposeConfig::new()
                    .with_encode_padding(false)
                    .with_decode_padding_mode(DecodePaddingMode::RequireNone),
            );
            engine.decode(normalized).ok()
        }
        None => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

/// The whole request: the query string as sent, the covered headers, the
/// body by its content.
fn whole(request: &Request<'_>, scope: &Scope<'_>, c: &mut Covered) {
    let input = request.input();
    if let Some(q) = input.query {
        c.components.push(("query".into(), q.as_bytes().to_vec()));
        c.shown.push(("request.query".into(), q.to_string()));
    }

    // The body.
    let body = input.body.unwrap_or(&[]);
    // Its Content-Type sources: each `content-type` header, and a `$ct`
    // query parameter (Google's API front end reads one).
    let types: Vec<&[u8]> = input
        .headers
        .iter()
        .filter(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_slice())
        .collect();
    let ct_query = input
        .query
        .is_some_and(|q| url::form_urlencoded::parse(q.as_bytes()).any(|(k, _)| k == "$ct"));
    let json = crate::service::strict_json::parse(body).ok();
    let mut structured_type = None;
    let mut body_components = Vec::new();
    match (&json, scope.encoded.is_empty()) {
        (Some(json), false) => encoded_json(json, scope.encoded, &mut body_components),
        _ => {
            structured_type = match (types.as_slice(), ct_query) {
                ([one], false) => {
                    Walker::default().entity("body", Some(*one), body, 0, &mut body_components)
                }
                _ => {
                    body_components.push(("body".into(), body.to_vec()));
                    None
                }
            };
        }
    }
    c.components.extend(body_components);
    if let (Some(Json::Object(members)), None) = (&json, &structured_type) {
        for (k, v) in members {
            c.detail.push((format!("body.{k}"), jcs(v)));
        }
    }
    c.shown.push(("request.body".into(), shown_bytes(body)));

    // The headers: those HTTP defines for a request and every one carrying a
    // phantom, as forwarded, `name: value` lines by name, repeats in order.
    let mut headers: BTreeMap<&str, Vec<&[u8]>> = BTreeMap::new();
    for (name, value) in input.headers {
        let covered = COVERED_HEADERS.contains(&name.as_str())
            || name == "authorization"
            || std::str::from_utf8(value).is_ok_and(crate::proxy::resolver::contains_phantom);
        if covered {
            headers.entry(name.as_str()).or_default().push(value);
        }
    }
    for (name, values) in headers {
        let shown: Vec<String> = match (name, &structured_type) {
            ("content-type", Some(t)) => vec![t.clone()],
            _ => values.iter().map(|v| String::from_utf8_lossy(v).into_owned()).collect(),
        };
        let lines: Vec<String> = shown.iter().map(|v| format!("{name}: {v}")).collect();
        c.components
            .push((format!("headers.{name}"), lines.join("\n").into_bytes()));
        let label = ReadPath::new(Field::Headers, vec![Step::Key(name.to_string())]).to_string();
        c.shown.push((label, shown.join("\n")));
    }
}

/// A JSON body with compiled-in `encoded` values: its JCS text with each
/// declared string value taken out (`null` in its place) and covered by its
/// content under its own name (`body.raw.Subject`).
fn encoded_json(
    json: &Json,
    encoded: &BTreeMap<String, Encoded>,
    out: &mut Vec<(String, Vec<u8>)>,
) {
    let mut doc = json.clone();
    let mut taken = Vec::new();
    for (path_text, enc) in encoded {
        let Ok(path) = ReadPath::parse(path_text) else {
            continue;
        };
        if path.field != Field::Body {
            continue;
        }
        let Some(slot) = member_mut(&mut doc, &path.steps) else {
            continue;
        };
        let Json::String(s) = &*slot else {
            continue;
        };
        let Some(decoded) = decode_encoded(s, enc) else {
            continue;
        };
        *slot = Json::Null;
        let prefix = read_name(&path).trim_start_matches("read:").to_string();
        let media = enc.content_media_type.as_deref().map(str::as_bytes);
        Walker::default().entity(&prefix, media, &decoded, 0, out);
        taken.push(path_text.clone());
    }
    out.push(("body".into(), jcs(&doc)));
    out.push(("body.encoded".into(), taken.join("\n").into_bytes()));
}

fn member_mut<'j>(mut cur: &'j mut Json, steps: &[Step]) -> Option<&'j mut Json> {
    for step in steps {
        cur = match (cur, step) {
            (Json::Object(m), Step::Key(k)) => m.get_mut(k)?,
            (Json::Array(a), Step::Index(i)) => a.get_mut(*i as usize)?,
            _ => return None,
        };
    }
    Some(cur)
}

// ── Covered by content ──────────────────────────────────────────────────────

/// A Content-Type field read for coverage: unfolded (RFC 5322 §2.2.3: each
/// line break before whitespace dropped), each run of whitespace one space,
/// parsed by `mime`.
struct ContentType {
    /// `type/subtype`, lowercase.
    essence: String,
    boundaries: Vec<String>,
    /// The media type and its parameters without `boundary`: how a field
    /// that declares a body covered by its structure is covered.
    normalized: String,
}

fn content_type(raw: &[u8]) -> Option<ContentType> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut unfolded = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let line_break = c == '\n' || (c == '\r' && chars.peek() == Some(&'\n'));
        if line_break {
            if c == '\r' {
                chars.next();
            }
            if matches!(chars.peek(), Some(' ' | '\t')) {
                continue;
            }
        }
        unfolded.push(c);
    }
    let collapsed = unfolded.split_whitespace().collect::<Vec<_>>().join(" ");
    let m: mime::Mime = collapsed.parse().ok()?;
    let essence = m.essence_str().to_ascii_lowercase();
    let mut normalized = essence.clone();
    let mut boundaries = Vec::new();
    for (name, value) in m.params() {
        if name.as_str().eq_ignore_ascii_case("boundary") {
            boundaries.push(value.as_str().to_string());
        } else {
            normalized.push_str(&format!(
                "; {}={}",
                name.as_str().to_ascii_lowercase(),
                value.as_str()
            ));
        }
    }
    Some(ContentType {
        essence,
        boundaries,
        normalized,
    })
}

/// RFC 2046 `boundary := 0*69<bchars> bcharsnospace`.
fn valid_boundary(b: &str) -> bool {
    let bchar = |c: char| c.is_ascii_alphanumeric() || "'()+_,-./:=? ".contains(c);
    (1..=70).contains(&b.len()) && b.chars().all(bchar) && !b.ends_with(' ')
}

/// One header field of a section: its name lowercase, as written, and the
/// field's bytes as sent (continuation lines and line ending included).
struct FieldLine<'b> {
    lower: String,
    name: String,
    raw: &'b [u8],
}

/// The header fields of `bytes` up to its blank line (`mailparse`), and where
/// the body starts; `None` when a field doesn't parse.
fn header_fields(bytes: &[u8]) -> Option<(Vec<FieldLine<'_>>, usize, bool)> {
    let mut fields = Vec::new();
    let mut ix = 0;
    loop {
        if ix >= bytes.len() {
            return Some((fields, ix, false));
        }
        if bytes[ix] == b'\n' {
            return Some((fields, ix + 1, true));
        }
        if bytes[ix..].starts_with(b"\r\n") {
            return Some((fields, ix + 2, true));
        }
        let (h, n) = mailparse::parse_header(&bytes[ix..]).ok()?;
        if n == 0 {
            return None;
        }
        let name = h.get_key_ref().into_owned();
        fields.push(FieldLine {
            lower: name.to_ascii_lowercase(),
            name,
            raw: &bytes[ix..ix + n],
        });
        ix += n;
    }
}

/// The one Content-Type of a set of fields: its value bytes, `None` when
/// there is none, `Some(None)` when there are several (ambiguous).
fn one_content_type<'b>(fields: &[FieldLine<'b>]) -> Option<Option<&'b [u8]>> {
    let mut found = fields.iter().filter(|f| f.lower == "content-type");
    let first = found.next()?;
    if found.next().is_some() {
        return Some(None);
    }
    let raw = first.raw;
    let colon = raw.iter().position(|&b| b == b':')?;
    Some(Some(&raw[colon + 1..]))
}

/// Walks a body covered by its content, counting parts.
#[derive(Default)]
struct Walker {
    parts: usize,
}

impl Walker {
    /// Cover `body` (declared `content_type`) under `prefix`: by structure
    /// when its media type has one and it is unambiguous, else as its bytes.
    /// The normalized Content-Type when it was covered by structure (the
    /// declaring field is covered as that).
    fn entity(
        &mut self,
        prefix: &str,
        content_type_raw: Option<&[u8]>,
        body: &[u8],
        depth: usize,
        out: &mut Vec<(String, Vec<u8>)>,
    ) -> Option<String> {
        let mut parts = Vec::new();
        let structured = content_type_raw
            .and_then(content_type)
            .filter(|_| depth < MAX_NESTING)
            .and_then(|ct| {
                let ok = match ct.essence.as_str() {
                    t if t.starts_with("multipart/") => match ct.boundaries.as_slice() {
                        [b] if valid_boundary(b) => {
                            self.multipart(prefix, b.as_bytes(), body, depth, &mut parts)
                        }
                        _ => false,
                    },
                    "message/rfc822" => self.message(prefix, body, depth, &mut parts),
                    "application/http" => self.embedded_request(prefix, body, depth, &mut parts),
                    _ => false,
                };
                ok.then_some(ct.normalized)
            });
        match structured {
            Some(_) => out.extend(parts),
            None => out.push((prefix.to_string(), body.to_vec())),
        }
        structured
    }

    /// A multipart body (RFC 2046), when unambiguous: the preamble, each
    /// part's header fields as sent but `Content-ID`, each part's content by
    /// its own Content-Type, the epilogue.
    fn multipart(
        &mut self,
        prefix: &str,
        boundary: &[u8],
        body: &[u8],
        depth: usize,
        out: &mut Vec<(String, Vec<u8>)>,
    ) -> bool {
        let dash = [b"--".as_slice(), boundary].concat();
        let finder = memchr::memmem::Finder::new(&dash);
        let mut at = Vec::new();
        let mut from = 0;
        while let Some(i) = finder.find(&body[from..]) {
            at.push(from + i);
            from += i + 1;
        }
        let Some(&first) = at.first() else {
            return false;
        };
        // The structural line ending, from the first delimiter line.
        let after = &body[first + dash.len()..];
        let eol: &[u8] = if after.starts_with(b"\r\n") {
            b"\r\n"
        } else if after.starts_with(b"\n") {
            b"\n"
        } else {
            return false;
        };
        let line_start = |o: usize| {
            o == 0
                || (body[..o].ends_with(eol)
                    && (eol == b"\r\n" || !body[..o].ends_with(b"\r\n")))
        };
        for &o in &at {
            let rest = &body[o + dash.len()..];
            let ends = (rest.starts_with(eol) && !(eol == b"\n" && rest.starts_with(b"\r")))
                || rest.starts_with(b"--");
            if !line_start(o) || !ends {
                return false;
            }
        }
        let Some(close) = at
            .iter()
            .position(|&o| body[o + dash.len()..].starts_with(b"--"))
        else {
            return false;
        };
        if close != at.len() - 1 || close == 0 {
            return false;
        }
        if self.parts + close > MAX_PARTS {
            return false;
        }
        self.parts += close;
        let preamble = if first == 0 {
            &body[..0]
        } else {
            &body[..first - eol.len()]
        };
        let mut covered = vec![(format!("{prefix}.preamble"), preamble.to_vec())];
        for i in 0..close {
            let start = at[i] + dash.len() + eol.len();
            let Some(end) = at[i + 1].checked_sub(eol.len()).filter(|&e| e >= start) else {
                return false;
            };
            let part = &body[start..end];
            // The header section, up to the blank line, in the structural
            // line ending.
            let (section, content) = if part.starts_with(eol) {
                (&part[..0], &part[eol.len()..])
            } else {
                let blank = [eol, eol].concat();
                match memchr::memmem::find(part, &blank) {
                    Some(p) => (&part[..p + eol.len()], &part[p + blank.len()..]),
                    None => return false,
                }
            };
            let mixed = if eol == b"\r\n" {
                section
                    .iter()
                    .enumerate()
                    .any(|(j, &b)| (b == b'\n' && (j == 0 || section[j - 1] != b'\r')) || (b == b'\r' && section.get(j + 1) != Some(&b'\n')))
            } else {
                section.contains(&b'\r')
            };
            if mixed {
                return false;
            }
            let Some((fields, used, _)) = header_fields(section) else {
                return false;
            };
            if used != section.len() {
                return false;
            }
            let at_prefix = format!("{prefix}.parts[{i}]");
            let declared = one_content_type(&fields).flatten();
            let structured =
                self.entity(&format!("{at_prefix}.content"), declared, content, depth + 1, &mut covered);
            covered.push((format!("{at_prefix}.headers"), field_bytes(&fields, &["content-id"], structured.as_deref())));
        }
        let close_end = at[close] + dash.len() + 2;
        covered.push((format!("{prefix}.epilogue"), body[close_end..].to_vec()));
        out.extend(covered);
        true
    }

    /// An email (RFC 5322): every header field as sent but `Date` and
    /// `Message-ID`, in order, and the body by its own Content-Type.
    fn message(
        &mut self,
        prefix: &str,
        bytes: &[u8],
        depth: usize,
        out: &mut Vec<(String, Vec<u8>)>,
    ) -> bool {
        let Some((fields, body_start, _)) = header_fields(bytes) else {
            return false;
        };
        let declared = one_content_type(&fields).flatten();
        let mut covered = Vec::new();
        let structured = self.entity(
            &format!("{prefix}.body"),
            declared,
            &bytes[body_start..],
            depth + 1,
            &mut covered,
        );
        let mut names: BTreeMap<String, usize> = BTreeMap::new();
        let mut order = Vec::new();
        for f in fields
            .iter()
            .filter(|f| f.lower != "date" && f.lower != "message-id")
        {
            let n = names.entry(f.lower.clone()).or_default();
            *n += 1;
            let name = if *n == 1 {
                format!("{prefix}.{}", f.name)
            } else {
                format!("{prefix}.{}[{}]", f.name, *n - 1)
            };
            let raw = match (&structured, f.lower.as_str()) {
                (Some(t), "content-type") => format!("{}: {}", f.name, t).into_bytes(),
                _ => f.raw.to_vec(),
            };
            covered.push((name, raw));
            order.push(f.lower.clone());
        }
        covered.push((format!("{prefix}.fields"), order.join("\n").into_bytes()));
        out.extend(covered);
        true
    }

    /// An embedded request (`application/http`, a Google batch part) that
    /// `httparse` accepts whole: its request line, the named headers, its
    /// body by its own Content-Type.
    fn embedded_request(
        &mut self,
        prefix: &str,
        bytes: &[u8],
        depth: usize,
        out: &mut Vec<(String, Vec<u8>)>,
    ) -> bool {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let Ok(httparse::Status::Complete(n)) = req.parse(bytes) else {
            return false;
        };
        let (Some(method), Some(target), Some(version)) = (req.method, req.path, req.version)
        else {
            return false;
        };
        let mut named: BTreeMap<String, Vec<&[u8]>> = BTreeMap::new();
        let mut types = Vec::new();
        for h in req.headers.iter() {
            let lower = h.name.to_ascii_lowercase();
            if lower == "content-type" {
                types.push(h.value);
            }
            if COVERED_HEADERS.contains(&lower.as_str()) {
                named.entry(lower).or_default().push(h.value);
            }
        }
        let declared = match types.as_slice() {
            [one] => Some(*one),
            _ => None,
        };
        let mut covered = vec![(
            format!("{prefix}.request"),
            format!("{method} {target} HTTP/1.{version}").into_bytes(),
        )];
        let structured =
            self.entity(&format!("{prefix}.body"), declared, &bytes[n..], depth + 1, &mut covered);
        for (name, values) in named {
            let lines: Vec<Vec<u8>> = match (&structured, name.as_str()) {
                (Some(t), "content-type") => vec![format!("{name}: {t}").into_bytes()],
                _ => values
                    .iter()
                    .map(|v| [format!("{name}: ").as_bytes(), v].concat())
                    .collect(),
            };
            covered.push((format!("{prefix}.headers.{name}"), lines.join(&b'\n')));
        }
        out.extend(covered);
        true
    }
}

/// A part's header fields as sent, in order, without those named in
/// `left_out`; its Content-Type as `structured` when its content was covered
/// by structure.
fn field_bytes(fields: &[FieldLine<'_>], left_out: &[&str], structured: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields.iter().filter(|f| !left_out.contains(&f.lower.as_str())) {
        match (structured, f.lower.as_str()) {
            (Some(t), "content-type") => out.extend(format!("{}: {}\n", f.name, t).into_bytes()),
            _ => out.extend_from_slice(f.raw),
        }
    }
    out
}

// ── Identity ────────────────────────────────────────────────────────────────

/// What an approval of a request is keyed by, kept in the daemon's approval
/// record (never in the op the relay carries).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// The content-key generation it was computed under.
    pub generation: u64,
    /// HMAC-SHA-256 over every covered component, hex; empty when the
    /// approval is keyed by a unit (a rule or floor window).
    pub digest: String,
    /// Each component's own HMAC, finer ones included: what a re-run that
    /// misses this approval is told it changed, by name only.
    pub components: Arc<Vec<(String, [u8; 32])>>,
}

/// The identity key of a vault's current content-key generation.
pub struct IdentityKey {
    key: zeroize::Zeroizing<[u8; 32]>,
    generation: u64,
}

impl IdentityKey {
    /// `HKDF-SHA-256(content_key, info = IDENTITY_INFO)` for `generation`.
    pub fn derive(content_key: &[u8], generation: u64) -> IdentityKey {
        use sudp::primitives::{Kdf, PrimitiveSuite, StdPrimitives};
        IdentityKey {
            key: zeroize::Zeroizing::new(
                <StdPrimitives as PrimitiveSuite>::Kdf::derive_32(content_key, &[], IDENTITY_INFO)
                    .expect("HKDF-SHA-256 expands 32 bytes"),
            ),
            generation,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn mac(&self, tag: &[u8], parts: &[(String, Vec<u8>)]) -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.key[..]).expect("HMAC takes any key length");
        mac.update(tag);
        for (name, bytes) in parts {
            mac.update(&(name.len() as u64).to_be_bytes());
            mac.update(name.as_bytes());
            mac.update(&(bytes.len() as u64).to_be_bytes());
            mac.update(bytes);
        }
        mac.finalize().into_bytes().into()
    }

    /// The identity of a request covered as `covered`.
    pub fn identity(&self, covered: &Covered) -> Identity {
        let digest = self.mac(b"identity", &covered.components);
        let components = covered
            .components
            .iter()
            .chain(covered.detail.iter())
            .map(|c| (c.0.clone(), self.mac(b"component", std::slice::from_ref(c))))
            .collect();
        Identity {
            generation: self.generation,
            digest: digest.iter().map(|b| format!("{b:02x}")).collect(),
            components: Arc::new(components),
        }
    }

    /// The identity of an approval keyed by a unit: its generation only.
    pub fn unit(&self) -> Identity {
        Identity {
            generation: self.generation,
            ..Identity::default()
        }
    }
}

/// The covered components in which `now` differs from an `approved`
/// request, by name only: the finest that differ (a JSON body's member over
/// the body), `read:` dropped, each once.
pub fn differing(approved: &[(String, [u8; 32])], now: &[(String, [u8; 32])]) -> Vec<String> {
    let index = |list: &[(String, [u8; 32])]| -> BTreeMap<String, BTreeSet<[u8; 32]>> {
        let mut m: BTreeMap<String, BTreeSet<[u8; 32]>> = BTreeMap::new();
        for (n, h) in list {
            m.entry(n.clone()).or_default().insert(*h);
        }
        m
    };
    let (a, b) = (index(approved), index(now));
    let names: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    let differ: BTreeSet<String> = names
        .into_iter()
        .filter(|n| a.get(*n) != b.get(*n))
        .map(|n| n.trim_start_matches("read:").to_string())
        .collect();
    differ
        .iter()
        .filter(|n| {
            !differ
                .iter()
                .any(|m| m.starts_with(&format!("{n}.")) || m.starts_with(&format!("{n}[")))
        })
        .cloned()
        .collect()
}

/// SHA-256 of `bytes`, hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// What an approval of a request read as `read` (against its definition's
/// `[requests]` shapes) covers, with `rule_reads` the condition reads of the
/// rules that matched at the winning level. A shape of a compiled-in
/// definition may narrow; a vault definition's single-use approval covers
/// the whole request besides (it can widen, never narrow), and its
/// `encoded` is for display only.
pub fn cover_read(
    read: &crate::service::ReadRequest<'_>,
    path: &str,
    rule_reads: &[Read],
    compiled_in: bool,
    single_use: bool,
) -> Result<Covered, Unreadable> {
    let none = BTreeMap::new();
    let (whole, listed, consent_reads, encoded): (bool, &[ReadPath], &[ReadPath], _) =
        match &read.scope {
            None => (true, &[], &[], &none),
            Some(s) => (
                s.whole || (single_use && !compiled_in),
                &s.listed,
                &s.consent_reads,
                if compiled_in { &s.encoded } else { &none },
            ),
        };
    let mut reads: Vec<Read> = rule_reads.to_vec();
    reads.extend(consent_reads.iter().map(|p| Read {
        path: p.clone(),
        presence: false,
    }));
    reads.sort();
    reads.dedup();
    cover(
        &read.request,
        &Scope {
            path,
            whole,
            listed,
            reads: &reads,
            encoded,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::request::{BodyFormat, RequestInput};

    /// A request as the proxy reads it.
    struct Req<'a> {
        method: &'a str,
        host: &'a str,
        path: &'a str,
        query: Option<&'a str>,
        headers: Vec<(String, Vec<u8>)>,
        body: Vec<u8>,
    }

    fn req<'a>(headers: &[(&str, &str)], body: impl AsRef<[u8]>) -> Req<'a> {
        Req {
            method: "POST",
            host: "api.x.com",
            path: "/x",
            query: None,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
                .collect(),
            body: body.as_ref().to_vec(),
        }
    }

    fn covered_as(r: &Req<'_>, listed: &[ReadPath], reads: &[Read], encoded: &BTreeMap<String, Encoded>, whole: bool) -> Covered {
        let request = Request::new(
            RequestInput {
                method: r.method,
                host: r.host,
                path: r.path,
                query: r.query,
                headers: &r.headers,
                body: Some(&r.body),
                body_error: None,
            },
            BodyFormat::Json,
            Default::default(),
        );
        cover(
            &request,
            &Scope {
                path: r.path,
                whole,
                listed,
                reads,
                encoded,
            },
        )
        .unwrap()
    }

    fn key() -> IdentityKey {
        IdentityKey::derive(&[9u8; 32], 0)
    }

    /// The whole request's identity.
    fn whole(r: &Req<'_>) -> String {
        key().identity(&covered_as(r, &[], &[], &BTreeMap::new(), true)).digest
    }

    fn names(c: &Covered) -> Vec<&str> {
        c.components.iter().map(|(n, _)| n.as_str()).collect()
    }

    const JSON: (&str, &str) = ("content-type", "application/json");
    const AUTH: (&str, &str) = ("authorization", "Bearer __sprott__svc__");

    #[test]
    fn the_whole_request_is_its_line_query_named_headers_and_body() {
        let base = || req(&[JSON, AUTH], r#"{"amount":5}"#);
        let id = whole(&base());
        assert_eq!(id, whole(&base()), "the same replay");
        // Client metadata is not covered.
        let mut r = base();
        r.headers.push(("traceparent".into(), b"00-abc-01".to_vec()));
        r.headers.push(("user-agent".into(), b"curl/9".to_vec()));
        r.headers.push(("x-goog-api-client".into(), b"gccl-invocation-id/7".to_vec()));
        assert_eq!(whole(&r), id);
        // The body, the query, the port, a covered header, a phantom-bearing
        // header: each asks again.
        let mut changed = Vec::new();
        let mut r = base();
        r.body = br#"{"amount":5000}"#.to_vec();
        changed.push(r);
        let mut r = base();
        r.query = Some("a=1");
        changed.push(r);
        let mut r = base();
        r.host = "api.x.com:9443";
        changed.push(r);
        for (k, v) in [
            ("if-match", "\"e1\""),
            ("prefer", "resolution=merge-duplicates"),
            ("destination", "https://api.x.com/other"),
            ("cookie", "s=__sprott__svc__session__"),
        ] {
            let mut r = base();
            r.headers.push((k.into(), v.as_bytes().to_vec()));
            changed.push(r);
        }
        for r in &changed {
            assert_ne!(whole(r), id);
        }
        // A repeated query value is another request.
        let mut once = base();
        once.query = Some("a=1");
        let mut twice = base();
        twice.query = Some("a=1&a=1");
        assert_ne!(whole(&once), whole(&twice));
        // The card shows what is covered.
        let c = covered_as(&base(), &[], &[], &BTreeMap::new(), true);
        assert!(c.shown.contains(&("request.body".into(), r#"{"amount":5}"#.into())));
        assert!(c.shown.contains(&("request.headers['content-type']".into(), "application/json".into())));
        assert!(c.shown.iter().all(|(l, _)| !l.contains("user-agent")));
    }

    #[test]
    fn listed_values_and_reads_are_covered_as_jcs_and_absent_is_not_null() {
        let amount = ReadPath::parse("request.body.amount").unwrap();
        let id = |body: &str| {
            key().identity(&covered_as(&req(&[JSON], body), std::slice::from_ref(&amount), &[], &BTreeMap::new(), false)).digest
        };
        assert_eq!(id(r#"{"amount":5,"memo":"a"}"#), id(r#"{"memo":"b","amount":5}"#));
        assert_ne!(id(r#"{"amount":5}"#), id(r#"{"amount":"5"}"#));
        assert_ne!(id("{}"), id(r#"{"amount":null}"#));
        // A header named by a scope widens the whole request.
        let acl = ReadPath::parse("request.headers['x-goog-acl']").unwrap();
        let with_acl = |acl_value: Option<&str>| {
            let mut headers = vec![JSON];
            if let Some(v) = acl_value {
                headers.push(("x-goog-acl", v));
            }
            key().identity(&covered_as(&req(&headers, "data"), std::slice::from_ref(&acl), &[], &BTreeMap::new(), true)).digest
        };
        assert_ne!(with_acl(None), with_acl(Some("publicRead")));
        assert_eq!(with_acl(Some("private")), with_acl(Some("private")));
        // A presence read covers only presence.
        let account = Read {
            path: ReadPath::parse("request.headers['x-account']").unwrap(),
            presence: true,
        };
        let present = |v: Option<&str>| {
            let mut headers = vec![JSON];
            if let Some(v) = v {
                headers.push(("x-account", v));
            }
            key().identity(&covered_as(&req(&headers, ""), &[], std::slice::from_ref(&account), &BTreeMap::new(), false)).digest
        };
        assert_eq!(present(Some("prod")), present(Some("dev")));
        assert_ne!(present(Some("prod")), present(None));
    }

    fn multipart(boundary: &str, eol: &str, parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (headers, content) in parts {
            out.extend(format!("--{boundary}{eol}{headers}{eol}").into_bytes());
            out.extend_from_slice(content);
            out.extend(eol.as_bytes());
        }
        out.extend(format!("--{boundary}--{eol}").into_bytes());
        out
    }

    /// A form upload (curl `-F`, requests, httpx, Go): CRLF structure, an LF
    /// text file and a PNG inside.
    fn upload(boundary: &str, file: &[u8], png: &[u8]) -> Req<'static> {
        let body = multipart(
            boundary,
            "\r\n",
            &[
                ("Content-Disposition: form-data; name=\"note\"\r\n", b"a note"),
                (
                    "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n",
                    file,
                ),
                (
                    "Content-Disposition: form-data; name=\"logo\"; filename=\"l.png\"\r\nContent-Type: image/png\r\n",
                    png,
                ),
            ],
        );
        let ct = format!("multipart/form-data; boundary={boundary}");
        let mut r = req(&[], body);
        r.headers.push(("content-type".into(), ct.into_bytes()));
        r
    }

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\r\n\x00\x00";

    #[test]
    fn a_multipart_body_is_covered_by_its_parts() {
        let file = b"line one\nline two\n";
        let id = whole(&upload("------------------------a1", file, PNG));
        assert_eq!(id, whole(&upload("X-BOUNDARY-b2", file, PNG)), "a fresh boundary redeems");
        assert_ne!(id, whole(&upload("X-BOUNDARY-b2", b"line one\nline 2\n", PNG)), "a changed part");
        assert_ne!(id, whole(&upload("X-BOUNDARY-b2", file, b"\x89PNG other")));
        // An added part, and parts in another order.
        let base = |parts: &[(&str, &[u8])]| {
            let body = multipart("bb", "\r\n", parts);
            let mut r = req(&[("content-type", "multipart/mixed; boundary=bb")], body);
            r.path = "/m";
            whole(&r)
        };
        let a = ("Content-Type: text/plain\r\n", &b"a"[..]);
        let b = ("Content-Type: text/plain\r\n", &b"b"[..]);
        assert_ne!(base(&[a, b]), base(&[a, b, b]));
        assert_ne!(base(&[a, b]), base(&[b, a]));
        // A part's Content-ID is left out; its other headers are covered.
        let cid = |id: &str| "Content-Type: text/plain\r\nContent-ID: <".to_string() + id + ">\r\n";
        let (c1, c2) = (cid("1@x"), cid("2@x"));
        assert_eq!(base(&[(c1.as_str(), b"a")]), base(&[(c2.as_str(), b"a")]));
        assert_ne!(base(&[a]), base(&[("Content-Type: text/html\r\n", b"a")]));
    }

    /// Structure is taken only when it is unambiguous; else the body is its
    /// bytes, so only the same bytes redeem.
    #[test]
    fn an_ambiguous_multipart_body_is_covered_as_bytes() {
        let structured = |r: &Req<'_>| {
            names(&covered_as(r, &[], &[], &BTreeMap::new(), true)).contains(&"body.preamble")
        };
        let ct = ("content-type", "multipart/mixed; boundary=bb");
        let ok = req(&[ct], "--bb\r\nContent-Type: text/plain\r\n\r\na\r\n--bb--\r\n");
        assert!(structured(&ok));
        for body in [
            // Mixed line endings in a delimiter line.
            "--bb\r\nContent-Type: text/plain\r\n\r\na\n--bb--\r\n",
            // Mixed line endings in a part's header section.
            "--bb\r\nContent-Type: text/plain\nX-A: 1\r\n\r\na\r\n--bb--\r\n",
            // A dash-boundary that isn't at a line start.
            "--bb\r\nContent-Type: text/plain\r\n\r\na --bb b\r\n--bb--\r\n",
            // A dash-boundary followed by something else.
            "--bb\r\nContent-Type: text/plain\r\n\r\na\r\n--bbx\r\n--bb--\r\n",
            // No close delimiter.
            "--bb\r\nContent-Type: text/plain\r\n\r\na\r\n",
        ] {
            assert!(!structured(&req(&[ct], body)), "{body:?}");
        }
        let body = "--bb\r\nContent-Type: text/plain\r\n\r\na\r\n--bb--\r\n";
        // Two Content-Type sources, two boundary parameters, a `$ct`.
        assert!(!structured(&req(&[ct, ct], body)));
        assert!(!structured(&req(&[("content-type", "multipart/mixed; boundary=bb; boundary=cc")], body)));
        let mut ct_query = req(&[ct], body);
        ct_query.query = Some("$ct=application/json");
        assert!(!structured(&ct_query));
        // An LF structure is structure too.
        assert!(structured(&req(&[ct], "--bb\nContent-Type: text/plain\n\na\n--bb--\n")));
    }

    /// A Google batch (google-cloud-storage, google-api-python-client): a
    /// re-run with a fresh boundary, fresh Content-IDs and a fresh SDK
    /// invocation id redeems; a changed sub-request asks.
    #[test]
    fn a_google_batch_is_covered_by_its_requests() {
        let batch = |boundary: &str, n: u32, path2: &str, body2: &str| {
            let one = format!("GET /storage/v1/b/bkt/o/obj HTTP/1.1\r\nx-goog-api-client: gccl-invocation-id/{n}\r\n\r\n");
            let two = format!("PATCH {path2} HTTP/1.1\r\nContent-Type: application/json\r\nx-goog-api-client: gccl-invocation-id/{n}\r\n\r\n{body2}");
            let h1 = format!("Content-Type: application/http\r\nContent-ID: <{n}+1>\r\n");
            let h2 = format!("Content-Type: application/http\r\nContent-ID: <{n}+2>\r\n");
            let body = multipart(boundary, "\r\n", &[(h1.as_str(), one.as_bytes()), (h2.as_str(), two.as_bytes())]);
            let ct = format!("multipart/mixed; boundary=\"{boundary}\"");
            let mut r = req(&[], body);
            r.path = "/batch/storage/v1";
            r.headers.push(("content-type".into(), ct.into_bytes()));
            whole(&r)
        };
        let id = batch("===1==", 1, "/storage/v1/b/bkt/o/obj2", r#"{"metadata":{"a":"b"}}"#);
        assert_eq!(id, batch("===2==", 2, "/storage/v1/b/bkt/o/obj2", r#"{"metadata":{"a":"b"}}"#));
        assert_ne!(id, batch("===2==", 2, "/storage/v1/b/bkt/o/obj3", r#"{"metadata":{"a":"b"}}"#));
        assert_ne!(id, batch("===2==", 2, "/storage/v1/b/bkt/o/obj2", r#"{"metadata":{"a":"c"}}"#));
    }

    /// A Python `email` message (LF): headers, then a multipart/alternative
    /// body.
    fn python_email(boundary: &str, fold: bool, date: &str, msg_id: &str, to: &str, subject: &str, text: &str) -> String {
        let ct = if fold {
            format!("Content-Type: multipart/alternative;\n boundary=\"{boundary}\"\n")
        } else {
            format!("Content-Type: multipart/alternative; boundary=\"{boundary}\"\n")
        };
        format!(
            "{ct}MIME-Version: 1.0\nFrom: a@x.com\nTo: {to}\nSubject: {subject}\nDate: {date}\nMessage-ID: {msg_id}\n\n\
             --{boundary}\nContent-Type: text/plain; charset=\"us-ascii\"\nMIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n\n{text}\n\
             --{boundary}\nContent-Type: text/html; charset=\"us-ascii\"\nMIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n\n<p>{text}</p>\n\
             --{boundary}--\n"
        )
    }

    /// A nodemailer message: CRLF structure, LF text inside, mixed >
    /// alternative > related nesting with an inline image.
    fn nodemailer(n: &str, date: &str, bcc: &str) -> String {
        let (b1, b2, b3) = (format!("--_NmP-{n}-Part_1"), format!("--_NmP-{n}-Part_2"), format!("--_NmP-{n}-Part_3"));
        format!(
            "Content-Type: multipart/mixed;\r\n boundary=\"{b1}\"\r\nFrom: a@x.com\r\nTo: b@y.com\r\nBcc: {bcc}\r\nSubject: Hi\r\n\
             Message-ID: <{n}@x.com>\r\nDate: {date}\r\nMIME-Version: 1.0\r\n\r\n\
             --{b1}\r\nContent-Type: multipart/alternative;\r\n\tboundary=\"{b2}\"\r\n\r\n\
             --{b2}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nline one\nline two\r\n\
             --{b2}\r\nContent-Type: multipart/related;\r\n type=\"text/html\";\r\n boundary=\"{b3}\"\r\n\r\n\
             --{b3}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>hi<img src=\"cid:logo@x\"></p>\r\n\
             --{b3}\r\nContent-Type: image/png; name=logo.png\r\nContent-ID: <logo@x>\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n\
             --{b3}--\r\n\r\n--{b2}--\r\n\r\n\
             --{b1}\r\nContent-Type: text/plain; name=a.txt\r\nContent-Disposition: attachment; filename=a.txt\r\n\r\nattached\r\n\
             --{b1}--\r\n"
        )
    }

    fn b64url(bytes: &[u8], padded: bool) -> String {
        use base64::Engine;
        let s = base64::engine::general_purpose::URL_SAFE.encode(bytes);
        if padded {
            s
        } else {
            s.trim_end_matches('=').to_string()
        }
    }

    fn gmail_encoded() -> BTreeMap<String, Encoded> {
        [(
            "request.body.raw".to_string(),
            Encoded {
                content_encoding: Some("base64url".into()),
                content_media_type: Some("message/rfc822".into()),
            },
        )]
        .into()
    }

    /// Gmail's JSON send: `raw` covered by its content.
    fn gmail_json(email: &str, padded: bool) -> (String, Covered) {
        let body = format!(r#"{{"raw":"{}","threadId":"t1"}}"#, b64url(email.as_bytes(), padded));
        let r = req(&[JSON], body);
        let c = covered_as(&r, &[], &[], &gmail_encoded(), true);
        (key().identity(&c).digest, c)
    }

    /// Gmail's upload: multipart/related, JSON metadata then the email.
    fn gmail_upload(boundary: &str, email: &str) -> String {
        let body = multipart(
            boundary,
            "\r\n",
            &[
                ("Content-Type: application/json; charset=UTF-8\r\n", br#"{"threadId":"t1"}"#),
                ("Content-Type: message/rfc822\r\n", email.as_bytes()),
            ],
        );
        let ct = format!("multipart/related; boundary={boundary}");
        let mut r = req(&[], body);
        r.path = "/upload/gmail/v1/users/me/messages/send";
        r.query = Some("uploadType=multipart");
        r.headers.push(("content-type".into(), ct.into_bytes()));
        whole(&r)
    }

    #[test]
    fn a_rebuilt_email_redeems_and_a_changed_one_asks() {
        let (d1, d2) = ("Thu, 29 Oct 2026 10:00:00 +0000", "Thu, 29 Oct 2026 10:05:00 +0000");
        let py = |b: &str, fold: bool, date: &str, id: &str| python_email(b, fold, date, id, "b@y.com", "Hi", "hello");
        let first = py("===============1111==", false, d1, "<1@x.com>");
        let rebuilt = py("===============2222==", true, d2, "<2@x.com>");
        let (id, c) = gmail_json(&first, true);
        assert_eq!(id, gmail_json(&rebuilt, false).0, "fresh boundary, Date, Message-ID; unpadded");
        assert!(names(&c).contains(&"body.raw.Subject"), "{:?}", names(&c));
        assert!(names(&c).iter().all(|n| !n.contains("Date") && !n.contains("Message-ID")));
        for changed in [
            python_email("===============3333==", false, d2, "<3@x.com>", "c@z.com", "Hi", "hello"),
            python_email("===============3333==", false, d2, "<3@x.com>", "b@y.com", "Hey", "hello"),
            python_email("===============3333==", false, d2, "<3@x.com>", "b@y.com", "Hi", "goodbye"),
        ] {
            assert_ne!(id, gmail_json(&changed, true).0);
        }
        // Through the upload endpoint too.
        assert_eq!(gmail_upload("up-1", &first), gmail_upload("up-2", &rebuilt));
        // nodemailer: nested structure, CRLF headers, LF text.
        let nm = nodemailer("aaaa", d1, "c@z.com");
        let (id, _) = gmail_json(&nm, true);
        assert_eq!(id, gmail_json(&nodemailer("bbbb", d2, "c@z.com"), false).0);
        assert_ne!(id, gmail_json(&nodemailer("bbbb", d2, "d@z.com"), true).0, "a changed Bcc");
        assert_eq!(gmail_upload("up-1", &nm), gmail_upload("up-9", &nodemailer("cccc", d2, "c@z.com")));
        // A `raw` that doesn't decode is covered as the string.
        let bad = |s: &str| {
            let r = req(&[JSON], format!(r#"{{"raw":"{s}"}}"#));
            key().identity(&covered_as(&r, &[], &[], &gmail_encoded(), true)).digest
        };
        assert_ne!(bad("not*base64"), bad("not*base65"));
        // Without the compiled-in declaration a JSON body is its bytes.
        let plain = |email: &str| {
            let body = format!(r#"{{"raw":"{}"}}"#, b64url(email.as_bytes(), true));
            whole(&req(&[JSON], body))
        };
        assert_ne!(plain(&first), plain(&rebuilt));
    }

    /// A re-run that differs is told which components, never their values.
    #[test]
    fn what_differs_is_named_without_values() {
        let id = |body: &str, query: Option<&'static str>, if_match: Option<&str>| {
            let mut r = req(&[JSON, AUTH], body);
            r.query = query;
            if let Some(m) = if_match {
                r.headers.push(("if-match".into(), m.as_bytes().to_vec()));
            }
            key().identity(&covered_as(&r, &[], &[], &BTreeMap::new(), true))
        };
        let approved = id(r#"{"summary":"a","conferenceData":{"createRequest":{"requestId":"r1"}}}"#, None, None);
        let now = id(r#"{"summary":"a","conferenceData":{"createRequest":{"requestId":"r2"}}}"#, Some("x=1"), Some("e1"));
        assert_eq!(
            differing(&approved.components, &now.components),
            ["body.conferenceData", "headers.if-match", "query"]
        );
        let email = |subject: &str| {
            gmail_json(&python_email("b", false, "d", "<1@x>", "b@y.com", subject, "t"), true).1
        };
        let k = key();
        assert_eq!(
            differing(&k.identity(&email("Hi")).components, &k.identity(&email("Yo")).components),
            ["body.raw.Subject"]
        );
        assert!(differing(&approved.components, &approved.components).is_empty());
    }
}
