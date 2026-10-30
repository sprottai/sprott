//! A request's readings (DESIGN §6, §7): each request a server may take it
//! for. Its method: the request line and each method-override header. Its
//! path: as normalized, and an encoded slash read as a `/` (core/path.rs).
//! A Google batch (`multipart/mixed` of `application/http` parts) besides
//! reads as each request it carries, on that request's own readings, with
//! the batch's host. Every reading is decided and the strictest decision
//! kept; a batch whose requests can't be read one by one is decided as
//! `ask-always`.

use crate::approval::coverage::{self, Batch, Embedded};
use crate::approval::reuse::{GrantUnit, Scoped};
use crate::core::policy::{stricter, AccessLevel, DecidedBy, Decision};
use crate::core::request::{method_readings, Request, RequestInput, Unreadable};
use crate::service::{read_request, ReadRequest, ServiceDef};

/// The label a batch whose requests can't be read one by one is decided
/// under (`ask-always`).
pub const UNREADABLE_BATCH: &str = "A batch whose requests can't be read one by one";

/// A request's readings, before they are decided.
pub struct Readings<'a> {
    input: RequestInput<'a>,
    methods: Vec<String>,
    paths: Vec<String>,
    parts: Vec<Part<'a>>,
    /// The body is a `multipart/mixed` that can't be read as a batch one
    /// request at a time.
    pub batch_unreadable: bool,
}

/// One request of a batch, read.
struct Part<'a> {
    methods: Vec<String>,
    paths: Vec<String>,
    query: Option<String>,
    headers: Vec<(String, Vec<u8>)>,
    body: &'a [u8],
}

/// One reading: a request to decide.
pub struct Reading<'r> {
    pub input: RequestInput<'r>,
    /// The batch request it is (`None`: the request itself).
    pub part: Option<usize>,
}

/// The readings, decided.
pub struct Decided<'r> {
    /// Every reading, in [`Readings::each`] order, with how it read and its
    /// decision.
    pub readings: Vec<(Reading<'r>, ReadRequest<'r>, Decision)>,
    /// The reading kept: the strictest; on a tie, the first a shape read
    /// (so an approval covers and shows what it can).
    pub kept: usize,
    /// The kept reading's decision, or `ask-always` for a batch that can't
    /// be read one request at a time when that is stricter.
    pub decision: Decision,
    /// The readings decided at the decision's level.
    pub tied: Vec<usize>,
    /// How an approval of the request is reused: single-use when the tied
    /// readings decide by different units (a rule or floor, read or write)
    /// than the request line's, when a shape's condition errored where no
    /// shape matched, or for an unreadable batch.
    pub scoped: Scoped,
}

impl<'a> Readings<'a> {
    /// `input`'s readings. Refused with why (400) when a method-override
    /// header isn't one method, or an encoded slash makes a dot segment.
    pub fn of(input: RequestInput<'a>) -> Result<Readings<'a>, String> {
        let methods = method_readings(input.method, input.headers)?;
        let paths = path_readings(input.path).map_err(|e| e.to_string())?;
        let mut readings = Readings {
            input,
            methods,
            paths,
            parts: Vec::new(),
            batch_unreadable: false,
        };
        let body = input.body.unwrap_or_default();
        match coverage::batch(input.headers, input.query, body) {
            Batch::No => {}
            Batch::Unreadable => readings.batch_unreadable = true,
            Batch::Requests(requests) => {
                let parts: Option<Vec<Part<'a>>> = requests.into_iter().map(Part::of).collect();
                match parts {
                    Some(parts) => readings.parts = parts,
                    None => readings.batch_unreadable = true,
                }
            }
        }
        Ok(readings)
    }

    /// The body reads as a batch's requests.
    pub fn is_batch(&self) -> bool {
        !self.parts.is_empty()
    }

    /// Batch request `i`'s path, as normalized.
    pub fn part_path(&self, i: usize) -> &str {
        &self.parts[i].paths[0]
    }

    /// A shape of `def` selects the request itself on one of its readings.
    pub fn selected(&self, def: Option<&ServiceDef>) -> bool {
        def.is_some_and(|d| {
            self.methods
                .iter()
                .any(|m| self.paths.iter().any(|p| d.shape_selects(m, p)))
        })
    }

    /// Every reading: the request itself on each method and path reading,
    /// then each batch request on each of its own.
    pub fn each(&self) -> Vec<Reading<'_>> {
        let mut out = Vec::new();
        for m in &self.methods {
            for p in &self.paths {
                out.push(Reading {
                    input: RequestInput {
                        method: m,
                        path: p,
                        ..self.input
                    },
                    part: None,
                });
            }
        }
        for (i, part) in self.parts.iter().enumerate() {
            for m in &part.methods {
                for p in &part.paths {
                    out.push(Reading {
                        input: RequestInput {
                            method: m,
                            host: self.input.host,
                            path: p,
                            query: part.query.as_deref(),
                            headers: &part.headers,
                            body: Some(part.body),
                            body_error: None,
                        },
                        part: Some(i),
                    });
                }
            }
        }
        out
    }

    /// Read each reading against `def`'s shapes and decide it with
    /// `evaluate`. A reading that can't be read refuses the request.
    pub fn decide(
        &self,
        def: Option<&ServiceDef>,
        mut evaluate: impl FnMut(&Request<'_>) -> Result<Decision, Unreadable>,
    ) -> Result<Decided<'_>, Unreadable> {
        let mut readings = Vec::new();
        for reading in self.each() {
            let read = read_request(def, reading.input)?;
            let decision = evaluate(&read.request)?;
            readings.push((reading, read, decision));
        }
        let kept = (1..readings.len()).fold(0, |k, i| {
            let (n, kk) = (readings[i].2 .0.restrictiveness(), readings[k].2 .0.restrictiveness());
            let shaped = readings[k].1.scope.is_none() && readings[i].1.scope.is_some();
            if n > kk || (n == kk && shaped) {
                i
            } else {
                k
            }
        });
        let mut decision = readings[kept].2.clone();
        if self.batch_unreadable {
            let label = Some(UNREADABLE_BATCH.to_string());
            let forced = (AccessLevel::AskAlways, DecidedBy::Rule { id: None, label }, None);
            decision = stricter(decision, forced);
        }
        let tied: Vec<usize> = (0..readings.len())
            .filter(|&i| readings[i].2 .0 == decision.0)
            .collect();
        let unit = GrantUnit::of(&decision.1, self.input.method);
        let kept_read = &readings[kept].1;
        let scoped = if self.batch_unreadable
            || tied
                .iter()
                .any(|&i| GrantUnit::of(&readings[i].2 .1, readings[i].0.input.method) != unit)
            || (kept_read.scope.is_none() && kept_read.errored)
        {
            Scoped::Once
        } else {
            Scoped::from(kept_read.scope.is_some())
        };
        Ok(Decided {
            readings,
            kept,
            decision,
            tied,
            scoped,
        })
    }
}

impl<'a> Part<'a> {
    /// A batch request's readings; `None` when one can't be taken
    /// unambiguously: a target that isn't an origin-form path (Google
    /// refuses a full URL in a batch), a path that doesn't normalize, a
    /// method-override header that isn't one method.
    fn of(e: Embedded<'a>) -> Option<Part<'a>> {
        if !e.target.starts_with('/') || e.target.contains('#') {
            return None;
        }
        let (path, query) = match e.target.split_once('?') {
            Some((p, q)) => (p, Some(q.to_string())),
            None => (e.target.as_str(), None),
        };
        let path = crate::core::path::normalize(path).ok()?;
        let methods = method_readings(&e.method, &e.headers).ok()?;
        let paths = path_readings(&path).ok()?;
        Some(Part {
            methods,
            paths,
            query,
            headers: e.headers,
            body: e.body,
        })
    }
}

/// A normalized path's readings: itself, then those of an encoded slash.
fn path_readings(path: &str) -> Result<Vec<String>, crate::core::path::PathError> {
    let others = crate::core::path::slash_decoded(path)?;
    Ok(std::iter::once(path.to_string()).chain(others).collect())
}
