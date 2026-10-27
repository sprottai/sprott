//! The request path, normalized once at the proxy's ingress the way Envoy
//! normalizes it for path-based access control (`normalize_path` plus
//! `merge_slashes`, its edge-proxy best practice). Policy, request shapes,
//! grant keys, the audit row and the forwarded request all use this one form,
//! so the upstream runs exactly the path that was checked.
//!
//! Steps: RFC 3986 normalization by iri-string (§6.2.2: a percent-encoded
//! unreserved character is decoded, `%67` → `g`, other escapes get uppercase
//! hex, dot segments are removed), then repeated slashes are merged (Envoy's
//! `merge_slashes`). A path that isn't valid RFC 3986, or holds `%00`, is
//! refused, as Envoy and Istio refuse it.
//!
//! An encoded slash (`%2F`, `%5C`) is kept as sent: servers really differ on it
//! (GitHub reads `heads%2Fmain` as `heads/main`, GitLab needs `%2F` kept in a
//! project path), and Envoy leaves the choice to each backend. Not knowing the
//! backend, the proxy decides on both readings and keeps the stricter result;
//! [`slash_decoded`] is the second reading.

/// Why a path was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Not a valid RFC 3986 path once escaped (a `%` not followed by two hex
    /// digits).
    Malformed,
    /// `%00`.
    Nul,
    /// An encoded slash that, decoded, makes a dot segment: servers that
    /// decode it resolve that in different orders, so no one reading is safe
    /// to decide on.
    Ambiguous,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PathError::Malformed => "the request path is not a valid URI path",
            PathError::Nul => "the request path contains %00",
            PathError::Ambiguous => {
                "the request path has an encoded slash next to a dot segment"
            }
        })
    }
}

/// The normalized form of an origin-form path (one that starts with `/`).
/// Anything else (`*`) is returned unchanged.
pub fn normalize(path: &str) -> Result<String, PathError> {
    if !path.starts_with('/') {
        return Ok(path.to_string());
    }
    let rfc3986 = rfc3986_normalize(&escape_outside_rfc3986(path))?;
    if rfc3986.contains("%00") {
        return Err(PathError::Nul);
    }
    Ok(merge_slashes(&rfc3986))
}

/// The other readings of a normalized path that holds an encoded slash or
/// backslash: taken as a `/`, both as is and with the slashes that makes
/// merged (servers differ on both). Empty when the path has none. Refused when
/// the decoded slash makes a dot segment, which servers resolve in different
/// orders (see [`PathError::Ambiguous`]).
pub fn slash_decoded(normalized: &str) -> Result<Vec<String>, PathError> {
    if !normalized.contains("%2F") && !normalized.contains("%5C") {
        return Ok(Vec::new());
    }
    let opened = normalized.replace("%2F", "/").replace("%5C", "/");
    if opened.split('/').any(|s| s == "." || s == "..") {
        return Err(PathError::Ambiguous);
    }
    let merged = merge_slashes(&opened);
    Ok(if merged == opened {
        vec![opened]
    } else {
        vec![opened, merged]
    })
}

/// The characters an HTTP request target may carry (http accepts them) but
/// an RFC 3986 path can't, percent-encoded: controls, space, `"` `<` `>` `\`
/// `^` `` ` `` `{` `|` `}` `[` `]` and every non-ASCII byte. A backslash
/// becomes `%5C`, which the second reading then covers.
fn escape_outside_rfc3986(path: &str) -> std::borrow::Cow<'_, str> {
    use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
    const OUTSIDE: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'\\')
        .add(b'^')
        .add(b'`')
        .add(b'{')
        .add(b'|')
        .add(b'}')
        .add(b'[')
        .add(b']');
    utf8_percent_encode(path, OUTSIDE).into()
}

/// RFC 3986 §6.2.2 (iri-string): case and percent-encoding normalization,
/// then dot-segment removal (§5.2.4). The path is read under a fixed
/// authority, so a leading `//` stays a path.
fn rfc3986_normalize(path: &str) -> Result<String, PathError> {
    use iri_string::format::ToDedicatedString;
    let uri = iri_string::types::UriAbsoluteString::try_from(format!("https://h{path}"))
        .map_err(|_| PathError::Malformed)?;
    let normal = uri.normalize();
    normal
        .ensure_rfc3986_normalizable()
        .map_err(|_| PathError::Malformed)?;
    Ok(normal.to_dedicated_string().path_str().to_string())
}

fn merge_slashes(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_a_server_treats_as_one_path_become_one() {
        for p in [
            "/graphql/v2",
            "//graphql/v2",
            "/%67raphql/v2",
            "/%67RAPHQL/../graphql/v2",
            "/graphql/./v2",
        ] {
            assert_eq!(normalize(p).unwrap(), "/graphql/v2", "{p}");
        }
        assert_eq!(normalize("/a/b/../../c").unwrap(), "/c");
        assert_eq!(normalize("/a/%2e%2e/b").unwrap(), "/b");
        assert_eq!(normalize("/a/b/.").unwrap(), "/a/b/");
        assert_eq!(normalize("/..").unwrap(), "/");
        assert_eq!(normalize("*").unwrap(), "*");
    }

    #[test]
    fn other_escapes_are_kept_with_uppercase_hex() {
        assert_eq!(normalize("/files/a%20b%2fc").unwrap(), "/files/a%20b%2Fc");
        assert_eq!(normalize("/q/%7e%41").unwrap(), "/q/~A");
    }

    #[test]
    fn malformed_and_nul_are_refused() {
        assert_eq!(normalize("/a%2"), Err(PathError::Malformed));
        assert_eq!(normalize("/a%zz"), Err(PathError::Malformed));
        assert_eq!(normalize("/a%+1"), Err(PathError::Malformed));
        assert_eq!(normalize("/a%00b"), Err(PathError::Nul));
    }

    #[test]
    fn an_encoded_slash_has_a_second_reading() {
        let p = normalize("/repos/o/r/git/refs/heads%2fmain").unwrap();
        assert_eq!(p, "/repos/o/r/git/refs/heads%2Fmain");
        assert_eq!(slash_decoded(&p), Ok(vec!["/repos/o/r/git/refs/heads/main".to_string()]));
        assert_eq!(slash_decoded("/plain/path"), Ok(vec![]));
        // Empty segments a decoded slash makes: decided both as is and merged
        // (a storage key may hold `//`).
        assert_eq!(
            slash_decoded("/o/logs%2F%2F2024"),
            Ok(vec!["/o/logs//2024".to_string(), "/o/logs/2024".to_string()])
        );
        // Dot segments it makes: no reading is safe.
        for p in ["/a%5C..%5Cb", "/repos/o/r/x%2F%2F..", "/a%2F.%2Fb"] {
            assert_eq!(slash_decoded(p), Err(PathError::Ambiguous), "{p}");
        }
    }

    #[test]
    fn characters_a_uri_cant_hold_are_escaped_not_refused() {
        assert_eq!(
            normalize("/contents/设计.md").unwrap(),
            "/contents/%E8%AE%BE%E8%AE%A1.md"
        );
        assert_eq!(normalize("/a b/{x}").unwrap(), "/a%20b/%7Bx%7D");
        assert_eq!(normalize("/repos\\o").unwrap(), "/repos%5Co");
    }
}
