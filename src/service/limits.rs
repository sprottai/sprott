//! Every size and count limit on a service definition, in one place. A
//! definition over any limit is rejected whole at the gate
//! ([`crate::service::gate::admit`]). Each value keeps at least 4x headroom
//! over the largest compiled-in service (the figure in parentheses), so a
//! real definition never meets one; they exist so that no definition text can
//! make the daemon or the CLI spend unbounded memory or time.

/// Bytes per file (service.toml, policy.toml), checked before parsing (3713:
/// cratesio's policy.toml).
pub const MAX_FILE_BYTES: usize = 64 * 1024;
/// Bytes of the `setup` prose handed to an agent (627: cloudflare).
pub const MAX_PROSE_BYTES: usize = 4 * 1024;
/// Bytes of any other string or table key: names, labels, hosts, URLs,
/// methods, path patterns, conditions, consent templates (945: railway's
/// change-access condition).
pub const MAX_STRING_BYTES: usize = 1024;
/// Compiled program size of the regex a `path` pattern matches with (its
/// `:name(regex)` groups included), set explicitly on the builder rather
/// than left at the crate default (10 MiB); it also bounds the work spent
/// compiling a pattern that fails.
pub const PATH_REGEX_SIZE_LIMIT: usize = 256 * 1024;
/// Lazy-DFA cache size of a `path` pattern's regex.
pub const PATH_REGEX_DFA_SIZE_LIMIT: usize = 256 * 1024;
/// Nesting depth of a `path` pattern's regex.
pub const PATH_REGEX_NEST_LIMIT: u32 = 64;

/// `[service] hosts` entries (14: gcp).
pub const MAX_HOSTS: usize = 64;
/// `[service] secrets` roles (2).
pub const MAX_SECRETS: usize = 16;
/// `[service] tags` (1).
pub const MAX_TAGS: usize = 16;
/// `[auth] scopes` (4: gmail).
pub const MAX_OAUTH_SCOPES: usize = 64;
/// `[auth] exposes` roles (1: openai_codex).
pub const MAX_EXPOSES: usize = 16;
/// `[auth.authorize_params]` entries (3: openai_codex).
pub const MAX_AUTHORIZE_PARAMS: usize = 16;
/// `[auth.claims]` entries (1: openai_codex).
pub const MAX_CLAIMS: usize = 16;
/// Segments of one claim path (2: openai_codex).
pub const MAX_CLAIM_PATH: usize = 16;
/// Policy rules, policy.toml or inline (17: cratesio).
pub const MAX_RULES: usize = 128;
/// Method × path pairs per rule or request shape (a 2.0 `match` list counts
/// its patterns) (27: github's change-org-access).
pub const MAX_MATCH_PATTERNS: usize = 32;
/// `[requests.<name>]` shapes (3: cloudflare).
pub const MAX_REQUESTS: usize = 32;
/// `scope` entries, and `encoded` entries, per request shape (9:
/// cloudflare's record shapes).
pub const MAX_SCOPE: usize = 32;

/// Seconds a definition's `ttl` (a rule's or `[default]`'s approval reuse
/// window) may be: one year, a product decision on how long one approval may
/// stand (1800: cratesio). The owner's own console and
/// per-connection settings are not definitions and are not bound by it.
pub const MAX_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;

/// Problems reported for one rejected definition; the rest are counted, so a
/// pathological file cannot produce an unbounded message.
pub const MAX_REPORTED_PROBLEMS: usize = 50;
