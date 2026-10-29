/// TOML-driven service registry (v4, phantom-only broker).
///
/// Each service is defined by a `service.toml` in `services/{id}/` (flat — the
/// dir name is the id; classification lives in the `tags` field, not layout).
/// A service declares what a minimal connection has — `hosts` + `secrets` —
/// plus the auth mechanism (`[auth]`, absent = static) and cosmetic helpers. No
/// routing/transport is declared: the phantom is the sole intent carrier and
/// the request already carries the real upstream URL.
pub mod gate;
pub mod graphql;
pub mod limits;
pub mod source;
pub mod strict_json;

use crate::auth::oauth2::OAuthStyle;
use std::collections::HashMap;

// ── ServiceDef: parsed from service.toml (v4) ───────────────────────────────

/// A service TYPE, as the gate admitted it ([`gate::admit`], the only
/// constructor: the private field keeps every other module from building one,
/// and there is no `Deserialize`). The schema it was parsed from rejects stale
/// v3 sections and any tool-named section (`[git]`, `[docker]`): auth is a
/// MECHANISM, never a tool, and the only auth section is `[auth]`
/// (type-discriminated).
#[derive(Debug, Clone)]
pub struct ServiceDef {
    pub service: ServiceMeta,
    /// The auth MECHANISM — how the wire credential is produced from the
    /// stored secret(s). Discriminated by `type` (the same shape as OpenAPI
    /// `securitySchemes.type`). ABSENT = static: the stored secret IS the wire
    /// value, substituted verbatim wherever the agent's phantom names it.
    /// When present, the default phantom resolves to a MINTED short-lived
    /// token and the mechanism's input role (`mint_input_role`) is internal
    /// by construction and never injectable.
    pub auth: Option<AuthDef>,
    /// Optional agent-facing `setup` prose: service-specific guidance on where a
    /// phantom goes for this service's tools (a header, an env var, a URL) when
    /// run under `sc run --`. Plain text — no template tokens.
    pub setup: Option<String>,
    /// The definition's policy, compiled at the gate: its policy.toml, or the
    /// inline `[policy]` section (`[policy.levels]` / `[[policy.rules]]`) of a
    /// service.toml without one. `None` when it declares neither.
    pub policy: Option<ServicePolicy>,
    /// Request shapes (`[requests.<name>]`): which requests they read and in
    /// what body format, which request values an approval covers (`scope`),
    /// and how to phrase them (`consent`). See [`RequestShape`].
    pub requests: HashMap<String, RequestShape>,
    /// The shapes' names in declaration order: the order they are tried in.
    pub request_order: Vec<String>,
    /// What the gate found worth saying about an admitted definition (a
    /// condition member read without a presence guard): printed by `sprott
    /// service validate` / `add`, never a refusal.
    pub warnings: Vec<String>,
    /// Set only by the gate.
    _gate: (),
}

/// A definition's policy, compiled at the gate: the read/write floor when no
/// rule matches, and the rules in file order, each with a parsed level and a
/// compiled `condition`.
#[derive(Debug, Clone, Default)]
pub struct ServicePolicy {
    /// `[default]` in policy.toml, `[policy.levels]` inline.
    pub defaults: Option<crate::core::policy::Levels>,
    pub rules: Vec<crate::core::policy::PolicyRule>,
}

impl ServicePolicy {
    /// The parts of this policy that can only tighten a decision, and a note
    /// for each part left out. A vault definition's policy is applied this
    /// way (tightening applies directly; loosening needs the owner's consent,
    /// which a definition any member can write does not carry): rules that
    /// decide `deny`, `ask` or `ask-always`, and a `[default]` read or write
    /// level other than `allow` (with its `ttl`). The decision then takes the
    /// stricter of the outcome with and without it
    /// ([`crate::core::policy::stricter`]).
    pub fn tightening(&self) -> (ServicePolicy, Vec<String>) {
        use crate::core::policy::{AccessLevel, Levels};
        const WHY: &str = "a vault service definition can only tighten policy; loosening is the owner's setting in the console";
        let mut notes = Vec::new();
        let mut rules = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            if matches!(r.level, Some(AccessLevel::Allow) | None) {
                let name =
                    r.id.as_deref()
                        .map(|id| format!("rule '{}'", id))
                        .unwrap_or_else(|| format!("[[policy.rules]] #{}", i + 1));
                notes.push(format!("{} (allow) is not applied: {}", name, WHY));
            } else {
                rules.push(r.clone());
            }
        }
        let defaults = self.defaults.as_ref().and_then(|d| {
            let keep = |dir: &str, l: Option<AccessLevel>, notes: &mut Vec<String>| match l {
                Some(AccessLevel::Allow) => {
                    notes.push(format!("default {} = allow is not applied: {}", dir, WHY));
                    None
                }
                other => other,
            };
            let read = keep("read", d.read, &mut notes);
            let write = keep("write", d.write, &mut notes);
            if read.is_none() && write.is_none() {
                if d.ttl.is_some() {
                    notes.push(format!(
                        "default ttl is not applied: the default levels it goes with are not ({})",
                        WHY
                    ));
                }
                return None;
            }
            Some(Levels {
                read,
                write,
                ttl: d.ttl,
            })
        });
        (ServicePolicy { defaults, rules }, notes)
    }
}

impl ServiceDef {
    /// This definition as a vault (`aux.services`) definition applies it: its
    /// policy reduced to [`ServicePolicy::tightening`], with a note for each
    /// part left out (`sc service validate` / `add` print them).
    pub fn for_vault(mut self) -> (ServiceDef, Vec<String>) {
        let mut notes = Vec::new();
        if let Some(p) = &self.policy {
            let (kept, n) = p.tightening();
            notes = n;
            self.policy = (!kept.rules.is_empty() || kept.defaults.is_some()).then_some(kept);
        }
        (self, notes)
    }
}

impl ServiceDef {
    /// The `[auth] type = "oauth2"` section, when that is this service's
    /// mechanism. Shorthand for the oauth-only call sites (consent flow,
    /// console wiring) so they don't each match on [`AuthDef`].
    pub fn oauth2(&self) -> Option<&OAuth2Def> {
        match self.auth.as_ref() {
            Some(AuthDef::Oauth2(o)) => Some(o),
            _ => None,
        }
    }

    /// The stored role that is the INPUT of a minted mechanism — the value the
    /// mint consumes (oauth2's refresh token, snaplii's api key). `Some` ⇔ the
    /// connection's wire credential is minted, and this role is internal by
    /// construction: a phantom naming it gets the precise never-injectable
    /// refusal. `None` for a static service.
    pub fn mint_input_role(&self) -> Option<String> {
        match self.auth.as_ref()? {
            AuthDef::Oauth2(o) => {
                let s = o.refresh_token.trim();
                (!s.is_empty()).then(|| s.to_string())
            }
            AuthDef::Snaplii(_) => self.first_secret(),
        }
    }

    fn first_secret(&self) -> Option<String> {
        self.service
            .secrets
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    /// Read a request against this definition's `[requests]` shapes: the
    /// first, in declaration order, whose `method`, `path` and `condition`
    /// select it (a condition that errors doesn't select), with what its
    /// approval covers, and the request object rules then read, in that
    /// shape's body format (`json` when no shape matched). A value a shape's
    /// condition, `scope` or `consent` reads that can't be read refuses the
    /// request.
    pub fn read_request<'a>(
        &self,
        input: crate::core::request::RequestInput<'a>,
    ) -> Result<ReadRequest<'a>, Unreadable> {
        read_request(Some(self), input)
    }

    /// Whether some `[requests]` shape's `method` and `path` select this
    /// request (its condition aside).
    pub fn shape_selects(&self, method: &str, path: &str) -> bool {
        self.requests
            .values()
            .any(|s| s.select.exec(method, path).is_some())
    }

    /// The stored secret role that backs this service's credential: the mint
    /// input role for a minted service, else its first `secrets` entry. `None`
    /// when it declares neither. A pure projection over the def — the SINGLE
    /// source of truth for "which vault role holds this service's secret", so a
    /// registry service and a vault-custom service resolve identically. Callers
    /// that only have a `service_id` and a registry go through
    /// [`service_env_key`]; callers that may face a custom service resolve the
    /// `ServiceDef` first (custom `.or_else(registry)`) and call this directly.
    pub fn env_role(&self) -> Option<String> {
        if let Some(r) = self.mint_input_role() {
            return Some(r);
        }
        self.service
            .secrets
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .map(|s| s.to_string())
    }
}

/// The `[auth]` section: which mechanism produces this service's wire
/// credential, discriminated by `type` — the same shape as OpenAPI's
/// `securitySchemes.type`. The rule that keeps this enum honest: a mechanism
/// whose wire format is STANDARDIZED (oauth2 — RFC 6749 fixes the vocabulary)
/// is declarative config; a bespoke envelope with no published vocabulary
/// (snaplii) is a code built-in and its variant carries no config, because
/// parameterizing an unstandardized wire would mean inventing a private DSL.
/// Absent `[auth]` = static (the 70% case): no mint, phantom substitutes the
/// stored secret verbatim.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthDef {
    /// OAuth 2.0 (RFC 6749): the stored refresh token mints access tokens at
    /// `token_url`. Fields are the RFC's own names, declared inline.
    Oauth2(OAuth2Def),
    /// Snaplii's bespoke key→JWT exchange (`auth::snaplii`). The envelope is
    /// unstandardized (JSON `{agent_id, api_key}` → JWT; no OAuth grant), so
    /// it lives in code; the variant is deliberately field-free.
    Snaplii(SnapliiDef),
}

/// `[auth] type = "snaplii"` carries no configuration — the exchange envelope
/// (URL, field names, response shape) is hard-coded in [`crate::auth::snaplii`]
/// and the input key is the service's first `secrets` role.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapliiDef {}

/// The oauth2 mechanism config. The section is SELF-SUFFICIENT: it
/// declares the endpoints + public client inline (`authorization_url`,
/// `token_url`, `client_id`, …) — the same shape whether it ships in-tree or is
/// user-authored (`aux.services`). There is no template/inheritance layer;
/// services sharing an OAuth client (the Google trio) simply repeat it.
/// `provider` is a pure display label ("Connect with Google").
///
/// Token slots use the RFC 6749 response field names: `refresh_token` maps the
/// durable refresh token to the vault secret KEY it is stored under (internal —
/// the mint reads it, no phantom exposes it); optional `id_token` maps a stored
/// OIDC id token likewise. The minted `access_token` is ephemeral (never
/// stored, never named) — it is what the default phantom resolves to. `exposes`
/// lists extra minted/derived roles surfaced as role-qualified phantoms (e.g.
/// openai-codex's `account_id`); `claims` maps such a role to its id_token
/// claim path (array of nested keys — a segment may itself contain dots or
/// slashes, e.g. a namespaced `https://api.openai.com/auth` claim). The flow
/// temps `code`/`code_verifier` are standard, not per-service — they live in
/// `aux.connecting.oauth2`, never here.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2Def {
    /// Pure display label for the frontend's connect button ("Connect with
    /// Google"). Carries NO configuration; absent reads as "custom".
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// RFC 6749 `refresh_token` → the vault secret KEY the durable refresh token
    /// is stored under (e.g. `GMAIL_REFRESH_TOKEN`). Named explicitly (not
    /// derived) so a service declaring more than one secret is unambiguous.
    pub refresh_token: String,
    /// RFC 6749 `id_token` → the vault secret KEY a stored OIDC id token is
    /// written under. Only for providers that return a durable id token; absent
    /// for the common access+refresh flow.
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub exposes: Vec<String>,
    /// `exposes` role → its claim path in the exchange's id_token payload, as an
    /// ARRAY of nested object keys (a plain string path would be ambiguous —
    /// OIDC namespace keys contain `.`/`/` themselves). A role with no mapping
    /// falls back to a top-level claim of the same name.
    #[serde(default)]
    pub claims: HashMap<String, Vec<String>>,

    // ── Inline endpoints + public client ──
    /// CONNECT step endpoint (user consent).
    #[serde(default)]
    pub authorization_url: Option<String>,
    /// REFRESH + code-exchange endpoint.
    #[serde(default)]
    pub token_url: Option<String>,
    /// OAuth client_id (a PUBLIC client's id — safe to declare in a recipe).
    #[serde(default)]
    pub client_id: Option<String>,
    /// OAuth client_secret. A literal secret in a definition is BY CONVENTION a
    /// PUBLIC client's (RFC 6749 §2.1) — non-confidential by the vendor's own
    /// design, like Google's Desktop client. A confidential secret must never
    /// sit in a recipe; that line is review-enforced (there is no client_type
    /// field to assert it — tooling stamped it automatically, so it proved
    /// nothing).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Whether the connect flow uses PKCE (RFC 7636). Defaults to `true`
    /// (every public client should).
    #[serde(default)]
    pub pkce: Option<bool>,
    /// The OAuth client's fixed redirect_uri. Falls back to
    /// [`DEFAULT_LOOPBACK_REDIRECT`].
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Body style for the `/token` call: `form` (default) or `json` (Anthropic).
    #[serde(default)]
    pub oauth_style: Option<String>,
    /// Extra static query params for the consent URL — the per-vendor quirks
    /// (Google's `access_type=offline`/`prompt=consent`, codex's
    /// `codex_cli_simplified_flow=true`). Reserved protocol params (client_id,
    /// redirect_uri, scope, state, response_type, code_challenge*) are rejected
    /// by the validator — these are ADDITIONS, never overrides.
    #[serde(default)]
    pub authorize_params: HashMap<String, String>,
    /// Extra params merged into the authorization_code exchange body (both
    /// form and json styles). The one placeholder a value may use is the
    /// literal `{state}`, replaced at exchange time with the consent `state`
    /// of the pending connect (a provider that echoes the consent state in
    /// the token body). Reserved protocol params (grant_type, code,
    /// code_verifier, client_id, client_secret, redirect_uri) are rejected by
    /// the validator — ADDITIONS, never overrides.
    #[serde(default)]
    pub token_params: HashMap<String, String>,
    /// Extra params merged into the refresh body. Static values only (no
    /// placeholders — there is no consent state at refresh time). Reserved:
    /// grant_type, refresh_token, client_id, client_secret.
    #[serde(default)]
    pub refresh_params: HashMap<String, String>,
    /// How the client authenticates at the token endpoint: `post` (default:
    /// client_id and client_secret in the body) or `basic`
    /// (`Authorization: Basic client_id:client_secret`, RFC 6749 §2.3.1, and
    /// neither in the body — the style some providers require).
    #[serde(default)]
    pub token_auth: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceMeta {
    pub id: String,
    pub name: String,
    /// Classification tags (lowercase-kebab, multiple allowed) — e.g. "ai",
    /// "app", "messaging", "payment". Replaces the old directory-derived single
    /// category. Dual use: browse/filter metadata on the registry wire, and
    /// policy tag-floor matching (`Policy.categories` keys; when several tags
    /// hit floors the most restrictive wins). Absent (per-vault custom
    /// services) = untagged: no tag floor applies, console buckets it as an
    /// app.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Anchored egress hosts — exact FQDNs or `*.suffix` wildcards (leftmost
    /// single label). The runtime anchor validates the destination against the
    /// exact entries (and pinned instances of the wildcards). Declared under the
    /// `[service]` table.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Stored secret role keys (`[A-Z0-9_]`). A phantom resolves to the value
    /// as-is; the injection SITE is the agent's (header/query/URL/Basic).
    /// Declared under the `[service]` table.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// If set, this service is grouped with the service whose id matches this value.
    /// Services sharing the same group are merged into one card in the UI.
    #[serde(default)]
    pub group: Option<String>,
    /// Optional, purely auxiliary: the page where a HUMAN mints/manages this
    /// service's secret (e.g. `https://crates.io/settings/tokens`). Pairs with
    /// `secrets` above. Display-only — consumers render it as a helper link
    /// (console "Open ... -> API tokens", CLI "Get a token: ..."); nothing ever
    /// FETCHES a secret from it, and it never participates in routing or
    /// policy. Must be http(s) when present (it is rendered as a link).
    #[serde(default)]
    pub secret_url: Option<String>,
    /// Help text returned by GET /{service}/help.
    /// Supports template variables: {{wallet.*}} resolved from vault service data.
    #[serde(default)]
    pub help: Option<String>,
    /// Activation mode: "auto" = starts automatically without credentials.
    /// Absent/None = requires user "connect" (provide API key / OAuth).
    #[serde(default)]
    pub activation: Option<String>,
    /// If true, exclude from `/registry` and `/v/{vid}/registry`. Use for
    /// services that are defined but not yet ready for agent discovery.
    #[serde(default)]
    pub hidden: bool,
}

/// The loopback redirect for desktop/PKCE OAuth clients when an `[oauth2]`
/// section doesn't pin its own `redirect_uri`. Matches the frontend
/// `DEFAULT_LOOPBACK_REDIRECT` so the consent request and the code→token
/// exchange always agree.
pub const DEFAULT_LOOPBACK_REDIRECT: &str = "http://127.0.0.1:8765/safeclaw/oauth/callback";

/// The loopback port of an OAuth redirect_uri — `Some(port)` only for an
/// `http://` URI whose host is a loopback NAME with an explicit port
/// (`http://127.0.0.1:8765/...`, `http://localhost:1455/...`). Anything else —
/// https, a real host, a default-port URI — is not a target our auto-catch
/// listener could serve, so `None`.
pub fn loopback_port(redirect_uri: &str) -> Option<u16> {
    let rest = redirect_uri.strip_prefix("http://")?;
    let authority = rest.split('/').next()?;
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        v6.split_once("]:")?
    } else {
        authority.rsplit_once(':')?
    };
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return None;
    }
    port.parse().ok()
}

/// A service's `[oauth2]` client/endpoint config with the defaults applied —
/// see `ServiceRegistry::resolve_oauth_config`.
#[derive(Debug, Clone)]
pub struct ResolvedOAuthConfig {
    pub token_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// The OAuth client's fixed redirect_uri (inline literal, or the loopback
    /// default). Sent in the daemon's code→token exchange so it matches the
    /// consent request the browser made.
    pub redirect_uri: String,
}

/// The OAuth wiring of a service's `[oauth2]` section, as broadcast on the
/// public `/registry` response — everything a frontend needs to START a
/// connect (consent URL) and to DISPLAY the wiring faithfully.
/// CONNECTIONS_AND_AUTH.md §4a.
///
/// This mirrors the definition 1:1 on purpose: a definition may only ever
/// contain PUBLIC-client material (a literal `client_secret` in a def is a
/// public client's by convention — see `OAuth2Def::client_secret`), so there
/// is nothing confidential to withhold — hiding fields here would only make
/// the console lie about what the toml says. The daemon still does the
/// code→token exchange locally; the browser only drives consent and seals the
/// resulting `{code, verifier}` into the vault.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectDescriptor {
    /// Display label ("Connect with Google"); "custom" when the def names none.
    pub provider: String,
    pub authorization_url: String,
    /// REFRESH + code-exchange endpoint (display/reference — the daemon uses it,
    /// the frontend never calls it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    pub client_id: String,
    /// The PUBLIC client's secret, when the def ships one (e.g. Google's
    /// Desktop client, non-confidential by design).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub pkce: bool,
    /// The OAuth client's fixed redirect_uri — the frontend builds the consent
    /// URL from this (not a hardcoded constant) so it always matches what the
    /// daemon sends at code→token exchange (CONNECTION_SCHEMA.md §5).
    pub redirect_uri: String,
    /// `/token` body style: `form` (default) or `json`.
    pub oauth_style: String,
    /// Extra static consent-URL query params (vendor quirks: Google's
    /// `access_type=offline`, codex's `codex_cli_simplified_flow=true`). The
    /// frontend appends these BEFORE setting the reserved protocol params, so
    /// they can never override client_id/redirect_uri/state/….
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub authorize_params: HashMap<String, String>,
}

// ── Request shapes: `[requests.<name>]` (request-model design §3) ──────────────

pub use crate::core::request::{BodyFormat, ReadPath, Unreadable};

/// One request shape, as the gate compiled it: which requests it reads
/// (`method`, `path` and `condition`, the selector a policy rule has), the
/// body format they are read in (`body`), which request values an approval
/// binds (`scope`), how the approval card phrases them (`consent`), and
/// which values carry encoded media (`encoded`).
#[derive(Debug, Clone)]
pub struct RequestShape {
    /// Which requests it reads ([`crate::core::selector`]).
    pub select: crate::core::selector::Select,
    /// AND-combined with the selector; it can't read `request.graphql`. One
    /// that errors doesn't select.
    pub condition: Option<crate::core::policy::Condition>,
    /// The server's body format (`body = "json" | "form" | "graphql" |
    /// "text"`, absent = `json`), never the caller's Content-Type.
    pub format: BodyFormat,
    /// The request paths whose values an approval covers, as written
    /// (`None`: absent, the whole request; `[]`: none beyond what is always
    /// covered). The token `request` stands for the whole request
    /// ([`Self::scope_whole`]).
    pub scope: Option<Vec<ReadPath>>,
    /// `scope` lists the token `request`: the whole request, plus the paths.
    pub scope_whole: bool,
    /// The approval card's phrasing: a template over request paths, with the
    /// `{{ x | filter }}` pipe syntax of git-integration's
    /// `{{ secret.X | basic }}` (the Liquid/Jinja convention):
    ///   - plain interpolation, `"Send {{ request.body.amount }} to {{ request.body.to }}"`;
    ///   - a rich renderer through a filter, `"{{ request.body.raw | email }}"`
    ///     (the console's `email` filter decodes a base64url message into a card).
    ///
    /// A filter names console code (declarative toml, code in the console,
    /// the same split as `[auth]`). Interpolated values are escaped by the
    /// renderer (they come from the agent).
    pub consent: Option<String>,
    /// The paths `consent` reads: always covered, so what the card phrases
    /// is what an approval covers.
    pub consent_reads: Vec<ReadPath>,
    /// Request paths whose string values carry encoded media, keyed by the
    /// path's text, in JSON Schema's own content keywords (2020-12 §8): a
    /// compiled-in definition's are covered by their content
    /// (`crate::approval::coverage`), a vault definition's are for display.
    pub encoded: std::collections::BTreeMap<String, Encoded>,
}

/// `encoded."<request path>" = { contentEncoding = …, contentMediaType = … }`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Encoded {
    #[serde(rename = "contentEncoding", skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(rename = "contentMediaType", skip_serializing_if = "Option::is_none")]
    pub content_media_type: Option<String>,
}

impl RequestShape {
    /// Whether an approval of a request this shape matched covers the whole
    /// request: `scope` absent, or listing the token `request`.
    pub fn covers_whole(&self) -> bool {
        self.scope.is_none() || self.scope_whole
    }

    /// What an approval of a request this shape matched covers, as text:
    /// `request` for the whole request, then the listed paths and what
    /// `consent` reads, sorted, each once. (A rule's condition reads join at
    /// the request.)
    pub fn covers(&self) -> Vec<String> {
        let mut paths: Vec<ReadPath> = self
            .scope
            .iter()
            .flatten()
            .chain(self.consent_reads.iter())
            .cloned()
            .collect();
        paths.sort();
        paths.dedup();
        self.covers_whole()
            .then(|| "request".to_string())
            .into_iter()
            .chain(paths.iter().map(ToString::to_string))
            .collect()
    }
}

/// One `{{ <request path> [| <filter>] }}` token of a consent template: the
/// path as written and the filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRef {
    pub path: String,
    pub filter: Option<String>,
}

/// The tokens of a consent template (`{{ request.body.raw | email }}`), in
/// order; `Err` when a `{{` is never closed. A filter is the name after the
/// last `|` (a header name may hold a `|` itself).
pub fn consent_refs(template: &str) -> Result<Vec<ConsentRef>, String> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err("an unclosed '{{'".into());
        };
        let inner = after[..end].trim();
        let is_name = |f: &str| !f.is_empty() && f.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let (path, filter) = match inner.rsplit_once('|') {
            Some((p, f)) if is_name(f.trim()) => (p.trim(), Some(f.trim().to_string())),
            _ => (inner, None),
        };
        out.push(ConsentRef {
            path: path.to_string(),
            filter,
        });
        rest = &after[end + 2..];
    }
    Ok(out)
}

/// A request read against a definition's `[requests]` shapes.
pub struct ReadRequest<'a> {
    /// The matched shape, `None` when none matched.
    pub scope: Option<RequestScope>,
    /// The request object, in the matched shape's body format.
    pub request: crate::core::request::Request<'a>,
    /// No shape matched, and a shape whose `method` and `path` selected the
    /// request has a condition that errored: an approval of it is
    /// single-use (a window would be the whole rule's, which is looser).
    pub errored: bool,
}

/// [`ServiceDef::read_request`] for a connection whose definition may be
/// missing (a raw connection named like nothing: no shapes).
pub fn read_request<'a>(
    def: Option<&ServiceDef>,
    input: crate::core::request::RequestInput<'a>,
) -> Result<ReadRequest<'a>, Unreadable> {
    use crate::core::request::Request;
    let mut errored = false;
    if let Some(def) = def {
        for name in &def.request_order {
            let Some(shape) = def.requests.get(name) else {
                continue;
            };
            let Some(params) = shape.select.exec(input.method, input.path) else {
                continue;
            };
            let request = Request::new(input, shape.format, params);
            if let Some(c) = &shape.condition {
                match c.eval(&request)? {
                    Some(true) => {}
                    Some(false) => continue,
                    None => {
                        errored = true;
                        continue;
                    }
                }
            }
            // Every value the consent reads is read now: one that can't be
            // read refuses the request before any decision.
            for path in shape.scope.iter().flatten().chain(shape.consent_reads.iter()) {
                request.value(path)?;
            }
            let scope = RequestScope {
                shape: name.clone(),
                consent: shape.consent.clone(),
                whole: shape.covers_whole(),
                listed: shape.scope.clone().unwrap_or_default(),
                consent_reads: shape.consent_reads.clone(),
                encoded: shape.encoded.clone(),
            };
            return Ok(ReadRequest {
                scope: Some(scope),
                request,
                errored: false,
            });
        }
    }
    Ok(ReadRequest {
        scope: None,
        request: Request::new(input, BodyFormat::Json, crate::core::selector::Params::new()),
        errored,
    })
}

/// The `[requests]` shape a request matched, as its approval covers it.
#[derive(Debug, Clone, Default)]
pub struct RequestScope {
    /// The matched shape's name (its `[requests.<name>]` key).
    pub shape: String,
    /// The shape's consent template.
    pub consent: Option<String>,
    /// The whole request is covered ([`RequestShape::covers_whole`]).
    pub whole: bool,
    /// The paths its `scope` lists.
    pub listed: Vec<ReadPath>,
    /// The paths its `consent` reads.
    pub consent_reads: Vec<ReadPath>,
    /// Its `encoded` declarations.
    pub encoded: std::collections::BTreeMap<String, Encoded>,
}

/// How much of a GraphQL request's calls `request.graphql.calls` shows
/// (graphql.rs `calls_var`).
pub(crate) const BOUND_VALUE_CAP: usize = 8 * 1024;

// ── Vault-custom definitions ──────────────────────────────────────────────────

/// Why a vault service entry named `"<id> (conflict copy)"` is not loaded:
/// the sync kept a second version of `<id>` beside the first.
/// Why an installed service is skipped while the vault's owner switch is off.
pub const INSTALLED_OFF_REASON: &str = "installed services are off for this vault";

/// Why `sc service add` / `update` is refused while the owner switch is off.
pub const INSTALLED_OFF_MSG: &str = "Installed services are off for this vault. A vault owner can turn them on in the console: Settings → Services.";

pub const CONFLICT_COPY_REASON: &str = "a conflict copy: the service was changed in two places at once and both versions were kept; keep the one you want in the console";

/// A vault's own service definitions (`aux.services`, id → stored entry) as
/// the daemon brokers them: every entry the gate admits under its storage key
/// (so the key is the declared id), with its stored policy.toml if any, and
/// whose id is not a compiled one (a custom def never shadows a built-in),
/// with its policy reduced to the parts that tighten
/// ([`ServiceDef::for_vault`]). An installed entry (stored with a source)
/// loads only while the owner allows installed services (`allow_installed`,
/// [`crate::core::policy::Policy::allow_installed_services`]). The skipped ids
/// come back with the reason. The unlock bootstrap loads exactly this set, so
/// every other reader of `aux.services` (the proxy, the console's registry
/// view) agrees with what is enforced.
pub fn vault_custom_services(
    aux_services: &std::collections::BTreeMap<String, source::StoredService>,
    allow_installed: bool,
    reg: &ServiceRegistry,
) -> (HashMap<String, ServiceDef>, Vec<(String, String)>) {
    let mut defs = HashMap::new();
    let mut skipped = Vec::new();
    for (id, entry) in aux_services {
        if crate::storage::item::is_conflict_copy_name(id) {
            skipped.push((id.clone(), CONFLICT_COPY_REASON.to_string()));
            continue;
        }
        if !allow_installed && entry.is_installed() {
            skipped.push((id.clone(), INSTALLED_OFF_REASON.to_string()));
            continue;
        }
        if reg.get(id).is_some() {
            skipped.push((id.clone(), "shadows a built-in id".to_string()));
            continue;
        }
        match entry.admit(id) {
            Ok(def) => {
                defs.insert(id.clone(), def.for_vault().0);
            }
            Err(problems) => {
                skipped.push((id.clone(), format!("rejected: {}", problems.join("; "))))
            }
        }
    }
    (defs, skipped)
}

/// The definitions a vault's connections resolve against: the vault's own
/// (custom) defs first, else the compiled registry, the same lookup the proxy
/// uses for a connection's service.
#[derive(Clone, Copy)]
pub struct ServiceDefs<'a> {
    pub reg: &'a ServiceRegistry,
    pub custom: &'a HashMap<String, ServiceDef>,
}

impl<'a> ServiceDefs<'a> {
    pub fn get(&self, id: &str) -> Option<&'a ServiceDef> {
        self.custom.get(id).or_else(|| self.reg.get(id))
    }

    /// Every service id a connection could name (compiled ∪ custom), sorted
    /// and deduplicated.
    pub fn ids(&self) -> Vec<&'a str> {
        let mut ids: Vec<&'a str> = self
            .reg
            .iter_sorted()
            .into_iter()
            .map(|(id, _)| id)
            .chain(self.custom.keys().map(String::as_str))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

// ── ServiceRegistry ───────────────────────────────────────────────────────────

pub struct ServiceRegistry {
    /// Every definition the gate admitted, with its policy (policy.toml or
    /// inline) compiled inside it.
    services: HashMap<String, ServiceDef>,
}

/// Read a definition file, refusing one over the size limit without reading
/// it whole (the gate re-checks the bytes it is given).
fn read_capped(path: &std::path::Path) -> Result<String, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    file.take(limits::MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() > limits::MAX_FILE_BYTES {
        return Err(format!(
            "larger than the {}-byte limit",
            limits::MAX_FILE_BYTES
        ));
    }
    String::from_utf8(buf).map_err(|_| "not UTF-8".to_string())
}

/// One service directory's files: (id = directory name, service.toml,
/// optional policy.toml).
type ServiceDirFiles = (
    String,
    Result<String, String>,
    Option<Result<String, String>>,
);

impl ServiceRegistry {
    /// Load all service definitions in priority layers, each through the gate
    /// (a definition and its policy.toml are admitted or skipped together,
    /// never mixed across layers):
    /// 1. Compiled-in defaults (always loaded as base)
    /// 2. $SPROTT_DATA/services/ (runtime override for dev/deployment)
    /// 3. ~/.sprott/services/ (user-installed services, highest priority)
    pub fn load() -> Self {
        let mut services = HashMap::new();
        // id → the policy.toml text its admitted definition carries, so an
        // override directory without a policy.toml keeps the policy of the
        // definition it overrides.
        let mut policy_texts = HashMap::new();

        // Layer 1: compiled-in defaults (always loaded as base)
        Self::load_compiled_defaults(&mut services, &mut policy_texts);

        // Layer 2: $SPROTT_DATA/services/ override
        for files in Self::discover_service_dirs() {
            Self::admit_dir(files, &mut services, &mut policy_texts);
        }

        // Layer 3: ~/.sprott/services/ (user-installed, overrides everything)
        Self::load_user_services(&mut services, &mut policy_texts);

        tracing::info!("Loaded {} service definitions", services.len());
        Self { services }
    }

    /// Build a registry from ONLY the compiled-in (in-tree) services — no
    /// `$SPROTT_DATA` / user-installed overrides, no filesystem I/O. Used by
    /// offline tooling (`sc registry`) and CI to render the exact catalog a
    /// freshly-built daemon serves, without booting a server or reading any
    /// deployment state.
    pub fn compiled_only() -> Self {
        let mut services = HashMap::new();
        Self::load_compiled_defaults(&mut services, &mut HashMap::new());
        Self { services }
    }

    /// Admit one service directory's files through the gate, keyed by the
    /// directory name; a definition that fails is logged and skipped. A
    /// directory with no policy.toml and no inline `[policy]` that overrides
    /// a definition which had a policy.toml keeps that policy (admitted again,
    /// paired with the new service.toml, so every cross-check reruns); if the
    /// two no longer fit, the override is skipped and the earlier definition
    /// stays. True when the directory's definition was admitted.
    fn admit_dir(
        (id, service, policy): ServiceDirFiles,
        services: &mut HashMap<String, ServiceDef>,
        policy_texts: &mut HashMap<String, String>,
    ) -> bool {
        let shown = crate::util::terminal_safe(&id).into_owned();
        let skip = |problems: Vec<String>| {
            tracing::warn!("service {} skipped: {}", shown, problems.join("; "));
            false
        };
        let svc = match service {
            Ok(s) => s,
            Err(e) => return skip(vec![e]),
        };
        let own_policy = match policy {
            Some(Ok(p)) => Some(p),
            Some(Err(e)) => return skip(vec![format!("policy.toml: {}", e)]),
            None => None,
        };
        if let Some(p) = own_policy {
            return match gate::admit(Some(&id), &svc, Some(&p)) {
                Ok(def) => {
                    services.insert(id.clone(), def);
                    policy_texts.insert(id, p);
                    true
                }
                Err(problems) => skip(problems),
            };
        }
        let def = match gate::admit(Some(&id), &svc, None) {
            Ok(def) => def,
            Err(problems) => return skip(problems),
        };
        let kept = policy_texts
            .get(&id)
            .filter(|_| def.policy.is_none())
            .cloned();
        let Some(kept) = kept else {
            // Its own inline policy, or nothing to keep.
            policy_texts.remove(&id);
            services.insert(id, def);
            return true;
        };
        match gate::admit(Some(&id), &svc, Some(&kept)) {
            Ok(def) => {
                tracing::info!(
                    "service {}: the override has no policy.toml; keeping the policy of the definition it overrides",
                    shown
                );
                services.insert(id, def);
                true
            }
            Err(problems) => {
                tracing::warn!(
                    "service {} override skipped: it has no policy.toml and does not fit the policy it would keep ({}); the earlier definition stays",
                    shown,
                    problems.join("; ")
                );
                false
            }
        }
    }

    /// One directory's files, read under the size limit.
    fn read_dir_files(id: String, dir: &std::path::Path) -> ServiceDirFiles {
        let service =
            read_capped(&dir.join("service.toml")).map_err(|e| format!("service.toml: {}", e));
        let policy_path = dir.join("policy.toml");
        let policy = policy_path.exists().then(|| read_capped(&policy_path));
        (id, service, policy)
    }

    fn discover_service_dirs() -> Vec<ServiceDirFiles> {
        let mut results = vec![];

        // Check $SPROTT_DATA/services/ first (runtime override)
        if let Ok(data) = std::env::var("SPROTT_DATA") {
            let dir = std::path::Path::new(&data).join("services");
            if dir.is_dir() {
                Self::scan_dir(&dir, &mut results);
                if !results.is_empty() {
                    return results;
                }
            }
        }

        // Fallback: relative to binary (for dev / standalone installs)
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let dir = parent.join("services");
                if dir.is_dir() {
                    Self::scan_dir(&dir, &mut results);
                    if !results.is_empty() {
                        return results;
                    }
                }
            }
        }

        results
    }

    /// Scan for service.toml and policy.toml files. Supports both flat and nested layouts.
    fn scan_dir(base: &std::path::Path, results: &mut Vec<ServiceDirFiles>) {
        let Ok(entries) = std::fs::read_dir(base) else {
            return;
        };
        let dir_id = |p: &std::path::Path| {
            p.file_name()
                .and_then(|n| n.to_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Check if this directory itself has service.toml (flat layout)
            if path.join("service.toml").exists() {
                if let Some(id) = dir_id(&path) {
                    results.push(Self::read_dir_files(id, &path));
                }
                continue;
            }

            // Otherwise, scan one level deeper — tolerant reader for the
            // retired nested services/{category}/{id}/ layout (pre-tags
            // user-installed dirs may still carry it).
            let Ok(sub_entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for sub_entry in sub_entries.flatten() {
                let sub_path = sub_entry.path();
                if sub_path.is_dir() && sub_path.join("service.toml").exists() {
                    if let Some(id) = dir_id(&sub_path) {
                        results.push(Self::read_dir_files(id, &sub_path));
                    }
                }
            }
        }
    }

    /// Load user-installed services from ~/.sprott/services/.
    /// Skips directories with a `.disabled` marker file.
    fn load_user_services(
        services: &mut HashMap<String, ServiceDef>,
        policy_texts: &mut HashMap<String, String>,
    ) {
        let user_dir = match user_services_dir() {
            Some(d) if d.is_dir() => d,
            _ => return,
        };

        let Ok(entries) = std::fs::read_dir(&user_dir) else {
            return;
        };
        let mut count = 0u32;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Skip disabled services
            if path.join(".disabled").exists() {
                continue;
            }

            let id = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            if !path.join("service.toml").exists() {
                continue;
            }
            if Self::admit_dir(Self::read_dir_files(id, &path), services, policy_texts) {
                count += 1;
            }
        }
        if count > 0 {
            tracing::info!(
                "Loaded {} user-installed services from {}",
                count,
                user_dir.display()
            );
        }
    }

    /// Compiled-in service definitions, admitted through the same gate as
    /// every other source (the compiled-defs tests hold each one to it).
    fn load_compiled_defaults(
        services: &mut HashMap<String, ServiceDef>,
        policy_texts: &mut HashMap<String, String>,
    ) {
        let policies: HashMap<&str, &str> = crate::generated_services::compiled_policy_tomls()
            .iter()
            .copied()
            .collect();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            match gate::admit(Some(id), toml_str, policies.get(id).copied()) {
                Ok(def) => {
                    services.insert(id.to_string(), def);
                    if let Some(p) = policies.get(id) {
                        policy_texts.insert(id.to_string(), p.to_string());
                    }
                }
                Err(problems) => {
                    tracing::error!("compiled service {} rejected: {}", id, problems.join("; "))
                }
            }
        }
    }

    /// Resolve a service by name. Returns None if not found.
    pub fn get(&self, service_name: &str) -> Option<&ServiceDef> {
        self.services.get(service_name)
    }

    /// Iterate all loaded service definitions, sorted by id for stable ordering.
    /// Used by the `/v/{vid}/registry` endpoint.
    pub fn iter_sorted(&self) -> Vec<(&str, &ServiceDef)> {
        let mut entries: Vec<(&str, &ServiceDef)> =
            self.services.iter().map(|(k, v)| (k.as_str(), v)).collect();
        entries.sort_by_key(|(k, _)| *k);
        entries
    }

    /// Classification tags for a service; empty for unknown ids and untagged
    /// (custom) services — no tag floor applies then, only the global floor.
    pub fn service_tags(&self, service_name: &str) -> &[String] {
        self.services
            .get(service_name)
            .map(|d| d.service.tags.as_slice())
            .unwrap_or(&[])
    }

    /// The stored secret role that backs a **registry** service's credential.
    /// Thin wrapper over [`ServiceDef::env_role`] — a registry-only lookup.
    /// A connection may reference a vault-custom service (`aux.services`) that
    /// is NOT in the compiled registry; such a caller must resolve the
    /// `ServiceDef` custom-awarely (registry `.or_else(custom_service)`) and
    /// call `def.env_role()` directly, or it will miss the custom def and fall
    /// back to the connection id — the bug this split removes.
    pub fn service_env_key(&self, service_id: &str) -> Option<String> {
        self.services.get(service_id).and_then(|d| d.env_role())
    }

    /// The `/token` body style for a service's `[oauth2]`: `oauth_style`,
    /// defaulting to `form`.
    pub fn oauth_style(&self, oauth: &OAuth2Def) -> OAuthStyle {
        match oauth.oauth_style.as_deref() {
            Some("json") => OAuthStyle::Json,
            _ => OAuthStyle::Form,
        }
    }

    /// How the client authenticates at the token endpoint: `token_auth`,
    /// defaulting to `post`.
    pub fn token_auth(&self, oauth: &OAuth2Def) -> crate::auth::oauth2::TokenAuth {
        match oauth.token_auth.as_deref() {
            Some("basic") => crate::auth::oauth2::TokenAuth::Basic,
            _ => crate::auth::oauth2::TokenAuth::Post,
        }
    }

    /// A service's `[oauth2]` client/endpoint config with the defaults applied
    /// (loopback redirect_uri). A missing field is `None` (caller decides
    /// whether it's fatal).
    /// Ports the on-demand OAuth auto-catch listener may bind: the loopback
    /// targets announced by LOCALLY-INSTALLED service defs (compiled-in +
    /// `$SPROTT_DATA` + `~/.sprott/services`) plus the canonical default —
    /// today `{8765, 1455}` (google-suite default + openai_codex's registered
    /// callback). This is the SECURITY BOUNDARY for which ports a connect can
    /// open: vault-synced custom defs (`aux.services`) are deliberately NOT
    /// consulted, or vault write access would escalate into "bind arbitrary
    /// local ports on every device". A custom service still gets auto-catch —
    /// exactly when its redirect lands on a target some local def already
    /// announces (in practice: the canonical 8765 the custom form defaults to).
    pub fn loopback_allowlist(&self) -> std::collections::HashSet<u16> {
        let mut allowed: std::collections::HashSet<u16> = loopback_port(DEFAULT_LOOPBACK_REDIRECT)
            .into_iter()
            .collect();
        for def in self.services.values() {
            if let Some(oauth) = def.oauth2() {
                if let Some(port) = loopback_port(&self.resolve_oauth_config(oauth).redirect_uri) {
                    allowed.insert(port);
                }
            }
        }
        allowed
    }

    pub fn resolve_oauth_config(&self, oauth: &OAuth2Def) -> ResolvedOAuthConfig {
        ResolvedOAuthConfig {
            token_url: oauth.token_url.clone(),
            client_id: oauth.client_id.clone(),
            client_secret: oauth.client_secret.clone(),
            redirect_uri: oauth
                .redirect_uri
                .clone()
                .unwrap_or_else(|| DEFAULT_LOOPBACK_REDIRECT.to_string()),
        }
    }

    /// The public OAuth wiring broadcast for `service_id` — see
    /// [`ConnectDescriptor`]. `None` when the service isn't oauth2 or its
    /// section lacks an authorization_url + client_id.
    pub fn connect_descriptor(&self, service_id: &str) -> Option<ConnectDescriptor> {
        let def = self.services.get(service_id)?;
        let oauth = def.oauth2()?;
        self.connect_descriptor_for(oauth)
    }

    /// [`Self::connect_descriptor`] for an `[oauth2]` section directly — shared
    /// with per-vault custom services that don't live in `self.services`.
    pub fn connect_descriptor_for(&self, oauth: &OAuth2Def) -> Option<ConnectDescriptor> {
        Some(ConnectDescriptor {
            provider: oauth
                .provider
                .clone()
                .unwrap_or_else(|| "custom".to_string()),
            authorization_url: oauth.authorization_url.clone()?,
            token_url: oauth.token_url.clone(),
            client_id: oauth.client_id.clone()?,
            client_secret: oauth.client_secret.clone(),
            scopes: oauth.scopes.clone(),
            pkce: oauth.pkce.unwrap_or(true),
            redirect_uri: oauth
                .redirect_uri
                .clone()
                .unwrap_or_else(|| DEFAULT_LOOPBACK_REDIRECT.to_string()),
            oauth_style: match oauth.oauth_style.as_deref() {
                Some("json") => "json".to_string(),
                _ => "form".to_string(),
            },
            authorize_params: oauth.authorize_params.clone(),
        })
    }

    /// A service's default read/write floor: its policy's `[default]`
    /// (policy.toml) or `[policy.levels]` (inline).
    pub fn default_policy_levels(&self, service_name: &str) -> Option<crate::core::policy::Levels> {
        self.services
            .get(service_name)?
            .policy
            .as_ref()?
            .defaults
            .clone()
    }

    /// A service's rules (policy.toml `[[rule]]` or inline `[[policy.rules]]`),
    /// compiled at the gate. `None` when it declares none.
    pub fn default_policy_rules(
        &self,
        service_name: &str,
    ) -> Option<&[crate::core::policy::PolicyRule]> {
        let rules = &self.services.get(service_name)?.policy.as_ref()?.rules;
        (!rules.is_empty()).then_some(rules.as_slice())
    }

    /// Return all service definitions (for catalog/UI use).
    pub fn all(&self) -> &HashMap<String, ServiceDef> {
        &self.services
    }
}

// ── User service directory ───────────────────────────────────────────────────

/// Returns ~/.sprott/services/ path, or None if home dir can't be resolved.
pub fn user_services_dir() -> Option<std::path::PathBuf> {
    crate::names::data_dir().map(|d| d.join("services"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::AccessLevel;
    use crate::core::request::RequestInput;

    fn reg(services: HashMap<String, ServiceDef>) -> ServiceRegistry {
        ServiceRegistry { services }
    }

    fn def(toml: &str) -> ServiceDef {
        gate::admit_toml(toml).unwrap_or_else(|e| panic!("fixture rejected: {:?}", e))
    }

    // ── inline [policy] (the policy.toml alternative) ────────────────────────

    const INLINE: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_KEY"]
[policy.levels]
read = "deny"
write = "ask-always"
[[policy.rules]]
method = "delete"
path_exact = "/v1/things/"
level = "ask"
"#;

    #[test]
    fn inline_policy_compiles_levels_and_rules() {
        let d = def(INLINE);
        let p = d.policy.as_ref().expect("inline policy");
        let sl = p.defaults.as_ref().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Deny));
        assert_eq!(sl.write, Some(AccessLevel::AskAlways));
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].select.display(), ["DELETE /v1/things"]);
        assert_eq!(p.rules[0].level, Some(AccessLevel::Ask));
        // A lowercase method word is a method at this rule source too.
        let mut services = HashMap::new();
        services.insert("acme".to_string(), d);
        let r = reg(services);
        let rules = r.default_policy_rules("acme").unwrap().to_vec();
        let access = crate::core::policy::evaluate(&crate::core::request::Request::bare("DELETE", "/v1/things"), Some(&rules), r.default_policy_levels("acme").as_ref(), &crate::core::policy::Policy::default(), &[]).unwrap();
        assert_eq!(access, AccessLevel::Ask);
    }

    #[test]
    fn inline_policy_never_drops_a_rule() {
        // path_suffix was skipped by the old converter; now the whole
        // definition is rejected, as is an unknown level or field.
        for bad in [
            INLINE.replace("path_exact = \"/v1/things/\"", "path_suffix = \"/things\""),
            INLINE.replace("level = \"ask\"", "level = \"sometimes\""),
            INLINE.replace("read = \"deny\"", "read = \"nope\""),
            INLINE.replace("level = \"ask\"", "level = \"ask\"\nlabel = \"x\""),
            INLINE.replace("method = \"delete\"", "method = \"DEL ETE\""),
        ] {
            assert!(gate::admit_toml(&bad).is_err(), "{bad}");
        }
        // Declared twice (inline and policy.toml): rejected, never mixed.
        let file = "[default]\nread = \"allow\"\n";
        let e = gate::admit(None, INLINE, Some(file)).unwrap_err();
        assert!(e.iter().any(|m| m.contains("declared twice")), "{e:?}");
    }

    // ── a vault definition's policy only tightens ───────────────────────────

    const VAULT_DEF: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_KEY"]
[policy.levels]
read = "allow"
write = "ask"
ttl = 60
[[policy.rules]]
method = "DELETE"
path_exact = "/v1/things"
level = "deny"
[[policy.rules]]
method = "POST"
path_exact = "/v1/pay"
level = "allow"
"#;

    #[test]
    fn vault_definitions_keep_only_the_parts_that_tighten() {
        let (d, notes) = def(VAULT_DEF).for_vault();
        let p = d.policy.as_ref().unwrap();
        assert_eq!(p.rules.len(), 1, "the allow rule is not applied");
        assert_eq!(p.rules[0].level, Some(AccessLevel::Deny));
        let lv = p.defaults.as_ref().unwrap();
        assert_eq!(lv.read, None, "read = allow is not applied");
        assert_eq!(lv.write, Some(AccessLevel::Ask));
        assert_eq!(lv.ttl, Some(60));
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("#2 (allow)")), "{notes:?}");
        assert!(
            notes.iter().any(|n| n.contains("default read = allow")),
            "{notes:?}"
        );
        // The registry reader applies it, so the console shows what is enforced.
        let mut aux = std::collections::BTreeMap::new();
        aux.insert("acme".to_string(), VAULT_DEF.into());
        let (defs, _) = vault_custom_services(&aux, true, &ServiceRegistry::compiled_only());
        assert_eq!(defs["acme"].policy.as_ref().unwrap().rules.len(), 1);
        // Nothing that tightens: no policy at all.
        let loose = VAULT_DEF
            .replace("level = \"deny\"", "level = \"allow\"")
            .replace("write = \"ask\"", "write = \"allow\"");
        let (d, notes) = def(&loose).for_vault();
        assert!(d.policy.is_none());
        assert_eq!(notes.len(), 5, "{notes:?}");
    }

    #[test]
    fn override_without_policy_keeps_the_overridden_policy() {
        let compiled = ServiceRegistry::compiled_only();
        let mut services = compiled.services.clone();
        let mut texts: HashMap<String, String> = crate::generated_services::compiled_policy_tomls()
            .iter()
            .map(|(id, t)| (id.to_string(), t.to_string()))
            .collect();
        let svc = crate::generated_services::compiled_service_tomls()
            .iter()
            .find(|(id, _)| *id == "github")
            .unwrap()
            .1
            .replace("hosts = [", "hosts = [\"git.acme.example\", ");
        assert!(ServiceRegistry::admit_dir(
            ("github".into(), Ok(svc.clone()), None),
            &mut services,
            &mut texts
        ));
        let gh = &services["github"];
        assert!(gh.service.hosts.iter().any(|h| h == "git.acme.example"));
        let rules = &gh.policy.as_ref().expect("compiled policy kept").rules;
        assert!(rules.iter().any(|r| r.id.as_deref() == Some("delete-repo")));
        // An override whose own policy.toml is given uses it instead.
        let own =
            "[[rule]]\nid = \"only\"\nlabel = \"Only\"\nmethod = \"DELETE\"\npath = \"/x\"\nlevel = \"deny\"\n";
        assert!(ServiceRegistry::admit_dir(
            ("github".into(), Ok(svc.clone()), Some(Ok(own.to_string()))),
            &mut services,
            &mut texts
        ));
        assert_eq!(services["github"].policy.as_ref().unwrap().rules.len(), 1);
        // An override that no longer fits the kept policy is skipped whole.
        let mut services = compiled.services.clone();
        let mut texts: HashMap<String, String> = [(
            "github".to_string(),
            "[[rule]]\nid = \"w\"\nlabel = \"W\"\nmethod = \"POST\"\npath = \"/x\"\nwhen = \"vars.amount > 1\"\nlevel = \"deny\"\n".to_string(),
        )]
        .into_iter()
        .collect();
        assert!(!ServiceRegistry::admit_dir(
            ("github".into(), Ok(svc), None),
            &mut services,
            &mut texts
        ));
        assert!(!services["github"]
            .service
            .hosts
            .iter()
            .any(|h| h == "git.acme.example"));
    }

    #[test]
    fn compiled_circleci_policy_covers_every_slug_form() {
        use crate::core::policy::{evaluate, Policy};
        let r = ServiceRegistry::compiled_only();
        let rules = r.default_policy_rules("circleci").unwrap().to_vec();
        let eval = |m: &str, p: &str| {
            evaluate(&crate::core::request::Request::bare(m, p), Some(&rules), r.default_policy_levels("circleci").as_ref(), &Policy::default(), &["dev".into()]).unwrap()
        };
        for slug in [
            "gh%2Forg%2Frepo",
            "gh/org%2Frepo",
            "gh%2Forg/repo",
            "gh/org/repo",
            "circleci/o-id/p-id",
        ] {
            for (m, tail) in [
                ("POST", "pipeline"),
                ("POST", "pipeline/run"),
                ("POST", "envvar"),
                ("POST", "schedule"),
                ("POST", "checkout-key"),
                ("PATCH", "settings"),
            ] {
                let path = format!("/api/v2/project/{}/{}", slug, tail);
                assert_eq!(eval(m, &path), AccessLevel::Ask, "{m} {path}");
            }
            // API v1.1 on the same host.
            for (m, tail) in [
                ("POST", ""),
                ("POST", "/build"),
                ("POST", "/tree/main"),
                ("POST", "/tree/feature%2Fx"),
                ("POST", "/tree/feature/x"),
                ("POST", "/42/retry"),
                ("POST", "/42/ssh"),
                ("POST", "/42/ssh-users"),
                ("POST", "/envvar"),
                ("POST", "/ssh-key"),
                ("POST", "/checkout-key"),
            ] {
                let path = format!("/api/v1.1/project/{}{}", slug, tail);
                assert_eq!(eval(m, &path), AccessLevel::Ask, "{m} {path}");
            }
            // Reads and removals ride the floor.
            let pipelines = format!("/api/v2/project/{}/pipeline", slug);
            assert_eq!(eval("GET", &pipelines), AccessLevel::Allow);
            let settings = format!("/api/v2/project/{}/settings", slug);
            assert_eq!(eval("GET", &settings), AccessLevel::Allow);
            let envvar = format!("/api/v2/project/{}/envvar/NAME", slug);
            assert_eq!(eval("DELETE", &envvar), AccessLevel::Allow);
            let v1_envvar = format!("/api/v1.1/project/{}/envvar/NAME", slug);
            assert_eq!(eval("DELETE", &v1_envvar), AccessLevel::Allow);
            assert_eq!(eval("GET", &v1_envvar), AccessLevel::Allow);
        }
        for (m, p) in [
            ("PUT", "/api/v2/context/c-1/environment-variable/TOKEN"),
            ("POST", "/api/v2/pipeline/continue"),
            ("POST", "/api/v2/workflow/w-1/rerun"),
            ("PATCH", "/api/v2/schedule/s-1"),
            (
                "POST",
                "/api/v2/projects/p-1/pipeline-definitions/d-1/triggers",
            ),
            ("PATCH", "/api/v2/projects/p-1/triggers/t-1"),
            ("POST", "/api/v2/workflow/w-1/approve/a-1"),
            ("POST", "/api/v2/projects/p-1/rollback"),
            ("POST", "/api/v2/projects/p-1/pipeline-definitions"),
            ("PATCH", "/api/v2/projects/p-1/pipeline-definitions/d-1"),
            ("PATCH", "/api/v2/org/o-1/oidc-custom-claims"),
            ("PATCH", "/api/v2/org/o-1/project/p-1/oidc-custom-claims"),
            ("DELETE", "/api/v2/context/c-1/restrictions/r-1"),
        ] {
            assert_eq!(eval(m, p), AccessLevel::Ask, "{m} {p}");
        }
        for (m, p) in [
            ("GET", "/api/v2/me"),
            ("GET", "/api/v2/projects/p-1/pipeline-definitions"),
            ("GET", "/api/v2/org/o-1/oidc-custom-claims"),
            ("POST", "/api/v2/context/c-1/restrictions"),
        ] {
            assert_eq!(eval(m, p), AccessLevel::Allow, "{m} {p}");
        }
    }

    // ── v4 service.toml parsing ──────────────────────────────────────────────

    #[test]
    fn parse_direct_service_hosts_and_secrets() {
        let toml_str = r#"
[service]
id = "github"
name = "GitHub"

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def = def(toml_str);
        assert_eq!(def.service.id, "github");
        assert_eq!(def.service.hosts, vec!["api.github.com", "github.com"]);
        assert_eq!(def.service.secrets, vec!["GITHUB_TOKEN"]);
        assert!(def.auth.is_none());
    }

    #[test]
    fn parse_oauth2_service() {
        let toml_str = r#"
[service]
id = "gmail"
name = "Gmail"

hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]

[auth]
type = "oauth2"
provider = "google"
scopes = ["https://www.googleapis.com/auth/gmail.send"]
refresh_token = "GMAIL_REFRESH_TOKEN"
authorization_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "public-client"
"#;
        let def = def(toml_str);
        let o = def.oauth2().unwrap();
        assert_eq!(o.provider.as_deref(), Some("google"));
        assert_eq!(o.refresh_token, "GMAIL_REFRESH_TOKEN");
        assert_eq!(o.scopes.len(), 1);
        assert!(o.exposes.is_empty());
    }

    #[test]
    fn parse_oauth2_exposes() {
        let toml_str = r#"
[service]
id = "openai_codex"
name = "OpenAI Codex"

hosts = ["api.openai.com"]
secrets = ["OPENAI_CODEX_REFRESH_TOKEN"]

[auth]
type = "oauth2"
provider = "openai"
refresh_token = "OPENAI_CODEX_REFRESH_TOKEN"
exposes = ["account_id"]
authorization_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "public-client"
"#;
        let def = def(toml_str);
        assert_eq!(def.oauth2().unwrap().exposes, vec!["account_id"]);
    }

    #[test]
    fn parse_auth_snaplii_and_mint_roles() {
        let toml_str = r#"
[service]
id = "snaplii"
name = "Snaplii"
hosts = ["aipayment.snaplii.com"]
secrets = ["SNAPLII_API_KEY"]

[auth]
type = "snaplii"
"#;
        let def = def(toml_str);
        assert!(matches!(def.auth, Some(AuthDef::Snaplii(_))));
        assert!(def.oauth2().is_none());
        // The mint input (and thus env_role / never-injectable role) is the
        // first secrets entry.
        assert_eq!(def.mint_input_role().as_deref(), Some("SNAPLII_API_KEY"));
        assert_eq!(def.env_role().as_deref(), Some("SNAPLII_API_KEY"));
    }

    #[test]
    fn auth_section_rejects_unknown_type_and_legacy_oauth2_section() {
        // Unknown mechanism type fails at parse, never a silent static fallback.
        let bad = r#"
[service]
id = "x"
name = "X"
hosts = ["x.example.com"]

[auth]
type = "sigv4-someday"
"#;
        assert!(gate::admit_toml(bad).is_err());

        // The retired section name is an unknown field at the top level. The
        // error points at it by line and column; definition text is never
        // echoed.
        let legacy = r#"
[service]
id = "x"
name = "X"
hosts = ["x.example.com"]

[oauth2]
refresh_token = "K"
"#;
        let err = gate::admit_toml(legacy).unwrap_err().join("; ");
        assert!(
            err.contains("unknown field at line 7") && !err.contains("oauth2"),
            "error should point at the offending section: {}",
            err
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_tool_and_v3_sections() {
        // A tool-named section is rejected — sections are auth MECHANISMS only.
        let git = r#"
[service]
id = "x"
name = "X"
hosts = ["x.com"]
[git]
helper = "sc"
"#;
        assert!(gate::admit_toml(git).is_err(), "[git] must be rejected");
        // A stale v3 `[[upstream]]` is rejected too.
        let v3 = r#"
[service]
id = "x"
name = "X"
[[upstream]]
id = "default"
url = "https://x.com"
"#;
        assert!(
            gate::admit_toml(v3).is_err(),
            "[[upstream]] must be rejected"
        );
    }

    #[test]
    fn oauth2_secret_drives_service_env_key() {
        let toml_str = r#"
[service]
id = "gmail"
name = "Gmail"
hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]
[auth]
type = "oauth2"
provider = "google"
refresh_token = "GMAIL_REFRESH_TOKEN"
authorization_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "public-client"
"#;
        let def = def(toml_str);
        let mut services = HashMap::new();
        services.insert("gmail".into(), def);
        let r = reg(services);
        assert_eq!(
            r.service_env_key("gmail").as_deref(),
            Some("GMAIL_REFRESH_TOKEN")
        );
    }

    #[test]
    fn direct_secret_drives_service_env_key() {
        let toml_str = r#"
[service]
id = "github"
name = "GitHub"
hosts = ["api.github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def = def(toml_str);
        let mut services = HashMap::new();
        services.insert("github".into(), def);
        let r = reg(services);
        assert_eq!(r.service_env_key("github").as_deref(), Some("GITHUB_TOKEN"));
    }

    #[test]
    fn custom_def_env_role_resolves_when_registry_misses() {
        // A vault-custom `[oauth2]` service (e.g. a user-added "gcp"): NOT in the
        // compiled registry. `service_env_key(id)` is a registry-only lookup, so
        // it returns None and the ask/approve path would fall back to the
        // connection id as the op `target` — the "secret 'gcp' not found" bug.
        // Resolving the def and calling `env_role()` directly is source-agnostic
        // and names the real refresh key.
        let toml_str = r#"
[service]
id = "gcp"
name = "Google Cloud"
hosts = ["compute.googleapis.com"]
secrets = ["GCP_REFRESH_TOKEN"]
[auth]
type = "oauth2"
provider = "google"
refresh_token = "GCP_REFRESH_TOKEN"
authorization_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "public-client"
"#;
        let def = def(toml_str);
        // The pure projection resolves regardless of where the def came from —
        // the single source of truth both the forward and approve paths share.
        assert_eq!(def.env_role().as_deref(), Some("GCP_REFRESH_TOKEN"));
        // A registry WITHOUT this custom service confirms the asymmetry the fix
        // removes: the id-based lookup misses, so a caller that may face a custom
        // service must go through the resolved def's `env_role`, never the
        // registry-only `service_env_key`.
        let r = reg(HashMap::new());
        assert_eq!(r.service_env_key("gcp"), None);
    }

    #[test]
    fn setup_block_parses_plain_prose() {
        let toml_str = r#"
setup = """
Put the phantom in the URL: sprott run -- git clone https://x:__sprott__github__@github.com/o/r
"""

[service]
id = "github"
name = "GitHub"
hosts = ["github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def = def(toml_str);
        let setup = def.setup.as_deref().unwrap();
        assert!(setup.contains("sprott run --"));
    }

    // ── [oauth2] inline resolution ────────────────────────────────────────────

    #[test]
    fn oauth_style_defaults_form_inline_json_wins() {
        let r = reg(HashMap::new());
        let oauth = |style: Option<&str>| OAuth2Def {
            provider: None,
            scopes: vec![],
            refresh_token: "RT".into(),
            id_token: None,
            exposes: vec![],
            claims: HashMap::new(),
            authorization_url: None,
            token_url: None,
            client_id: None,
            client_secret: None,
            pkce: None,
            redirect_uri: None,
            oauth_style: style.map(|s| s.to_string()),
            authorize_params: HashMap::new(),
            token_params: HashMap::new(),
            refresh_params: HashMap::new(),
            token_auth: None,
        };
        assert!(matches!(r.oauth_style(&oauth(None)), OAuthStyle::Form));
        assert!(matches!(
            r.oauth_style(&oauth(Some("form"))),
            OAuthStyle::Form
        ));
        assert!(matches!(
            r.oauth_style(&oauth(Some("json"))),
            OAuthStyle::Json
        ));
    }

    // ── compiled-in sanity (post-migration) ──────────────────────────────────

    #[test]
    fn compiled_services_parse_and_validate() {
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            let def = gate::admit(Some(id), toml_str, None)
                .unwrap_or_else(|e| panic!("service '{}' rejected: {:?}", id, e));
            // Non-hidden services must anchor at least one host.
            if !def.service.hidden {
                assert!(
                    !def.service.hosts.is_empty(),
                    "service '{}' declares no hosts",
                    id
                );
            }
            // [oauth2] is self-sufficient: every compiled oauth service must be
            // inline-complete (there is no template layer to fill gaps).
            if let Some(o) = def.oauth2() {
                assert!(
                    !o.refresh_token.is_empty(),
                    "service '{}' oauth2 has empty refresh_token",
                    id
                );
                assert!(
                    o.authorization_url.is_some(),
                    "service '{}' oauth2 missing authorization_url",
                    id
                );
                assert!(
                    o.token_url.is_some(),
                    "service '{}' oauth2 missing token_url",
                    id
                );
                assert!(
                    o.client_id.is_some(),
                    "service '{}' oauth2 missing client_id",
                    id
                );
            }
        }
    }

    #[test]
    fn compiled_codex_resolves_fully_inline() {
        let mut services = HashMap::new();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            if let Ok(def) = gate::admit_toml(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
        let r = reg(services);
        let oauth = r
            .get("openai_codex")
            .unwrap()
            .oauth2()
            .cloned()
            .expect("codex [auth] oauth2");
        let cfg = r.resolve_oauth_config(&oauth);
        assert_eq!(
            cfg.token_url.as_deref(),
            Some("https://auth.openai.com/oauth/token")
        );
        assert_eq!(
            cfg.client_id.as_deref(),
            Some("app_EMoamEEZ73f0CkXaXp7hrann")
        );
        assert!(cfg.client_secret.is_none(), "codex is pure PKCE");
        assert_eq!(cfg.redirect_uri, "http://localhost:1455/auth/callback");
        let d = r
            .connect_descriptor("openai_codex")
            .expect("codex descriptor");
        assert!(d.pkce);
        assert_eq!(d.provider, "openai");
        assert_eq!(
            d.authorize_params
                .get("codex_cli_simplified_flow")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            oauth.claims.get("account_id").map(Vec::as_slice),
            Some(
                &[
                    "https://api.openai.com/auth".to_string(),
                    "chatgpt_account_id".to_string()
                ][..]
            )
        );
    }

    #[test]
    fn descriptor_labels_custom_when_no_provider() {
        let r = reg(HashMap::new());
        let mut oauth: OAuth2Def = toml::from_str(
            "refresh_token=\"RT\"\nauthorization_url=\"https://b.example/auth\"\nclient_id=\"cid\"\n[authorize_params]\nprompt=\"login\"\n",
        ).unwrap();
        let d = r.connect_descriptor_for(&oauth).unwrap();
        assert_eq!(d.provider, "custom");
        assert_eq!(d.client_id, "cid");
        assert_eq!(
            d.authorize_params.get("prompt").map(String::as_str),
            Some("login")
        );
        // A provider name is a pure label — it changes nothing but the label.
        oauth.provider = Some("g".into());
        let d2 = r.connect_descriptor_for(&oauth).unwrap();
        assert_eq!(d2.provider, "g");
        assert_eq!(d2.client_id, "cid");
    }

    #[test]
    fn compiled_google_trio_is_inline_complete_and_shares_one_client() {
        let mut services = HashMap::new();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            if let Ok(def) = gate::admit_toml(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
        let r = reg(services);
        let mut client_ids = std::collections::HashSet::new();
        for id in ["gmail", "gdrive", "gcalendar"] {
            let oauth = r
                .get(id)
                .unwrap()
                .oauth2()
                .cloned()
                .unwrap_or_else(|| panic!("{} missing [oauth2]", id));
            assert_eq!(oauth.provider.as_deref(), Some("google"), "{}", id);
            let cfg = r.resolve_oauth_config(&oauth);
            assert_eq!(
                cfg.token_url.as_deref(),
                Some("https://oauth2.googleapis.com/token"),
                "{}",
                id
            );
            client_ids.insert(cfg.client_id.expect("client_id"));
            assert!(!oauth.scopes.is_empty(), "{} scopes", id);
        }
        assert_eq!(
            client_ids.len(),
            1,
            "the trio must share ONE Desktop client (rotate together)"
        );
    }

    #[test]
    fn connect_descriptor_for_gmail_mirrors_the_full_wiring() {
        // The descriptor is a 1:1 mirror of the def — a def can only hold
        // public-client material (validator), so nothing is withheld and the
        // console can display the wiring faithfully.
        let r = ServiceRegistry::load();
        let d = r.connect_descriptor("gmail").expect("gmail is oauth2");
        assert_eq!(d.provider, "google");
        assert!(d
            .authorization_url
            .starts_with("https://accounts.google.com/"));
        assert_eq!(
            d.token_url.as_deref(),
            Some("https://oauth2.googleapis.com/token")
        );
        assert!(d.client_id.ends_with(".apps.googleusercontent.com"));
        assert!(
            d.client_secret
                .as_deref()
                .is_some_and(|s| s.starts_with("GOCSPX-")),
            "the public Desktop client_secret is part of the wiring"
        );
        assert!(d.pkce);
        assert_eq!(d.oauth_style, "form");
        assert!(d.scopes.iter().any(|s| s.contains("gmail.send")));
        assert_eq!(
            d.authorize_params.get("access_type").map(String::as_str),
            Some("offline")
        );
    }

    #[test]
    fn connect_descriptor_none_for_non_oauth_service() {
        let r = ServiceRegistry::load();
        assert!(r.connect_descriptor("openai").is_none());
    }

    #[test]
    fn compiled_gmail_policy_resolves_risk_tiers() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r
            .default_policy_rules("gmail")
            .expect("gmail policy.toml must parse and yield rules")
            .to_vec();
        let policy = Policy::default();
        let eval = |m: &str, p: &str| {
            evaluate(&crate::core::request::Request::bare(m, p), Some(&rules), None, &policy, &["app".into()]).unwrap()
        };
        assert_eq!(
            eval("GET", "/gmail/v1/users/me/messages"),
            AccessLevel::Allow
        );
        assert_eq!(
            eval("GET", "/gmail/v1/users/me/messages/abc123"),
            AccessLevel::Ask
        );
        assert_eq!(
            eval("POST", "/gmail/v1/users/me/messages/send"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("DELETE", "/gmail/v1/users/me/messages/abc123"),
            AccessLevel::AskAlways
        );
    }

    #[test]
    fn compiled_cratesio_policy_gates_publish_surface() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r
            .default_policy_rules("cratesio")
            .expect("cratesio policy.toml must parse and yield rules")
            .to_vec();
        let policy = Policy::default();
        let eval = |m: &str, p: &str| {
            evaluate(&crate::core::request::Request::bare(m, p), Some(&rules), None, &policy, &["app".into()]).unwrap()
        };
        // Routine traffic rides the allow floor.
        assert_eq!(eval("GET", "/api/v1/me"), AccessLevel::Allow);
        assert_eq!(eval("GET", "/api/v1/crates"), AccessLevel::Allow);
        assert_eq!(
            eval("PUT", "/api/v1/crates/serde/follow"),
            AccessLevel::Allow
        );
        // Publish + version availability ask once per window.
        assert_eq!(eval("PUT", "/api/v1/crates/new"), AccessLevel::Ask);
        assert_eq!(
            eval("DELETE", "/api/v1/crates/serde/1.0.219/yank"),
            AccessLevel::Ask
        );
        assert_eq!(
            eval("PUT", "/api/v1/crates/serde/1.0.219/unyank"),
            AccessLevel::Ask
        );
        assert_eq!(
            eval("PATCH", "/api/v1/crates/serde/1.0.219"),
            AccessLevel::Ask
        );
        // Ownership + supply chain gate every time.
        assert_eq!(
            eval("PUT", "/api/v1/crates/serde/owners"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("DELETE", "/api/v1/crates/serde/owners"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("POST", "/api/v1/trusted_publishing/github_configs"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("PATCH", "/api/v1/crates/serde"),
            AccessLevel::AskAlways
        );
        // Publish approvals cover a workspace release train, not one crate.
        let publish = rules
            .iter()
            .find(|ru| ru.id.as_deref() == Some("publish"))
            .unwrap();
        assert_eq!(publish.ttl, Some(1800));
    }

    #[test]
    fn compiled_railway_policy_gates_only_destroys() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r
            .default_policy_rules("railway")
            .expect("railway policy.toml must parse and yield rules")
            .to_vec();
        let policy = Policy::default();
        let def = r.get("railway").expect("railway service");
        let eval = |body: &str| {
            // The whole API is one POST endpoint; the mutation name lives in the
            // body and reaches policy as `request.graphql.fields` through
            // [requests.graphql].
            let read = def
                .read_request(input("POST", "/graphql/v2", body))
                .unwrap_or_else(|e| panic!("unreadable: {body}: {e:?}"));
            assert!(read.scope.is_some(), "the graphql shape covers every POST");
            evaluate(&read.request, Some(&rules), None, &policy, &["app".into()]).unwrap()
        };
        // Routine GraphQL (queries + non-destroy mutations) rides the allow floor.
        assert_eq!(
            eval(r#"{"query":"query { me { name } }"}"#),
            AccessLevel::Allow
        );
        assert_eq!(
            eval(r#"{"query":"mutation { serviceInstanceRedeploy(id: 1) }"}"#),
            AccessLevel::Allow
        );
        assert_eq!(
            eval(r#"{"query":"mutation { variableUpsert(input: {}) }"}"#),
            AccessLevel::Allow
        );
        // Each irreversible destroy is caught by mutation name (incl. the biggest,
        // workspaceDelete — every project under the workspace).
        assert_eq!(
            eval(r#"{"query":"mutation { workspaceDelete(id: \"w\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { projectDelete(id: \"p\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { serviceDelete(id: \"s\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { environmentDelete(id: \"e\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { volumeDelete(id: \"v\") }"}"#),
            AccessLevel::AskAlways
        );
        // Minting a durable token escapes the broker → gated.
        assert_eq!(
            eval(r#"{"query":"mutation { projectTokenCreate(input: {}) }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { apiTokenCreate(input: {}) }"}"#),
            AccessLevel::AskAlways
        );
        // Access-posture changes (member/role/transfer/ssh key) → gated.
        assert_eq!(
            eval(r#"{"query":"mutation { projectMemberAdd(input: {}) }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { projectTransferInitiate(id: \"p\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { sshPublicKeyCreate(input: {}) }"}"#),
            AccessLevel::AskAlways
        );
        // The field is read from the parsed request, so an alias, a fragment,
        // a JSON escape or a second call can't hide it.
        for hidden in [
            r#"{"query":"mutation { x: serviceDelete(id: \"s\") }"}"#,
            r#"{"query":"mutation { ...F } fragment F on Mutation { serviceDelete(id: \"s\") }"}"#,
            r#"{"query":"mutation { service\u0044elete(id: \"s\") }"}"#,
            r#"{"query":"mutation { serviceInstanceRedeploy(serviceId: \"a\") serviceDelete(id: \"s\") }"}"#,
            r#"{"query":"mutation D($i: String!) { serviceDelete(id: $i) }","variables":{"i":"s"}}"#,
        ] {
            assert_eq!(eval(hidden), AccessLevel::AskAlways, "{hidden}");
        }
        // A name in a comment or a string is not a call.
        assert_eq!(
            eval(r##"{"query":"# serviceDelete\nmutation { variableUpsert(input: {name: \"serviceDelete\"}) }"}"##),
            AccessLevel::Allow
        );
    }

    /// A request with a body, no query and no headers.
    fn input<'a>(method: &'a str, path: &'a str, body: &'a str) -> RequestInput<'a> {
        RequestInput {
            method,
            path,
            host: "api.example.com",
            body: Some(body.as_bytes()),
            ..Default::default()
        }
    }

    /// Evaluate a compiled service's default policy on one request (no
    /// headers), read by the service's `[requests]` shapes.
    fn eval_compiled(service: &str, method: &str, path: &str, body: &str) -> crate::core::policy::AccessLevel {
        eval_with(service, input(method, path, body))
    }

    /// [`eval_compiled`] on any request input.
    fn eval_with(service: &str, input: RequestInput<'_>) -> crate::core::policy::AccessLevel {
        use crate::core::policy::{evaluate, Policy};
        let r = ServiceRegistry::load();
        let rules = r.default_policy_rules(service).expect("policy").to_vec();
        let def = r.get(service).expect("service");
        let body = String::from_utf8_lossy(input.body.unwrap_or_default()).into_owned();
        let read = def
            .read_request(input)
            .unwrap_or_else(|e| panic!("unreadable: {body}: {e:?}"));
        evaluate(&read.request, Some(&rules), None, &Policy::default(), &["dev".into()])
            .unwrap_or_else(|e| panic!("unreadable: {body}: {e:?}"))
    }

    /// The shape a service's shapes match a request with.
    fn scope_of(def: &ServiceDef, method: &str, path: &str, body: &str) -> RequestScope {
        def.read_request(input(method, path, body))
            .unwrap_or_else(|e| panic!("unreadable: {body}: {e:?}"))
            .scope
            .expect("a shape matches")
    }

    /// What a single-use approval of a request covers (the shape's scope and
    /// consent; no rule's condition reads), as the card shows it and as its
    /// permit identity under a test key.
    fn covered(
        def: &ServiceDef,
        method: &str,
        path: &str,
        body: &str,
    ) -> (Vec<(String, String)>, String) {
        let read = def
            .read_request(input(method, path, body))
            .unwrap_or_else(|e| panic!("unreadable: {body}: {e:?}"));
        let c = crate::approval::coverage::cover_read(&read, path, &[], true, true).unwrap();
        let id = crate::approval::coverage::IdentityKey::derive(&[3u8; 32], 0).identity(&c);
        (c.shown, id.digest)
    }

    fn shown<'s>(shown: &'s [(String, String)], label: &str) -> Option<&'s str> {
        shown.iter().find(|(l, _)| l == label).map(|(_, v)| v.as_str())
    }

    /// Why a service's shapes and rules refuse a request (its status).
    fn refusal(def: &ServiceDef, method: &str, path: &str, body: &str) -> Option<u16> {
        def.read_request(input(method, path, body)).err().map(|e| e.status)
    }

    #[test]
    fn compiled_github_make_public_reads_the_visibility_fields() {
        use crate::core::policy::AccessLevel;
        let eval = |body: &str| eval_compiled("github", "PATCH", "/repos/o/r", body);
        for public in [
            r#"{"private": false}"#,
            r#"{"visibility": "public"}"#,
            r#"{"name": "x", "priv\u0061te": false}"#,
        ] {
            assert_eq!(eval(public), AccessLevel::AskAlways, "{public}");
        }
        for routine in [r#"{"private": true}"#, r#"{"description": "private: false"}"#, r#"{"visibility": "internal"}"#] {
            assert_eq!(eval(routine), AccessLevel::Allow, "{routine}");
        }
    }

    /// A gated operation can't be reached another way: through a Google batch
    /// endpoint, the Cloud Storage XML API, GitHub's REST twins of its gated
    /// GraphQL mutations and its org, user and environment variants, or
    /// Vercel's member invite and role change. Paths from the vendors' own
    /// API descriptions (GitHub rest-api-description, Vercel OpenAPI).
    #[test]
    fn compiled_policies_gate_every_spelling_of_a_gated_operation() {
        use crate::core::policy::AccessLevel;
        for (service, method, path) in [
            ("gcp", "DELETE", "/storage/v1/b/bkt"),
            ("gcp", "DELETE", "/bkt"),
            ("gcp", "DELETE", "/bkt/"),
            ("gcp", "POST", "/batch/storage/v1"),
            ("gcp", "POST", "/batch/compute/v1"),
            ("gcalendar", "POST", "/batch/calendar/v3"),
            ("github", "POST", "/repos/o/r/rulesets"),
            ("github", "PUT", "/repos/o/r/rulesets/7"),
            ("github", "DELETE", "/repos/o/r/rulesets/7"),
            ("github", "DELETE", "/repositories/42/rulesets/7"),
            ("github", "PUT", "/orgs/acme/rulesets/7"),
            ("github", "DELETE", "/organizations/9/rulesets/7"),
            ("github", "PUT", "/orgs/acme/actions/secrets/TOKEN/repositories/99"),
            ("github", "PUT", "/orgs/acme/actions/secrets/TOKEN/repositories"),
            ("github", "PUT", "/orgs/acme/dependabot/secrets/TOKEN"),
            ("github", "PUT", "/user/codespaces/secrets/TOKEN/repositories/99"),
            ("github", "PUT", "/repos/o/r/environments/prod/secrets/TOKEN"),
            ("github", "PUT", "/repos/o/r/dependabot/secrets/TOKEN"),
            ("github", "PUT", "/orgs/acme/teams/devs/repos/acme/app"),
            ("github", "PUT", "/teams/5/repos/acme/app"),
            ("github", "PUT", "/orgs/acme/memberships/mallory"),
            ("github", "POST", "/orgs/acme/invitations"),
            ("github", "DELETE", "/orgs/acme/outside_collaborators/bob"),
            ("github", "POST", "/orgs/acme/actions/runners/registration-token"),
            ("github", "POST", "/repos/o/r/actions/runners/generate-jitconfig"),
            ("github", "POST", "/orgs/acme/hooks"),
            ("github", "PATCH", "/orgs/acme/hooks/3/config"),
            ("github", "PATCH", "/repos/o/r/hooks/3/config"),
            ("github", "PATCH", "/repos/o/r/branches/main/protection/required_pull_request_reviews"),
            ("github", "POST", "/repos/o/r/branches/main/protection/restrictions/users"),
            ("vercel", "POST", "/v2/teams/t1/members"),
            ("vercel", "PATCH", "/v1/teams/t1/members/u1"),
            ("vercel", "DELETE", "/v9/projects/web"),
            ("vercel", "DELETE", "/v6/domains/example.com"),
            ("vercel", "DELETE", "/v1/teams/t1/members/u1"),
            ("vercel", "POST", "/v1/webhooks"),
            ("neon", "POST", "/api/v2/organizations/org-1/api_keys"),
            ("gcp", "DELETE", "/compute/beta/projects/p/zones/z/instances/vm"),
            ("gcp", "DELETE", "/compute/alpha/projects/p/zones/z/instances/vm"),
            ("gcalendar", "DELETE", "/calendar/v3/calendars/cal1"),
            ("gcalendar", "POST", "/calendar/v3/calendars/primary/clear"),
            ("supabase", "GET", "/v1/projects/ref/config/database/pgbouncer"),
        ] {
            assert_eq!(eval_compiled(service, method, path, ""), AccessLevel::AskAlways, "{service} {method} {path}");
        }
        for (service, method, path, body) in [
            ("openai", "POST", "/v1/threads/runs", r#"{"assistant_id": "a", "model": "o3"}"#),
            ("openai", "POST", "/v1/threads/t1/runs", r#"{"assistant_id": "a", "model": "o4-mini"}"#),
            ("openai", "POST", "/v1/assistants", r#"{"model": "o3"}"#),
            ("openai", "POST", "/v1/assistants/a1", r#"{"model": "gpt-4.5-preview"}"#),
            ("openai", "POST", "/v1/batches", r#"{"input_file_id": "f", "endpoint": "/v1/chat/completions", "completion_window": "24h"}"#),
            ("circleci", "DELETE", "/api/v2/org/o1/oidc-custom-claims", ""),
            ("circleci", "DELETE", "/api/v2/org/o1/project/p1/oidc-custom-claims", ""),
            ("googletasks", "POST", "/tasks/v1/lists/l1/clear", ""),
            // CircleCI routes a POST with a form `_method` field to that method's handler.
            ("circleci", "POST", "/api/v2/schedule/s1", "_method=PATCH"),
            ("circleci", "POST", "/api/v2/org/o1/oidc-custom-claims", "_method=DELETE"),
        ] {
            assert_eq!(eval_compiled(service, method, path, body), AccessLevel::Ask, "{service} {method} {path}");
        }
        for field in ["updateRefs", "addEnterpriseOrganizationMember"] {
            let body = format!(r#"{{"query":"mutation {{ {field}(input: {{}}) {{ clientMutationId }} }}"}}"#);
            assert_eq!(eval_compiled("github", "POST", "/graphql", &body), AccessLevel::AskAlways, "{field}");
        }
        for field in ["workspacePolicyItemUpdate", "workspacePolicyDeploySourceAllowlistAdd", "workspacePolicyDeploySourceAllowlistRemove"] {
            let body = format!(r#"{{"query":"mutation {{ {field}(id: \"x\") }}"}}"#);
            assert_eq!(eval_compiled("railway", "POST", "/graphql/v2", &body), AccessLevel::AskAlways, "{field}");
        }
        // An assistant on a routine model, and a run without an override, ride the floor.
        assert_eq!(eval_compiled("openai", "POST", "/v1/assistants", r#"{"model": "gpt-4o-mini"}"#), AccessLevel::Allow);
        assert_eq!(eval_compiled("openai", "POST", "/v1/threads/t1/runs", r#"{"assistant_id": "a"}"#), AccessLevel::Allow);
        // Object deletes stay routine; reading rulesets is a read.
        for (service, method, path) in [
            ("gcp", "DELETE", "/storage/v1/b/bkt/o/obj"),
            ("gcp", "DELETE", "/bkt/obj"),
            ("github", "GET", "/repos/o/r/rulesets"),
        ] {
            assert_eq!(eval_compiled(service, method, path, ""), AccessLevel::Allow, "{service} {method} {path}");
        }
    }

    /// A shape reads members of an object. A body that has no object where a
    /// shape reads one (Google's array-encoded JSPB, a bare string) is refused
    /// (422) instead of binding nothing; a null or a missing member is absent.
    #[test]
    fn a_body_member_read_through_a_non_object_is_refused() {
        let r = ServiceRegistry::load();
        let gmail = r.get("gmail").expect("gmail service");
        let send = "/gmail/v1/users/me/messages/send";
        for body in ["[]", r#"[null,"cmF3"]"#, r#""raw""#, "5", "true"] {
            assert_eq!(refusal(gmail, "POST", send, body), Some(422), "{body}");
        }
        let (ok, _) = covered(gmail, "POST", send, r#"{"raw":"cmF3"}"#);
        assert_eq!(shown(&ok, "request.body.raw"), Some("cmF3"));
        for absent in ["{}", r#"{"raw":null}"#] {
            assert_eq!(refusal(gmail, "POST", send, absent), None, "{absent}");
        }

        let snaplii = r.get("snaplii").expect("snaplii service");
        let buy = |body: &str| refusal(snaplii, "POST", "/v2/purchase", body);
        assert_eq!(buy(r#"{"orderInfo":"CB_1"}"#), Some(422));
        assert_eq!(buy(r#"{"orderInfo":{"item":[1]}}"#), Some(422));
        assert_eq!(buy(r#"{"orderInfo":null}"#), None);
    }

    /// Snaplii's purchase and transfer gates read the fields its OpenAPI spec
    /// sends (`orderInfo.item.price` as a decimal string; `to_phone`, `amount`),
    /// and an approval binds what moves money.
    #[test]
    fn compiled_snaplii_policy_reads_the_fields_its_api_sends() {
        use crate::core::policy::AccessLevel;
        let purchase = |price: &str| {
            format!(r#"{{"orderInfo": {{"orderType": "GIFT_CARD", "item": {{"itemId": "CB_1", "price": {price}}}}}}}"#)
        };
        let eval = |body: &str| eval_compiled("snaplii", "POST", "/v2/purchase", body);
        assert_eq!(eval(&purchase(r#""40.00""#)), AccessLevel::Ask);
        for large in [r#""100.01""#, r#""5000""#, "40", r#"" 40""#, r#""4e1""#, "null"] {
            assert_eq!(eval(&purchase(large)), AccessLevel::AskAlways, "{large}");
        }
        assert_eq!(eval(r#"{"orderInfo": {"orderType": "BILL_PAY"}}"#), AccessLevel::AskAlways);
        assert_eq!(
            eval_compiled("snaplii", "POST", "/v2/transfers", r#"{"to_phone": "4165550006", "amount": "12.50"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(eval_compiled("snaplii", "POST", "/v2/quote", &purchase(r#""40.00""#)), AccessLevel::Allow);

        let r = ServiceRegistry::load();
        let def = r.get("snaplii").expect("snaplii service");
        // A purchase approval covers the whole order (DESIGN §7) and shows
        // what the consent reads.
        let body = purchase(r#""40.00""#);
        let (card, _) = covered(def, "POST", "/v2/purchase", &body);
        assert_eq!(shown(&card, "request.body"), Some(body.as_str()));
        assert_eq!(shown(&card, "request.body.orderInfo.item.itemId"), Some("CB_1"));
        assert_eq!(shown(&card, "request.body.orderInfo.item.price"), Some("40.00"));
        assert_eq!(shown(&card, "request.body.orderInfo.orderType"), Some("GIFT_CARD"));
        // A gift to someone else, or another payment method, is another approval.
        let mine = format!(r#"{{"orderInfo": {{"item": {{"itemId": "CB_1", "price": "40.00"}}}}, "delivery": {{"type": "WALLET"}}}}"#);
        let gift = format!(r#"{{"orderInfo": {{"item": {{"itemId": "CB_1", "price": "40.00"}}, "orderContext": {{"giftOrder": "true"}}}}, "delivery": {{"type": "WALLET"}}}}"#);
        let identity = |body: &str| covered(def, "POST", "/v2/purchase", body).1;
        assert_ne!(identity(&mine), identity(&gift));
        assert_eq!(identity(&mine), identity(&mine.clone()));
        // A transfer covers its recipient, amount and note.
        let (card, _) = covered(def, "POST", "/v2/transfers", r#"{"to_phone": "4165550006", "amount": "12.50"}"#);
        assert_eq!(shown(&card, "request.body.amount"), Some("12.50"));
        assert_eq!(shown(&card, "request.body.to_phone"), Some("4165550006"));
        assert_eq!(shown(&card, "request.body.remark"), None);
        assert_eq!(shown(&card, "request.body"), None, "a narrowed scope shows what it covers");
    }

    /// Every Cloudflare change that can remove or re-point traffic is gated,
    /// in each spelling the API accepts (a trailing slash too); an approval
    /// binds the fields a record write sets.
    #[test]
    fn compiled_cloudflare_policy_gates_record_changes_and_binds_them() {
        use crate::core::policy::AccessLevel;
        let z = "/client/v4/zones/z1";
        let record = r#"{"type": "A", "name": "x.example.com", "content": "192.0.2.1"}"#;
        for (method, path, body) in [
            ("PATCH", format!("{z}/dns_records/r1"), r#"{"proxied": true}"#),
            ("PATCH", format!("{z}/dns_records/r1/"), r#"{"proxied": true}"#),
            ("PUT", format!("{z}/dns_records/r1"), record),
            ("DELETE", format!("{z}/dns_records/r1"), ""),
            ("POST", format!("{z}/dns_records/batch"), r#"{"deletes": [{"id": "r1"}]}"#),
            ("DELETE", z.to_string(), ""),
            ("DELETE", format!("{z}/"), ""),
        ] {
            assert_eq!(eval_compiled("cloudflare", method, &path, body), AccessLevel::AskAlways, "{method} {path}");
        }
        for (method, path) in [("GET", format!("{z}/dns_records")), ("POST", format!("{z}/dns_records"))] {
            assert_eq!(eval_compiled("cloudflare", method, &path, record), AccessLevel::Allow, "{method} {path}");
        }

        let r = ServiceRegistry::load();
        let def = r.get("cloudflare").expect("cloudflare service");
        let path = format!("{z}/dns_records/r1");
        let (card, id) = covered(def, "PATCH", &path, r#"{"proxied": true, "comment": "x"}"#);
        assert_eq!(shown(&card, "request.body.proxied"), Some("true"));
        assert_eq!(shown(&card, "request.body.comment"), None);
        // The same approval can't carry a new target; a comment is not covered.
        let (_, other) = covered(def, "PATCH", &path, r#"{"proxied": true, "content": "198.51.100.7"}"#);
        assert_ne!(id, other);
        let (_, commented) = covered(def, "PATCH", &path, r#"{"proxied": true, "comment": "y"}"#);
        assert_eq!(id, commented);
        let (batch, _) = covered(def, "POST", &format!("{z}/dns_records/batch"), r#"{"deletes": [{"id": "r1"}]}"#);
        assert_eq!(shown(&batch, "request.body.deletes"), Some(r#"[{"id":"r1"}]"#));
    }

    /// Every Railway mutation that deletes, mints a credential or changes who
    /// can get in is gated; routine ones with the same words ride the floor.
    /// Names from introspection of backboard.railway.com (2026-10-27).
    #[test]
    fn compiled_railway_policy_classifies_the_consequential_mutations() {
        use crate::core::policy::AccessLevel;
        let eval = |field: &str| {
            eval_compiled(
                "railway",
                "POST",
                "/graphql/v2",
                &serde_json::json!({ "query": format!("mutation {{ {field} }}") }).to_string(),
            )
        };
        for gated in [
            "workspaceDelete", "projectDelete", "projectScheduleDelete", "projectScheduleDeleteForce",
            "serviceDelete", "environmentDelete", "volumeDelete", "volumeInstanceBackupDelete",
            "volumeInstanceBackupRestore", "signalDelete", "userDelete", "apiTokenCreate",
            "projectTokenCreate", "clearanceTokenCreate", "projectMemberAdd", "projectMemberRemove",
            "projectLeave", "workspaceUserRemove", "workspaceLeave", "workspaceInviteCodeUse",
            "inviteCodeUse", "accessGroupUpdate", "accessGroupMemberRemove", "twoFactorInfoCreate",
            "databasePasswordReset", "bucketCredentialsReset", "usageLimitRemove",
        ] {
            assert_eq!(eval(gated), AccessLevel::AskAlways, "{gated}");
        }
        for routine in [
            "serviceInstanceRedeploy", "variableUpsert", "variableDelete", "customDomainDelete",
            "deploymentRemove", "apiTokenDelete", "projectTokenDelete", "projectScheduleDeleteCancel",
            "volumeInstancePITRRestore", "clearanceTokenRevoke", "environmentPatchCommitStaged",
        ] {
            assert_eq!(eval(routine), AccessLevel::Allow, "{routine}");
        }
    }

    /// A service, volume or bucket deleted through an environment change is
    /// gated; any other environment change is routine.
    #[test]
    fn compiled_railway_policy_gates_deletion_through_an_environment_change() {
        use crate::core::policy::AccessLevel;
        let eval = |field: &str, arg: &str, patch: serde_json::Value| {
            let q = format!("mutation($p: EnvironmentConfig) {{ {field}(environmentId: \"e\", {arg}: $p) }}");
            let body = serde_json::json!({ "query": q, "variables": { "p": patch } }).to_string();
            eval_compiled("railway", "POST", "/graphql/v2", &body)
        };
        let delete = serde_json::json!({"services": {"0b1c": {"isDeleted": true}}});
        let tweak = serde_json::json!({"services": {"0b1c": {"variables": {"isDeleted": {"value": "true"}}}}});
        assert_eq!(eval("environmentPatchCommit", "patch", delete.clone()), AccessLevel::AskAlways);
        assert_eq!(eval("environmentStageChanges", "input", delete), AccessLevel::AskAlways);
        assert_eq!(eval("environmentPatchCommit", "patch", tweak), AccessLevel::Allow);
        let body = serde_json::json!({"query": "mutation($c: JSON) { environmentApplyChangeSet(input: $c) }", "variables": {"c": {}}}).to_string();
        assert_eq!(eval_compiled("railway", "POST", "/graphql/v2", &body), AccessLevel::AskAlways);
    }

    #[test]
    fn compiled_github_graphql_queries_and_routine_mutations_ride_the_floor() {
        use crate::core::policy::AccessLevel;
        for body in [
            r#"{"query":"query { viewer { login } }"}"#,
            r#"{"query":"mutation { addComment(input: {subjectId: \"I\", body: \"hi\"}) { clientMutationId } }"}"#,
        ] {
            assert_eq!(eval_compiled("github", "POST", "/graphql", body), AccessLevel::Allow, "{body}");
        }
    }

    #[test]
    fn compiled_github_policy_covers_every_spelling_of_a_repository() {
        use crate::core::policy::AccessLevel;
        for (method, path, body) in [
            ("DELETE", "/repositories/1296269", ""),
            ("PATCH", "/repositories/1296269", r#"{"private": false}"#),
            ("POST", "/repos/o/r", r#"{"visibility": "public"}"#),
            ("PUT", "/repositories/1296269/collaborators/x", "{}"),
            ("POST", "/repositories/1296269/transfer", "{}"),
            ("PUT", "/organizations/9919/actions/secrets/X", "{}"),
            ("POST", "/graphql", r#"{"query":"mutation { deleteBranchProtectionRule(input: {branchProtectionRuleId: \"B\"}) { clientMutationId } }"}"#),
        ] {
            assert_eq!(
                eval_compiled("github", method, path, body),
                AccessLevel::AskAlways,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn compiled_openai_expensive_model_reads_the_model() {
        use crate::core::policy::AccessLevel;
        for path in ["/v1/chat/completions", "/v1/responses"] {
            let eval = |body: &str| eval_compiled("openai", "POST", path, body);
            assert_eq!(eval(r#"{"model": "o3-pro", "input": "hi"}"#), AccessLevel::Ask);
            assert_eq!(eval(r#"{"model": "gpt-4.5-preview"}"#), AccessLevel::Ask);
            assert_eq!(eval(r#"{"model": "ft:o4-mini-2025:acme::x"}"#), AccessLevel::Ask);
            // A prompt that mentions a model is not the model.
            assert_eq!(eval(r#"{"model": "gpt-4o-mini", "input": "compare with o3"}"#), AccessLevel::Allow);
        }
    }

    #[test]
    fn railway_graphql_shape_binds_and_refuses_what_it_cannot_read() {
        let r = ServiceRegistry::load();
        let def = r.get("railway").expect("railway service");
        let body = r#"{"query":"mutation { serviceDelete(id: \"3ec1\") }"}"#;
        let (card, id) = covered(def, "POST", "/graphql/v2", body);
        let call = r#"[{"args":{"id":"3ec1"},"field":"serviceDelete"}]"#.to_string();
        assert_eq!(shown(&card, "request.graphql.calls"), Some(call.as_str()));
        assert_eq!(shown(&card, "request.graphql.fields"), Some(r#"["serviceDelete"]"#));
        let request = format!(r#"{{"calls":{call}}}"#);
        assert_eq!(shown(&card, "request.graphql.request"), Some(request.as_str()));
        assert_eq!(
            scope_of(def, "POST", "/graphql/v2", body).consent.as_deref(),
            Some("{{ request.graphql.calls | graphql }}")
        );
        // A different target is a different approval.
        let (_, other) = covered(def, "POST", "/graphql/v2", r#"{"query":"mutation { serviceDelete(id: \"9999\") }"}"#);
        assert_ne!(id, other);
        // A request a server would refuse is refused with the server's status.
        for (body, status) in [
            (r#"[{"query":"mutation { serviceDelete(id: \"s\") }"}]"#, 400),
            (r#"{"query":"mutation { serviceDelete(id: \"s\") "}"#, 400),
            ("not json", 400),
            (r#"{"query":"query { me { id } }","query":"mutation { serviceDelete(id: \"s\") }"}"#, 400),
            (r#"{"query":"mutation { ...Missing }"}"#, 422),
        ] {
            assert_eq!(refusal(def, "POST", "/graphql/v2", body), Some(status), "{body}");
        }
        // An empty body makes no call: not a refusal.
        assert_eq!(refusal(def, "POST", "/graphql/v2", ""), None);
    }

    #[test]
    fn compiled_supabase_policy_gates_the_consequential_few() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r
            .default_policy_rules("supabase")
            .expect("supabase policy.toml must parse and yield rules")
            .to_vec();
        let policy = Policy::default();
        let eval = |m: &str, p: &str| {
            evaluate(&crate::core::request::Request::bare(m, p), Some(&rules), None, &policy, &["app".into()]).unwrap()
        };
        // Routine developer work — incl. arbitrary SQL — rides the allow floor.
        assert_eq!(eval("GET", "/v1/projects"), AccessLevel::Allow);
        assert_eq!(eval("POST", "/v1/projects"), AccessLevel::Allow);
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/database/query"),
            AccessLevel::Allow
        );
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/secrets"),
            AccessLevel::Allow
        );
        // A sub-resource delete (function, secret, branch) is recoverable → floor.
        assert_eq!(
            eval("DELETE", "/v1/projects/abcdef/functions/hello"),
            AccessLevel::Allow
        );
        // Editing/deleting a specific api-key is a deeper path → floor.
        assert_eq!(
            eval("PATCH", "/v1/projects/abcdef/api-keys/key1"),
            AccessLevel::Allow
        );
        // Deleting the whole project is the one irreversible catastrophe.
        assert_eq!(
            eval("DELETE", "/v1/projects/abcdef"),
            AccessLevel::AskAlways
        );
        // Minting a new API key escapes the broker → gated.
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/api-keys"),
            AccessLevel::AskAlways
        );
        // Opening the database to the network → gated on BOTH endpoints (no bypass).
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/network-restrictions/apply"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("PATCH", "/v1/projects/abcdef/network-restrictions"),
            AccessLevel::AskAlways
        );
        // Handing the project to another owner → gated.
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/claim-token"),
            AccessLevel::AskAlways
        );
        // Reads whose response holds a secret value ask every time.
        for path in [
            "/v1/projects/abcdef/api-keys",
            "/v1/projects/abcdef/api-keys?reveal=true",
            "/v1/projects/abcdef/api-keys/key1",
            "/v1/projects/abcdef/postgrest",
            "/v1/projects/abcdef/pgsodium",
            "/v1/branches/br1",
        ] {
            assert_eq!(eval("GET", path), AccessLevel::AskAlways, "{path}");
        }
        // Reads that return only hashes, placeholders or no secrets stay allowed.
        for path in [
            "/v1/projects/abcdef",
            "/v1/projects/abcdef/config/auth",
            "/v1/projects/abcdef/secrets",
            "/v1/projects/abcdef/config/database/pooler",
            "/v1/projects/abcdef/branches",
            "/v1/branches/br1/diff",
        ] {
            assert_eq!(eval("GET", path), AccessLevel::Allow, "{path}");
        }
    }

    // ── [requests] extraction + scope digest (Phase 2) ───────────────────────

    fn snaplii_def() -> ServiceDef {
        gate::admit_toml(
            r#"
[service]
id = "snaplii"
name = "Snaplii"
hosts = ["aipayment.snaplii.com"]
secrets = ["SNAPLII_API_KEY"]
[auth]
type = "snaplii"
[requests.purchase]
method = "POST"
path = "/v2/purchase"
scope   = ["request.body.amount", "request.query.force"]
consent = "Buy from {{ request.body.merchant_id }} for {{ request.body.amount }}"
"#,
        )
        .unwrap()
    }

    #[test]
    fn a_shape_binds_its_scope_and_what_its_consent_reads() {
        let def = snaplii_def();
        let body = r#"{"amount": 80, "merchant_id": "m_1", "nonce": "xyz"}"#;
        let read = def
            .read_request(RequestInput {
                query: Some("force=true"),
                ..input("POST", "/v2/purchase", body)
            })
            .unwrap();
        let c = crate::approval::coverage::cover_read(&read, "/v2/purchase", &[], true, true).unwrap();
        // Shown = covered: the scope and the consent's paths; the body
        // `nonce` is not covered.
        let mut card = c.shown.clone();
        card.sort();
        assert_eq!(
            card,
            vec![
                ("request.body.amount".to_string(), "80".to_string()),
                ("request.body.merchant_id".to_string(), "m_1".to_string()),
                ("request.query.force".to_string(), "true".to_string()),
            ]
        );
        let rs = read.scope.expect("purchase shape matches");
        assert_eq!(
            rs.consent.as_deref(),
            Some("Buy from {{ request.body.merchant_id }} for {{ request.body.amount }}")
        );
        assert_eq!(rs.shape, "purchase");
        // No shape matches a GET; an absent value is covered as absent.
        assert!(def.read_request(input("GET", "/v2/balance", "")).unwrap().scope.is_none());
        let (card, _) = covered(&def, "POST", "/v2/purchase", r#"{"amount": 5}"#);
        assert_eq!(card, vec![("request.body.amount".to_string(), "5".to_string())]);
        // A read value given twice refuses the request; one nothing reads
        // doesn't.
        let twice = def.read_request(RequestInput {
            query: Some("force=1&force=2"),
            ..input("POST", "/v2/purchase", "{}")
        });
        assert_eq!(twice.err().map(|e| e.status), Some(400));
        assert!(def
            .read_request(RequestInput {
                query: Some("other=1&other=2"),
                ..input("POST", "/v2/purchase", "{}")
            })
            .is_ok());
    }

    #[test]
    fn a_shape_condition_selects_and_an_error_does_not() {
        let def = gate::admit_toml(
            r#"
[service]
id = "pay"
name = "Pay"
hosts = ["api.pay.com"]
[requests.big]
method = "POST"
path = "/pay"
condition = "request.body.amount > 100"
scope = ["request.body.amount"]
[requests.small]
method = "POST"
path = "/pay"
scope = ["request.body.memo"]
"#,
        )
        .unwrap();
        assert_eq!(scope_of(&def, "POST", "/pay", r#"{"amount": 500}"#).shape, "big");
        assert_eq!(scope_of(&def, "POST", "/pay", r#"{"amount": 5}"#).shape, "small");
        // An erroring condition (an absent amount) doesn't select.
        assert_eq!(scope_of(&def, "POST", "/pay", "{}").shape, "small");
        // Shapes are tried in declaration order, and an erroring condition
        // with no shape matched makes the approval single-use.
        assert_eq!(def.request_order, ["big", "small"]);
        let only_big = gate::admit_toml(
            "[service]\nid = \"pay\"\nname = \"Pay\"\nhosts = [\"api.pay.com\"]\n[requests.z]\nmethod = \"POST\"\npath = \"/pay\"\ncondition = \"request.body.amount > 100\"\n[requests.a]\nmethod = \"POST\"\npath = \"/other\"\n",
        )
        .unwrap();
        assert_eq!(only_big.request_order, ["z", "a"]);
        let read = only_big.read_request(input("POST", "/pay", "{}")).unwrap();
        assert!(read.scope.is_none() && read.errored);
        let read = only_big.read_request(input("POST", "/pay", r#"{"amount": 5}"#)).unwrap();
        assert!(read.scope.is_none() && !read.errored, "false is not an error");
    }

    #[test]
    fn consent_is_one_template_with_pipe_filters() {
        assert_eq!(
            consent_refs("Buy from {{ request.body.merchant }} for {{request.body.amount}}").unwrap(),
            vec![
                ConsentRef {
                    path: "request.body.merchant".into(),
                    filter: None
                },
                ConsentRef {
                    path: "request.body.amount".into(),
                    filter: None
                },
            ]
        );
        // A rich renderer is a FILTER in the same one template field — same
        // `{{ x | filter }}` grammar as git's `{{ secret.X | basic }}`.
        assert_eq!(
            consent_refs("{{ request.body.raw | email }}").unwrap(),
            vec![ConsentRef {
                path: "request.body.raw".into(),
                filter: Some("email".into())
            }]
        );
        // A `|` in a header name is part of the path.
        assert_eq!(
            consent_refs("{{ request.headers['a|b'] }}").unwrap()[0].path,
            "request.headers['a|b']"
        );
        assert!(consent_refs("{{ request.body.raw").is_err());
    }

    /// DESIGN §7: a GitHub secret's sealed value is fresh on every run, so an
    /// approval covers the secret's path, the key it is sealed to, its
    /// visibility and its repositories; Gmail's sends are covered whole, with
    /// the email by its content, on any `users/:user`.
    #[test]
    fn compiled_scopes_follow_the_built_in_rule_sets() {
        let r = ServiceRegistry::load();
        let gh = r.get("github").unwrap();
        let secret = "/repos/o/r/actions/secrets/TOKEN";
        let id = |body: &str| covered(gh, "PUT", secret, body).1;
        let a = id(r#"{"encrypted_value":"c2VhbGVkLTE=","key_id":"k1"}"#);
        assert_eq!(a, id(r#"{"encrypted_value":"c2VhbGVkLTI=","key_id":"k1"}"#));
        assert_ne!(a, id(r#"{"encrypted_value":"c2VhbGVkLTI=","key_id":"k2"}"#));
        assert_ne!(a, covered(gh, "PUT", "/repos/o/r/actions/secrets/OTHER", r#"{"encrypted_value":"x","key_id":"k1"}"#).1);
        let org = "/orgs/acme/actions/secrets/TOKEN";
        let vis = |v: &str| covered(gh, "PUT", org, &format!(r#"{{"encrypted_value":"x","key_id":"k1","visibility":"{v}"}}"#)).1;
        assert_ne!(vis("private"), vis("all"));
        // The repository settings shape covers the whole request.
        let repo = |body: &str| covered(gh, "PATCH", "/repos/o/r", body).1;
        assert_ne!(repo(r#"{"private":false}"#), repo(r#"{"private":false,"description":"x"}"#));

        let gmail = r.get("gmail").unwrap();
        let email = |date: &str, b: &str| {
            format!("Content-Type: multipart/alternative; boundary=\"{b}\"\nTo: b@y.com\nSubject: Hi\nDate: {date}\n\n--{b}\nContent-Type: text/plain\n\nhello\n--{b}--\n")
        };
        let raw = |e: &str| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE.encode(e.as_bytes())
        };
        for (path, field) in [
            ("/gmail/v1/users/me/messages/send", "raw"),
            ("/gmail/v1/users/a@x.com/messages/send", "raw"),
            ("/gmail/v1/users/me/drafts/send", "message"),
        ] {
            let body = |e: &str| match field {
                "raw" => format!(r#"{{"raw":"{}"}}"#, raw(e)),
                _ => format!(r#"{{"message":{{"raw":"{}"}}}}"#, raw(e)),
            };
            let send = |e: &str| covered(gmail, "POST", path, &body(e)).1;
            assert_eq!(send(&email("Mon", "b1")), send(&email("Tue", "b2")), "{path}");
            assert_ne!(send(&email("Mon", "b1")), send(&email("Mon", "b1").replace("hello", "bye")), "{path}");
        }
    }

    #[test]
    fn a_narrowed_identity_is_stable_and_tamper_sensitive() {
        // The $80/$180 guarantee: the same covered values → the same
        // identity whatever the member order; a field not covered (a nonce)
        // never affects it; a changed value does.
        let def = snaplii_def();
        let id = |body: &str| covered(&def, "POST", "/v2/purchase", body).1;
        let a = id(r#"{"amount":80,"merchant_id":"m_1"}"#);
        assert_eq!(a, id(r#"{"merchant_id":"m_1","amount":80,"nonce":"Q"}"#));
        assert_ne!(a, id(r#"{"amount":180,"merchant_id":"m_1"}"#));
        assert_ne!(a, id(r#"{"amount":"80","merchant_id":"m_1"}"#), "JCS keeps the type");
        assert_ne!(id(r#"{"merchant_id":"m_1"}"#), id(r#"{"amount":null,"merchant_id":"m_1"}"#), "absent is not null");
    }

    /// Body format (DESIGN §9): GitHub's make-public is read from a JSON body
    /// sent as `text/plain` and from a form body too.
    #[test]
    fn compiled_github_make_public_reads_every_body_reading() {
        use crate::core::policy::AccessLevel;
        let eval = |content_type: Option<&str>, body: &str| {
            let headers: Vec<(String, Vec<u8>)> = content_type
                .map(|c| vec![("content-type".to_string(), c.as_bytes().to_vec())])
                .unwrap_or_default();
            eval_with(
                "github",
                RequestInput {
                    headers: &headers,
                    ..input("PATCH", "/repos/o/r", body)
                },
            )
        };
        for (ct, body) in [
            (Some("text/plain"), r#"{"private":false}"#),
            (Some("application/json"), r#"{"private":false}"#),
            (None, "private=false"),
            (Some("application/x-www-form-urlencoded"), "private=false"),
            (None, r#"{"visibility":"public"}"#),
        ] {
            assert_eq!(eval(ct, body), AccessLevel::AskAlways, "{ct:?} {body}");
        }
        for (ct, body) in [
            (Some("application/json"), r#"{"private":true}"#),
            (None, "private=true"),
            (Some("application/json"), r#"{"description":"x"}"#),
        ] {
            assert_eq!(eval(ct, body), AccessLevel::Allow, "{ct:?} {body}");
        }
    }

    /// Every shipped condition evaluates on its service's routine requests
    /// without an error (an error would decide by "never loosen", not by the
    /// condition).
    #[test]
    fn every_shipped_condition_reads_its_routine_requests_cleanly() {
        let r = ServiceRegistry::load();
        let routine: &[(&str, &str, &str, &str)] = &[
            ("github", "PATCH", "/repos/o/r", r#"{"description": "docs"}"#),
            ("github", "PATCH", "/repos/o/r", r#"{"private": true}"#),
            ("github", "PATCH", "/repositories/1", r#"{"has_issues": false}"#),
            ("github", "POST", "/repos/o/r", r#"{"name": "r2"}"#),
            ("github", "POST", "/graphql", r#"{"query":"query { viewer { login } }"}"#),
            ("github", "POST", "/graphql", r#"{"query":"mutation { addComment(input: {subjectId: \"I\", body: \"hi\"}) { clientMutationId } }"}"#),
            ("openai", "POST", "/v1/chat/completions", r#"{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}"#),
            ("openai", "POST", "/v1/responses", r#"{"model": "gpt-4o", "input": "hi"}"#),
            ("openai", "POST", "/v1/threads/t1/runs", r#"{"assistant_id": "a"}"#),
            ("openai", "POST", "/v1/threads/t1/runs", r#"{"assistant_id": "a", "model": null}"#),
            ("railway", "POST", "/graphql/v2", r#"{"query":"query { me { name } }"}"#),
            ("railway", "POST", "/graphql/v2", r#"{"query":"mutation { serviceInstanceRedeploy(serviceId: \"s\") }"}"#),
            ("snaplii", "POST", "/v2/purchase", r#"{"orderInfo": {"orderType": "GIFT_CARD", "item": {"itemId": "CB_1", "price": "40.00"}}}"#),
            ("snaplii", "POST", "/v2/purchase", r#"{"orderInfo": {"orderType": "GIFT_CARD", "item": {"itemId": "CB_1", "price": "250.00"}}, "delivery": {"type": "WALLET"}}"#),
        ];
        let mut evaluated = std::collections::BTreeSet::new();
        for (service, method, path, body) in routine {
            let def = r.get(service).expect("service");
            let request = def.read_request(input(method, path, body)).expect("readable").request;
            for rule in r.default_policy_rules(service).unwrap_or_default() {
                let Some(c) = &rule.condition else { continue };
                if rule.select.exec(method, path).is_none() {
                    continue;
                }
                let got = c.eval(&request).expect("readable");
                assert!(got.is_some(), "{service} {}: errors on {method} {path} {body}", c.as_str());
                evaluated.insert(format!("{service}/{}", rule.id.clone().unwrap_or_default()));
            }
        }
        // Every shipped condition was reached.
        let mut shipped = std::collections::BTreeSet::new();
        for (id, def) in r.iter_sorted() {
            for rule in def.policy.iter().flat_map(|p| p.rules.iter()) {
                if rule.condition.is_some() {
                    shipped.insert(format!("{id}/{}", rule.id.clone().unwrap_or_default()));
                }
            }
        }
        assert_eq!(shipped.len(), 8, "{shipped:?}");
        assert_eq!(evaluated, shipped);
    }

    #[test]
    fn compiled_openai_lets_a_null_model_ride_the_floor() {
        use crate::core::policy::AccessLevel;
        for path in ["/v1/chat/completions", "/v1/threads/t1/runs"] {
            assert_eq!(eval_compiled("openai", "POST", path, r#"{"model": null}"#), AccessLevel::Allow);
        }
        // A chat body whose tool schema has both `ID` and `id` is not refused.
        let tools = r#"{"model": "gpt-4o", "tools": [{"type": "function", "function": {"name": "f", "parameters": {"properties": {"ID": {}, "id": {}}}}}]}"#;
        assert_eq!(eval_compiled("openai", "POST", "/v1/chat/completions", tools), AccessLevel::Allow);
        // A JSON chat body sent as JSON whose text holds a form spelling of
        // the model is read as JSON only.
        let headers = vec![("content-type".to_string(), b"application/json".to_vec())];
        let chat = r#"{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "a&model=o3"}]}"#;
        assert_eq!(
            eval_with(
                "openai",
                RequestInput {
                    headers: &headers,
                    ..input("POST", "/v1/chat/completions", chat)
                }
            ),
            AccessLevel::Allow
        );
        // `{"Model": …}` beside the model a rule reads is refused.
        let r = ServiceRegistry::load();
        let def = r.get("openai").unwrap();
        let rules = r.default_policy_rules("openai").unwrap().to_vec();
        let body = r#"{"model": "gpt-4o-mini", "Model": "o3"}"#;
        let refused = def
            .read_request(input("POST", "/v1/chat/completions", body))
            .and_then(|read| {
                let req = read.request;
                crate::core::policy::evaluate(&req, Some(&rules), None, &crate::core::policy::Policy::default(), &[])
            });
        assert_eq!(refused.unwrap_err().status, 422);
    }
}
