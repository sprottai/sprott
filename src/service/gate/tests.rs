use super::*;
use crate::core::request::BodyFormat;

const GITHUB: &str = r#"
[service]
id = "github"
name = "GitHub"

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]
"#;

fn ok(toml: &str) -> ServiceDef {
    admit(None, toml, None).unwrap_or_else(|e| panic!("expected admit, got {:?}", e))
}

fn rejected(toml: &str) -> Vec<String> {
    admit(None, toml, None).expect_err("expected rejection")
}

fn rejected_with(toml: &str, policy: &str) -> Vec<String> {
    admit(None, toml, Some(policy)).expect_err("expected rejection")
}

fn mentions(errs: &[String], needle: &str) -> bool {
    errs.iter().any(|e| e.contains(needle))
}

// ── compiled-in definitions ──────────────────────────────────────────────────

/// Every compiled service, with its policy.toml, passes the gate under its
/// directory name: the build-time check for in-tree definitions (a condition
/// that is not CEL over the request, an unknown level, a request path that
/// names nothing, ... fails the suite here). Every shipped condition guards
/// what it reads: no warnings.
#[test]
fn compiled_services_pass_validator() {
    let policies: HashMap<&str, &str> = crate::generated_services::compiled_policy_tomls()
        .iter()
        .copied()
        .collect();
    for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
        let def = admit(Some(id), toml_str, policies.get(id).copied())
            .unwrap_or_else(|e| panic!("compiled service '{}' rejected: {:?}", id, e));
        assert!(def.warnings.is_empty(), "{id}: {:?}", def.warnings);
        for rule in def.policy.iter().flat_map(|p| p.rules.iter()) {
            assert!(rule.level.is_some(), "{id}: every rule decides");
        }
    }
    for (id, _) in crate::generated_services::compiled_policy_tomls() {
        assert!(
            crate::generated_services::compiled_service_tomls()
                .iter()
                .any(|(s, _)| s == id),
            "policy.toml for '{}' has no service.toml",
            id
        );
    }
    let reg = crate::service::ServiceRegistry::compiled_only();
    assert_eq!(
        reg.all().len(),
        crate::generated_services::compiled_service_tomls().len(),
        "the registry loads every compiled service"
    );
}

// ── one gate: storage key = declared id ──────────────────────────────────────

#[test]
fn key_must_equal_declared_id() {
    assert!(admit(Some("github"), GITHUB, None).is_ok());
    let e = admit(Some("gitlab"), GITHUB, None).unwrap_err();
    assert!(
        mentions(&e, "stored as 'gitlab' but declares id 'github'"),
        "{e:?}"
    );
    // The vault reader applies it: a def stored under another key is skipped.
    let mut aux = std::collections::BTreeMap::new();
    aux.insert(
        "mine".to_string(),
        GITHUB.replace("\"github\"", "\"other\"").into(),
    );
    let reg = crate::service::ServiceRegistry::compiled_only();
    let (defs, skipped) = crate::service::vault_custom_services(&aux, true, &reg);
    assert!(defs.is_empty());
    assert!(skipped[0].1.contains("declares id 'other'"), "{skipped:?}");
}

// ── service.toml schema (moved from the old validator) ───────────────────────

#[test]
fn valid_direct_service() {
    ok(GITHUB);
}

#[test]
fn oauth2_must_be_inline_complete() {
    let label_only = r#"
[service]
id = "gmail"
name = "Gmail"
hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]
[auth]
type = "oauth2"
provider = "google"
refresh_token = "GMAIL_REFRESH_TOKEN"
"#;
    rejected(label_only);
}

const ACME_OAUTH: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_REFRESH_TOKEN"]
[auth]
type = "oauth2"
authorization_url = "https://auth.acme.dev/authorize"
token_url = "https://auth.acme.dev/token"
client_id = "acme-public"
refresh_token = "ACME_REFRESH_TOKEN"
"#;

#[test]
fn inline_oauth2_is_self_sufficient() {
    ok(ACME_OAUTH);
    let labeled = ACME_OAUTH.replace(
        "type = \"oauth2\"",
        "type = \"oauth2\"\nprovider = \"acme\"",
    );
    ok(&labeled);
    rejected(&ACME_OAUTH.replace("token_url = \"https://auth.acme.dev/token\"\n", ""));
    rejected(&ACME_OAUTH.replace("https://auth.acme.dev/token", "http://auth.acme.dev/token"));
    let secret = ACME_OAUTH.replace(
        "client_id = \"acme-public\"",
        "client_id = \"acme-public\"\nclient_secret = \"shh\"",
    );
    ok(&secret);
    // The retired client_type assertion is an unknown field.
    rejected(&secret.replace(
        "client_secret = \"shh\"",
        "client_secret = \"shh\"\nclient_type = \"public\"",
    ));
    // oauth_style is form or json, nothing else.
    ok(&ACME_OAUTH.replace(
        "client_id = \"acme-public\"",
        "client_id = \"acme-public\"\noauth_style = \"json\"",
    ));
    let e = rejected(&ACME_OAUTH.replace(
        "client_id = \"acme-public\"",
        "client_id = \"acme-public\"\noauth_style = \"xml\"",
    ));
    assert!(mentions(&e, "oauth_style 'xml' is unknown"), "{e:?}");
}

#[test]
fn oauth2_claims_and_authorize_params_are_checked() {
    let base = format!("{ACME_OAUTH}exposes = [\"account_id\"]\n");
    ok(&format!(
        "{base}[auth.claims]\naccount_id = [\"ns\", \"leaf\"]\n"
    ));
    rejected(&format!("{base}[auth.claims]\nother = [\"x\"]\n"));
    rejected(&format!("{base}[auth.claims]\naccount_id = []\n"));
    ok(&format!(
        "{base}[auth.authorize_params]\nfoo_flag = \"true\"\n"
    ));
    rejected(&format!(
        "{base}[auth.authorize_params]\nredirect_uri = \"https://evil.example\"\n"
    ));
}

/// The token-endpoint knobs: `token_auth` is post or basic; `token_params` /
/// `refresh_params` are additions (reserved protocol keys refused), and the
/// one placeholder allowed is `{state}` in token_params only.
#[test]
fn oauth2_token_knobs_are_checked() {
    // token_auth: post or basic, nothing else.
    ok(&format!("{ACME_OAUTH}token_auth = \"basic\"\n"));
    ok(&format!("{ACME_OAUTH}token_auth = \"post\"\n"));
    let e = rejected(&format!("{ACME_OAUTH}token_auth = \"header\"\n"));
    assert!(mentions(&e, "token_auth 'header' is unknown"), "{e:?}");

    // token_params: additions ok, {state} ok, reserved and other placeholders refused.
    ok(&format!(
        "{ACME_OAUTH}[auth.token_params]\necho_state = \"{{state}}\"\naudience = \"api\"\n"
    ));
    for reserved in [
        "grant_type",
        "code",
        "code_verifier",
        "client_id",
        "client_secret",
        "redirect_uri",
    ] {
        let e = rejected(&format!(
            "{ACME_OAUTH}[auth.token_params]\n{reserved} = \"x\"\n"
        ));
        assert!(
            mentions(&e, &format!("token_params may not set the reserved param '{reserved}'")),
            "{e:?}"
        );
    }
    let e = rejected(&format!(
        "{ACME_OAUTH}[auth.token_params]\necho = \"{{code}}\"\n"
    ));
    assert!(
        mentions(&e, "token_params 'echo' uses a placeholder other than {state}"),
        "{e:?}"
    );
    let e = rejected(&format!(
        "{ACME_OAUTH}[auth.token_params]\necho = \"{{state}} and {{more}}\"\n"
    ));
    assert!(mentions(&e, "placeholder other than {state}"), "{e:?}");

    // refresh_params: additions ok, reserved refused, NO placeholders (there
    // is no consent state at refresh time).
    ok(&format!(
        "{ACME_OAUTH}[auth.refresh_params]\naudience = \"api\"\n"
    ));
    for reserved in ["grant_type", "refresh_token", "client_id", "client_secret"] {
        let e = rejected(&format!(
            "{ACME_OAUTH}[auth.refresh_params]\n{reserved} = \"x\"\n"
        ));
        assert!(
            mentions(&e, &format!("refresh_params may not set the reserved param '{reserved}'")),
            "{e:?}"
        );
    }
    let e = rejected(&format!(
        "{ACME_OAUTH}[auth.refresh_params]\necho = \"{{state}}\"\n"
    ));
    assert!(
        mentions(&e, "refresh_params 'echo' uses a placeholder; refresh values are static"),
        "{e:?}"
    );
}

#[test]
fn rejects_tool_named_and_v3_sections() {
    let e = rejected(&format!("{}\n[git]\nhelper = \"x\"\n", GITHUB));
    assert!(mentions(&e, "parse error"), "{e:?}");
    let v3 = "[service]\nid = \"x\"\nname = \"X\"\n[[upstream]]\nid = \"default\"\nurl = \"https://x.com\"\n";
    assert!(mentions(&rejected(v3), "parse error"));
}

/// A parse error names its kind, line and column, never the text: neither the
/// offending line nor a key or value from it is echoed.
#[test]
fn parse_errors_give_kind_and_position_never_the_text() {
    let leaks = |e: &[String], text: &str| e.iter().any(|p| p.contains(text));
    // Syntax, in service.toml and policy.toml.
    let e = rejected("[service]\nid = \"x\"\nname = LEAK_ONE\n");
    assert_eq!(
        e,
        ["service.toml: parse error: syntax error at line 3, column 8"]
    );
    let e = rejected_with(GITHUB, "[[rule]\nid = \"LEAK_TWO\"\n");
    assert!(
        mentions(&e, "policy.toml: parse error: syntax error at line 1"),
        "{e:?}"
    );
    assert!(!leaks(&e, "LEAK_TWO"), "{e:?}");
    let e = rejected("[service]\nid = \"x\"\nid = \"LEAK_THREE\"\n");
    assert!(mentions(&e, "duplicate key at line 3"), "{e:?}");
    assert!(!leaks(&e, "LEAK_THREE"), "{e:?}");
    // Schema: a value of the wrong type, an unknown key.
    let e = rejected(&GITHUB.replace(
        "hosts = [\"api.github.com\", \"github.com\"]",
        "hosts = \"leak-four.example\"",
    ));
    assert!(
        mentions(&e, "a value has the wrong type at line 6"),
        "{e:?}"
    );
    assert!(!leaks(&e, "leak-four"), "{e:?}");
    let e = rejected(&format!("{GITHUB}leak_five = 1\n"));
    assert!(mentions(&e, "unknown field at line 8"), "{e:?}");
    assert!(!leaks(&e, "leak_five"), "{e:?}");
}

#[test]
fn unknown_fields_are_rejected_everywhere() {
    // A typo in [service] (it used to be silently ignored there).
    let e = rejected(&GITHUB.replace("secrets =", "secret ="));
    assert!(mentions(&e, "unknown field at line"), "{e:?}");
    // [requests] shape, and an `encoded` entry.
    let req =
        "[requests.buy]\nmethod = \"POST\"\npath = \"/buy\"\nscope = [\"request.body.amount\"]\n";
    ok(&format!("{GITHUB}{req}"));
    rejected(&format!("{GITHUB}{req}scopes = [\"request.body.amount\"]\n"));
    rejected(&format!(
        "{GITHUB}{req}encoded.\"request.body.raw\" = {{ contentEncoding = \"base64\", as = \"int\" }}\n"
    ));
    // policy.toml: top level, [default], [[rule]].
    let rule =
        "[[rule]]\nid = \"del\"\nlabel = \"Delete\"\nmethod = \"DELETE\"\npath = \"/x\"\nlevel = \"ask\"\n";
    assert!(admit(None, GITHUB, Some(rule)).is_ok());
    rejected_with(GITHUB, &format!("{rule}[extra]\na = 1\n"));
    rejected_with(
        GITHUB,
        &format!("[default]\nread = \"allow\"\nwirte = \"deny\"\n{rule}"),
    );
    rejected_with(
        GITHUB,
        &rule.replace("level = \"ask\"", "level = \"ask\"\nlevl = \"deny\""),
    );
}

#[test]
fn host_rules() {
    let ok_toml = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.com", "*.openai.azure.com"]
secrets = ["ACME_TOKEN"]
"#;
    ok(ok_toml);
    for (from, to) in [
        ("\"*.openai.azure.com\"", "\"*\""),
        ("\"*.openai.azure.com\"", "\"*.com\""),
        ("\"*.openai.azure.com\"", "\"*.10.0.0.1\""),
        ("\"*.openai.azure.com\"", "\"a.*.azure.com\""),
        ("\"api.acme.com\"", "\"https://api.acme.com\""),
        ("\"api.acme.com\"", "\"api.acme.com/v1\""),
        ("\"api.acme.com\"", "\"api.acme.com:443\""),
    ] {
        rejected(&ok_toml.replace(from, to));
    }
}

#[test]
fn rejects_private_loopback_and_noncanonical_hosts() {
    for bad in [
        "10.0.0.5",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "localhost",
        "2130706433",
        "0x7f.1",
        "0177.0.0.1",
        "127.1",
    ] {
        let e = rejected(&GITHUB.replace("\"api.github.com\"", &format!("\"{}\"", bad)));
        assert!(
            mentions(&e, "not an egress target") || mentions(&e, "non-canonical"),
            "{bad}: {e:?}"
        );
    }
    // Names are not special-cased: a self-hosted `.internal` service is fine.
    ok(&GITHUB.replace("\"api.github.com\"", "\"metadata.google.internal\""));
    ok(&GITHUB.replace("\"api.github.com\"", "\"vault.corp.internal\""));
}

#[test]
fn urls_are_parsed_by_the_client_parser_and_refuse_userinfo() {
    for (from, to) in [
        (
            "https://auth.acme.dev/token",
            "https://user@auth.acme.dev/token",
        ),
        ("https://auth.acme.dev/token", "https://2130706433/token"),
        ("https://auth.acme.dev/token", "https://127.0.0.1/token"),
        (
            "https://auth.acme.dev/authorize",
            "https://u:p@auth.acme.dev/authorize",
        ),
    ] {
        rejected(&ACME_OAUTH.replace(from, to));
    }
    let redirect = |u: &str| {
        ACME_OAUTH.replace(
            "client_id = \"acme-public\"",
            &format!("client_id = \"acme-public\"\nredirect_uri = \"{}\"", u),
        )
    };
    // redirect_uri is where the consent lands, not an egress target: any
    // host, in the forms OAuth clients use (http(s), out-of-band, a
    // reverse-domain app scheme).
    for u in [
        "http://127.0.0.1:8765/safeclaw/oauth/callback",
        "http://localhost:1455/auth/callback",
        "urn:ietf:wg:oauth:2.0:oob",
        "com.example.app:/oauth2redirect",
        "com.googleusercontent.apps.123-abc:/oauth2redirect",
        "Com.Example.App:/cb",
        "https://app.example.com/cb",
    ] {
        ok(&redirect(u));
    }
    for u in ["/relative/cb", "not a uri", "cb"] {
        let e = rejected(&redirect(u));
        assert!(mentions(&e, "not an absolute URI"), "{u}: {e:?}");
    }
    for u in [
        "javascript:alert(1)",
        "data:text/html,hi",
        "file:///etc/passwd",
        "ftp://example.com/cb",
        "myapp:/cb",
        "urn:ietf:wg:oauth:2.0:other",
        "com..example:/cb",
        "com.example.:/cb",
        "com.ex+ample:/cb",
    ] {
        let e = rejected(&redirect(u));
        assert!(mentions(&e, "must be an http(s) URL"), "{u}: {e:?}");
    }
    let e = rejected(&redirect("com.example.app:/cb\\u202e"));
    assert!(mentions(&e, "control or bidi"), "{e:?}");
}

#[test]
fn rejects_bad_service_id_and_roles() {
    for id in ["Git Hub", "git__hub", "git-hub", ""] {
        let e = rejected(&GITHUB.replace("id = \"github\"", &format!("id = \"{}\"", id)));
        assert!(mentions(&e, "not valid"), "{id}: {e:?}");
    }
    let e = rejected(&GITHUB.replace("\"GITHUB_TOKEN\"", "\"github-token\""));
    assert!(mentions(&e, "env key"));
    let e = rejected(&GITHUB.replace("name = \"GitHub\"", "name = \" \""));
    assert!(mentions(&e, "name must not be empty"));
}

#[test]
fn secret_url_optional_and_web_only() {
    let with = GITHUB.replace(
        "secrets = [\"GITHUB_TOKEN\"]",
        "secrets = [\"GITHUB_TOKEN\"]\nsecret_url = \"https://github.com/settings/tokens?type=beta\"",
    );
    ok(&with);
    let e = rejected(&with.replace(
        "https://github.com/settings/tokens?type=beta",
        "javascript:alert(1)",
    ));
    assert!(mentions(&e, "secret_url"));
    rejected(&with.replace("https://github.com/", "https://me@github.com/"));
}

#[test]
fn tags_group_and_activation() {
    ok(&GITHUB.replace(
        "name = \"GitHub\"",
        "name = \"GitHub\"\ntags = [\"app\", \"code-hosting\"]",
    ));
    for bad in [
        "[\"App\"]",
        "[\"code_hosting\"]",
        "[\"-app\"]",
        "[\"\"]",
        "[\"app\", \"app\"]",
    ] {
        let e = rejected(&GITHUB.replace(
            "name = \"GitHub\"",
            &format!("name = \"GitHub\"\ntags = {}", bad),
        ));
        assert!(mentions(&e, "tag"), "{bad}");
    }
    ok(&GITHUB.replace(
        "name = \"GitHub\"",
        "name = \"GitHub\"\nactivation = \"auto\"\ngroup = \"gitlab\"",
    ));
    rejected(&GITHUB.replace(
        "name = \"GitHub\"",
        "name = \"GitHub\"\nactivation = \"always\"",
    ));
    rejected(&GITHUB.replace(
        "name = \"GitHub\"",
        "name = \"GitHub\"\ngroup = \"Git Lab\"",
    ));
}

// ── [requests] ───────────────────────────────────────────────────────────────

const REQ_SERVICE: &str = r#"
[service]
id = "pay"
name = "Pay"
hosts = ["api.pay.com"]
secrets = ["PAY_KEY"]
[requests.purchase]
method = "POST"
path = "/buy"
scope = ["request.body.amount"]
consent = "Spend {{ request.body.amount }}"
"#;

#[test]
fn requests_shapes_are_checked() {
    let def = ok(REQ_SERVICE);
    let shape = &def.requests["purchase"];
    assert_eq!(shape.format, BodyFormat::Json);
    assert_eq!(shape.binds().iter().map(ToString::to_string).collect::<Vec<_>>(), ["request.body.amount"]);
    // A consent path is bound with the scope.
    let def = ok(&REQ_SERVICE.replace("{{ request.body.amount }}", "{{ request.body.memo }}"));
    assert_eq!(
        def.requests["purchase"].binds().iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["request.body.amount", "request.body.memo"]
    );
    // `scope` absent or empty is accepted.
    ok(&REQ_SERVICE.replace("scope = [\"request.body.amount\"]\n", ""));
    ok(&REQ_SERVICE.replace("scope = [\"request.body.amount\"]", "scope = []"));
    for (from, to, why) in [
        ("{{ request.body.amount }}", "{{ secret.raw }}", "is not a request path"),
        ("{{ request.body.amount }}", "{{ request }}", "`request` is read whole"),
        ("\"request.body.amount\"]", "\"request.body.amount\", \"ghost\"]", "'ghost' is not a request path"),
        ("\"request.body.amount\"]", "\"request.body.amount\", \"request.body['amount']\"]", "lists request.body.amount more than once"),
        ("\"request.body.amount\"]", "\"request.nope\"]", "request has no field 'nope'"),
        ("\"request.body.amount\"]", "\"request.headers['X-Acl']\"]", "header names are lowercase"),
        ("\"request.body.amount\"]", "\"request.graphql.calls\"]", "is read only with body = \"graphql\""),
        ("path = \"/buy\"", "path = \"/buy\"\nbody = \"xml\"", "body = \"xml\" is not a body format (json, form, graphql, text)"),
        ("path = \"/buy\"", "path = \"/buy\"\nvars.amount = \"/amount\"", "`vars` is not read; name each value by its request path"),
        ("path = \"/buy\"", "path = \"/buy\"\ncondition = \"request.graphql.fields.size() > 0\"", "can't read request.graphql"),
        ("path = \"/buy\"", "path = \"/buy\"\ncondition = \"request.path == '/buy'\"", "select the path with `path"),
    ] {
        let e = rejected(&REQ_SERVICE.replace(from, to));
        assert!(mentions(&e, why), "{to}: {e:?}");
    }
    // A shape's condition and the graphql body format.
    let def = ok(&REQ_SERVICE.replace(
        "path = \"/buy\"",
        "path = \"/buy\"\ncondition = \"has(request.body.amount)\"\nbody = \"form\"",
    ));
    assert_eq!(def.requests["purchase"].format, BodyFormat::Form);
    assert!(def.requests["purchase"].condition.is_some());
    ok(&REQ_SERVICE
        .replace("path = \"/buy\"", "path = \"/buy\"\nbody = \"graphql\"")
        .replace("\"request.body.amount\"]", "\"request.graphql.calls\"]"));
    // A 2.0 `match` is refused, with the replacement spelled out.
    let e = rejected(&REQ_SERVICE.replace("method = \"POST\"\npath = \"/buy\"", "match = \"POST /buy\""));
    assert!(mentions(&e, "[requests.purchase]: `match` is not read; use method = \"DELETE\" and path = \"/v1/x/:id\""), "{e:?}");
    let e = rejected(&REQ_SERVICE.replace("method = \"POST\"", "match = \"POST /buy\"\nmethod = \"POST\""));
    assert!(mentions(&e, "`match` is not read"), "{e:?}");
    // A path that could never match a request, or a 2.0 glob.
    for (bad, why) in [
        ("buy", "must start with '/'"),
        ("/buy?x=1", "is not a URL Pattern pathname"),
        ("/a/**/b", "'**'"),
        ("/a/*/b", "write ':name' for one segment"),
        ("/buy/", "ends with '/'"),
        ("/a/:", "is not a URL Pattern pathname"),
    ] {
        let e = rejected(&REQ_SERVICE.replace("path = \"/buy\"", &format!("path = \"{}\"", bad)));
        assert!(mentions(&e, why), "{bad}: {e:?}");
    }
    for (bad, why) in [("GE T", "not an HTTP method token"), ("", "not an HTTP method token")] {
        let e = rejected(&REQ_SERVICE.replace("method = \"POST\"", &format!("method = \"{}\"", bad)));
        assert!(mentions(&e, why), "{bad}: {e:?}");
    }
    let e = rejected(&REQ_SERVICE.replace("method = \"POST\"", "method = []"));
    assert!(mentions(&e, "`method = []` lists no method"), "{e:?}");
    let e = rejected(&REQ_SERVICE.replace("path = \"/buy\"", "path = []"));
    assert!(mentions(&e, "`path = []` lists no path"), "{e:?}");
    let e = rejected(&REQ_SERVICE.replace("method = \"POST\"\npath = \"/buy\"\n", ""));
    assert!(mentions(&e, "selects every request"), "{e:?}");
    // A method alone selects that method on any path; one is stored uppercase.
    let def = ok(&REQ_SERVICE.replace("method = \"POST\"\npath = \"/buy\"\n", "method = \"post\"\n"));
    assert!(def.shape_selects("POST", "/anything"));
}

#[test]
fn encoded_values_are_declared_in_json_schema_content_keywords() {
    let with = |entry: &str| REQ_SERVICE.replace("consent =", &format!("{entry}\nconsent ="));
    let def = ok(&with(
        "encoded.\"request.body.raw\" = { contentEncoding = \"base64url\", contentMediaType = \"message/rfc822\" }",
    ));
    let e = &def.requests["purchase"].encoded["request.body.raw"];
    assert_eq!(e.content_encoding.as_deref(), Some("base64url"));
    assert_eq!(e.content_media_type.as_deref(), Some("message/rfc822"));
    for (entry, why) in [
        ("encoded.\"request.body.raw\" = { contentEncoding = \"rot13\" }", "contentEncoding \"rot13\" is unknown"),
        ("encoded.\"request.body.raw\" = { contentMediaType = \"not a type\" }", "is not a media type"),
        ("encoded.\"request.body.raw\" = {}", "declares neither"),
        ("encoded.\"body.raw\" = { contentEncoding = \"base64\" }", "is not a request path"),
        ("encoded.\"request.host\" = { contentEncoding = \"base64\" }", "names no value that carries media"),
        ("encoded.\"request.body.raw\" = { contentEncoding = \"base64\", schema = \"x\" }", "unknown field"),
    ] {
        let e = rejected(&with(entry));
        assert!(mentions(&e, why), "{entry}: {e:?}");
    }
}

#[test]
fn consent_filters_are_the_ones_the_console_implements() {
    let raw = |consent: &str| {
        format!(
            "[service]\nid = \"m\"\nname = \"M\"\nhosts = [\"api.m.com\"]\n[requests.send]\nmethod = \"POST\"\npath = \"/send\"\nscope = [\"request.body.raw\"]\nconsent = \"{}\"\n",
            consent
        )
    };
    ok(&raw("{{ request.body.raw | email }}"));
    // `graphql` renders only a GraphQL request's calls.
    let e = rejected(&raw("{{ request.body.raw | graphql }}"));
    assert!(mentions(&e, "consent filter 'graphql' reads only request.graphql.calls"), "{e:?}");
    ok(&raw("{{ request.graphql.calls | graphql }}").replace("path = \"/send\"", "path = \"/send\"\nbody = \"graphql\""));
    ok(&raw("Send {{request.body.raw}} now"));
    ok(&raw("To {{ request.headers['x-to'] }}"));
    let e = rejected(&raw("{{ request.body.raw | html }}"));
    assert!(
        mentions(&e, "consent filter 'html' is unknown (known: email, graphql)"),
        "{e:?}"
    );
    // A token the console's grammar does not read is refused, not left literal.
    for bad in [
        "{{ raw }}",
        "{{ vars.raw }}",
        "{{ request.body.a-b }}",
        "{{ request.body.raw",
        "{{ secret.raw | basic }}",
    ] {
        rejected(&raw(bad));
    }
}

// ── policy.toml ──────────────────────────────────────────────────────────────

const RULE: &str = r#"
[[rule]]
id = "big"
label = "Big purchase"
method = "POST"
path = "/buy"
condition = "has(request.body.amount) && request.body.amount > 80"
level = "ask-always"
"#;

#[test]
fn policy_rules_are_recognized_whole_or_rejected() {
    let def = admit(None, REQ_SERVICE, Some(RULE)).expect("valid policy");
    let rule = &def.policy.as_ref().unwrap().rules[0];
    assert_eq!(rule.level, Some(AccessLevel::AskAlways));
    assert!(rule.condition.is_some());
    assert!(def.warnings.is_empty(), "{:?}", def.warnings);
    for (from, to, why) in [
        (
            "level = \"ask-always\"",
            "level = \"sometimes\"",
            "level 'sometimes' is unknown",
        ),
        ("level = \"ask-always\"\n", "", "declares no level"),
        (
            "has(request.body.amount) && request.body.amount > 80",
            "amount is big",
            "is not valid",
        ),
        (
            "label = \"Big purchase\"",
            "label = \"  \"",
            "label must not be empty",
        ),
        ("id = \"big\"", "id = \"Big One\"", "the id must be"),
        (
            "path = \"/buy\"",
            "path = \"/buy?x\"",
            "is not a URL Pattern pathname",
        ),
        (
            "method = \"POST\"\npath = \"/buy\"",
            "match = \"POST /buy\"",
            "rule 'big': `match` is not read; use method = \"DELETE\" and path = \"/v1/x/:id\"",
        ),
    ] {
        let e = rejected_with(REQ_SERVICE, &RULE.replace(from, to));
        assert!(mentions(&e, why), "{to}: {e:?}");
    }
    let dup = format!("{RULE}{RULE}");
    assert!(mentions(
        &rejected_with(REQ_SERVICE, &dup),
        "used by more than one rule"
    ));
    let bad_default = format!("[default]\nread = \"allow\"\nwrite = \"maybe\"\n{RULE}");
    assert!(mentions(
        &rejected_with(REQ_SERVICE, &bad_default),
        "level 'maybe' is unknown"
    ));
}

/// A rule that names nothing it matches (no `method`, `path` or condition)
/// matches every request: refused. With a condition it decides on that.
#[test]
fn a_rule_matching_every_request_is_refused() {
    let all = "[[rule]]\nid = \"all\"\nlabel = \"All\"\nlevel = \"deny\"\n";
    let e = rejected_with(GITHUB, all);
    assert!(mentions(&e, "matches every request"), "{e:?}");
    let conditioned = all.replace("level", "condition = \"request.query.force == '1'\"\nlevel");
    assert!(admit(None, GITHUB, Some(&conditioned)).is_ok());
}

/// The 2.0 `when` and `body` regex are refused with the replacement spelled
/// out.
#[test]
fn the_2_0_rule_syntax_is_refused_with_its_replacement() {
    let e = rejected_with(
        REQ_SERVICE,
        &RULE.replace("condition = \"has(request.body.amount) && request.body.amount > 80\"", "when = \"vars.amount > 80\""),
    );
    assert!(
        mentions(&e, "rule 'big': `when` is not read; use condition = \"request.body.amount > 80\""),
        "{e:?}"
    );
    let e = rejected_with(GITHUB, &RULE.replace("level", "body = \"gift\"\nlevel"));
    assert!(
        mentions(&e, "rule 'big': `body` (a regex) is not read; use condition = \"request.body.amount > 80\""),
        "{e:?}"
    );
}

#[test]
fn a_condition_that_is_not_cel_over_the_request_is_rejected() {
    let cond = "has(request.body.amount) && request.body.amount > 80";
    for (bad, why) in [
        ("request.body.amount > 80usd", "is not valid"),
        ("request.body.amount >= NaN", "`NaN` is not a known name"),
        ("request.body.amount == unlimited", "`unlimited` is not a known name"),
        ("vars.amount > 80", "`vars` is not a known name"),
        ("request.path == '/buy'", "select the path with `path"),
        ("request.method == 'POST'", "select the method with `method"),
        ("request.params.owner == 'x'", "name the segment in `path`"),
        ("request.body.model.lowerAscii() == 'o3'", "`lowerAscii()` is not a function"),
        ("request.body.contains('x') && request.body.a == 1", "whole (its text) and a member"),
    ] {
        let e = rejected_with(REQ_SERVICE, &RULE.replace(cond, bad));
        assert!(mentions(&e, why), "{bad}: {e:?}");
    }
    // Standard CEL is accepted: macros, functions, comparisons of any type,
    // headers and the query.
    for good in [
        "request.body.amount == 'unlimited'",
        "double(request.body.amount) > 80.0",
        "['a', 'b'].exists(p, string(request.body.amount).startsWith(p))",
        "'x-account' in request.headers && request.headers['x-account'] == 'prod'",
        "request.query.force == '1'",
    ] {
        assert!(
            admit(None, REQ_SERVICE, Some(&RULE.replace(cond, good))).is_ok(),
            "{good}"
        );
    }
}

/// A member read with no presence guard is admitted with a warning that says
/// what it means and offers the guard.
#[test]
fn an_unguarded_read_is_a_warning_not_a_refusal() {
    let cond = "has(request.body.amount) && request.body.amount > 80";
    let def = admit(None, REQ_SERVICE, Some(&RULE.replace(cond, "request.body.max_tokens > 1000"))).unwrap();
    assert_eq!(
        def.warnings,
        ["rule 'big': the condition reads request.body.max_tokens with no presence test: a request without it is decided ask-always by this rule too; guard it with has(request.body.max_tokens) && …"]
    );
    let deny = RULE.replace(cond, "request.headers['x-account'] == 'prod'").replace("ask-always", "deny");
    let def = admit(None, REQ_SERVICE, Some(&deny)).unwrap();
    assert!(mentions(&def.warnings, "is denied by this rule too; guard it with 'x-account' in request.headers && …"), "{:?}", def.warnings);
    let allow = RULE.replace(cond, "request.body.amount < 10").replace("ask-always", "allow");
    let def = admit(None, REQ_SERVICE, Some(&allow)).unwrap();
    assert!(mentions(&def.warnings, "this rule doesn't allow a request without it"), "{:?}", def.warnings);
    let shape = REQ_SERVICE.replace("path = \"/buy\"", "path = \"/buy\"\ncondition = \"request.body.amount > 1\"");
    assert!(mentions(&ok(&shape).warnings, "[requests.purchase]: the condition reads request.body.amount with no presence test: a request without it doesn't match this shape"));
}

#[test]
fn rule_method_word_is_case_insensitive() {
    let policy = "[[rule]]\nid = \"del\"\nlabel = \"Delete repo\"\nmethod = \"delete\"\npath = \"/repos/:owner/:repo\"\nlevel = \"deny\"\n";
    let def = admit(None, GITHUB, Some(policy)).unwrap();
    let rules = def.policy.unwrap().rules;
    let decide = |m: &str, p: &str| {
        crate::core::policy::evaluate(&crate::core::request::Request::bare(m, p), Some(&rules), None, &crate::core::policy::Policy::default(), &[]).unwrap()
    };
    assert_eq!(decide("DELETE", "/repos/o/r"), AccessLevel::Deny);
    assert_eq!(decide("GET", "/repos/o/r"), AccessLevel::Allow);
}

// ── limits ───────────────────────────────────────────────────────────────────

#[test]
fn over_limit_lists_are_refused_on_their_counts() {
    // A shape and a rule with huge path lists: refused on the counts, before
    // anything is compiled.
    let matches = vec!["\"/b\""; 12_000].join(",");
    let svc = format!(
        "[service]\nid = \"pay\"\nname = \"Pay\"\nhosts = [\"api.pay.com\"]\n[requests.purchase]\npath = [{}]\nscope = [\"request.body.amount\"]\n",
        matches
    );
    let rule = format!(
        "[[rule]]\nid = \"g\"\nlabel = \"G\"\nmethod = \"POST\"\npath = [{}]\ncondition = \"request.body.gift == true\"\nlevel = \"ask\"\n",
        matches
    );
    assert!(svc.len() < MAX_FILE_BYTES && rule.len() < MAX_FILE_BYTES);
    let started = std::time::Instant::now();
    let e = rejected_with(&svc, &rule);
    assert!(
        mentions(&e, "[requests.purchase] has 12000 method × path pairs"),
        "{e:?}"
    );
    assert!(mentions(&e, "rule 'g' has 12000 method × path pairs"), "{e:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn limits_reject_oversized_definitions() {
    let pad = format!("{GITHUB}# {}\n", "x".repeat(MAX_FILE_BYTES));
    assert!(mentions(&rejected(&pad), "the limit is"));
    let e = rejected_with(GITHUB, &format!("# {}\n", "x".repeat(MAX_FILE_BYTES)));
    assert!(mentions(&e, "policy.toml is"));

    let long = GITHUB.replace(
        "name = \"GitHub\"",
        &format!("name = \"{}\"", "n".repeat(MAX_STRING_BYTES + 1)),
    );
    assert!(mentions(&rejected(&long), "service.name is"));
    let setup = format!(
        "setup = \"\"\"\n{}\n\"\"\"\n{GITHUB}",
        "s".repeat(MAX_PROSE_BYTES + 1)
    );
    assert!(mentions(&rejected(&setup), "setup is"));

    let hosts: Vec<String> = (0..=MAX_HOSTS)
        .map(|i| format!("\"h{}.example.com\"", i))
        .collect();
    let many = GITHUB.replace(
        "hosts = [\"api.github.com\", \"github.com\"]",
        &format!("hosts = [{}]", hosts.join(", ")),
    );
    assert!(mentions(&rejected(&many), "hosts has"));

    let rules: String = (0..=MAX_RULES)
        .map(|i| {
            format!(
                "[[rule]]\nid = \"r{i}\"\nlabel = \"R\"\nmethod = \"GET\"\npath = \"/r{i}\"\nlevel = \"ask\"\n"
            )
        })
        .collect();
    assert!(mentions(&rejected_with(GITHUB, &rules), "rules has"));

    let pats: Vec<String> = (0..=MAX_MATCH_PATTERNS)
        .map(|i| format!("\"/p{}\"", i))
        .collect();
    let rule = format!(
        "[[rule]]\nid = \"m\"\nlabel = \"M\"\npath = [{}]\nlevel = \"ask\"\n",
        pats.join(", ")
    );
    assert!(mentions(&rejected_with(GITHUB, &rule), "method × path pairs"));
    // The limit counts each method with each path.
    let half: Vec<String> = (0..=MAX_MATCH_PATTERNS / 2).map(|i| format!("\"/p{}\"", i)).collect();
    let rule = format!(
        "[[rule]]\nid = \"m\"\nlabel = \"M\"\nmethod = [\"POST\", \"PUT\"]\npath = [{}]\nlevel = \"ask\"\n",
        half.join(", ")
    );
    assert!(mentions(&rejected_with(GITHUB, &rule), "34 method × path pairs"));
}

// ── display strings ──────────────────────────────────────────────────────────

#[test]
fn control_and_bidi_characters_are_rejected_and_never_echoed() {
    for (field, value) in [
        ("name", "Git\\u001b[31mHub"),
        ("name", "Git\\u0085Hub"),
        ("name", "Git\\u202eHub"),
        ("name", "Git\\u2066Hub"),
        ("name", "Git\\nHub"),
    ] {
        let toml = GITHUB.replace("name = \"GitHub\"", &format!("{} = \"{}\"", field, value));
        let e = rejected(&toml);
        assert!(mentions(&e, "control or bidi character"), "{value}: {e:?}");
        for m in &e {
            assert!(!m.chars().any(crate::util::is_unsafe_display_char), "{m:?}");
        }
    }
    // A rule label in policy.toml, and a table key.
    let label = "[[rule]]\nid = \"x\"\nlabel = \"Delete\\u200f repo\"\nmethod = \"DELETE\"\npath = \"/x\"\nlevel = \"ask\"\n";
    assert!(mentions(&rejected_with(GITHUB, label), "rule[0].label"));
    let key = format!("{ACME_OAUTH}[auth.authorize_params]\n\"a\\u001bb\" = \"1\"\n");
    assert!(mentions(&rejected(&key), "a key in auth.authorize_params"));
    // `setup` may carry \n and \t, nothing else.
    ok(&format!("setup = \"line one\\n\\tline two\"\n{GITHUB}"));
    let e = rejected(&format!("setup = \"ring\\u0007\"\n{GITHUB}"));
    assert!(mentions(&e, "only \\n and \\t are allowed"), "{e:?}");
    // A raw control character in the file fails the TOML parse; the message
    // that quotes the line is sanitized.
    let raw = GITHUB.replace("name = \"GitHub\"", "name = \"GitHub\"\n# \u{1b}[2J");
    if let Err(e) = admit(None, &raw, None) {
        for m in e {
            assert!(!m.contains('\u{1b}'), "{m:?}");
        }
    }
}

#[test]
fn problems_are_capped() {
    let hosts: Vec<String> = (0..MAX_HOSTS)
        .map(|i| format!("\"10.0.0.{}\"", i))
        .collect();
    let toml = GITHUB.replace(
        "hosts = [\"api.github.com\", \"github.com\"]",
        &format!("hosts = [{}]", hosts.join(", ")),
    );
    let e = rejected(&toml);
    assert_eq!(e.len(), MAX_REPORTED_PROBLEMS + 1);
    assert!(e.last().unwrap().contains("more problems"));
}

mod corpus;
