---
description: "Write a Sprott service definition: hosts, secrets, tags, OAuth, and how each credential shape is declared."
---

# service.toml

A service is a folder:

```
my-api/
  service.toml     # this page
  policy.toml      # optional: labelled rules, see Policy rules
  icon.png         # optional: a PNG of at most 32 KiB
```

Add it to a vault with `sprott service add ./my-api`
([Add a service](../add-a-service.md)). Rules: [Policy rules](policy.md).

## A minimal service

```toml
[service]
id = "github"            # required; [a-z0-9_], no "__"
name = "GitHub"          # display name
tags = ["app"]           # classification, several allowed

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]
```

That is a complete service. A top-level `setup = """…"""` string, next to
`[service]` and not inside it, carries setup notes for agents. Add `[auth]`
only if the service mints tokens.

## `hosts`

The only destinations this service's secrets may be sent to.

- An entry is an exact domain, or `*.suffix`. The `*` is leftmost only and
  matches one label: `*.openai.azure.com` matches `foo.openai.azure.com`,
  not `a.b.openai.azure.com`. A bare `*` is rejected.
- Domains only: no scheme, no path.
- With a wildcard entry, each connection pins its exact hosts when it is
  created. Checks always run against exact domains.
- Routing hints for a tool, such as npm's `--registry`, go in `setup`.

## `secrets`

The keys a connection of this service stores. Keys are `[A-Z0-9_]`. An OAuth
service lists its refresh-token key here too. A connection is connected when
all of them are present.

What a phantom resolves to:

- With no `[auth]`, the phantoms resolve to the secrets themselves.
- With `[auth]`, the phantom resolves to the minted access token. The
  secrets `[auth]` names, such as the refresh token, are stored and never
  sent: a phantom for one gets `refresh_forbidden`.
- `__sprott__<conn>__` resolves to the connection's only value. With several,
  use `__sprott__<conn>__<key>__`, with the key in lower case.
  `sprott connection ls` lists each connection's phantoms.

A phantom needs no placement declaration. The value replaces the phantom
wherever the tool puts it: a header, a query parameter, a URL path, the body,
or inside `Authorization: Basic`. Never in the host.

## `tags`

Lower-case slugs, several allowed, no duplicates. Common tags: `ai` (model
providers), `app` (apps and SaaS), `messaging`, `dev`, `payment`. Any slug
is accepted.

The console groups and filters services by tag. Policy applies tag floors:
when several of a service's tags have one, the strictest wins. An untagged
service gets only the global floor.

## `secret_url`

Optional. The page where a person creates the secret, such as
`https://crates.io/settings/tokens`. The console shows it as a link, and
`sprott connection add --service` prints it. Must be `http(s)`. Display
only.

## `[auth] type = "oauth2"`

Only for a service that authenticates with minted OAuth2 access tokens.

```toml
[service]
# …
secrets = ["GMAIL_REFRESH_TOKEN"]   # the refresh key is listed here too

[auth]
type = "oauth2"
provider = "google"                 # display label ("Connect with Google")
scopes   = ["https://www.googleapis.com/auth/gmail.send"]
refresh_token = "GMAIL_REFRESH_TOKEN"  # the secret key the refresh token is stored under
authorization_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url         = "https://oauth2.googleapis.com/token"
pkce              = true
client_id         = "499410884315-…apps.googleusercontent.com"
# client_secret only for a public client
# id_token = "GMAIL_ID_TOKEN"       # when the provider returns an OIDC id token to keep
# exposes = ["account_id"]          # extra values, as __sprott__<conn>__account_id__
```

Token endpoint options, all optional:

```toml
[auth]
# …
oauth_style = "form"               # token request body: form (default) or json
token_auth  = "post"               # client auth: post (default, in the body)
                                   #   or basic (Authorization: Basic)

[auth.token_params]                # extra params for the code exchange
echo_state = "{state}"             #   {state} is the only placeholder

[auth.refresh_params]              # extra params for the refresh
audience = "api"                   #   static values only
```

`token_params` and `refresh_params` add parameters; they never override the
protocol's own (`grant_type`, `code`, `code_verifier`, `client_id`,
`client_secret`, `redirect_uri`, and `refresh_token` on refresh). Every token
request sends `Accept: application/json`.

`refresh_token` (required) and `id_token` (optional) use the RFC 6749 field
names and map each token to the secret key it is stored under. The access
token is minted on demand and never stored.

## Basic auth

The proxy decodes `Authorization: Basic` and fills phantoms inside it.
Nothing to declare. Put the phantom where the password goes:

- git: inside `sprott run`, git's credential helper sends the phantom for you.
  By hand: `https://x:__sprott__github__@github.com/owner/repo`. If the
  service checks the username, type the real one.
- docker: `docker login -u <user> -p __sprott__dockerhub__`.

## Which shape needs what

| How the service takes the credential | Example | Declare |
|---|---|---|
| `Authorization: Bearer <token>` | openai, npm | `hosts` + `secrets` |
| a custom header | anthropic `x-api-key` | same |
| a raw token, no prefix | crates.io | same |
| a query parameter | Gemini `?key=` | same |
| a token in the URL path | Telegram `/bot<token>/` | same |
| a Basic pair | GitHub and GitLab over git | same |
| OAuth2 | Gmail; openai-codex (`exposes`) | + `[auth]` |
| an approval bound to request values | an amount, a recipient | + `[requests]` ([Policy rules](policy.md#value-scoped-requests)) |
