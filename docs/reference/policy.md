---
description: "How Sprott policy levels, rules and read and write floors are written in policy.toml, the order in which they decide a request, and how approvals are reused."
---

# Policy rules

Every brokered request gets one level, from a service's rules or a floor.
What the levels mean day to day: [Policy and approvals](../approvals.md).

## Levels

| Level | Behaviour |
|---|---|
| `allow` | Runs with no approval. |
| `ask` | One approval, reused for the rule's window. |
| `ask-always` | An approval every time. Never reused. |
| `deny` | Refused. |

From least to most strict: `allow` < `ask` < `ask-always` < `deny`.

There are no risk scores. A rule says what an action is ("Delete
repository"); its level is your decision about it.

## policy.toml

A service's rules live in `policy.toml` next to its
[`service.toml`](services.md).

```toml
[default]                 # the floor when no rule matches
read  = "allow"
write = "ask"
ttl   = 900               # optional window, in seconds, for an ask

[[rule]]
id    = "delete-repo"     # [a-z0-9][a-z0-9_-]*, unique in the file
label = "Delete repository"
method = "DELETE"
path  = "/repos/:owner/:repo"
level = "ask-always"
```

`[default]` takes `read`, `write` and `ttl`, all optional.

`[[rule]]` fields:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable id. Your overrides refer to it. |
| `label` | yes | What the action is, in words. Shown on approval cards and in the console. |
| `method` | no | An HTTP method, or a list (any one matches). Unset: any method. |
| `path` | no | A path pattern, or a list (any one matches). Unset: any path. |
| `level` | yes | `allow`, `ask`, `ask-always` or `deny`. |
| `body` | no | A regular expression the request body must match. |
| `when` | no | A condition on a request value: `"vars.<name> <op> <literal>"`, with `>`, `<`, `>=`, `<=`, `==` or `!=`. |
| `ttl` | no | The approval window for `ask`, in seconds. |

Unknown keys reject the whole file.

### Method and path

A rule matches a request when its `method` and its `path` both match.

- `method` is an HTTP method token, stored uppercase: `"DELETE"` or
  `["PUT", "PATCH"]`.
- `path` is a [URL Pattern](https://urlpattern.spec.whatwg.org/) pathname
  starting with `/`. `:name` matches one segment; a final `/*` matches the rest
  of the path: `"/repos/:owner/:repo/branches/*"`. `:name(a|b)` limits a
  segment to those words; `{/:name}?` makes a segment optional.
- A path is matched without its query string and without one trailing `/`.
- The host is fixed by the connection.
- A rule with no `method`, `path`, `body` or `when` rejects the file; the level
  for every request is `[default]`.
- `match` (the 2.0 `"METHOD /path"` with `*` and `**`) rejects the file.
  Write `method = "DELETE"` and `path = "/repos/:owner/:repo"` instead.

### Limits

- `ttl` is at most 31536000 seconds (one year). A larger value rejects the
  file; it is never cut down. Your own settings in the console have no cap.
- A file is at most 64 KiB, with at most 128 rules, 32 method × path pairs
  per rule and 16 `body` rules.
- A `body` pattern is at most 1024 bytes.

## How a request is decided

1. **Rules.** Of all the rules that match, the strictest level wins. Among
   rules at the same level, the first one decides: the service's rules in
   file order, then yours.
2. **Connection floor.** No rule matched: the connection's `read` or `write`
   floor decides.
3. **Tag floors.** Unset there: the floors of the service's tags. If several
   tags have one, the strictest wins.
4. **Global floor.** Unset there too: your vault's global floor.
5. **Last fallback.** Every floor unset: `ask-always`.

`GET`, `HEAD` and `OPTIONS` are reads. Every other method is a write.

Out of the box, the global floor and the `ai` and `messaging` tag floors are
`allow` for reads and writes. A key you add works right away, and a service's
rules tighten the actions it names.

## Your overrides

On the vault's **Permissions** tab, per connection, you can:

- change any rule's level and window, or reset it to the service's default;
- set the connection's read and write floors ("Everything else").

Under **Vault defaults** you set the read and write levels by service type,
how long an approval request waits, and the default window for an `ask`.

Rules apply per connection, so two connections of the same service are
decided separately. On a shared vault, admins edit policy; members see it.

Service definitions you add to a vault with `sprott service add` only
tighten: their `allow` rules and `allow` floors are dropped. Loosening is
your setting in the console.

## Approval windows

An approval covers only the agent that asked, on that connection and host.
What it lets through afterwards:

| What asked | What the approval covers |
|---|---|
| `ask` from a rule | Later requests the same rule decides, for the rule's window, of the same kind (read or write). |
| `ask` from a floor | Later reads (or writes) on that connection that no rule matches, for the floor's window. |
| `ask` on a value-scoped request | This exact request with the same values, for the window. |
| `ask-always` | This one request. |

With no `ttl` on the rule or floor, the window is 900 seconds. A read
approval never lets a write through. Locking the vault or changing it ends
every window. An approval request waits 1800 seconds for a decision.

## Value-scoped requests

A service can name the request values an approval binds to, in
`service.toml`:

```toml
[requests.purchase]
method  = "POST"
path    = "/v2/purchase"
vars.amount   = "/amount"            # a JSON pointer into the body
vars.merchant = "/merchant_id"
scope   = ["amount", "merchant"]     # these values bind the approval
consent = "Buy from {{ vars.merchant }} for {{ vars.amount }}"
```

and decide on them in `policy.toml`:

```toml
[[rule]]
id    = "purchase-large"
label = "Large purchase"
method = "POST"
path  = "/v2/purchase"
when  = "vars.amount > 100"
level = "ask-always"
```

- A var is a JSON pointer into the body, or `{ in = "query", at = "<param>" }`.
- `scope` lists the vars whose values the approval binds. A different value
  asks again.
- `consent` is the line on the approval card. It may show only vars in
  `scope`.
- On a path a request shape covers, an `ask` or `ask-always` rule may not
  decide on `body`, and a `when` must use a var the shape binds. An approval
  there could not pin anything else.

## Example: Gmail

```toml
[default]
read  = "ask"
write = "ask-always"

[[rule]]
id    = "list-emails"
label = "List emails"
method = "GET"
path  = "/gmail/v1/users/me/messages"
level = "allow"

[[rule]]
id    = "read-email"
label = "Read email content"
method = "GET"
path  = "/gmail/v1/users/me/messages/:id"
level = "ask"

[[rule]]
id    = "send-email"
label = "Send email"
method = "POST"
path  = "/gmail/v1/users/me/messages/send"
level = "ask-always"
```
