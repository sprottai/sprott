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
| `condition` | no | A [CEL](https://cel.dev) expression over the request: `"has(request.body.amount) && request.body.amount > 100"`. Unset: any request. |
| `level` | yes | `allow`, `ask`, `ask-always` or `deny`. |
| `ttl` | no | The approval window for `ask`, in seconds. |

Unknown keys reject the whole file.

### Method and path

A rule matches a request when its `method`, its `path` and its `condition`
all match.

- `method` is an HTTP method token, stored uppercase: `"DELETE"` or
  `["PUT", "PATCH"]`.
- `path` is a [URL Pattern](https://urlpattern.spec.whatwg.org/) pathname
  starting with `/`. `:name` matches one segment; a final `/*` matches the rest
  of the path: `"/repos/:owner/:repo/branches/*"`. `:name(a|b)` limits a
  segment to those words; `{/:name}?` makes a segment optional.
- A path is matched without its query string and without one trailing `/`.
- The host is fixed by the connection.
- A rule with no `method`, `path` or `condition` rejects the file; the level
  for every request is `[default]`.
- `match` (the 2.0 `"METHOD /path"` with `*` and `**`) rejects the file.
  Write `method = "DELETE"` and `path = "/repos/:owner/:repo"` instead.
- `when` and a rule's `body` regex (2.0) reject the file. Write `condition`.

### Condition

`condition` reads one object, `request`:

| Field | Value |
|---|---|
| `request.host` | The host, lowercase, with the port unless it is 443. |
| `request.query` | The query parameters, by name: `request.query.addParents`. |
| `request.headers` | The headers as forwarded, by lowercase name: `request.headers['x-account']`. |
| `request.body` | A member of the body (`request.body.amount`, `request.body.order.price`), or the body's text when the condition reads `request.body` itself. |
| `request.graphql` | The `calls`, `fields` and `request` of a GraphQL request, on a path whose request shape says `body = "graphql"`. |

- `method` and `path` select the method and the path. A condition that reads
  `request.method`, `request.path` or `request.params` rejects the file, and
  so does one that calls a function CEL here lacks, or reads `request.body`
  whole and a member of it.
- The body is read as JSON where it parses as JSON, and as a form unless its
  one Content-Type names another type. Both readings must agree on every
  value read.
- A request is refused when a value the condition reads is ambiguous: a query
  parameter or header given twice, a body with a byte-order mark, JSON with a
  duplicate key or with a member that differs from a read name only in case
  (`Amount` beside `amount`).
- A value the request leaves out makes the condition an error. An error
  matches a `deny`, `ask-always` or `ask` rule where that makes the decision
  stricter, and leaves an `allow` rule unmatched. Guard a value a request may
  leave out: `has(request.body.amount) && …`, or
  `'x-account' in request.headers && …` for a name `has()` can't select.
  `sprott service validate` warns about each read with no guard.
- A server may take `"false"` for `false`. Compare such a value as text:
  `string(request.body.private) == 'false'`.

### Limits

- `ttl` is at most 31536000 seconds (one year). A larger value rejects the
  file; it is never cut down. Your own settings in the console have no cap.
- A file is at most 64 KiB, with at most 128 rules and 32 method × path pairs
  per rule.
- A condition is at most 1024 bytes.

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

Servers differ in how they read a request, so it is decided on each reading
and the strictest decision wins:

- the method on the request line, and the value of each of
  `X-HTTP-Method-Override`, `X-HTTP-Method` and `X-Method-Override`. A value
  that isn't exactly one method, or a header given twice, is refused. A
  `_method` parameter is not read; on a server that takes one, gate `POST` too;
- the path as sent, and with an encoded slash (`%2F`) read as `/`;
- for a Google batch (a `multipart/mixed` body of `application/http` parts),
  each request in it, on its own method, path, query and body, at the batch's
  host. A batch whose requests can't be read one by one is `ask-always`.

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
| `ask` on a request a `[requests]` shape matched | Later requests covered the same way (below), for the window. |
| `ask-always` | This one request. |

With no `ttl` on the rule or floor, the window is 900 seconds. A read
approval never lets a write through. When the readings that decide a request
fall under different rules or floors, or one reads and one writes, its
approval is for that one request. Locking the vault or changing it ends
every window, and a re-key of the vault ends every approval. An approval
request waits 1800 seconds for a decision.

### What an approval covers

An approval covers the method, the host (with its port) and the path, and:

- with no request shape, or a shape with no `scope`: the whole request. That
  is the query string, the headers HTTP defines for a request
  (`content-type`, `content-language`, `content-location`, `content-range`,
  `if-match`, `if-none-match`, `if-modified-since`, `if-unmodified-since`,
  `if-range`, `destination`, `overwrite`, `depth`, `prefer`), the three
  method-override headers, every header carrying a phantom, and the body;
- with `scope = [...]`: the values it lists; `scope = []`: nothing more;
  `"request"` in the list adds the whole request;
- always: the values the deciding rules' conditions read and every value the
  consent shows;
- for a Google batch: the whole batch, besides what covers each deciding
  request in it.

A request that differs in anything covered asks again. A body is covered by
its content: a multipart body's boundary and its parts' `Content-ID`, a batch
part's SDK headers, and an email's `Date` and `Message-ID` are left out, so a
client that builds the same request again is let through. A one-time approval
from a service added with `sprott service add` always covers the whole request.

When a request misses a one-time approval made for the same request line, the
agent is told which parts differ, by name only (`query`, `headers.if-match`,
`body.amount`).

## Request shapes

A service can say how it reads a request, and which values an approval binds
to, in `service.toml`:

```toml
[requests.purchase]
method  = "POST"
path    = "/v2/purchase"
body    = "json"           # json (the default), form, graphql or text
scope   = ["request.body.amount", "request.body.merchant"]
consent = "Buy from {{ request.body.merchant }} for {{ request.body.amount }}"
```

and decide on the request in `policy.toml`:

```toml
[[rule]]
id    = "purchase-large"
label = "Large purchase"
method = "POST"
path  = "/v2/purchase"
condition = "!has(request.body.amount) || request.body.amount > 100"
level = "ask-always"
```

- `method`, `path` and `condition` select requests, as in a rule. The first
  shape in the file that selects a request reads it.
- `body` is the format the service reads the body in. With `graphql`, rules
  can read `request.graphql`.
- `scope` lists the request paths whose values an approval covers (above).
  Unset: the whole request.
- `consent` is the line on the approval card, over request paths, with the
  filters `email` and `graphql`. The values it shows are covered too.
- `encoded."<request path>"` names a value that carries encoded media, with
  JSON Schema's `contentEncoding` and `contentMediaType`. A built-in
  service's encoded values are covered by their content.
- `vars` (2.0) rejects the file. Name each value by its request path.

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
