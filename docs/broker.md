---
description: "How Sprott's local proxy swaps a phantom for the real value at the last hop, only toward the connection's own hosts and only on traffic you route through sprott run."
---

# Phantoms and the proxy

An agent never holds a credential. It holds a **phantom**, a placeholder such
as `__sprott__github__`, and puts it exactly where the credential would go.
A proxy on your machine swaps in the real value as the request leaves.

![One brokered request, end to end: the agent holds only a phantom, the local broker resolves it, checks host and policy, and swaps in the real value at the last hop; the vault stays sealed under your passkey, and the cloud syncs only sealed data it cannot decrypt](assets/architecture.svg)

## The phantom

Every [connection](connections.md) has a phantom: `__sprott__<connection>__`,
or `__sprott__<connection>__<key>__` when the connection holds several
values. The phantom works in any position the credential would: an env var,
a header, a query parameter, a request body, a URL path, or inside
`Authorization: Basic`. It never works in the host name.

A phantom is worthless anywhere except the proxy. Sent anywhere else, it
reaches the service as a literal string and fails with a 401.

## The broker

The broker is a daemon on your machine. `sprott run -- <cmd>` starts the
command with its HTTPS traffic going through the broker's proxy. Every
brokered request answers three questions, each with one owner:

| Question | Owner | Carried by |
|---|---|---|
| Where does the credential go? | the agent | the phantom's position in the request |
| Which value? | the vault | phantom, then connection, then secret (or the OAuth token it manages) |
| Is it allowed? | the vault | the agent's identity, the connection's hosts and [policy](approvals.md) |

The agent controls placement and nothing else. There is no call that returns
a value and no endpoint that rewrites URLs. Every use of a credential is a
request with a phantom in it, routed through the proxy.

## The phantom is the only trigger

Inside a `sprott run` command:

- a request carrying a phantom is checked and, if allowed, gets the real
  value at the last hop;
- a request with no phantom is forwarded untouched.

Traffic outside `sprott run` is not touched at all. Sprott is not a
machine-wide interceptor.

## What the broker checks

Before it swaps a value in, the broker checks:

1. **The agent.** Each tunnel the command opens through the proxy carries a
   fresh proof signed with the agent's identity key. The agent must be
   admitted to your account and allowed on the vault ([Identity](agents.md)).
2. **The destination.** The host must be one of the connection's own hosts.
   Private and cloud-metadata addresses are refused for every connection.
3. **Policy.** The connection's rules and floors decide `allow`, `ask`,
   `ask-always` or `deny` ([Policy and approvals](approvals.md)).

The value is added inside the proxy, after these checks, on the way to that
host. The response streams back to the command. The value does not, and
nothing between the agent and the proxy ever sees it.

## Runs where your agents run

Each machine runs its own broker. It reaches whatever that machine reaches,
including private networks and internal APIs. Your traffic and plaintext
values never pass through Sprott's cloud. The cloud syncs the sealed vault
and relays approvals.

## Failing loudly

A request that can't proceed says so in the command's own output, with a
stable `Sprott: <code>` line: vault locked, approval needed (with the link),
host not on the connection, store unreachable. Each code and its fix is in
[Error codes](reference/diagnostics.md).

How to use this day to day: [Use a credential](sc-run.md).
