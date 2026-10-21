---
description: "Short answers on what Sprott is, how it differs from secrets managers, hosted proxies and .env files, what needs approval, teams, platforms and the licence."
---

# FAQ

## What is Sprott?

Sprott is the access layer for AI agents: your agents get access, never the
keys, and you see what every agent does. The agent puts a phantom, such as
`__sprott__github__`, where a key goes. A broker on your machine swaps in
the real value as the request leaves, only toward that service's hosts and
only when policy allows. Every action is signed by the agent that took it,
and by the person who approved it. More: [What is Sprott](README.md).

Sprott was called SafeClaw before 2.0.

## How is it different from a secrets manager?

A secrets manager hands the value to the program that asks, and from then
on what that program does with it is not bound to anything. Sprott never
hands the value over. The agent holds a phantom; the value is added inside
the local proxy, for the one request the agent made, after the agent's
identity, the host and your policy are checked. A value can also stay in a
cloud secret store you already run ([Connections](connections.md)).

## How is it different from a hosted credential proxy?

A hosted proxy keeps the key from the agent, but sits in someone else's
cloud: it sees your traffic and can't reach your private networks. Sprott's
broker runs on each of your machines. Your traffic and plaintext keys never
pass through Sprott's cloud, and private APIs work like any other.

## How is it different from keeping keys in .env files?

In a `.env` file the key sits on disk in plain text, and every process that
loads it can read it, log it or send it anywhere. With Sprott the variable
holds a phantom, such as `HF_TOKEN=__sprott__hf_token__`, and the command
runs through `sprott run --`. The value stays sealed in the vault and goes
only to that connection's hosts. To move an existing file in, use
[.env import](connections.md#import-a-env-file).

## Does my agent ever see the key?

No. The agent works with phantoms only: in its environment, its files, its
commands and its logs. `sprott get` does print a value, but it asks for your
passkey every time and is for you at a terminal.

## What needs my approval?

By default a call through a connection runs without asking, so a key you add
works right away. Catalog services mark their sensitive actions, such as
sending an email or deleting a repository, to ask once for a window or ask
every time. You can change any level per connection. Your passkey is also
needed to unlock a vault, approve a new machine or agent, show a value with
`sprott get`, and send a key to a host its connection doesn't list yet. A
`deny` rule refuses with no prompt. Details:
[Policy and approvals](approvals.md).

## Does it work for a team?

Yes. A shared vault gives the team one set of credentials, with members,
admins and one owner, and a team overview of every agent and call. Shared
vaults are available on Team. [Work as a team](team.md).

## How do I install it?

Paste this to your coding agent:

```text
Set up Sprott for me: run `curl -fsSL https://sprott.ai/install.sh | sh` and follow what it prints. I only open links and tap my passkey; you run every command.
```

Step by step, by hand or with an agent: [Quickstart](quickstart.md).

## Which platforms are supported?

The `sprott` command and daemon run on macOS (Apple Silicon and Intel) and
Linux (x86_64 and aarch64). Approvals use a passkey in your browser, and not
every passkey can seal a vault. Details:
[Platform support](reference/platform-support.md) and
[Passkey support](reference/passkey-support.md).

## Where is the code, and what is the licence?

The `sprott` command, its daemon, the agent skill and the service catalog
are on GitHub at
[github.com/sprottai/sprott](https://github.com/sprottai/sprott).

The licence is the Functional Source License 1.1 with an Apache 2.0 future
licence (FSL-1.1-ALv2). It is Fair Source: eventually open source. You may
use, copy, change and share the code for any purpose except a Competing Use,
which means making it available to others in a commercial product or service
that substitutes for Sprott or offers substantially similar features. Two
years after each release, that release becomes available under Apache 2.0.
