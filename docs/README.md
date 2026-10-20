---
description: "Sprott is the access layer for AI agents: your agents get access, never the keys, and you get a live picture of every agent, with control over every permission. What it is, how it works, and where to start."
---

# What is Sprott

**The access layer for AI agents.**

Your agents get access, never the keys. You get a live picture of every
agent on your team, with control over every permission.

1. **Credential broker.** The agent works with a placeholder, and the broker
   on its machine swaps in the real key on the way out. It works on any
   network, and our cloud never sees your traffic.
2. **Connect once.** Connect a service once, and every agent you allow can
   use it, on every machine. OAuth tokens renew on their own.
3. **Passkey approvals.** Everyday calls pass your rules. Only the risky call
   waits for your face or fingerprint.
4. **Know your agent.** Every action is signed by the agent that took it and
   by the person who approved it. SUDP, our published protocol, ties each
   approval to that one call.
5. **Activity log.** Every call: which agent, on which machine, for whom,
   and who approved it.
6. **Team overview.** See every agent on your team, live, and control every
   permission: the [team overview](team.md#the-team-overview).

## Start

| | |
|---|---|
| [Quickstart](quickstart.md) | Install, pair, add a key and make the first call. |
| [Set up with your agent](for-your-agent.md) | One prompt, and your agent runs the setup. |
| [Work as a team](team.md) | One shared vault for the whole team's agents. |
| [FAQ](faq.md) | Short answers. |

Are you an AI agent? Run `curl -fsSL https://sprott.ai/install.sh | sh` and
follow what it prints.

## How it works

The agent never holds a key. It puts a **phantom** where the key goes, and
runs the command through Sprott:

```bash
GITHUB_TOKEN=__sprott__github__ sprott run -- gh pr list
```

A broker on your machine checks the agent's signature, the destination and
your policy, then swaps in the real token on the way to `api.github.com`. The
agent gets the response, never the key. That check, on every request and
before any key is used, is zero trust for agents.

| Part | What it does |
|---|---|
| [Vaults](vault.md) | Hold your credentials, sealed under your passkey. Personal, or shared with your team. |
| [Connections](connections.md) | Bind a credential to a service's hosts and give it a phantom. |
| [Phantoms and the proxy](broker.md) | Swap the phantom for the real value as the request leaves your machine. |
| [Identity](agents.md) | Give every agent, machine and person its own key. |
| [Policy and approvals](approvals.md) | Decide each request. Sensitive ones wait for your passkey. |
| [Activity](activity.md) | Record every call: which agent, which machine, who approved. |

Approvals are built on SUDP, our protocol for passkey-signed, single-use
grants ([paper](https://arxiv.org/pdf/2604.24920)). The guarantees:
[Security model](security-model.md).

## Reference

[CLI](reference/cli.md) · [service.toml](reference/services.md) ·
[Policy rules](reference/policy.md) · [Error codes](reference/diagnostics.md) ·
[Platforms](reference/platform-support.md) ·
[Passkeys](reference/passkey-support.md) · [Plans](reference/plans.md)
