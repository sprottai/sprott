---
description: "Sprott gives your AI agents the keys they need without handing them over, and shows you what each one did with them. What it is, how it works, and where to start."
---

# What is Sprott

**Every AI agent on your team, with real access, in one picture.**

Sprott gives your agents the keys they need without handing them over, and
shows you what each one did with them.

One screen shows every agent, the machine it runs on, the services it
reaches, and what got blocked or approved, and by whom: the
[team overview](team.md#the-team-overview).

> **Every action your agents take is signed by the agent that took it, and by the person who approved it.**

## Why it makes sense

1. **Every action has a signature.** Each agent has its own identity key and
   signs everything it does. Every approval and every policy change is
   signed by a person. Every record traces back to both.
2. **Access to exactly what was asked.** A key is used only for the request
   the agent made. Rules clear the routine calls. You approve the rest on a
   screen that shows exactly what will run.
3. **Runs where your agents run.** A broker runs on every machine, so it
   works on any network, including private ones. Your traffic and plaintext
   keys never pass through our cloud.
4. **Set up once, works for every agent.** Add a credential once, and every
   agent and teammate you allow can use it. Pair an agent once, and it gets
   every connection it's allowed.

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
agent gets the response, never the key. Zero trust for agents: every request
is checked against the agent that signed it and the scope it asks for.

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
