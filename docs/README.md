---
description: "Docs for Sprott, the credential broker for AI agents: setup, concepts, security and reference pages."
---

# Sprott Docs

Sprott is a credential broker for AI agents. Your agent puts a placeholder
where a key goes, and Sprott's local proxy swaps in the real value on the way
out, with sensitive calls waiting for your passkey.

New here? Read [Overview](overview.md), then do the
[Quickstart](quickstart.md). Short answers: [FAQ](faq.md).

## Concepts

| Page | The module |
|---|---|
| [Overview](overview.md) | The whole model on one page: phantoms, the broker, passkey approvals |
| [Vault](vault.md) | Where credentials live: sealed under your passkey, synced blind |
| [Connections](connections.md) | The catalog, host anchors, and how a secret becomes a phantom |
| [Broker](broker.md) | `sprott run`: one local egress point that swaps phantoms for values |
| [Approvals & policy](approvals.md) | Who decides what runs: levels, rules, single-use grants |
| [Agents](agents.md) | Agent identities: attribution without possession |

## Guides

| Page | The task |
|---|---|
| [Quickstart](quickstart.md) | Zero to first brokered call in five minutes |
| [`sprott run` and phantoms](sc-run.md) | The patterns, and the `sprott get` anti-pattern |
| [For your agent](for-your-agent.md) | Handing Sprott to an agent: skill file, paste-ready prompt |

## Security

| Page | The question |
|---|---|
| [Design principles](design-principles.md) | The rules the whole system is built on |
| [Security model](security-model.md) | Where keys live, what the cloud sees, what compromise costs |

## Reference

For users and service authors, in [`reference/`](reference/):
[services.md](reference/services.md) (writing a `service.toml`),
[policy.md](reference/policy.md) (per-action decisions),
[diagnostics.md](reference/diagnostics.md) (every error code, with fixes),
[passkey-support.md](reference/passkey-support.md) (which devices can encrypt a vault),
[platform-support.md](reference/platform-support.md) (which OSes run the `sprott` binary),
[consent-templates.md](reference/consent-templates.md) (approval-copy grammar).

Contributors: the design docs behind the source are in [`design/`](https://github.com/sprottai/sprott/tree/main/design).
