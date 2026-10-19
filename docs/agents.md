# Agents: attribution without possession

This page explains agent identities, the setup commands that create them, and how policy controls what each agent may do.

## Setup commands

| Command | What it does | Who runs it | How often |
|---|---|---|---|
| `sprott login` | Pairs this machine to the account | A person at a terminal, or `sprott setup` under the hood | Once per machine, or after re-pairing |
| `sprott agent add <name>` | Registers an agent and creates its identity and env file | A person at a terminal, or `sprott setup` under the hood | Once per agent |
| `sprott setup --name <name>` | Runs whichever pairing or registration is still needed, then writes the env file, installs the skill, and asks for vault unlock | A person or their agent | First setup and safe to re-run |

To Sprott, an agent is an **identity**, not a trust decision. Each agent
gets its own keypair; what any agent may *do* is decided elsewhere, by
[policy](approvals.md), per action, at use time.

## The identity

`sprott agent add <name>` mints one identity and writes its env file at
`~/.safeclaw/agents/<name>/agent.env`. The file contains two non-secret values:

| Var | Meaning |
|---|---|
| `SAFECLAW_BROKER_URL` | the local broker, e.g. `http://127.0.0.1:23294` |
| `SAFECLAW_AGENT_IDENTITY` | path to the agent's identity file (its keypair). Not a secret; `sprott run` signs a fresh proof with it per request, and no key is stored or sent. |

The vault is not part of the env: each request names one in its URL
(`/v/<vault>/…`), and `sprott run` binds one per launched command
(`sprott run --vault <id> -- <cmd>` to pick). `sprott vault ls` lists ids (`*` = default).

One identity per agent keeps the audit trail attributable: every brokered
request and every approval you grant is tied to a named agent, so "which agent
did what, when, with which credential" is a query, not a reconstruction. Keep
one identity file per agent, and don't re-mint when the env already exists.

## What an agent can do

Discover connections through the registry, place phantoms, route commands
through `sprott run`, wait on approvals (`sprott op wait`). The full behavioral
contract fits in one file, [the skill](https://github.com/getsafeclaw/safeclaw/blob/main/skills/safeclaw/SKILL.md), and
one habit: **phantoms, not values** ([`sprott run` and phantoms](sc-run.md)).

## What an agent can't do

Read a secret (`sprott get` is passkey-gated, a human primitive), move a
credential toward a host its connection didn't anchor, approve anything, or
steer *your* CLI: your commands read the active vault from your own config,
never from an agent's env. The worst a fully compromised agent can do is ask
the broker for things, inside policy, under your taps; the accounting of that
is exactly what the audit trail records. Costs and limits in detail:
[Security model](security-model.md).

## Handing it over

Agent-driven setup delivers pairing, env, and skill in one loop. Doing it by
hand: [For your agent](for-your-agent.md).
