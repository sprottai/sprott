---
description: "Hand Sprott setup to your coding agent with one prompt, then give it the skill and the identity it uses to work without seeing credentials."
---

# Set up with your agent

Your agent runs every command. You open links and approve with your passkey.

## Paste-ready prompt

Paste this to your coding agent:

```text
Set up Sprott for me: run `curl -fsSL https://sprott.ai/install.sh | sh` and follow what it prints. I only open links and tap my passkey; you run every command.
```

The agent runs the installer and `sprott setup`, and hands you each link to
open. What happens at each step: [Quickstart](quickstart.md#2-run-setup).

Never paste a key or a code into the chat. Setup prints the sentence to relay
and the next command to run.

## The skill

The skill teaches an agent everything it needs: finding connections, placing
phantoms, `sprott run`, approvals and setup. Read it at
[sprott.ai/skill.md](https://sprott.ai/skill.md).

The installer adds it with `sprott skill install`, and `sprott upgrade`
installs it again so it stays current. An agent without `sprott` can add it
with:

```bash
npx skills add sprottai/sprott
```

Install only from [sprott.ai](https://sprott.ai) or
[github.com/sprottai/sprott](https://github.com/sprottai/sprott).

## Load the agent's identity

Each agent has its own identity and env file. If `SPROTT_AGENT_IDENTITY` is
unset, the agent loads its file before running `sprott`:

```bash
set -a; . ~/.sprott/agents/<name>/agent.env; set +a
```

`sprott setup` prints this line when it reports `done`. What the file holds:
[Identity](agents.md#the-agent-identity).

## What your agent can propose

An agent can ask for a change to the vault. Nothing changes until you approve
it with your passkey, and the approval card lists every key and host
involved.

- A new host on a connection: `sprott connection add-host`.
- A new connection that uses a secret already in the vault:
  `sprott connection add <id> --service <svc> --use ROLE=KEY`.

When a task needs a service with no connection, you add it on the vault's
Connections page in the console. `sprott status` prints the vault's console
URL. Add `#custom` to the Connections page URL to open the form for an API
that is not in the catalog.
