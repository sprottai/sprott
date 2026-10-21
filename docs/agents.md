---
description: "Every agent, machine and person in Sprott has its own key: how agents are added and given vault access, how machines are paired, and what each signature proves."
---

# Identity

Every agent, every machine and every person has its own identity key.

| Who | Key | Signs |
|---|---|---|
| An agent | agent identity key (AIK) | its requests to the broker |
| A machine | device identity key (DIK) | its requests to your account in the cloud |
| A person | user identity key (UIK), opened with a passkey | approvals, and changes to vaults, policy, members and access |

Each record in [Activity](activity.md) traces back to these keys: which
agent, on which machine, and who approved.

## Agents

### Adding an agent

`sprott setup` adds the agent it runs for ([Quickstart](quickstart.md)). To add
another by hand, run `sprott agent add <name>`. Either way you approve the
agent in the browser, and choose which vaults it may use.

### The agent identity

Each agent gets its own identity and an env file at
`~/.sprott/agents/<name>/agent.env`, with two values:

| Variable | Meaning |
|---|---|
| `SPROTT_BROKER_URL` | The local broker, for example `http://127.0.0.1:23294`. |
| `SPROTT_AGENT_IDENTITY` | Path to the agent's identity file. `sprott run` signs a fresh proof with it for each tunnel the command opens through the proxy. |

Neither is a credential: neither can reveal a value. Keep one identity per
agent; don't share an identity file between agents. The vault is not in the
env: each request names its vault, and `sprott run --vault <vault>` picks one.

Agents that run as the same OS user can read each other's identity files,
the way they can read each other's `~/.ssh` keys. To keep agents apart, run
each as its own OS user, so each can read only its own identity.

### Subagents

An agent is an identity, not a process. Subagents, background jobs and
helper scripts that an agent starts inherit its env, so they act as that
agent: one agent in Agent access, one name in Activity, one toward your
plan's agent limit. Give a helper its own identity (`sprott agent add`) only
when you want to grant or revoke it separately, or see its calls under its
own name.

### Two checks on every request

1. **Admitted to your account.** You approved the agent and haven't revoked
   it. Otherwise the request gets `agent_not_admitted`.
2. **Allowed on this vault.** The vault's Agent access list has the agent
   turned on. Otherwise the request gets `agent_not_authorized`.

Then the connection's [policy](approvals.md) decides the request itself.

### Agent access

The vault's **Agent access** tab lists every agent with its status: **No
access**, **All connections**, or **N restricted**.

- Turn an agent on or off for the vault. Turned off, it loses the vault's
  connections at once.
- Open an agent to choose which connections it may reach. A connection
  turned off for an agent gets `mask_not_enabled`.

An agent gets access when you approve it at pairing, from the **Authorize
all** prompt on a shared vault, or on this tab. You manage your own agents;
on a shared vault, admins manage anyone's.

### Removing an agent

Console: **Account → Agents → Revoke agent**. It stops working on every
machine within about 30 seconds. `sprott agent rm <name>` prints the page
where you sign the removal.

## Machines

A machine is paired once, by `sprott setup` or `sprott login`, and approved
with your passkey. Its device key signs every request it makes to your
account.

**Account → Devices** lists your machines with their last-seen date and
whether their Sprott is up to date. **Revoke device** disconnects a lost
machine. On the machine itself, `sprott logout` unpairs it.

## Passkeys

Your passkey opens your identity key, which signs every approval and every
change you make. Any active passkey unlocks all your vaults.

**Account → Passkeys** lists them. **Add a passkey** starts with a touch on
a passkey you already have. You can't delete your only active passkey. Keep
two, so losing one device doesn't lock you out
([Vaults](vault.md#lose-every-passkey)).

## What an agent can't do

- Read a value. `sprott get` asks for your passkey, and is for you.
- Send a credential to a host its connection doesn't list.
- Approve anything, or change policy or access.
- Change your default vault: your commands read it from your own config.

The most a compromised agent can do is ask the broker for things, within
policy, with sensitive calls waiting for you. Activity records every attempt.
More: [Security model](security-model.md).
