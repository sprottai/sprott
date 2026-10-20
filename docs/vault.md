---
description: "Where Sprott keeps your credentials: personal and shared vaults, sealed under your passkey, opened only in memory on your machine and synced sealed."
---

# Vaults

A vault holds your credentials. It is sealed under your passkey. Plaintext
exists in one place only: the daemon's memory on your machine, while the
vault is unlocked.

## What's inside

- **Secrets**: `KEY = value` pairs. A secret is just stored; it becomes
  usable when a [connection](connections.md) uses it.
- **Connections**: secrets bound to a service's hosts, each with its phantom.
- **Policy**: your rules and floors per connection
  ([Policy and approvals](approvals.md)).
- **Agent access**: which agents may use the vault, and which connections
  each one may reach ([Identity](agents.md)).
- **Activity**: a record of every brokered call ([Activity](activity.md)).

## Personal and shared vaults

| | Personal | Shared |
|---|---|---|
| Who | only you | your team: members, admins and one owner |
| Credentials | yours | one set for the whole team, used by everyone's agents |
| Approvals | you | the requester or an admin |
| Overview tab | your vault's status | the [team overview](team.md#the-team-overview) |

You choose the kind when you create a vault (console: **New vault**), and it
never changes. Shared vaults are available on Team. Setting one up:
[Work as a team](team.md).

## No password

A vault is sealed under a key derived from your passkey (Touch ID, Windows
Hello, a security key, or a passkey manager). There is no master password to
reuse, phish or forget. The same passkey signs your approvals. Not every
passkey can seal a vault: [Passkey support](reference/passkey-support.md).

## Lock and unlock

```bash
sprott up       # start the daemon and unlock: one passkey approval
sprott lock     # wipe the decrypted keys from memory
sprott status   # which vault, locked or not, daemon health
```

On disk, yours or the cloud's, a vault exists only sealed. `sprott lock`, or
stopping the daemon, ends the plaintext copy.

## Sync across machines

The cloud keeps the sealed vault as a backup and syncs it to your other
machines item by item, so two machines editing different entries don't
overwrite each other. Sealing and unsealing happen only on your devices; the
cloud cannot read what it syncs. Add a machine with `sprott setup` (or
`sprott login`) and approve it with your passkey. Revoking a machine cuts its
access in your account ([Identity](agents.md#machines)).

Multi-device sync is available on Pro and Team.

## Several vaults

One account can hold several vaults, for example work and personal. The
daemon serves all of them at once. Each request names its vault, so one
agent's traffic never lands in another vault by accident.

- `sprott vault ls` lists them; `*` marks your default.
- `sprott vault use <vault>` sets the default for your own commands.
- `--vault <vault>` targets another one for a single command.

An agent's env never changes your default vault.

Multiple vaults are available on Pro and Team.

## Lose every passkey

If you lose every passkey on your account, the vault stays sealed for good.
Nobody, including Sprott, can open it. Add a second passkey on day one:
console, **Account → Passkeys → Add a passkey**.
