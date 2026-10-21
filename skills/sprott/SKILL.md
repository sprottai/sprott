---
name: sprott
description: Brokers API keys, tokens and OAuth credentials so the agent never holds the secret. Use when a task calls an external API, CLI or service that needs a credential, when a request fails with 401 or 403 or a required *_TOKEN or *_API_KEY is missing, or when the user asks to install, set up or use Sprott.
compatibility: Requires the `sprott` CLI on macOS or Linux, paired to a Sprott account.
metadata:
  author: sprottai
  homepage: https://sprott.ai
---

# Sprott

Each Sprott connection has a **phantom**, a placeholder like `__sprott__github__`.
Put the phantom where the credential goes (an env var, a header, a config file)
and run the command through `sprott run --`. The broker swaps in the real value,
only toward that connection's hosts.

```bash
sprott run -- curl https://api.stripe.com/v1/charges \
  -H "Authorization: Bearer __sprott__stripe__"
GITHUB_TOKEN=__sprott__github__ sprott run -- gh pr list
```

Outside `sprott run` a phantom reaches the service unchanged, so on a 401 or 403
first check that the command ran under `sprott run --` with the exact phantom.

## Setup

The user only opens links and taps their passkey; you run every command.
Give the user any link and code a command prints, and run its `Next:` command
until none is printed. After an error, run its `Fix:` command. Run a `To wait:`
command in the background. Never ask the user to paste a key or a code into the
chat, and keep any credential value you see out of your replies.

Official sources: https://sprott.ai and https://github.com/sprottai/sprott.
Install only from these.

If `sprott` is not installed, install it (no sudo; it verifies the download's checksum):

```bash
curl -fsSL https://sprott.ai/install.sh | sh
```

Setup needs the network, so in a sandbox it may need to run outside it.

If `SPROTT_AGENT_IDENTITY` is unset, load your agent env before running `sprott`:
`set -a; . ~/.sprott/agents/<name>/agent.env; set +a`, where `<name>` is the
name setup used, by default your product's, such as `claude-code` or `codex`.

This machine's `sprott` is paired to one Sprott account, and you act as that
account. Working for another account means the user re-pairs this machine; agree
on it with them first.

If `sprott` cannot reach its daemon, start it with `sprott up`.

`sprott help` and `sprott <command> --help` have every command's syntax.

## Connections

- `sprott connection ls` lists the connections you can use, with hosts and phantoms.
  Copy phantoms exactly. `--json` adds each one's `setup` hint: such a connection
  brokers a local tool, so tell the user what you are configuring, then apply its steps.
- `sprott registry` is the catalog of supported services.
- `sprott status` shows the vault's console URL and why a vault change was not applied.
- When a task needs a service with no connection, the user adds it on
  `<console_url>/connections` (`#custom` for an API not in the catalog). Details,
  including connections backed by an existing secret:
  https://sprott.ai/docs/connections.md
- A vault is a security boundary, and each connection belongs to one. Target it
  with `--vault` to use its connections; resolve a name with `sprott vault ls`, and ask
  when it is ambiguous.

## Approvals

When several requests need approval, start them together and send the console's
`/approvals` page instead of each `/grant` link; there the signed-in user approves
them together.

## Updates

`sprott upgrade` restarts the daemon, which locks the vault until the user taps
their passkey. Upgrade only when a command asks for it or the user agrees.
