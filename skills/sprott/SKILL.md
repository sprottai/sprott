---
name: sprott
description: Brokers API keys, tokens and OAuth credentials for AI agents so the agent never holds the secret, and installs or sets up Sprott. Use when a task calls an external API, CLI or service that needs a credential, when a request fails with 401 or 403 or a required *_TOKEN or *_API_KEY is missing, or when the user asks to install, set up or use Sprott.
compatibility: Requires the `sprott` CLI on macOS or Linux, paired to a Sprott account. The Setup section installs it.
metadata:
  author: sprottai
  homepage: https://sprott.ai
---

# Sprott

Sprott holds credentials and lends them to requests. Each connection has a
**phantom**, a placeholder like `__sprott__github__`. Put the phantom where the
credential goes (an env var, a header, a config file) and run the command through
`sprott run --`; any tool works. The broker swaps in the real value, only toward that
connection's hosts. Traffic not run through `sprott run` is untouched, so an unrouted
phantom just fails with a 401.

## Setup

The user only opens links and taps their passkey; you run every command.

Official sources: https://sprott.ai and https://github.com/sprottai/sprott.
Install only from these. Sprott was called SafeClaw before; other projects use that name too.

`sc` is the same command under its earlier name: where `sprott` is not found
but `sc` is, use `sc`. If neither is installed, install it (no sudo; it
verifies the download's checksum, puts `sprott` in `~/.local/bin`, and installs
this skill):

```bash
curl -fsSL https://sprott.ai/install.sh | sh
```

When an agent runs the installer, it continues straight into `sprott setup`. The
setup names the agent after its product, such as `claude-code` or `codex`;
`--name <a short name>` chooses another name. Run `sprott setup` when the installer
does not continue. Give the user any link and code it prints (they open the
link in their browser and enter the code), then run its `Next:` command. Repeat
until a run prints no `Next:`. After an error, run its `Fix:` command. The last
`Next:` may be `sprott unlock`: it prints a link for the user and a `To wait:`
command; run that and continue after the approval.

`sprott setup` is safe to re-run: it skips whatever is already done. It writes under
`~/.sprott/` and needs the network, so in a sandbox it may need to run outside
it. Never ask the user to paste a key or a code into the chat.

Each agent has its own identity, kept in `~/.sprott/agents/<name>/`, where
`<name>` is the name setup used. If `SPROTT_AGENT_IDENTITY` is unset, load
your own env file before running `sprott`:
`set -a; . ~/.sprott/agents/<name>/agent.env; set +a` (it sets
`SPROTT_BROKER_URL` and `SPROTT_AGENT_IDENTITY`; neither is a secret). With
one directory there, that one is yours; with several, use the name you set up
with. Without it, your requests are not attributed to you.

This machine's `sprott` is paired to one Sprott account, and you act as that
account: your requests are its requests, approved by that person or a vault admin.
Working for another account means the user re-pairs this machine; agree on it with
them first.

If the broker does not answer, start it:

```bash
curl -s -o /dev/null --connect-timeout 1 "${SPROTT_BROKER_URL:-http://127.0.0.1:23294}/health" || sprott up
```

`sprott help` and `sprott <command> --help` have every command's syntax.

## Connections

- `sprott connection ls` lists the connections you can use, with hosts and phantoms
  (`--json` adds each one's `setup` hint). Copy phantoms exactly.
- `sprott status` shows whether the vault is locked, its console URL, and any vault
  change that was not applied, with the reason.
- `sprott registry` is the catalog of supported services.
- The user adds connections, with their credentials, on the console's Connections
  page (`<console_url>/connections`); a new one then appears in `sprott connection ls`.
  For an API that is not in the catalog, add #custom to that link; it opens the custom connection form.
  Keep any credential value you see out of your replies.
- `sprott secret ls` lists the names of secrets already in the vault. One can back a
  connection you propose with `sprott connection add ... --from-secret`, so no value
  passes through you.
- An API outside the catalog is a custom connection: its host and key. A service
  (`sprott service --help`) adds named rules for an API from a third-party source; an
  admin must first allow third-party services in the vault's Settings, and the
  user approves each install. The user can also install one from that page.
- A vault is a security boundary, and each connection belongs to one. Target it
  with `--vault` to use its connections; resolve a name with `sprott vault ls`, and ask
  when it is ambiguous.

## Using a connection

```bash
sprott run -- curl https://api.stripe.com/v1/charges \
  -H "Authorization: Bearer __sprott__stripe__"
GITHUB_TOKEN=__sprott__github__ sprott run -- gh pr list
```

- Two accounts of one service differ by phantom (`__sprott__github__`,
  `__sprott__github_work__`). One request carries one connection's phantoms.
- A connection with a `setup` hint brokers a local tool: tell the user what you are
  configuring, then apply its steps.
- On a 401 or 403, first check the command ran under `sprott run --` with the exact
  phantom.

## Approvals

A request that needs approval stops and prints a `/grant/<op_id>` link and
`sprott op wait <op_id>`. Background the wait; its exit code says what comes next
(`sprott op wait --help`). After an approval, re-run the same command.

Where the user approves:

- `/grant/<op_id>`: one request, no sign-in.
- `/approvals` in the console, signed in: every pending request; the ticked ones
  are approved together, one passkey tap per vault.
- The bell in the console's top bar counts pending requests and opens `/approvals`.

One request: send its `/grant` link. Several at once for a signed-in user: start
them together and send `/approvals`.

`agent_not_authorized` means you are not turned on for this vault; its message
links the vault's Agent access page for the user.

A locked vault: run `sprott unlock`; it prints a link for the user and the `sprott op wait` command, like an approval.

## Updates

`sprott upgrade` updates `sprott` and restarts the daemon, which locks the vault until the
user taps their passkey. Upgrade when a command asks for it or the user agrees, then
run `sprott unlock` and send the unlock link.

A machine still on Sprott 1.x moves to 2.0 by running the installer above (its
`sc upgrade` fails and changes nothing). The installer moves `~/.safeclaw` to
`~/.sprott`; reload your agent env from there.
