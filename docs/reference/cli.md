---
description: "Every sprott command and subcommand with its purpose, the global flags, ports, environment variables and exit codes."
---

# CLI

`sprott --help` prints the grouped list. `sprott <command> --help` prints a
command's flags. `sc` and `safeclaw` are links to the same binary.

## Global flags

| Flag | Purpose |
|---|---|
| `--vault <vault>` | Target vault for this command: an id, a unique id prefix, or the exact name. Works on any subcommand, in any position. |
| `--json` | Machine-readable output on commands that support it (`status`, `doctor`, `registry`, `setup`, the `ls` listings). |
| `-v`, `-vv`, `-vvv` | More logging to stderr. |
| `-h`, `--help` · `-V`, `--version` | Help and version. |

Commands that open a browser approval also take `--no-browser` (print the
link only), `--cb-port <port>` (a fixed port for the local callback, for SSH
port forwarding) and `--timeout <seconds>` (default 120).

## Setup

| Command | Purpose |
|---|---|
| `sprott setup [--name <name>] [--wait]` | Set up this machine and one agent without prompting. Re-run after each browser step until it reports `done`. ([Quickstart](../quickstart.md)) |
| `sprott skill install [--force]` · `skill remove [--force]` | Install, update or remove the agent skill. |
| `sprott login [--device-name <label>]` | Pair this machine to your account: prints a code and an approval link. |
| `sprott logout [--keep-remote]` | Unpair this machine and revoke its device key in your account. |
| `sprott up` | Start the daemon if needed, then unlock the vault. Safe to repeat. |
| `sprott down` | Stop the daemon. |
| `sprott restart` | Restart the daemon and unlock again. |
| `sprott status` | The daemon and the active vault: which one, locked or unlocked, its console URL. |

## Secrets

| Command | Purpose |
|---|---|
| `sprott set <KEY> [<value> \| -] [--host <host>]...` | Write a secret. With no value it asks (hidden); `-` reads it from stdin. `--host` anchors it to a host and creates its connection. `--no-broker` stores it with no host. |
| `sprott get <KEY>` | Print a secret's value. Asks for your passkey every time. |
| `sprott ls` | List secret names. |
| `sprott rm <KEY> [-y]` | Delete a secret. `-y` removes it even when connections use it. |

These are short forms of `sprott secret set|get|ls|rm`.

## Connections

| Command | Purpose |
|---|---|
| `sprott run [--vault <vault>] -- <cmd>` | Run a command through the proxy. `--export-env` prints the proxy environment as `export` lines instead. |
| `sprott connection ls` | List the connections the agent can use, with hosts and phantoms. |
| `sprott connection add [<id>]` | Create a connection in one approval. Flags: `--service <id>`, `--host <host>`, `--from-literal SLOT=VALUE` (`SLOT=-` reads stdin), `--from-secret SLOT=KEY`. |
| `sprott connection rm <id> [-y] [--keep-secrets]` | Remove a connection and the secrets it wrote. |
| `sprott connection add-host <id> <host>` | Propose a new host for a connection: an exact domain or a leftmost `*.domain`. |
| `sprott connection rm-host <id> <host>` | Propose removing a host from a connection. |
| `sprott registry` | The built-in service catalog. Works offline. |
| `sprott service add <source> [--id <id>] [--ref <ref>]` | Add service definitions from a folder or a GitHub repository. ([Add a service](../add-a-service.md)) |
| `sprott service update [<id or source>] [--all] [--check] [-y] [--ref <ref>]` | Re-read a source and store what changed. |
| `sprott service ls [<id>]` | List the vault's service definitions by source. |
| `sprott service rm <id or source>` | Remove one service, or every service of a source. |
| `sprott service validate <source> [--ref <ref>]` | Run the `add` checks without a vault. |
| `sprott store ls` | List the external stores connected to the vault. |

`sprott conn` is short for `sprott connection`.

## Account

| Command | Purpose |
|---|---|
| `sprott agent add <name>` | Create an agent identity and print its env. |
| `sprott agent ls` | List the account's agents: name, key prefix, last used. |
| `sprott agent rm <name>` | Remove an agent: prints the console page where you sign the removal. |
| `sprott device login` · `device logout` | Same as `sprott login` and `sprott logout`. |
| `sprott passkey ls` | List the passkeys enrolled on the vault. |
| `sprott passkey add` | Prints the console page where passkeys are added. |
| `sprott vault ls` | List vaults this machine knows; `*` marks the default. |
| `sprott vault use <vault>` | Set the default vault for your commands. |
| `sprott vault status` | The current vault: state, passkey count, secret count. |
| `sprott vault create` | Prints the console page where vaults are created. |
| `sprott vault forget <vault>` | Remove a vault from this machine's list. Changes nothing else. |
| `sprott vault rm <vault> [-y]` | Delete the vault's state in the daemon. Irreversible; asks for your passkey. |

Short forms: `sprott a` (agent), `sprott p` (passkey), `sprott v` (vault).

## Maintenance

| Command | Purpose |
|---|---|
| `sprott unlock` | Unlock the vault. `--vault` picks another one. |
| `sprott lock` | Wipe the vault's keys from the daemon's memory. Asks for your passkey. |
| `sprott sync` | Pull the latest vault state from the cloud now. |
| `sprott op wait <op_id> [--timeout <seconds>]` | Wait for an approval. The exit code is the outcome (below). |
| `sprott log [-f] [-n <lines>] [--raw]` | Show the daemon's logs. |
| `sprott doctor` | Health and reachability checks. Exits non-zero if a check fails. |
| `sprott upgrade [--force] [--stable \| --prerelease]` | Install the latest release and the skill. |
| `sprott proxy set <url>` · `proxy get` · `proxy unset` | Set the HTTP proxy the daemon uses to reach the internet, for corporate networks. |
| `sprott env` | Print `export` lines for your own shell (`eval "$(sprott env)"`). |
| `sprott config set\|get\|unset\|ls` | CLI preferences in `~/.sprott/config.toml`. |
| `sprott version` | Print the version. |
| `sprott serve` | Run the daemon in the foreground, for Docker or a hand-written service unit. `sprott up` uses it for you. |

## Ports and environment

| Name | Default | Purpose |
|---|---|---|
| `SPROTT_PORT` | `23293` | The daemon's control port, on `127.0.0.1`. |
| `SPROTT_PROXY_PORT` | `23294` | The proxy `sprott run` routes through. |
| `SPROTT_BROKER_URL` | | The local broker, set in an agent's env file. |
| `SPROTT_AGENT_IDENTITY` | | Path to the agent's identity file, set in its env file. |
| `SPROTT_STATE_DIR` | `~/.sprott/state` | Where the daemon keeps its state. |
| `SPROTT_BODY_CAP` | 32 MiB | The largest request body the broker inspects (`sprott serve --body-cap`). |
| `SPROTT_CB_PORT` | | Same as `--cb-port`. |

The installer reads `SPROTT_BIN_DIR` (default `~/.local/bin`).

## Exit codes

All commands: `0` success, `1` error, `2` usage error.

`sprott op wait`:

| Code | Meaning |
|---|---|
| `0` | Approved. Run the original command again. |
| `3` | Expired or unknown. Run the command again for a fresh link. |
| `4` | Stopped waiting (`--timeout`). The request may still be pending; wait again. |
| `5` | Not approved. Don't retry it unchanged. |
| `6` | Withdrawn, or replaced by a newer request. Run the command again to ask again. |
