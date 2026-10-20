---
description: "Move a machine from Sprott 1.x to 2.0 by running the installer again, and what changes for your agent."
---

# Upgrading

## From 1.x to 2.0

Sprott was called SafeClaw before 2.0. A machine on 1.x moves to 2.0 by running
the installer again, not `sc upgrade`:

```bash
curl -fsSL https://sprott.ai/install.sh | sh
```

On 1.x, once 2.0 is the latest release, `sc upgrade` (or `sprott upgrade`)
changes nothing and fails with:

```
no checksum for safeclaw-<platform> in the latest release
```

The installer puts `sprott` in `~/.local/bin`, with `sc` and `safeclaw` as
links to it. It then moves `~/.safeclaw` to `~/.sprott`, renames the
daemon's service to `sprott.service` (Linux) or `ai.sprott.daemon` (macOS), and
restarts the daemon if it was running. Vault data and keys are not touched.

Afterwards:

- The agent loads its env file again, from its new place:
  `set -a; . ~/.sprott/agents/<name>/agent.env; set +a`
  (`~/.sprott/agent.env` on an older setup). 2.0 does not read the 1.x
  variable names.
- Old phantoms are refused: a phantom from before Sprott 2.0 (`__sc__<conn>__`)
  gets `phantom_renamed`, and the message names its replacement
  (`__sprott__<conn>__`). Use the new name.

## Later upgrades

From 2.0 on, `sprott upgrade` installs the newest release.
