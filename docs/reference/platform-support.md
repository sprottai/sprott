---
description: "Which operating systems and CPUs run the sprott CLI and daemon, how to install and verify it, and how it runs on each."
---

# Platform support

The `sprott` command and daemon run on these platforms. Which passkeys and
browsers can seal a vault: [Passkey support](passkey-support.md).

| Platform | Architecture | Binary |
|---|---|---|
| macOS | Apple Silicon (arm64) | `sprott-macos-aarch64` |
| macOS | Intel (x86_64) | `sprott-macos-x86_64` |
| Linux | x86_64 | `sprott-linux-x86_64` (static, musl) |
| Linux | aarch64 | `sprott-linux-aarch64` (static, musl) |

On any other platform the installer exits with "Unsupported platform".

## Install

```bash
curl -fsSL https://sprott.ai/install.sh | sh
```

Puts the `sprott` command in `~/.local/bin` (override with `$SPROTT_BIN_DIR`),
with `sc` and `safeclaw` as links to it,
verifies the download's SHA256, installs the agent skill, and prints
`sprott setup --name <name>` as the next step. Run on a machine set up before
2.0, it also moves `~/.safeclaw` to `~/.sprott` and the daemon to the 2.0
service name below ([Upgrading](../upgrade.md)). No sudo, no system changes, no
telemetry. Linux binaries are statically linked (musl), so there is no glibc or
runtime-dependency requirement.

## Verifying the download

Every release publishes a `SHA256SUMS` file, which the installer checks. Each
release also carries a sigstore build-provenance attestation. To verify a
binary yourself:

```bash
gh attestation verify ~/.local/bin/sprott --repo sprottai/sprott
```

## macOS

The binary is not Apple-notarized. The `curl | sh` install above runs
without a Gatekeeper prompt; a binary downloaded through a browser would be
quarantined and blocked as "unidentified developer" instead. Verify provenance
with the attestation command above if you obtained it another way.

`sprott up` installs a launchd LaunchAgent (`ai.sprott.daemon`) that starts the
daemon at login and restarts it on crash; `sprott down` removes it. Logs at
`~/.sprott/daemon.log`.

## Linux

A single static binary, no runtime dependencies. `sprott up` installs a per-user
systemd unit (`~/.config/systemd/user/sprott.service`, `systemctl --user`)
that starts the daemon and restarts it on failure; `sprott log` reads its journal.
Running it as a system-wide service is possible by hand-writing your own unit.

## Runtime

The daemon (`sprott serve`, started by `sprott up`) listens on `127.0.0.1:23293`
(control) and `127.0.0.1:23294` (the proxy `sprott run` routes agent traffic
through). Both are localhost-only and overridable via `$SPROTT_PORT`. Unlock
uses your platform passkey, see [Passkey support](passkey-support.md).

Related: [Quickstart](../quickstart.md) · [Security model](../security-model.md)
