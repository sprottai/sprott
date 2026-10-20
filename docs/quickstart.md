---
description: "Install Sprott, pair your machine and agent, add a credential and make your first call through the local proxy."
---

# Quickstart

Five steps from nothing to the first brokered call.

## 1. Install

Paste this to your coding agent:

```text
Set up Sprott for me: run `curl -fsSL https://sprott.ai/install.sh | sh` and follow what it prints. I only open links and tap my passkey; you run every command.
```

Or run the installer yourself:

```bash
curl -fsSL https://sprott.ai/install.sh | sh
```

The installer uses no sudo, checks the download's SHA256, puts `sprott` in
`~/.local/bin` and installs the agent skill. Run by an agent, it continues
straight into `sprott setup`. In a terminal, it prints the next step.
Platforms: [Platform support](reference/platform-support.md).

## 2. Run setup

```bash
sprott setup
```

`--name <name>` names the agent. It defaults to the agent's product name,
such as `claude-code` or `codex`.

`sprott setup` never prompts. Each run prints what it needs from you, if
anything, and the command to run next:

```
To pair this machine, open this link on a device with your passkey and enter the code:
  https://app.sprott.ai/pair
  Code: 4821-0937-5563 (expires in about 15 minutes)
Next: sprott setup --name codex --wait
```

Run each `Next:` until a run prints none. After an error, run the printed
`Fix:`. With `--json`, each run prints one object whose `status` is
`action_required`, `waiting`, `done` or `error`.

In the browser you:

1. sign in, or create an account the first time;
2. create a passkey, which also creates your first vault;
3. approve the machine;
4. approve the agent and choose which vaults it may use.

Setup pairs the machine (`sprott login`) and registers the agent
(`sprott agent add`) when either is still needed, writes the agent's env file
and installs the skill. It is safe to run again. To add a second agent by
hand, run `sprott agent add <name>`.

## 3. Unlock the vault

The last `Next:` is usually `sprott unlock`. It prints an unlock link and a
`sprott op wait` command. Open the link and approve with your passkey.

With several vaults, run `sprott vault ls`, then
`sprott unlock --vault <name>`.

## 4. Add a credential

**In the console**, for OAuth services such as GitHub or Gmail: open your
vault's Connections tab, pick the service, and sign in or paste the key.
Values you type there are encrypted in your browser before upload.

**In a terminal**, for any API key:

```bash
sprott set HF_TOKEN --host huggingface.co
```

It prompts for the value, asks for one passkey approval, and creates the
phantom `__sprott__hf_token__` for `huggingface.co`. Entered this way, the
value never leaves your machine. More ways: [Connections](connections.md).

## 5. Make the first call

Put the phantom where the credential goes and run the command through
`sprott run --`:

```bash
HF_TOKEN=__sprott__hf_token__ sprott run -- huggingface-cli whoami
```

The proxy swaps in the real value on the way to `huggingface.co`. The
command gets the response. The agent, its environment and your shell history
hold only the phantom.

If the call needs an approval, the output carries a link: open it, approve,
and run the command again.

## Every day

```bash
sprott up      # start the daemon and unlock the vault
sprott lock    # wipe the keys from the daemon's memory
sprott doctor  # health and reachability checks
```

Next: [Use a credential](sc-run.md) for the everyday patterns, or
[Work as a team](team.md) to share a vault.
