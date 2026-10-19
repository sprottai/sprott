# Quickstart

This page explains how to install Sprott, run agent-driven setup, approve the browser steps, and make the first brokered call.

## 1. Install

```bash
curl -fsSL https://sprott.ai/install.sh | sh
```

The installer uses no sudo, verifies the download's SHA256, puts `sprott` in
`~/.local/bin`, and installs the skill at `~/.agents/skills/sprott/SKILL.md`. When run by
an agent, it continues straight into `sprott setup`; in a terminal it prints one
next step. It also installs the skill with `sprott skill install`. Official sources
are [sprott.ai](https://sprott.ai) and
[github.com/sprottai/sprott](https://github.com/sprottai/sprott).
Supported platforms: [Platform support](reference/platform-support.md).

## 2. Run setup

Run this as the person or as their agent:

```bash
sprott setup
```

`--name <a short name for the agent>` is optional and defaults to the agent's
product name, such as `claude-code` or `codex`.
`sprott setup` never prompts. Each run prints what it needs from the person, if
anything, and the command to run next:

```
To pair this machine, open this link on a device with your passkey and enter the code:
  https://app.sprott.ai/pair
  Code: 4821-0937-5563 (expires in about 15 minutes)
Next: sprott setup --name codex --wait
```

The agent gives the person the link and code, runs `Next:`, and repeats until a
run prints no `Next:`. After an error it runs the printed `Fix:`. The last
`Next:` is usually `sprott unlock`, which prints an unlock link and a `sprott op wait`
command. Continue to the next section after approval. With `--json`, each run
prints one object whose `status` is `action_required`, `waiting`, `done` or
`error`, with the same values as fields.

In the browser, the person signs in or creates an account the first time,
creates a passkey, and approves the machine. The passkey also creates the
first vault. They then approve the agent and choose which vaults it may use.
Under the hood, setup runs `sprott login` if the machine is not paired and `sprott agent
add` if the agent is not registered. It writes
`~/.sprott/agents/<name>/agent.env` and installs the skill. It is safe to run
again.

At a terminal, a person can still use `sprott login` to pair a machine or `sprott agent
add <name>` to add an agent by hand, such as a second agent. `sprott setup` runs
whichever of those is still needed and also handles the env file and skill.

## 3. Add a credential

Two doors, same result: a **connection** with hosts and a **phantom**.

**Console** (recommended for OAuth services like GitHub or Gmail): open your
vault's Connections tab, pick the service, sign in or paste the key. Values
you type there are encrypted in your browser before upload.

**Terminal**, for any bare API key:

```bash
sprott set HF_TOKEN --host huggingface.co
```

Prompts for the value, asks for one passkey approval, and mints the phantom
`__sprott__hf_token__` anchored to `huggingface.co`. Entered this way the value
never leaves your machine.

## 4. Unlock the vault

After approving the machine and the agent, run `sprott unlock`. It prints an unlock
link for the person and the `sprott op wait` command. For several vaults, run
`sprott vault ls`, choose one, then run `sprott unlock --vault <name>`.

## 5. First brokered call

Put the phantom where the credential belongs and route the command through
`sprott run --`:

```bash
HF_TOKEN=__sprott__hf_token__ sprott run -- huggingface-cli whoami
GITHUB_TOKEN=__sprott__github__ sprott run -- gh pr list
```

The proxy swaps the phantom for the real value on the way out, only toward
that connection's own hosts. The command gets the API response; the
environment, the shell history, and the agent hold only the phantom.

## 6. When an approval is needed

Policy-gated uses don't fail silently: the command's error output carries an
approval link. Open it, tap your passkey, re-run the same command. Agents can
block on `sprott op wait <op_id>` instead of asking you to say "done". Approvals
are cached per policy, so routine calls don't nag.

## 7. Daily rhythm

```bash
sprott up      # start of day: daemon up + vault unlocked, one passkey tap
sprott lock    # done for the day: wipe keys from the daemon's memory
sprott doctor  # something's off: health + reachability checks
```

Next: teach the agent the full patterns in
[`sprott run` and phantoms](sc-run.md), or hand it the skill directly via
[For your agent](for-your-agent.md).
