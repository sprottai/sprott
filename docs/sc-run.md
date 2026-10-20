---
description: "Use a credential without seeing it: find the phantom, place it, run the command through sprott run, use several accounts and debug a 401 or 403."
---

# Use a credential

The habit that makes Sprott work: **the agent handles phantoms, never
values.** How phantoms work: [Phantoms and the proxy](broker.md).

## Three steps

1. **Find the phantom.** `sprott connection ls` lists every connection with
   its hosts and phantom (`--json` for a machine-readable list). Copy the
   phantom exactly as shown.
2. **Place it** where the credential belongs: an env var a tool reads, an
   `Authorization` header, a config file, or a URL path.
3. **Run the command** through `sprott run --`.

```bash
HF_TOKEN=__sprott__hf_token__ sprott run -- python train.py
GITHUB_TOKEN=__sprott__github__ sprott run -- gh pr list
sprott run -- curl -s "https://api.telegram.org/bot__sprott__telegram__/getMe"
```

`sprott run --vault <name> -- <cmd>` picks a vault other than your default.

## Several accounts

Accounts differ by phantom, not by env var name. The same `GITHUB_TOKEN`
variable, two connections:

```bash
GITHUB_TOKEN=__sprott__github__ sprott run -- gh pr list        # personal
GITHUB_TOKEN=__sprott__github_work__ sprott run -- gh pr list   # work
```

## Git and Docker

Inside `sprott run`, git uses Sprott as its credential helper: for a host
with a connection, git sends that connection's phantom as the password, and
the proxy swaps in the real token.

```bash
sprott run -- git push
```

The proxy also fills phantoms inside `Authorization: Basic`, so for other
tools a phantom goes where the password goes:

```bash
sprott run -- docker login -u <user> -p __sprott__dockerhub__
```

## When an approval is needed

The command fails with an approval link in its output. Open it, approve with
your passkey, and run the same command again. An agent runs
`sprott op wait <op_id>` in the background and re-runs the command when it
exits 0. Details: [Policy and approvals](approvals.md#for-agents).

## Don't use `$(sprott get)`

```bash
HF_TOKEN=$(sprott get HF_TOKEN) python train.py     # don't
```

This puts the value in the process environment, where the agent and every
child process can read it. `sprott get` asks for your passkey every time,
because it shows a value. It is for you at a terminal: checking what is
stored, a one-off command you type yourself, moving away. An agent never
needs it.

## Debugging a 401 or 403

On a brokered call, an auth failure is usually routing, not the credential.
Check in order:

1. Did the command run under `sprott run --`?
2. Is the phantom exactly as `sprott connection ls` shows it?
3. Is the destination one of that connection's hosts?
4. Run `sprott doctor`. A `Sprott: <code>` line in the output maps to a fix
   in [Error codes](reference/diagnostics.md).
