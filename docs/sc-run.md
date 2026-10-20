---
description: "Use a credential without seeing it: place the phantom, run the command through sprott run, handle approvals and debug a 401 or 403."
---

# `sprott run` and phantoms: use a key without seeing it

The one habit that makes Sprott work: **the agent handles phantoms, never
values**. A phantom is a placeholder like `__sprott__github__`. Put it exactly
where the credential would go, prefix the command with `sprott run --`, and the
proxy substitutes the real value at egress, only toward that connection's own
hosts.

## The pattern

```bash
HF_TOKEN=__sprott__hf_token__ sprott run -- python train.py
```

The env var carries the phantom, not a value. Nothing in the agent's world
ever holds the token; the swap happens inside the proxy, on the way to
`huggingface.co` and nowhere else. No approval ceremony per read, because
nothing is revealed.

Three steps, always the same:

1. **Find the phantom.** `sprott connection ls` lists every connection with its
   hosts and phantom (add `--json` for a machine-readable list). Copy it exactly
   as shown.
2. **Place it** where the credential belongs: an env var a tool reads, an
   `Authorization` header, a config file, even a URL path
   (`https://api.telegram.org/bot__sprott__telegram__/sendMessage`).
3. **Route the command** through `sprott run --`. Unrouted traffic is untouched,
   and an unrouted phantom reaches the upstream as a literal string: a clean
   401, never a leak.

## Multi-account

Accounts are distinguished by phantom *value*, not env-var name. Same
`GITHUB_TOKEN` variable, different phantom:

```bash
GITHUB_TOKEN=__sprott__github__ sprott run -- gh pr list        # personal
GITHUB_TOKEN=__sprott__github_work__ sprott run -- gh pr list   # work
```

## Approvals mid-run

A policy-gated use fails the command with an approval link in its error
output. Open the link, tap your passkey, re-run the exact same command; the
approval is cached. Agents background `sprott op wait <op_id>` and treat its exit
as the signal (0 = approved).

## The anti-pattern: `$(sprott get)`

If you learned other secret managers first, this feels natural:

```bash
HF_TOKEN=$(sprott get HF_TOKEN) python train.py     # don't
```

It runs, but it defeats the point. The plaintext now sits in the process
environment where the agent, `python`, and every child process can read it,
and you paid a passkey ceremony for the privilege: every `sprott get` is
approval-gated because it reveals a value. You have reproduced "paste the key
into the env" with extra steps.

`sprott get` exists for *you* at a terminal: a one-off `curl` you type yourself,
checking what's stored, migrating away. It is not an agent primitive.

## Debugging a 401/403

On a brokered call, an auth failure is usually routing, not the credential.
Check in order:

1. Did the command actually run under `sprott run --`?
2. Is the phantom verbatim from `sprott connection ls`?
3. Is the destination one of that connection's hosts?
4. Still failing: `sprott doctor`, and the error's `Sprott: <code>` line maps to
   a fix in [DIAGNOSTICS.md](reference/diagnostics.md).
