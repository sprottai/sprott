---
description: "How Sprott signs every action, where your keys live, what the cloud can and cannot read, what a compromised agent or server can do, and the principles behind it."
---

# Security model

Zero trust for agents: every request is checked against the agent that
signed it and the scope it asks for.

Approvals are built on SUDP, a protocol for passkey-signed, single-use
grants ([paper](https://arxiv.org/pdf/2604.24920)).

## Every action has a signature

| Action | Signed by |
|---|---|
| An agent's request to the broker | the agent's identity key (AIK) |
| A machine's request to your account | the machine's device key (DIK) |
| An approval | the approver's passkey and identity key (UIK) |
| A change to policy, members, agent access or vault settings | the person who made it (UIK) |

The broker accepts a request only from an agent your account admits and the
vault allows. It applies only policy signed by a vault admin. It accepts an
approval only when the signature covers exactly the operation it would
grant, from the requester or an admin. Each record in
[Activity](activity.md) is attributable to signed identities: which agent,
which machine, who approved. More: [Identity](agents.md).

## Where is the plaintext?

In one place: the daemon's memory on your machine, while the vault is
unlocked. On disk, yours or ours, a vault exists only sealed under a key
derived from your passkey. `sprott lock`, or stopping the daemon, wipes the
decrypted copy.

## What does the cloud store?

The sealed vault, for backup and sync; your machine and agent registrations;
and approval and activity metadata. It cannot open the vault: sealing and
unsealing happen on your devices. Values you add in the console are
encrypted in your browser before upload. Values you enter at the CLI never
leave your machine.

Your traffic doesn't pass through the cloud either. The broker runs on your
machine and sends requests straight to the service.

## What if Sprott's servers are breached?

The attacker gets sealed vaults. Without one of your passkeys, they stay
sealed. The same property has a cost: lose every passkey and nobody,
including Sprott, can open your vault. Keep a second passkey
([Vaults](vault.md#lose-every-passkey)).

## What can a compromised agent do?

It holds phantoms, which are worthless outside Sprott's proxy. Through the
proxy it can use a credential only toward that connection's own hosts, under
your policy, and sensitive calls wait for your passkey. It cannot read a
value, send a credential to its own server, or approve its own requests.
Every attempt is in Activity.

## Is Sprott intercepting all my traffic?

No. Only commands run through `sprott run` are brokered. Everything else on
your machine goes out untouched.

## What does an approval authorize?

One operation. The approval page shows the pending operation, your passkey
signs it, and the signature is good for that operation only. There is no
session-wide approval to steal.

## Can I verify this?

The `sprott` command, its daemon and the agent skill are on GitHub at
[github.com/sprottai/sprott](https://github.com/sprottai/sprott). The
sealing, the proxy and the approval checks are in that code, and you can
build it with `cargo build --release`. Each release carries a build
provenance attestation that ties the binary to the release workflow and
commit:

```bash
gh attestation verify ~/.local/bin/sprott --repo sprottai/sprott
```

## Design principles

1. **Use is not possession.** The agent gets the use of a credential, never
   the credential. The value appears only inside the proxy, on your machine.
2. **One way out.** Brokered traffic leaves through one local proxy, and the
   proxy touches only traffic you route through it. A request without a
   phantom passes untouched.
3. **The host is a limit, not a selector.** A connection's hosts bound where
   its credential may go. The broker never picks a credential because of
   where a request is going.
4. **You decide the floor.** Rules decide the actions they name. A request
   no rule matches falls to the connection's floor, then the service type's,
   then the vault's. When rules disagree, the strictest wins.
5. **Boundaries refuse.** A request outside policy is a clear error, not an
   approval prompt. Prompts are kept for actions you marked as sensitive.
6. **One approval, one operation.** An approval is a passkey-signed grant
   for the operation on the card.
7. **Plaintext in one place.** The daemon's memory, on your machine, while
   unlocked.
8. **A gate, not a wall.** `deny` is never a default. Sprott exists to let
   agents do real work, with you deciding at the point that matters.
9. **No risk scores.** Rules state facts: what an action is, read or write.
   The level is your decision.
10. **Fail loudly.** Every refusal carries a stable `Sprott: <code>` line and
    a documented fix ([Error codes](reference/diagnostics.md)).
