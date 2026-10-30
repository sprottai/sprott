---
description: "How Sprott decides each request (allow, ask, ask-always or deny), where the rules come from, what one passkey approval covers, and the Approvals inbox."
---

# Policy and approvals

A key is used only for the request the agent made. Rules clear the routine
calls. You approve the rest on a screen that shows exactly what will run.

## Four levels

Every brokered request gets one level:

| Level | Console label | Behaviour |
|---|---|---|
| `allow` | Allowed | Runs with no approval. |
| `ask` | Ask once | One approval, then reused for that rule's window. |
| `ask-always` | Ask every time | An approval every time. |
| `deny` | Never | Refused. |

When several rules match, the strictest wins.

## Where the level comes from

1. **Rules.** Each catalog service ships labelled rules for its actions,
   such as "Read email content" or "Delete repository". A rule matches the
   request's method and path.
2. **Floors.** A request no rule matches falls to the connection's read or
   write floor, then the floors for the service's type, then the vault's
   global floor. `GET`, `HEAD` and `OPTIONS` are reads; every other method
   is a write.

You decide every level. On the vault's **Permissions** tab you can change
any rule, set a connection's floors ("Everything else"), and set the vault
defaults by service type.

Out of the box the floors are `allow`, so a key you add works right away.
A service's rules tighten the actions it names, such as making a file
public or deleting a repository. A custom connection has no rules until you add some
or set its floors. `deny` is never a default.

There are no risk scores. A rule says what an action is; the level is your
decision about it. Writing rules: [Policy rules](reference/policy.md).

## What an approval covers

The approval card shows the exact operation: the agent, the connection, the
host, and the action. Your passkey signs that operation and nothing else.
There is no session-wide approval to steal, and an approval can't be
replayed into a different request.

### Details

An approval covers only the agent that asked, on that connection and host,
with the same credentials (the same secrets of the connection):

- `ask-always`: this one request.
- `ask` on a request the service scopes by its values (such as an amount):
  this request with the same values, for the window.
- `ask` from a rule: later requests the same rule decides, for the rule's
  window, of the same kind (read or write).
- `ask` from a floor: later reads (or writes) on that connection that no
  rule matches, for the floor's window.

A read approval never lets a write through. A request that uses another
secret of the connection, or one more, asks again; so does one after the
connection is rebound to other secrets. A new value for the same secret
keeps the approval.

The card states what the approval covers, and the daemon refuses an approval
whose signed card differs from what it would grant. It may grant less, never
more: approving while the vault is locked lets nothing through (the request
says the vault is locked), and a window approved after the vault's policy
changed is not kept (the request asks again).

How long a window lasts:

- Any change to the vault's policy ends its windows, also one made while it
  was locked. Other changes to the vault keep them.
- Locking the vault ends every approval.
- A window lasts its full length even if the person who approved it is
  removed from the vault meanwhile.
- An agent that is removed from the vault is refused before any approval is
  looked at. Added back, its approvals that have not run out apply again.

Values the daemon read from an external store are read again after any
change to the vault, or after a lock and unlock.

## Boundaries refuse

A request outside a connection's hosts, to a private address, or against a
`deny` rule is refused at once. So is one naming a secret the connection
doesn't have, or one the vault doesn't hold (`unknown_role`,
`secret_not_set`), and one an external store can't answer
(`store_unavailable`). None of these becomes an approval prompt.
Prompts are kept for the actions you marked as sensitive, so each one means
something. A host the connection doesn't list yet comes with one approval to
add it permanently.

## The Approvals inbox

**Approvals**, in the console sidebar, lists every request waiting for you,
across all your vaults, grouped by vault: credential uses, unlocks, new
hosts, removals and other changes. Join requests for shared vaults appear
here too.

- Select several and **Approve N**: one passkey touch per vault and machine.
- **Reject** needs no passkey.

On a shared vault, the requester or a vault admin can approve. Teammates'
requests are listed under **Team members' requests** and don't count toward
your badge.

## For agents

A command that needs an approval fails with the approval link in its output.
The agent gives you the link, runs `sprott op wait <op_id>` in the background
(exit `0` means approved), and runs the same command again. With several
requests waiting, the agent sends you the console's Approvals page instead of
each link.
