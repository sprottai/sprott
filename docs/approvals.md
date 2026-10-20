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
A service's rules tighten the actions it names, such as sending email or
deleting a repository. A custom connection has no rules until you add some
or set its floors. `deny` is never a default.

There are no risk scores. A rule says what an action is; the level is your
decision about it. Writing rules: [Policy rules](reference/policy.md).

## What an approval covers

The approval card shows the exact operation: the agent, the connection, the
host, and the action. Your passkey signs that operation and nothing else.
There is no session-wide approval to steal, and an approval can't be
replayed into a different request.

### Details

An approval covers only the agent that asked, on that connection and host:

- `ask-always`: this one request.
- `ask` on a request the service scopes by its values (such as an amount):
  this request with the same values, for the window.
- `ask` from a rule: later requests the same rule decides, for the rule's
  window, of the same kind (read or write).
- `ask` from a floor: later reads (or writes) on that connection that no
  rule matches, for the floor's window.

A read approval never lets a write through. The card states what the
approval covers, and the daemon refuses an approval whose signed card differs
from what it would grant.

## Boundaries refuse

A request outside a connection's hosts, to a private address, or against a
`deny` rule is refused at once. It does not become an approval prompt.
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
