---
description: "What Sprott records for every brokered call: who asked, from which machine, what was decided and who approved, and what is never recorded."
---

# Activity

Every brokered call is recorded: the agent that made it, the machine it ran
on, the decision, and who approved it. Open a vault's **Activity** tab.

## What a row shows

| Column | What it is |
|---|---|
| Time | When the request arrived. |
| Request | The method, the service and the path. |
| Member | The person whose agent made the call (shared vaults). |
| Agent | The agent that signed the request. |
| Device | The machine it ran on. |
| Approved by | The person who approved it (shared vaults). |
| Outcome | What happened (below). |

Filter by type, target, member, agent or device from the column headers. The
tiles at the top count each outcome; click one to filter.

## Outcomes

| Outcome | Meaning |
|---|---|
| allowed | Policy let it through with no approval. |
| approved | A person approved it with a passkey. |
| pending | Waiting for an approval. |
| blocked | Refused by a `deny` rule, or sent to a host the connection doesn't list, or to an address that is never allowed. |
| rejected | A person said no. |
| expired | Nobody answered in time. |
| cancelled | The request was withdrawn or replaced by a newer one. |

## The detail drawer

Click a row to see the request, who asked (member, agent, device), the
decision (outcome, who approved and how long it waited, or who rejected),
and the basis, such as "Allowed by policy". Rejecting needs no passkey, so
the drawer marks who rejected as unconfirmed.

## What is never recorded

Only the method and path are recorded. Never query parameters, request
bodies, response bodies or credential values.

## Where it lives

Each machine keeps the full history of its own calls. The cloud keeps a
copy of the metadata above so the console can show it across machines, for
the window your plan includes ([Plans](reference/plans.md)).

On a shared vault, Activity covers the whole team, and the
[team overview](team.md#the-team-overview) sums it up in one picture.
