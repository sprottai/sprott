---
description: "Share one vault with your team: create a shared vault, invite people by link, set roles, let everyone's agents use it, and watch it all on the team overview."
---

# Work as a team

A shared vault gives your team one set of credentials. Every member's agents
use it, every call is attributed to a person, an agent and a machine, and
the team overview shows all of it in one picture.

Shared vaults are available on Team.

## 1. Create a shared vault

In the console, **New vault → Shared**. Name it and create it with your
passkey. It starts a 30-day team trial, no card needed. You become its
owner.

A vault's kind is fixed when you create it. A personal vault stays personal.

## 2. Invite people

On the vault's **Members** tab, the **Invite link** card has one link for
the vault, valid for 7 days. **Copy link** and send it. **Reset link**
replaces it.

1. The person opens the link, signs in or creates an account, and creates a
   passkey.
2. They click **Request to join**.
3. Their request appears on the Members tab and in your
   [Approvals inbox](approvals.md#the-approvals-inbox). Pick a role and click
   **Approve**. The vault must be unlocked: approving seals the vault key to
   them.

They see the vault only after you approve.

## 3. Roles

| | Member | Admin | Owner |
|---|:--:|:--:|:--:|
| Use the vault's connections through their agents | ✅ | ✅ | ✅ |
| Add connections and secrets | ✅ | ✅ | ✅ |
| Approve their own agents' requests | ✅ | ✅ | ✅ |
| Approve anyone's requests | | ✅ | ✅ |
| Edit policy | | ✅ | ✅ |
| Manage any member's agent access | | ✅ | ✅ |
| Invite, approve join requests, change roles, remove members | | ✅ | ✅ |
| Allow third-party services, rename, clear or delete the vault | | ✅ | ✅ |

A vault has one owner, shown as **Admin · Owner**. The owner is the billing
account and can't be removed or made a member. A vault always has at least
one admin.

Every role change and removal is signed by the admin who made it.

## 4. Let the agents in

Each member pairs their own machines and agents ([Quickstart](quickstart.md)).
On a shared vault, the overview offers **Authorize all** to turn on every
agent that can use it. The **Agent access** tab sets which agents may use the
vault and which connections each may reach ([Identity](agents.md#agent-access)).

## The team overview

On a shared vault, the [overview](activity.md#the-overview) covers the whole
team: the map starts from every member, then their machines and agents, and
Approvals splits each person's own requests from their teammates'.

## Remove a member

On the Members tab, a member's **⋯ → Remove**. The vault must be unlocked.
Removing a member:

1. removes them from the members list, signed by you;
2. revokes their agents;
3. replaces the vault key, so they can't read anything added later;
4. ends their access.

Their machines stop using the vault right away. People they invited or
promoted stay. They may remember credentials they saw in the console, so
create new ones at each service and update them in the vault.

## Billing

After the trial, a shared vault is billed per seat. Seats count people,
the owner included; agents don't take seats. Prices: [sprott.ai/pricing](https://sprott.ai/pricing).
