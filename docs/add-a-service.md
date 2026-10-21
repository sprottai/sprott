---
description: "Add a service that is not in Sprott's catalog to a vault, from a local folder or a GitHub repository, and keep it up to date."
---

# Add a service

Any HTTPS API works as a custom connection. To give a service its own hosts,
OAuth and labelled rules, add its definition to the vault. Writing one:
[service.toml](reference/services.md).

## Turn on third-party services

A service you add is third-party: Sprott does not review it. A vault loads
added services only while **Settings → Services → Allow third-party
services** is on. Only an admin can change it. While it is off, `add` and
`update` are refused, `sprott service ls` shows them skipped, and
connections that use them fail.

## Sources

A source is a folder holding one service (`service.toml`, an optional
`policy.toml` and an optional `icon.png`), or a collection
(`services/<id>/service.toml`, and so on).

| Source | Example |
|---|---|
| Local folder | `./my-api`, `/abs/path/tools` |
| GitHub repository, with an optional sub-folder | `github:owner/repo`, `github:owner/repo:services/acme` |

## Commands

| Command | Does |
|---|---|
| `sprott service add <source> [--id <id>] [--ref <ref>]` | Reads the source, checks every definition, and stores them with one passkey approval. |
| `sprott service update <id or source> [--all] [--check] [-y] [--ref <ref>]` | Re-reads a source and stores what changed, with one passkey approval. |
| `sprott service ls [<id>]` | Lists the vault's definitions by source, with the pinned commit, and which are loaded or skipped and why. |
| `sprott service rm <id or source>` | Removes one service, or every service of a source. |
| `sprott service validate <source> [--ref <ref>]` | Runs the same checks as `add`, without a vault. For authors and CI. |

The same actions are on **Settings → Services** in the console.

## How it works

- **One approval.** The card lists each service, every host that receives
  its credentials or OAuth data, `PKCE: off` when the flow has no PKCE, the
  rules it applies with any approval window, the source with its ref and
  commit, and the definition text.
- **Pinned.** A GitHub source is pinned to a full commit. `--ref` takes a
  branch or tag; the default is the default branch. The daemon fetches the
  source itself and checks that the commit holds the same definitions you
  approve.
- **Read, never run.** Only `service.toml`, `policy.toml` and `icon.png` are
  read, as regular files. Links are not followed, `..` and absolute paths are
  refused, and sizes are capped.
- **All or nothing.** One invalid definition refuses the whole source.
- **Only tightens.** An added definition's `allow` rules and `allow` floors
  are dropped. Loosening is your setting on the Permissions tab.
- **Ids.** A definition is stored under its `[service] id`. It can't reuse a
  built-in id or one another source holds. `--id` renames a single-service
  source.
- **Updates.** `update` shows what changes and marks new hosts
  (`+ NEW HOST`) and anything that lets requests through more easily
  (`! LOOSENED`: a rule gone or less strict, a longer window, a value an
  approval no longer binds, PKCE turned off). `--check` only shows. `-y`
  skips the terminal question, never the passkey. A local source is re-read
  from the path you pass: `sprott service update ./my-api`. Services the
  source no longer has are removed.
- **Shared vaults.** Any member can add, update or remove a definition after
  approving the card.
- **Sync.** If a definition changed in two places at once, both are kept:
  the second as `<id> (conflict copy)`, which is never used. Keep the one you
  want in the console.
- **Removal.** Connections that use a removed service are kept and listed;
  they stop working until the definition is added again.
- **Icons.** An `icon.png` must be a real PNG of at most 32 KiB. Icons show
  for catalog services; an added service's icon never reaches the approval
  card.
