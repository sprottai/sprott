---
description: "Every Sprott error code, what it means and what to do next, plus where codes appear, CLI exit codes and the cases with no code."
---

# Error codes

Sprott reports every refusal with a stable code and leaves upstream errors
that are not its own unmarked. Codes are snake_case and never reused.

## Where you see a code

| Where | Shape |
|---|---|
| A command run through `sprott run` | The response body starts with `Sprott: <code>: <message>`, and carries the header `x-sprott-error: <code>`. The body is plain text, so it is never mistaken for the service's own reply. |
| The daemon's local API | RFC 9457 `application/problem+json` with `type` (`https://sprott.ai/errors/<code>`), `title`, `status`, `detail`, and the extensions `code`, `action` and `cause`. |
| CLI output | `<code>: <message>` on stderr. |

`action` says what to do next:

- `unlock`: unlock the vault;
- `approve`: open the approval link in the body;
- `retry`: try again;
- `configure`: change the setting the message names;
- `fix_request`: change the request;
- `none`: a deliberate refusal; don't work around it.

`cause` says whose problem it is: `request`, `auth`, `vault`, `policy`,
`config` or `internal`. `environment` and `upstream` are not Sprott problems;
Sprott reports them because it saw them happen.

## Codes

### Vault and setup

| Code | Status | What it means | What to do |
|---|---|---|---|
| `vault_locked` | 423 | The vault is locked. | Run `sprott unlock`, then retry. |
| `no_vault` | 403 | No vault is bound to the request. | Route credential traffic with `sprott run`. |
| `vault_access_revoked` | 403 | This account is no longer a member of the vault. | Ask a vault admin to add it back. |
| `vault_deleted` | 410 | The vault was deleted. | None. |
| `vault_key_changed` | 409 | The vault's members changed and its key was replaced. This device doesn't have the new key yet. | Run `sprott unlock`. |
| `team_lease_expired` | 403 | This machine has not reached the cloud for too long, so the shared vault's credentials stop serving. | Restore the network; it serves again once it reconnects. |
| `ledger_stale` | 423 | Sprott could not reach your account for 7 days, so vaults are locked. Data stays. | Check the network, then `sprott up`. |
| `upgrade_required` | 426 | This vault needs a newer Sprott. | Run `sprott upgrade`. |

### Identity

| Code | Status | What it means | What to do |
|---|---|---|---|
| `unauthorized` | 401 | The request carries no valid agent identity or credential. | Run the agent through `sprott run`, or set it up with `sprott agent add`. |
| `agent_key` | 407 | A request with a phantom has no verified agent identity. | Run the agent through `sprott run`; set it up with `sprott setup --agent-name <name>`. |
| `agent_not_admitted` | 403 | The agent proved who it is, but your account does not admit it (never approved, or removed). It is refused on every vault. | Run `sprott setup --agent-name <name>` or `sprott agent add`. |
| `agent_not_in_account` | 403 | The agent is not registered to the account this machine is signed in to. | Run `sprott agent add` on this machine. |
| `agent_not_authorized` | 403 | The agent is not turned on for this vault. | Turn it on in the vault's Agent access page; the message has the link. |
| `mask_not_enabled` | 403 | The connection exists, but is not turned on for this agent. | The responsible member turns it on in the vault's Agent access page. |
| `device_not_admitted` | 403 | This machine needs to be paired again. | Run `sprott login`. |
| `ledger_device_revoked` | 403 | This machine was removed from the account. | Run `sprott login` to pair it again. |
| `ledger_head_invalid` | 403 | The account's device list does not match its signed head. The daemon keeps its previous view. | None. |

### Approvals

| Code | Status | What it means | What to do |
|---|---|---|---|
| `approval_needed` | 401 | Policy asks for an approval. The body has the approval link and the op id. | Open the link, or run `sprott op wait <op_id>`, then retry. |
| `approval_register` | 503 | The approval request could not be opened. | Retry. |
| `approver_not_authorized` | 403 | The person who approved is neither the requester nor an admin of this shared vault. The request stays pending. | Ask the requester or an admin to approve. |
| `grant_id_invalid` | 403 | The approval's identity signature is missing, does not verify, or names someone other than the passkey's owner. The request stays pending. | Approve again from the approval page. |
| `wk_refused_v2` | 400 | An approval delivered an unlock secret instead of the vault key and the approver's signature. The request stays pending. | Reload the approval page and approve again. |
| `batch_verify_failed` | 409 | A batch approval could not be verified against the requests it covers. | Approve again from the Approvals page. |

### Policy and hosts

| Code | Status | What it means | What to do |
|---|---|---|---|
| `policy_denied` | 403 | A `deny` rule blocks this request. | None. |
| `host_not_anchored` | 403 | The destination is not one of the connection's hosts. The body offers an approval to add it. | Approve the new host, or fix the URL. |
| `host_forbidden` | 403 | The destination is a private or cloud-metadata address. | None. |
| `refresh_forbidden` | 403 | A refresh token never leaves the vault. | Use the connection's main phantom. |
| `broker_body_limit` | 413 | The request body is larger than the broker inspects. | Raise `--body-cap` on `sprott serve` if the body is legitimate. |
| `forbidden` | 403 | Authenticated, but not allowed. | None. |

### Phantoms and requests

| Code | Status | What it means | What to do |
|---|---|---|---|
| `unknown_connection` | 400 | The phantom names no connection. | Copy the phantom from `sprott connection ls`. |
| `phantom_unresolved` | 424 | A phantom could not be resolved, so the request was blocked before it left. | Check the name with `sprott connection ls`, or run `sprott unlock`. |
| `ambiguous_phantom` | 400 | A bare phantom on a connection with several values. | Use the per-key phantom, `__sprott__<conn>__<key>__`. |
| `multi_connection` | 400 | One request named several connections. | Send one connection per request. |
| `phantom_plain_http` | 400 | Phantoms need HTTPS. | Use an `https://` URL. |
| `phantom_renamed` | 400 | The request uses a phantom from before Sprott 2.0 (`__sc__<conn>__`). | Use the name in the message (`__sprott__<conn>__`). |
| `exposes_unsupported` | 400 | That value can't be produced for this connection. | Use one of the connection's listed phantoms. |
| `bad_request` | 400 | Malformed request. | Fix the request. |
| `not_found` | 404 | No such resource. | Fix the request. |
| `method_not_allowed` | 405 | The local API accepts only GET. | Fix the request. |
| `conflict` | 409 | State conflict. | Fix the request. |
| `rate_limited` | 429 | Too many requests. | Slow down. |

### Network and services

| Code | Status | What it means | What to do |
|---|---|---|---|
| `egress_unreachable` | 502 | The daemon could not connect onward. Not a credential problem. | Check the network, or `sprott config set proxy <url>` behind a corporate proxy. |
| `upstream_error` | 502 | The service answered, but the exchange failed. Not a credential problem. | Retry. |
| `upstream_body` | 502 | The request body could not be read. | Retry. |
| `oauth_mint` | 502 | The provider refused to issue a token. | Retry; reconnect the account in the console if it keeps failing. |
| `store_unavailable` | 502 | An external secret store failed while resolving a value. | Retry; `sprott log` has the full error. |

### Internal

| Code | Status | What it means | What to do |
|---|---|---|---|
| `internal` | 500 | Daemon failure. | Retry; `sprott log` for details. |
| `ca_unavailable` | 500 | The local certificate authority could not be read. | Retry; `sprott restart`. |
| `secret_encoding` | 500 | The stored value is not valid UTF-8. | Store the value again. |

## Exit codes

All commands exit `0` on success, `1` on error and `2` on a usage error.
`sprott doctor` exits non-zero if any check fails. `sprott op wait` has its
own codes: [CLI](cli.md#exit-codes).

## When there is no Sprott code

- **The command was not routed.** Without `sprott run`, the phantom reaches
  the service as a literal string. The service refuses it (usually 401) and
  there is no `Sprott:` line. Check that the command runs under `sprott run`.
- **The daemon restarted and the vault was never unlocked.** The broker
  can't recognise a connection's hosts until the vault has been unlocked
  once, so it passes that traffic through. Run `sprott unlock`. After the
  first unlock, a phantom sent while locked gets `vault_locked`.
