# Compat sunset — what to delete once all users have upgraded

Short ledger of **intentional backward-compat** kept live during the identity wave /
甲 / team rollout. Each row is dead weight to remove **after its trigger fires** — NOT
before (removing early drops protection for un-upgraded clients). Pairs with
`../../IDENTITY_WAVE_BUILD_LOG.md` → JOINT E2E PLAN + RESIDUE SWEEP.

Repos: `core` = safeclaw/ · `be` = safeclaw-pro-backend/ · `fe` = safeclaw-pro-frontend/.

| # | Compat kept | Why kept | Delete trigger | Where (repo:paths) |
|---|---|---|---|---|
| 1 | **Dual-window agent-id keying `identity_id \|\| prefix`** (and `?? prefix`) | legacy api-key agents have no `ag_`/`identity_id` yet | agent census: every agent has minted an AIK (`identity_id` non-null) | fe: `tab-agents.tsx` grantKey, `connections-tab.tsx` selKey, `team-dashboard.tsx` agentMap · core: `state.rs` mask consult legacy-prefix branch |
| 2 | **hop-A legacy Basic api-key** — now serves ONLY legacy DIRECT (non-shim) agents. The shim path is api-key-free (CONNECT was always PoP-only; api-face + forward moved off the key in slice 4, `60a9629`). Remaining: proxy-auth fallback for direct agents + key in env on the non-shim path + `sc agent add` prints it | AIK PoP path is opt-in until every agent has an authorized AIK | DIRECT-agent census → 0, then fail-closed flip (AIK sole path). Authorize-AIK UX is now shipped for BOTH team + personal cloud vaults (`c01318a`), so the flip is e2e/census-gated only | core: `api_key.rs`, `proxy/handler.rs` `key_is_valid` else-branch + `api_face.rs::require_agent` legacy branch, `cli/agent.rs` env print, `cli/run.rs` direct (non-shim) path |
| 3 | **hop-B legacy device bearer** (`.bearer_auth(dk)` alongside `dik_pop`; backend accepts bearer) | DIK PoP is additive/compute-only until enforced | bump `MIN_TEAM_DAEMON_VERSION` → enforce DIK; flip `SC_DEVICE_SIG_AUDIT` from audit to reject | core: `sync.rs`/`relay/client.rs`/`sync_stream.rs` bearer sites · be: `vault-routes.mjs` `resolveAuth` bearer path + `deviceSigVerdict` (audit→enforce) |
| 4 | **config-sig record fallback + `vault_config_ids` registry gate** | pre-甲 owner-config protection, belt-and-suspenders with `recordWriteGate` | 甲 cutover: bump gate → require item-sig | core: `storage/sealed_vault.rs` config-sig fold fallback + `unwrap_verified_config`/`unwrap_verified_agent_grant` config-sig arms · be: `vault-routes.mjs` `handleConfigIdsRegister` + `/config-ids` route + `team.registerConfigIds`/`isConfigId` + `vault_config_ids` table · core daemon: `sync.rs` `/config-ids` POST in `deliver_team_marks` |
| 5 | **NoUik / fmt1-personal unsigned path** (unsigned records honored; `vault_keys` /keys path; `vault_keys.author_account_id` write-only col) | pre-team prod = single-user fmt1 personal vaults | fmt1 census → 0 (task B1b) | core: NoUik trust / unsigned-honored fold arms · be: `vault-routes.mjs` fmt=1 `/keys` path + `author_account_id` write; drop the column |
| 6 | **`~/.sprott/device-key` alongside the DIK identity file** | device migrates to a keypair; both live during rollout | after DIK is the sole device auth (with #3) | core: `sync.rs::device_key`, `cli/login.rs` device-key write, `cli/logout.rs` |
| 7 | **`SC_DEVICE_SIG_AUDIT` compute-only flag** | validate hop-B parity over the real wire before enforcing | when #3 enforces (audit becomes the gate) | be: `vault-routes.mjs` `resolveAuth` audit block + `keyset-roles.mjs::deviceSigVerdict` |
| 8 | **The 2.0 move from `~/.safeclaw` to `~/.sprott`** (the only code that reads a pre-2.0 path, unit or plist) | a 1.x device moves when the installer runs its first 2.0 command | 2.1: `MIN_DAEMON_VERSION` at least 2.0.0 everywhere and the census at 100% on 2.0 | core: `cli/migrate.rs` + `cli/migrate/tests.rs` + `tests/migrate_exempt.rs`, its call in `entry.rs::run_cli`, the `serve_must_wait` check in `entry.rs::run_daemon`, the 2.0 rows in `cli/doctor.rs` |
| 9 | **H1: a pre-2.0 phantom `__sc__...__` is refused with its 2.0 name** (`phantom_renamed`) | phantoms saved in git remotes, scripts and notes would otherwise leave unauthenticated | 2.1, with #8 | core: `proxy/resolver.rs::old_phantom`, the check in `proxy/handler.rs::pipeline`, `error.rs::ScCode::PhantomRenamed`, its row in `docs/reference/diagnostics.md` |
| 10 | **Backend reads of the pre-2.0 daemon header names** (`x-safeclaw-version`, `x-sc-device-{id,ts,sig}`) next to the `x-sprott-*` ones | 1.x daemons send the old names until they move | `MIN_DAEMON_VERSION` at least 2.0.0 everywhere (an old daemon is refused either way) | be: `daemonVersion(req)` and `deviceHeaders(req)` and their call sites |

## Pre-existing tech-debt (optional, not rollout-gated)
- **`now_unix` sprawl:** identity-wave copies now share `core:util.rs::now_unix`, but pre-existing
  named copies remain (`store/adapters/gcp.rs`, `storage/pending_passkey.rs`, `cli/webauthn.rs`[pub])
  plus ~40 inline `SystemTime::now().duration_since(UNIX_EPOCH)` idioms. Fold into `crate::util::now_unix`
  opportunistically; no rollout dependency.

## Discipline
Nothing here is removed on a hunch — each waits for its trigger. When a trigger fires, delete the row's
code + this row together, and re-run the green gates for the touched repos.
