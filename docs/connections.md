---
description: "How a stored secret becomes a phantom your agent can use: connections, hosts, the service catalog, the ways to connect, external stores and .env import."
---

# Connections

A secret in the vault is just a value. A **connection** makes it usable: it
binds one or more secrets to a service's hosts, and gives the agent a
phantom for them.

```
secret      HF_TOKEN = hf_xxx…                 stored
  +
host        huggingface.co                     where it may be sent
  =
connection  hf_token  →  phantom __sprott__hf_token__
```

Three rules keep this unambiguous:

- **A phantom resolves to exactly one value.** Each slot of a connection is
  bound to one secret. Two connections may use the same secret; the approval
  that creates the second one says so.
- **Hosts come from one place.** A catalog service declares its hosts; a
  custom connection lists its own. The agent can't change either.
- **The host is a limit, not a selector.** The broker checks the
  destination against the connection's hosts. It never picks a credential
  because of where a request is going.

## The catalog

GitHub, OpenAI, Anthropic, Gemini, Gmail, Google Drive, GCP, Supabase,
Railway, GitLab, npm, crates.io, Telegram and more are built in, each with
its hosts, the secrets it needs, OAuth where it has it, and labelled
[rules](approvals.md). `sprott registry` lists the catalog;
`sprott connection ls` lists what is connected.

Any other HTTPS API works as a custom connection. To add a service
definition of your own: [Add a service](add-a-service.md).

## Ways to connect

- **OAuth, in the console.** Pick the service on the vault's Connections tab
  and sign in. Sprott runs the flow and refreshes the token. The phantom stays
  the same across refreshes.
- **Paste a key in the console.** The value is encrypted in your browser
  before upload.
- **In a terminal.** `sprott set HF_TOKEN --host huggingface.co` prompts for
  the value and asks for one passkey approval. The value never leaves your
  machine.
- **`sprott connection add`**, which fills each slot from a new value or from
  a secret already in the vault:

  ```bash
  sprott connection add codex_work --service openai_codex \
      --from-secret OPENAI_CODEX_REFRESH_TOKEN=WORK_REFRESH_TOKEN
  sprott connection add myapi --host api.example.com --from-literal API_TOKEN=…
  ```

  With `--service`, a slot is one of the service's secret roles. For a custom
  connection it is the key itself. A service's main credential is required;
  its other roles, such as Cloudflare's account ID, are optional.

  Your agent may run this to propose a connection. Nothing is written until
  you approve. The approval lists every key the connection binds, every host
  it sends them to, and any other connection already using the same key.

`sprott connection rm <id>` deletes the secrets that connection wrote, unless
another connection uses them. A secret bound with `--from-secret` stays in
the vault. The command lists each kept key and why.

`sprott connection add-host <id> <host>` proposes a new host for a
connection, and `rm-host` proposes removing one. Both need your approval.

## Several accounts

Two accounts of one service are two connections, such as
`__sprott__github__` and `__sprott__github_work__`. How to use them:
[Use a credential](sc-run.md).

## External stores

A value can stay in a secret manager you already run. Connect it on the
vault's **Stores** tab. Sprott looks the value up when a request needs it,
and the agent still never sees it.

- **GCP Secret Manager**: paste a service account JSON and give the store a
  label. You can point it at a different GCP project.
- **Lookup order**: the vault's own secrets come first, then each store in
  the order you set.

`sprott store ls` lists the stores connected to the vault.

## Import a .env file

On the vault's **Raw secrets** tab, **Import .env** takes anything with
`KEY=VALUE` lines, pasted or dropped. The file is parsed in your browser and
never uploaded. Options cover `:` separators, comments as notes, skipping
placeholder values, and a prefix or suffix for every key.

The import fills a draft; **Encrypt & save** writes it. Imported secrets have
no hosts yet. Give each one a connection so an agent can use it.
