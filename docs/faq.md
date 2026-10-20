---
description: "Short answers on what Sprott is, how it differs from secrets managers, password managers and .env files, what needs approval, setup and license."
---

# FAQ

## What is Sprott?

Sprott is a credential broker for AI agents. Your agent uses API keys, tokens
and OAuth credentials without holding them: it puts a placeholder called a
phantom, such as `__sprott__github__`, where the credential goes, and Sprott's
local proxy swaps in the real value as the request leaves your machine.
Sensitive calls wait until you approve them with your passkey. Sprott is a
command (`sprott`) and a daemon on your machine, plus a web console at
[sprott.ai](https://sprott.ai) for approvals and sealed backup.
Sprott was called SafeClaw before 2.0.

## How is it different from a secrets manager?

A secrets manager stores a value and gives it to the program that asks for it,
so that program then holds the value. Sprott does not give the value to the
agent. The agent holds only the phantom; the value is added inside the local
proxy, only on requests to the hosts that connection lists, and only when your
policy allows the call. A value can also stay in a cloud secret store Sprott
supports; Sprott fetches it when a request needs it, and the agent still never
sees it.

## How is it different from a password manager?

A password manager keeps your logins and fills them in for you. Sprott is for
the credentials your agent's commands send to APIs: API keys, tokens and OAuth.
It does not put the value anywhere the agent can read it; the value goes into the
outgoing request inside the proxy. The vault has no master password: it is
sealed under your passkey, and the same passkey approves sensitive calls.

## How is it different from keeping keys in .env files?

In a `.env` file the key sits on disk in plain text, and every process that
loads it, including your agent and anything it runs, can read it, log it or
send it anywhere. With Sprott the same variable holds a phantom, for example
`HF_TOKEN=__sprott__hf_token__`, and the command runs through `sprott run --`.
The real value stays sealed in the vault, is decrypted only in the daemon's
memory on your machine, and is sent only to that connection's own hosts.

## Does my agent ever see the key?

No. The agent works with phantoms only, in its environment, its files, its
commands and its logs. Sprott adds the real value inside the proxy, as the
request leaves for one of the connection's hosts. `sprott get` does show a
value, but it asks for your passkey every time and is meant for you at a
terminal; an agent never needs it.

## What needs my approval?

By default, a call through a connection runs without asking, so a key you add
works right away. Built-in services mark their sensitive actions, such as
sending an email or deleting a repository, to ask once for a time window or
every time. A connection you define yourself has no such rules until you add
them, and you can change any level per connection. Your passkey is also needed
to unlock a vault, approve a new machine or agent, show a value with
`sprott get`, and let a key go to a host its connection does not list yet. A
call that a `deny` rule covers is refused, with no prompt. Details:
[Approvals & policy](approvals.md).

## How do I install it?

With your agent: paste this to your coding agent.

```text
Set up Sprott for me: run `curl -fsSL https://sprott.ai/install.sh | sh` and follow what it prints. I only open links and tap my passkey; you run every command.
```

The agent runs the installer and setup and gives you each link to open.

By hand: run the installer in a terminal, then the `sprott setup` command it
prints, and follow each step until it reports `done`.

```bash
curl -fsSL https://sprott.ai/install.sh | sh
```

Either way you sign in or create an account, create a passkey, approve the
machine and the agent, and unlock the vault. Step by step:
[Quickstart](quickstart.md).

## Which platforms are supported?

The `sprott` command and daemon run on macOS (Apple Silicon and Intel) and
Linux (x86_64 and aarch64). Native Windows is in progress and not in the
standard install yet. Approvals use a passkey in your browser, and not every
passkey can encrypt a vault: [Passkey support](reference/passkey-support.md)
lists which can. Details: [Platform support](reference/platform-support.md).

## Is it open source?

The client is public: the `sprott` command, the daemon and its local proxy, the
agent skill and the service catalog are at
[github.com/sprottai/sprott](https://github.com/sprottai/sprott) under the
Functional Source License 1.1 with an Apache 2.0 future license
(FSL-1.1-ALv2). You may use, copy, change and share it for any purpose except
a Competing Use: making it available to others in a commercial product or
service that substitutes for Sprott or offers substantially similar features.
Two years after each release, that release is also available under Apache 2.0.
Until then FSL is a source-available license, not an open source license by
the OSI definition. The cloud service behind sprott.ai is not public, and
neither is the small add-on the official binary uses for shared team vaults.
