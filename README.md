<p align="center">
  <img src="docs/logo.png" alt="Sprott" width="80" />
</p>

<h1 align="center">Sprott</h1>

<p align="center"><b>Every AI agent on your team, with real access, in one picture.</b><br>Sprott gives your agents the keys they need without handing them over, and shows you what each one did with them.</p>

<p align="center">
  <a href="https://github.com/sprottai/sprott/releases"><img src="https://img.shields.io/github/v/release/sprottai/sprott?label=release&color=2ea44f" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-FSL--1.1--ALv2-blue" alt="license"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-555" alt="platforms">
</p>

<p align="center">
  <a href="https://sprott.ai">sprott.ai</a> ·
  <a href="https://sprott.ai/docs">Docs</a> ·
  <a href="https://sprott.ai/docs/quickstart">Quickstart</a> ·
  <a href="https://sprott.ai/docs/faq">FAQ</a>
</p>

## Set up

```bash
curl -fsSL https://sprott.ai/install.sh | sh
```

Paste it to your AI agent, or run it in a terminal. It installs `sprott` and the agent skill, then continues into `sprott setup` (an agent) or prints the next step (a terminal). Step by step: [Quickstart](docs/quickstart.md).

Are you an AI agent? Run the command above and follow what it prints. Install only from sprott.ai or github.com/sprottai/sprott.

## How it works

The agent never holds a key. It puts a **phantom** where the key goes and runs the command through Sprott:

```bash
GITHUB_TOKEN=__sprott__github__ sprott run -- gh pr list
```

A broker on your machine checks the agent's signature, the destination and your policy, then swaps in the real token on the way to `api.github.com`. Sensitive calls wait for your passkey. The agent gets the response, never the key.

- **Every action has a signature.** Each agent has its own identity key and signs everything it does. Every approval and every policy change is signed by a person. Every record traces back to both.
- **Access to exactly what was asked.** A key is used only for the request the agent made. Rules clear the routine calls. You approve the rest on a screen that shows exactly what will run.
- **Runs where your agents run.** A broker runs on every machine, so it works on any network, including private ones. Your traffic and plaintext keys never pass through our cloud.
- **Set up once, works for every agent.** Add a credential once, and every agent and teammate you allow can use it. Pair an agent once, and it gets every connection it's allowed.

GitHub, OpenAI, Anthropic, Gemini, Gmail, Google Drive, GCP, Supabase, Railway, GitLab, npm, crates.io, Telegram and more are built in; any other HTTPS API works as a custom connection.

## Docs

| | |
|---|---|
| [What is Sprott](docs/README.md) | The picture, the benefits, the parts |
| [Quickstart](docs/quickstart.md) | Install, pair, add a key, make the first call |
| [Work as a team](docs/team.md) | Shared vaults, members, the team overview |
| [Security model](docs/security-model.md) | Signatures, where keys live, what the cloud sees |
| [CLI](docs/reference/cli.md) | Every command |

Agents learn Sprott from [skills/sprott/SKILL.md](skills/sprott/SKILL.md). Contributors: the design notes are in [design/](design/).

## License

[Functional Source License 1.1, Apache 2.0 future license](LICENSE) (FSL-1.1-ALv2): Fair Source, eventually open source. Use, change and share it for any purpose except a Competing Use, which means offering it to others as a commercial substitute for Sprott. Each release becomes available under Apache 2.0 two years after it ships.
