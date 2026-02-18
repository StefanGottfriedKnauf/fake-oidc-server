# Fake OIDC Server

A lightweight server that mimics Okta's OIDC endpoints, allowing you to run the Upload Portal locally **without internet access or real Okta credentials**. Built for [Bun](https://bun.sh).

No changes to the application code are needed — you just point the existing `OKTA_*` env vars at this server.

## Prerequisites

- [Bun](https://bun.sh) v1.0+

## Quick Start

```bash
bun install                # install dependencies
bun run server.mjs         # interactive profile + target project picker
```

The TUI will ask you to:
1. Pick a **profile** (mock user identity)
2. Enter the **target project path** (where `.env.local` gets written)

Your target path is remembered between runs.

Open http://localhost:3000 and click "Log In".

## Profiles

Switch between pre-configured users via `--profile`, and specify the target project via `--target`:

```bash
bun run server.mjs --profile admin --target /path/to/your-app
```

Both flags also accept env vars: `FAKE_OIDC_PROFILE` and `FAKE_OIDC_TARGET`.

| Profile | Description |
|---|---|
| `default` | Local developer with DE + UK markets |
| `single-market` | FR-only user |
| `all-markets` | Every market + COMMON group |
| `admin` | DE + UK + COMMON group (import/publish) |
| `unauthorized` | No matching market groups |

Profiles live in `profiles/` — add your own as JSON files.

## Documentation

| Document | Description |
|---|---|
| [Initial Setup](docs/SETUP.md) | Prerequisites, environment file, starting the servers |
| [General Usage](docs/USAGE.md) | How it works, profiles, env var reference, available groups |
| [Use Cases](docs/USE_CASES.md) | Market access scenarios, permissions, user identity, session expiry |
