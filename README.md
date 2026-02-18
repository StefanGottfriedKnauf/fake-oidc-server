# Fake OIDC Server

A zero-dependency Node.js server that mimics Okta's OIDC endpoints, allowing you to run the Upload Portal locally **without internet access or real Okta credentials**.

No changes to the application code are needed — you just point the existing `OKTA_*` env vars at this server.

## Quick Start

```bash
node server.mjs          # interactive profile picker
pnpm dev                 # in a second terminal, start Next.js
```

Open http://localhost:3000 and click "Log In".

## Profiles

Switch between pre-configured users via `--profile`:

```bash
node server.mjs --profile admin
```

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
