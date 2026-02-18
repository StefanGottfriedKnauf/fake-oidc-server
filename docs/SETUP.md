# Initial Setup

## Prerequisites

- [Bun](https://bun.sh) v1.0+

## 1. Install dependencies

```bash
bun install
```

## 2. Start the fake OIDC server

```bash
bun run server.mjs
```

The interactive TUI will prompt you to:
1. **Pick a profile** — select the mock user identity
2. **Enter the target project path** — the directory where `.env.local` will be written (e.g. `/Users/you/projects/your-app`)
3. **Confirm the write** — approve writing `.env.local` into the target

The target path is saved to `.fake-oidc-config.json` and offered as the default on the next run.

### Non-interactive mode

```bash
bun run server.mjs --profile admin --target /path/to/your-app
```

Or via environment variables:

```bash
FAKE_OIDC_PROFILE=admin FAKE_OIDC_TARGET=/path/to/your-app bun run server.mjs
```

This writes `.env.local` automatically (no prompts), overriding `OKTA_DOMAIN`, `OKTA_CLIENT_ID`, and `OKTA_CLIENT_SECRET` to point at the local fake server.

## 3. Start your app

In a separate terminal:

```bash
bun dev   # or however you start your app
```

Open http://localhost:3000 — clicking "Log In" will authenticate instantly against the fake server with no login form.
