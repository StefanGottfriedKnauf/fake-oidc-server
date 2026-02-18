# Initial Setup

## Prerequisites

- Node.js (same version as the main project)

## 1. Copy the mock environment file

```bash
cp .env.mock /path/to/your-app/.env.local
```

This overrides `OKTA_DOMAIN`, `OKTA_CLIENT_ID`, and `OKTA_CLIENT_SECRET` to point at the local fake server. The file is gitignored so it won't affect other developers.

## 2. Start the fake OIDC server

```bash
node server.mjs
```

Or with a specific profile:

```bash
node server.mjs --profile admin
```

## 3. Start the Next.js app

In a separate terminal:

```bash
pnpm dev
```

Open http://localhost:3000 — clicking "Log In" will authenticate instantly against the fake server with no login form.
