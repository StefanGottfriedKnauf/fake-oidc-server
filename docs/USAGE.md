# General Usage

## How it works

The server implements the OIDC endpoints that NextAuth's Okta provider and the `@knauf-group/ct-shared-nextjs` shared library expect:

| Endpoint | Purpose |
|---|---|
| `GET /oauth2/default/.well-known/openid-configuration` | OIDC discovery |
| `GET /oauth2/default/v1/authorize` | Authorization (auto-approves, redirects back with code) |
| `POST /oauth2/default/v1/token` | Token exchange (returns signed JWT with mock user claims) |
| `GET /oauth2/default/v1/userinfo` | User info |
| `GET /oauth2/default/v1/keys` | JWKS (public key for JWT verification) |
| `POST /oauth2/default/v1/introspect` | Token introspection (always returns `active: true`) |

The access token is a real RS256-signed JWT containing user claims in the same format the shared library expects (`knaufId`, `firstName`, `lastName`, `email`, `groups`, etc.). A new RSA key pair is generated each time the server starts.

## Configuring the mock user

The easiest way is to use a **profile** — a JSON file in `profiles/`:

```bash
bun run server.mjs --profile single-market
```

Or set the `FAKE_OIDC_PROFILE` env var:

```bash
FAKE_OIDC_PROFILE=admin bun run server.mjs
```

### Built-in profiles

| Profile | Description |
|---|---|
| `default` | Local developer with DE + UK markets |
| `single-market` | FR-only user (Marie Dupont) |
| `all-markets` | Every market + COMMON group |
| `admin` | DE + UK + COMMON group (Max Mustermann) |
| `unauthorized` | No matching market groups |

### Creating custom profiles

Add a JSON file to `profiles/`:

```json
{
  "description": "QA tester for Italian market",
  "firstName": "Giulia",
  "lastName": "Rossi",
  "email": "giulia.rossi@knauf.com",
  "knaufId": "knauf-qa-it",
  "groups": ["CT_UP_IT_GROUP", "CT_UP_COMMON_GROUP"]
}
```

Then use it: `bun run server.mjs --profile <filename-without-extension>`

### Env var overrides

Environment variables always take precedence over profile values:

```bash
FAKE_OIDC_FIRST_NAME=Jane \
FAKE_OIDC_LAST_NAME=Doe \
FAKE_OIDC_EMAIL=jane@example.com \
FAKE_OIDC_GROUPS="CT_UP_DE_GROUP,CT_UP_FR_GROUP,CT_UP_IT_GROUP" \
bun run server.mjs
```

## Environment variable reference

| Variable | Default | Description |
|---|---|---|
| `FAKE_OIDC_PORT` | `9980` | Port the server listens on |
| `FAKE_OIDC_CLIENT_ID` | `fake-client-id` | Must match `OKTA_CLIENT_ID` in `.env.local` |
| `FAKE_OIDC_CLIENT_SECRET` | `fake-client-secret` | Must match `OKTA_CLIENT_SECRET` in `.env.local` |
| `FAKE_OIDC_FIRST_NAME` | `Local` | User's first name |
| `FAKE_OIDC_LAST_NAME` | `Developer` | User's last name |
| `FAKE_OIDC_EMAIL` | `dev@localhost` | User's email |
| `FAKE_OIDC_KNAUF_ID` | `mock-knauf-id` | Knauf ID claim |
| `FAKE_OIDC_GROUPS` | `CT_UP_DE_GROUP,CT_UP_UK_GROUP` | Comma-separated group memberships (controls market access) |
| `FAKE_OIDC_PROFILE` | `default` | Profile name to load from `profiles/` directory |
| `FAKE_OIDC_TARGET` | — | Target project directory for `.env.local` |

## Available groups

See `MARKETS_MAPPED_WITH_GROUPS` in `src/utilities/constant.ts` for the full list. Common ones:

| Group | Market |
|---|---|
| `CT_UP_DE_GROUP` | DE (Germany) |
| `CT_UP_UK_GROUP` | UK |
| `CT_UP_FR_GROUP` | FR (France) |
| `CT_UP_AT_GROUP` | AT (Austria) |
| `CT_UP_IT_GROUP` | IT (Italy) |
| `CT_UP_ES_GROUP` | ES (Spain) |
| `CT_UP_PL_GROUP` | PL (Poland) |
| `CT_UP_CH_GROUP` | CH (Switzerland) |
| `CT_UP_COMMON_GROUP` | (not a market — used for import/publish permission checks) |

## Switching users without restarting the app

Stop the fake OIDC server (Ctrl+C), restart it with a different profile or env vars, then log out and back in within the app. No need to restart the dev server.

```bash
# was running with default, switch to admin
bun run server.mjs --profile admin
```

## Verifying the JWT contents

Inspect exactly what claims the app sees by decoding the access token:

```bash
curl -s -X POST http://localhost:9980/oauth2/default/v1/token \
  -d "grant_type=refresh_token&refresh_token=x" \
  | python3 -c "
import sys, json, base64
token = json.load(sys.stdin)['access_token']
payload = token.split('.')[1] + '=='
print(json.dumps(json.loads(base64.b64decode(payload)), indent=2))
"
```
