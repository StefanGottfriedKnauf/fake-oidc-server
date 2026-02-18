# Use Cases

## Single-market user

Test what a user sees when they only have access to one market (e.g. France):

```bash
bun run server.mjs --profile single-market
```

The market selector in the UI will only show FR.

## Multi-market user

Give the user access to several markets to test the market selector and switching:

```bash
bun run server.mjs --profile default
```

Or specify groups directly:

```bash
FAKE_OIDC_GROUPS="CT_UP_DE_GROUP,CT_UP_UK_GROUP,CT_UP_FR_GROUP,CT_UP_IT_GROUP" \
bun run server.mjs
```

## All markets at once

```bash
bun run server.mjs --profile all-markets
```

## Unauthorized access (no matching groups)

```bash
bun run server.mjs --profile unauthorized
```

The app calls `RequireUserSession` which triggers a 401 when no groups match.

## Import and publish permissions

Import and publish are gated by `IMPORT_GROUPS` and `PUBLISH_GROUPS` env vars in the app's `.env.local`. The app checks if the user's groups overlap with those lists.

**Allow everything** (default in `.env.mock`):
```env
IMPORT_GROUPS=*
PUBLISH_GROUPS=*
```

**Restrict to specific group** — e.g. only users in `CT_UP_COMMON_GROUP` can import/publish:
```env
IMPORT_GROUPS=CT_UP_COMMON_GROUP
PUBLISH_GROUPS=CT_UP_COMMON_GROUP
```
Then start the fake OIDC server with that group included:
```bash
FAKE_OIDC_GROUPS="CT_UP_DE_GROUP,CT_UP_COMMON_GROUP" bun run server.mjs
```

**Test with import/publish disabled** — use a group the user doesn't have:
```env
IMPORT_GROUPS=CT_UP_ADMIN_GROUP
PUBLISH_GROUPS=CT_UP_ADMIN_GROUP
```
The import and publish buttons will be hidden or disabled in the UI.

## Specific user identity

Simulate a particular person (useful for debugging user-specific issues or analytics):

```bash
bun run server.mjs --profile admin
```

Or with fully custom values:

```bash
FAKE_OIDC_FIRST_NAME=Max \
FAKE_OIDC_LAST_NAME=Mustermann \
FAKE_OIDC_EMAIL=max.mustermann@knauf.com \
FAKE_OIDC_KNAUF_ID=knauf-12345 \
FAKE_OIDC_GROUPS="CT_UP_DE_GROUP,CT_UP_AT_GROUP,CT_UP_CH_GROUP" \
bun run server.mjs
```

The navbar will show the configured name and API calls will carry this identity.

## Session expiry and token refresh

The fake server issues access tokens with a 1-hour lifetime by default. The shared library refreshes tokens automatically when they're about to expire. To test the refresh flow with a shorter window, edit `ACCESS_TOKEN_LIFETIME_SEC` in `server.mjs`:

```js
const ACCESS_TOKEN_LIFETIME_SEC = 60 // expire after 1 minute
```

The app's `SessionProvider` refetches the session every 3 minutes (`SESSION_REFETCH_INTERVAL_SEC`), which will trigger a token refresh via the `/v1/token` endpoint.
