/**
 * Fake OIDC server that mimics Okta for offline local development.
 *
 * Zero external dependencies — uses only Node.js built-ins (node:crypto, node:http, node:url).
 *
 * Implements the endpoints the app's shared library expects:
 *   - GET  /oauth2/default/.well-known/openid-configuration
 *   - GET  /oauth2/default/v1/authorize
 *   - POST /oauth2/default/v1/token
 *   - GET  /oauth2/default/v1/userinfo
 *   - GET  /oauth2/default/v1/keys
 *   - POST /oauth2/default/v1/introspect
 *
 * Configure the mock user via profiles or environment variables (see README).
 *
 * Usage:
 *   node server.mjs                        # interactive profile picker
 *   node server.mjs --profile admin        # skip picker, use "admin" profile
 *   FAKE_OIDC_PROFILE=admin node server.mjs
 */

import { createSign, generateKeyPairSync, randomUUID } from 'node:crypto'
import { existsSync, openSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { basename, dirname, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { ReadStream } from 'node:tty'
import { fileURLToPath, URL } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// TTY input — open /dev/tty directly when stdin is piped (e.g. via pnpm)
// ---------------------------------------------------------------------------

let _ttyInput = null

/**
 * Get a readable TTY stream for interactive input.
 * Returns process.stdin if it's already a TTY, otherwise opens /dev/tty.
 * Returns null if no TTY is available (CI, Docker, etc.).
 */
function getTTYInput() {
  if (process.stdin.isTTY) return process.stdin
  if (_ttyInput) return _ttyInput
  try {
    const fd = openSync('/dev/tty', 'r')
    _ttyInput = new ReadStream(fd)
    return _ttyInput
  } catch {
    return null
  }
}

/** Close the /dev/tty stream if we opened one. */
function closeTTYInput() {
  if (_ttyInput) {
    _ttyInput.destroy()
    _ttyInput = null
  }
}
const PROJECT_ROOT = resolve(__dirname, '..', '..')
const PROFILES_DIR = resolve(__dirname, 'profiles')
const ENV_MOCK_PATH = resolve(__dirname, '.env.mock')
const ENV_LOCAL_PATH = resolve(PROJECT_ROOT, '.env.local')

// ---------------------------------------------------------------------------
// Profile loader
// ---------------------------------------------------------------------------

/**
 * List all available profiles from the profiles/ directory.
 */
function listProfiles() {
  if (!existsSync(PROFILES_DIR)) return []
  return readdirSync(PROFILES_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => basename(f, '.json'))
    .sort()
}

/**
 * Load a profile JSON file from the profiles/ directory.
 * Returns an empty object if the file doesn't exist (falls back to defaults).
 */
function loadProfile(name) {
  const filePath = resolve(PROFILES_DIR, `${name}.json`)
  if (!existsSync(filePath)) {
    return {}
  }
  const raw = readFileSync(filePath, 'utf8')
  return JSON.parse(raw)
}

/**
 * Resolve profile name from --profile CLI flag or FAKE_OIDC_PROFILE env var.
 * Returns null if neither is set (triggers interactive picker).
 */
function resolveProfileFromArgs() {
  const flagIndex = process.argv.indexOf('--profile')
  if (flagIndex !== -1 && process.argv[flagIndex + 1]) {
    return process.argv[flagIndex + 1]
  }
  return process.env.FAKE_OIDC_PROFILE || null
}

// ---------------------------------------------------------------------------
// Interactive profile picker (TUI)
// ---------------------------------------------------------------------------

function pickProfileInteractively(profiles) {
  return new Promise((resolvePromise) => {
    if (profiles.length === 0) {
      resolvePromise('default')
      return
    }

    const ttyInput = getTTYInput()

    // No TTY available (CI, Docker, etc.) — fall back to default
    if (!ttyInput) {
      const fallback = profiles.includes('default') ? 'default' : profiles[0]
      resolvePromise(fallback)
      return
    }

    // Load descriptions for display
    const entries = profiles.map((name) => {
      const p = loadProfile(name)
      return { name, description: p.description || '' }
    })

    let selected = entries.findIndex((e) => e.name === 'default')
    if (selected === -1) selected = 0

    const DIM = '\x1b[2m'
    const RESET = '\x1b[0m'
    const BOLD = '\x1b[1m'
    const _CYAN = '\x1b[36m'
    const GREEN = '\x1b[32m'

    function render() {
      const lines = entries.length + 4
      process.stdout.write(`\x1b[${lines}A\x1b[J`)
      draw()
    }

    function draw() {
      for (let i = 0; i < entries.length; i++) {
        const { name, description } = entries[i]
        const _marker =
          i === selected ? `${GREEN}  ❯ ${BOLD}${name}${RESET}` : `    ${DIM}${name}${RESET}`
        const _desc = description ? `  ${DIM}— ${description}${RESET}` : ''
      }
    }

    // Initial draw
    draw()

    // Enable raw mode to capture individual keypresses
    ttyInput.setRawMode(true)
    ttyInput.resume()
    ttyInput.setEncoding('utf8')

    ttyInput.on('data', (key) => {
      // Ctrl+C
      if (key === '\x03') {
        process.stdout.write('\n')
        ttyInput.setRawMode(false)
        closeTTYInput()
        process.exit(0)
      }

      // Enter
      if (key === '\r' || key === '\n') {
        ttyInput.setRawMode(false)
        ttyInput.pause()
        ttyInput.removeAllListeners('data')
        // Clear the picker and show the selection
        const lines = entries.length + 4
        process.stdout.write(`\x1b[${lines}A\x1b[J`)
        resolvePromise(entries[selected].name)
        return
      }

      // Arrow keys come as escape sequences: \x1b[A (up), \x1b[B (down)
      if (key === '\x1b[A' || key === 'k') {
        selected = selected > 0 ? selected - 1 : entries.length - 1
        render()
      } else if (key === '\x1b[B' || key === 'j') {
        selected = selected < entries.length - 1 ? selected + 1 : 0
        render()
      }
    })
  })
}

// ---------------------------------------------------------------------------
// .env.local setup
// ---------------------------------------------------------------------------

/**
 * Offer to write .env.local from .env.mock.
 * In non-TTY mode, writes automatically.
 * In TTY mode, asks the user.
 */
async function ensureEnvLocal() {
  const DIM = '\x1b[2m'
  const RESET = '\x1b[0m'
  const _GREEN = '\x1b[32m'

  const ttyInput = getTTYInput()

  // No TTY — write silently
  if (!ttyInput) {
    writeEnvLocal()
    return
  }

  // Interactive — ask
  const shouldWrite = await askYesNo(
    `Write .env.local for fake OIDC? ${DIM}(y/N)${RESET} `,
    ttyInput,
  )
  if (shouldWrite) {
    writeEnvLocal()
  }
}

function writeEnvLocal() {
  const content = existsSync(ENV_MOCK_PATH)
    ? readFileSync(ENV_MOCK_PATH, 'utf8')
    : `${['OKTA_DOMAIN=http://localhost:' + PORT, 'OKTA_CLIENT_ID=fake-client-id', 'OKTA_CLIENT_SECRET=fake-client-secret', 'ENABLE_SHARED_AUTH=false'].join('\n')}\n`
  writeFileSync(ENV_LOCAL_PATH, content)
}

function askYesNo(question, ttyInput) {
  return new Promise((res) => {
    const rl = createInterface({ input: ttyInput, output: process.stdout })
    rl.question(question, (answer) => {
      rl.close()
      res(answer.trim().toLowerCase() === 'y')
    })
  })
}

// ---------------------------------------------------------------------------
// Build mock user from profile + env var overrides
// ---------------------------------------------------------------------------

function buildMockUser(profile) {
  return {
    sub: process.env.FAKE_OIDC_SUB || profile.sub || 'mock-user-001',
    knaufId: process.env.FAKE_OIDC_KNAUF_ID || profile.knaufId || 'mock-knauf-id',
    firstName: process.env.FAKE_OIDC_FIRST_NAME || profile.firstName || 'Local',
    lastName: process.env.FAKE_OIDC_LAST_NAME || profile.lastName || 'Developer',
    email: process.env.FAKE_OIDC_EMAIL || profile.email || 'dev@localhost',
    groups: process.env.FAKE_OIDC_GROUPS
      ? process.env.FAKE_OIDC_GROUPS.split(',').map((g) => g.trim())
      : profile.groups || ['CT_UP_DE_GROUP', 'CT_UP_UK_GROUP'],
    middleName: profile.middleName || '',
    preferredLanguage: profile.preferredLanguage || 'en',
    phoneNumber: profile.phoneNumber || '',
    mobileNumber: profile.mobileNumber || '',
    countryCode: profile.countryCode || 'DE',
    aboutYou: profile.aboutYou || '',
    locale: profile.locale || 'en',
    companyName: profile.companyName || 'Local Dev Inc.',
    companyStreet: profile.companyStreet || '',
    companyCity: profile.companyCity || '',
    companyZipCode: profile.companyZipCode || '',
    companyCountryCode: profile.companyCountryCode || 'DE',
  }
}

const PORT = Number(process.env.FAKE_OIDC_PORT) || 9980
const CLIENT_ID = process.env.FAKE_OIDC_CLIENT_ID || 'fake-client-id'
const _CLIENT_SECRET = process.env.FAKE_OIDC_CLIENT_SECRET || 'fake-client-secret'
const ACCESS_TOKEN_LIFETIME_SEC = 3600 // 1 hour

// MOCK_USER is set at boot time after profile selection
let MOCK_USER = {}
let ACTIVE_PROFILE_NAME = ''

// ---------------------------------------------------------------------------
// RSA key pair for signing JWTs (generated fresh on each start — that's fine
// since this is purely for local dev)
// ---------------------------------------------------------------------------

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
})

const KID = 'fake-oidc-key-1'

/**
 * Export the public key as a JWK for the /keys endpoint.
 */
function getJwks() {
  const jwk = publicKey.export({ format: 'jwk' })
  return {
    keys: [
      {
        ...jwk,
        kid: KID,
        use: 'sig',
        alg: 'RS256',
      },
    ],
  }
}

// ---------------------------------------------------------------------------
// JWT helpers (no dependencies — just crypto)
// ---------------------------------------------------------------------------

function base64url(input) {
  const str = typeof input === 'string' ? input : JSON.stringify(input)
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

function createJwt(payload) {
  const header = { alg: 'RS256', typ: 'JWT', kid: KID }
  const segments = [base64url(header), base64url(payload)]
  const signingInput = segments.join('.')
  const sign = createSign('RSA-SHA256')
  sign.update(signingInput)
  const signature = sign
    .sign(privateKey, 'base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
  return `${signingInput}.${signature}`
}

function createAccessToken() {
  const now = Math.floor(Date.now() / 1000)
  return createJwt({
    ...MOCK_USER,
    iss: `http://localhost:${PORT}/oauth2/default`,
    aud: 'api://default',
    iat: now,
    exp: now + ACCESS_TOKEN_LIFETIME_SEC,
    cid: CLIENT_ID,
    uid: MOCK_USER.sub,
    scp: ['openid', 'email', 'profile', 'offline_access'],
  })
}

function createIdToken(nonce) {
  const now = Math.floor(Date.now() / 1000)
  return createJwt({
    sub: MOCK_USER.sub,
    email: MOCK_USER.email,
    name: `${MOCK_USER.firstName} ${MOCK_USER.lastName}`,
    preferred_username: MOCK_USER.email,
    iss: `http://localhost:${PORT}/oauth2/default`,
    aud: CLIENT_ID,
    iat: now,
    exp: now + ACCESS_TOKEN_LIFETIME_SEC,
    nonce: nonce || undefined,
  })
}

// ---------------------------------------------------------------------------
// Stored authorization codes (in-memory, keyed by code string)
// ---------------------------------------------------------------------------

const authCodes = new Map()

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

const ISSUER = () => `http://localhost:${PORT}/oauth2/default`
const BASE = '/oauth2/default'

function handleDiscovery(req, res) {
  const issuer = ISSUER()
  respond(res, 200, {
    issuer,
    authorization_endpoint: `${issuer}/v1/authorize`,
    token_endpoint: `${issuer}/v1/token`,
    userinfo_endpoint: `${issuer}/v1/userinfo`,
    jwks_uri: `${issuer}/v1/keys`,
    introspection_endpoint: `${issuer}/v1/introspect`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email', 'profile', 'offline_access'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
  })
}

function handleAuthorize(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`)
  const redirectUri = url.searchParams.get('redirect_uri')
  const state = url.searchParams.get('state')
  const nonce = url.searchParams.get('nonce')

  if (!redirectUri) {
    respond(res, 400, { error: 'missing redirect_uri' })
    return
  }

  const code = randomUUID()
  authCodes.set(code, { nonce, redirectUri, createdAt: Date.now() })

  // Redirect back to the app with the authorization code
  const target = new URL(redirectUri)
  target.searchParams.set('code', code)
  if (state) target.searchParams.set('state', state)

  res.writeHead(302, { Location: target.toString() })
  res.end()
}

async function handleToken(req, res) {
  const body = await readBody(req)
  const params = new URLSearchParams(body)
  const grantType = params.get('grant_type')

  const now = Math.floor(Date.now() / 1000)
  const accessToken = createAccessToken()
  const nonce = authCodes.get(params.get('code'))?.nonce

  if (grantType === 'authorization_code') {
    const code = params.get('code')
    if (!code || !authCodes.has(code)) {
      respond(res, 400, {
        error: 'invalid_grant',
        error_description: 'Unknown authorization code',
      })
      return
    }
    authCodes.delete(code)
  }
  // For refresh_token grant, just issue new tokens without validation

  respond(res, 200, {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_LIFETIME_SEC,
    expires_at: now + ACCESS_TOKEN_LIFETIME_SEC,
    scope: 'openid email profile offline_access',
    id_token: createIdToken(nonce),
    refresh_token: `fake-refresh-${randomUUID()}`,
  })
}

function handleUserinfo(req, res) {
  respond(res, 200, {
    sub: MOCK_USER.sub,
    email: MOCK_USER.email,
    email_verified: true,
    name: `${MOCK_USER.firstName} ${MOCK_USER.lastName}`,
    preferred_username: MOCK_USER.email,
    given_name: MOCK_USER.firstName,
    family_name: MOCK_USER.lastName,
    groups: MOCK_USER.groups,
  })
}

function handleKeys(req, res) {
  respond(res, 200, getJwks())
}

async function handleIntrospect(req, res) {
  // Always return active: true for any token — this is a dev tool
  const body = await readBody(req)
  const params = new URLSearchParams(body)
  const token = params.get('token')

  if (!token) {
    respond(res, 200, { active: false })
    return
  }

  respond(res, 200, {
    active: true,
    sub: MOCK_USER.sub,
    client_id: CLIENT_ID,
    username: MOCK_USER.email,
    token_type: 'Bearer',
    exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_LIFETIME_SEC,
    iat: Math.floor(Date.now() / 1000),
    scope: 'openid email profile offline_access',
  })
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

function respond(res, status, body) {
  const json = JSON.stringify(body, null, 2)
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': '*',
  })
  res.end(json)
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
  })
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`)
  const path = url.pathname

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': '*',
    })
    res.end()
    return
  }

  try {
    // OIDC Discovery
    if (path === `${BASE}/.well-known/openid-configuration` && req.method === 'GET') {
      return handleDiscovery(req, res)
    }

    // Authorization (browser redirect)
    if (path === `${BASE}/v1/authorize` && req.method === 'GET') {
      return handleAuthorize(req, res)
    }

    // Token exchange
    if (path === `${BASE}/v1/token` && req.method === 'POST') {
      return handleToken(req, res)
    }

    // Userinfo
    if (path === `${BASE}/v1/userinfo` && req.method === 'GET') {
      return handleUserinfo(req, res)
    }

    // JWKS
    if (path === `${BASE}/v1/keys` && req.method === 'GET') {
      return handleKeys(req, res)
    }

    // Token introspection
    if (path === `${BASE}/v1/introspect` && req.method === 'POST') {
      return handleIntrospect(req, res)
    }

    respond(res, 404, { error: 'not_found', path })
  } catch (err) {
    respond(res, 500, { error: 'internal_error', message: err.message })
  }
})

// ---------------------------------------------------------------------------
// Boot sequence — interactive picker or direct profile load
// ---------------------------------------------------------------------------

async function boot() {
  const explicitProfile = resolveProfileFromArgs()

  if (explicitProfile) {
    // Direct mode — skip the TUI
    ACTIVE_PROFILE_NAME = explicitProfile
    const profile = loadProfile(ACTIVE_PROFILE_NAME)
    MOCK_USER = buildMockUser(profile)
  } else {
    // Interactive mode — show profile picker
    const profiles = listProfiles()
    ACTIVE_PROFILE_NAME = await pickProfileInteractively(profiles)
    const profile = loadProfile(ACTIVE_PROFILE_NAME)
    MOCK_USER = buildMockUser(profile)
  }

  // Ensure .env.local is configured
  await ensureEnvLocal()

  // Done with interactive input — release /dev/tty if we opened it
  closeTTYInput()

  // Start the HTTP server
  const groupsList = MOCK_USER.groups.join(', ')
  server.listen(PORT, () => {
    // biome-ignore lint/suspicious/noConsole: CLI tool startup banner
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  Fake OIDC Provider                                        ║
║                                                            ║
║  Listening:     http://localhost:${String(PORT).padEnd(27)}║
║                                                            ║
║  Profile:       ${ACTIVE_PROFILE_NAME.padEnd(41)}║
║  Mock user:     ${(`${MOCK_USER.firstName} ${MOCK_USER.lastName}`).padEnd(41)}║
║  Email:         ${MOCK_USER.email.padEnd(41)}║
║  Groups:        ${groupsList.length > 41 ? `${groupsList.slice(0, 38)}...` : groupsList.padEnd(41)}║
╚══════════════════════════════════════════════════════════════╝
`)
  })
}

boot()
