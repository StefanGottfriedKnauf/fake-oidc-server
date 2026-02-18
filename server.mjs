/**
 * Fake OIDC server that mimics Okta for offline local development.
 *
 * Runs on Bun (also compatible with Node.js).
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
 *   bun run server.mjs                        # interactive profile picker
 *   bun run server.mjs --profile admin        # skip picker, use "admin" profile
 *   FAKE_OIDC_PROFILE=admin bun run server.mjs
 */

import { createSign, generateKeyPairSync, randomUUID } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { basename, dirname, resolve } from 'node:path'
import { fileURLToPath, URL } from 'node:url'
import prompts from 'prompts'

const __dirname = dirname(fileURLToPath(import.meta.url))

const PROFILES_DIR = resolve(__dirname, 'profiles')
const ENV_MOCK_PATH = resolve(__dirname, '.env.mock')
const CONFIG_PATH = resolve(__dirname, '.fake-oidc-config.json')

// Set dynamically during boot via interactive target picker or CLI flag
let TARGET_PROJECT_DIR = null

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

/**
 * Resolve target project dir from --target CLI flag or FAKE_OIDC_TARGET env var.
 * Returns null if neither is set (triggers interactive picker).
 */
function resolveTargetFromArgs() {
  const flagIndex = process.argv.indexOf('--target')
  if (flagIndex !== -1 && process.argv[flagIndex + 1]) {
    return resolve(process.argv[flagIndex + 1])
  }
  return process.env.FAKE_OIDC_TARGET ? resolve(process.env.FAKE_OIDC_TARGET) : null
}

// ---------------------------------------------------------------------------
// Persistent config (remembers last target path)
// ---------------------------------------------------------------------------

function loadConfig() {
  try {
    if (existsSync(CONFIG_PATH)) {
      return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))
    }
  } catch { /* ignore corrupt config */ }
  return {}
}

function saveConfig(config) {
  try {
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n')
  } catch { /* best effort */ }
}

// ---------------------------------------------------------------------------
// Interactive profile picker (TUI)
// ---------------------------------------------------------------------------

async function pickProfileInteractively(profiles) {
  if (profiles.length === 0) return 'default'

  const entries = profiles.map((name) => {
    const p = loadProfile(name)
    const desc = p.description ? ` — ${p.description}` : ''
    return { title: `${name}${desc}`, value: name }
  })

  const initial = entries.findIndex((e) => e.value === 'default')

  const { profile } = await prompts({
    type: 'select',
    name: 'profile',
    message: 'Select a profile',
    choices: entries,
    initial: initial === -1 ? 0 : initial,
  }, { onCancel: () => process.exit(0) })

  return profile
}

// ---------------------------------------------------------------------------
// Interactive target project picker (TUI)
// ---------------------------------------------------------------------------

/**
 * Ask the user which project directory should receive the .env.local file.
 * Shows the last-used path as a default. Validates the path exists.
 */
async function pickTargetInteractively() {
  const config = loadConfig()
  const lastTarget = config.lastTarget || undefined

  const { target } = await prompts({
    type: 'text',
    name: 'target',
    message: 'Target project directory (where .env.local will be written)',
    initial: lastTarget,
    validate: (value) => {
      if (!value) return 'Please enter a directory path'
      const resolved = resolve(value)
      if (!existsSync(resolved)) return `Directory not found: ${resolved}`
      return true
    },
  }, { onCancel: () => process.exit(0) })

  return resolve(target)
}

// ---------------------------------------------------------------------------
// .env.local setup
// ---------------------------------------------------------------------------

/**
 * Offer to write .env.local from .env.mock into the target project dir.
 * In non-interactive mode, writes automatically.
 * In interactive mode, asks the user.
 */
async function ensureEnvLocal(interactive) {
  if (!TARGET_PROJECT_DIR) return

  const envLocalPath = resolve(TARGET_PROJECT_DIR, '.env.local')

  if (!interactive) {
    writeEnvLocal(envLocalPath)
    return
  }

  const { confirm } = await prompts({
    type: 'confirm',
    name: 'confirm',
    message: `Write .env.local to ${envLocalPath}?`,
    initial: true,
  }, { onCancel: () => process.exit(0) })

  if (confirm) {
    writeEnvLocal(envLocalPath)
  }
}

function writeEnvLocal(envLocalPath) {
  const content = existsSync(ENV_MOCK_PATH)
    ? readFileSync(ENV_MOCK_PATH, 'utf8')
    : `${['OKTA_DOMAIN=http://localhost:' + PORT, 'OKTA_CLIENT_ID=fake-client-id', 'OKTA_CLIENT_SECRET=fake-client-secret', 'ENABLE_SHARED_AUTH=false'].join('\n')}\n`
  writeFileSync(envLocalPath, content)
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
  const explicitTarget = resolveTargetFromArgs()
  const interactive = !explicitProfile || !explicitTarget

  if (explicitProfile) {
    ACTIVE_PROFILE_NAME = explicitProfile
    const profile = loadProfile(ACTIVE_PROFILE_NAME)
    MOCK_USER = buildMockUser(profile)
  } else {
    const profiles = listProfiles()
    ACTIVE_PROFILE_NAME = await pickProfileInteractively(profiles)
    const profile = loadProfile(ACTIVE_PROFILE_NAME)
    MOCK_USER = buildMockUser(profile)
  }

  // Resolve target project directory
  if (explicitTarget) {
    TARGET_PROJECT_DIR = explicitTarget
  } else {
    TARGET_PROJECT_DIR = await pickTargetInteractively()
  }

  // Persist the target for next run
  if (TARGET_PROJECT_DIR) {
    const config = loadConfig()
    config.lastTarget = TARGET_PROJECT_DIR
    saveConfig(config)
  }

  // Ensure .env.local is configured in the target project
  await ensureEnvLocal(interactive)

  // Start the HTTP server
  const groupsList = MOCK_USER.groups.join(', ')
  const targetDisplay = TARGET_PROJECT_DIR || 'none (skipped)'
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
║                                                            ║
║  Target:        ${targetDisplay.length > 41 ? `${targetDisplay.slice(0, 38)}...` : targetDisplay.padEnd(41)}║
╚══════════════════════════════════════════════════════════════╝
`)
  })
}

boot()
