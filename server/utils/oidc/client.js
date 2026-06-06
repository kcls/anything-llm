const { oidcConfig, validateOidcConfig } = require("./index");

/** @type {import("openid-client").Client | null} */
let cachedClient = null;
let cachedIssuerUrl = null;

/** In-memory login transactions keyed by `state`. */
const transactions = new Map();
const TRANSACTION_TTL_MS = 1000 * 60 * 10; // 10 minutes

function pruneTransactions() {
  const now = Date.now();
  for (const [state, tx] of transactions.entries()) {
    if (tx.expiresAt < now) transactions.delete(state);
  }
}

/**
 * Lazily import openid-client so the dependency is only touched when OIDC is
 * actually used (keeps cold-start and the "disabled" path clean).
 */
function lib() {
  return require("openid-client");
}

/**
 * Build (or return cached) OIDC client via issuer discovery.
 * @returns {Promise<import("openid-client").Client>}
 */
async function getClient() {
  const config = oidcConfig();
  const { ok, missing } = validateOidcConfig();
  if (!ok)
    throw new Error(
      `OIDC is enabled but misconfigured. Missing: ${missing.join(", ")}`
    );

  // Invalidate cache if the issuer changed (e.g. env reload).
  if (cachedClient && cachedIssuerUrl === config.issuer) return cachedClient;

  const { Issuer } = lib();
  const issuer = await Issuer.discover(config.issuer);
  cachedClient = new issuer.Client({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uris: [config.redirectUri],
    response_types: ["code"],
  });
  cachedIssuerUrl = config.issuer;
  return cachedClient;
}

/**
 * Begin a login transaction: returns the authorization URL to redirect the
 * user's browser to, and stores the PKCE verifier + nonce keyed by state.
 * @returns {Promise<{authorizationUrl: string, state: string}>}
 */
async function beginLogin() {
  const config = oidcConfig();
  const client = await getClient();
  const { generators } = lib();

  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);
  const state = generators.state();
  const nonce = generators.nonce();

  pruneTransactions();
  transactions.set(state, {
    code_verifier,
    nonce,
    expiresAt: Date.now() + TRANSACTION_TTL_MS,
  });

  const authorizationUrl = client.authorizationUrl({
    scope: config.scopes,
    code_challenge,
    code_challenge_method: "S256",
    state,
    nonce,
  });

  return { authorizationUrl, state };
}

/**
 * Complete the callback: validate the code/state, exchange for tokens, and
 * return the merged ID-token + userinfo claims. The transaction is consumed
 * (deleted) regardless of outcome.
 * @param {import("express").Request} request
 * @returns {Promise<object>} normalized claims
 */
async function handleCallback(request) {
  const config = oidcConfig();
  const client = await getClient();
  const params = client.callbackParams(request);

  const state = params.state;
  const tx = state ? transactions.get(state) : null;
  if (state) transactions.delete(state); // single-use

  if (!tx || tx.expiresAt < Date.now())
    throw new Error("Login session expired or invalid. Please try again.");

  const tokenSet = await client.callback(config.redirectUri, params, {
    code_verifier: tx.code_verifier,
    state,
    nonce: tx.nonce,
  });

  // Start from ID token claims, then enrich with userinfo (groups are often
  // only present at the userinfo endpoint depending on Keycloak mapper setup).
  let claims = tokenSet.claims();
  try {
    const userinfo = await client.userinfo(tokenSet);
    claims = { ...claims, ...userinfo };
  } catch (e) {
    // Non-fatal: ID token claims may already contain everything we need.
    console.error("[OIDC] userinfo fetch failed (continuing):", e.message);
  }
  return claims;
}

/**
 * Build the RP-initiated logout URL if the provider supports it.
 * @param {string|null} postLogoutRedirectUri
 * @returns {Promise<string|null>}
 */
async function endSessionUrl(postLogoutRedirectUri = null) {
  try {
    const client = await getClient();
    if (typeof client.endSessionUrl !== "function") return null;
    return client.endSessionUrl(
      postLogoutRedirectUri
        ? { post_logout_redirect_uri: postLogoutRedirectUri }
        : {}
    );
  } catch (e) {
    console.error("[OIDC] endSessionUrl failed:", e.message);
    return null;
  }
}

/** Test/dev helper to clear caches. */
function _resetClientCache() {
  cachedClient = null;
  cachedIssuerUrl = null;
  transactions.clear();
}

module.exports = {
  getClient,
  beginLogin,
  handleCallback,
  endSessionUrl,
  _resetClientCache,
};
