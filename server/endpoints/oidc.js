const { SystemSettings } = require("../models/systemSettings");
const { TemporaryAuthToken } = require("../models/temporaryAuthToken");
const { User } = require("../models/user");
const { Telemetry } = require("../models/telemetry");
const { EventLogs } = require("../models/eventLogs");
const { isOidcEnabled, oidcConfig } = require("../utils/oidc");
const {
  beginLogin,
  handleCallback,
  endSessionUrl,
} = require("../utils/oidc/client");

/**
 * Native OIDC (Keycloak) login endpoints.
 *
 * Mounted under /api/auth/oidc. Entirely inert unless OIDC_ENABLED=true AND
 * the instance is in multi-user mode (the only mode with a real users table).
 * The session handoff reuses the existing single-use temporary_auth_token
 * pattern (same as Simple SSO) so we do not introduce a second session system.
 */

const ID_TOKEN_TTL_MS = 1000 * 60 * 6; // matches TemporaryAuthToken expiry
const idTokenByTempToken = new Map();

function pruneIdTokens() {
  const now = Date.now();
  for (const [key, value] of idTokenByTempToken.entries())
    if (value.expiresAt < now) idTokenByTempToken.delete(key);
}

function stashIdToken(tempToken, idToken) {
  if (!tempToken || !idToken) return;
  pruneIdTokens();
  idTokenByTempToken.set(tempToken, {
    idToken,
    expiresAt: Date.now() + ID_TOKEN_TTL_MS,
  });
}

function takeIdToken(tempToken) {
  if (!tempToken) return null;
  const entry = idTokenByTempToken.get(tempToken);
  idTokenByTempToken.delete(tempToken); // single-use
  if (!entry || entry.expiresAt < Date.now()) return null;
  return entry.idToken;
}

/**
 * Redirect helper to the frontend OIDC handoff page (relative to this origin,
 * which serves the frontend in standard AnythingLLM deployments).
 */
function frontendRedirect(response, { token = null, error = null } = {}) {
  const params = new URLSearchParams();
  if (token) params.set("token", token);
  if (error) params.set("error", error);
  return response.redirect(`/sso/oidc?${params.toString()}`);
}

/** Guard: OIDC must be enabled and the instance in multi-user mode. */
async function ensureOidcUsable(response) {
  if (!isOidcEnabled()) {
    response.status(404).send("OIDC login is not enabled.");
    return false;
  }
  const multiUserMode = await SystemSettings.isMultiUserMode();
  if (!multiUserMode) {
    response
      .status(403)
      .send("OIDC login requires multi-user mode to be enabled.");
    return false;
  }
  return true;
}

function oidcEndpoints(app) {
  if (!app) return;

  // 1) Kick off login -> redirect the browser to Keycloak.
  app.get("/auth/oidc/login", async (request, response) => {
    try {
      if (!(await ensureOidcUsable(response))) return;
      const { authorizationUrl } = await beginLogin();
      return response.redirect(authorizationUrl);
    } catch (e) {
      console.error("[OIDC] login error:", e.message);
      return frontendRedirect(response, {
        error: "Unable to start SSO login. Please contact an administrator.",
      });
    }
  });

  // 2) Provider callback -> exchange code, provision user, hand off temp token.
  app.get("/auth/oidc/callback", async (request, response) => {
    try {
      if (!(await ensureOidcUsable(response))) return;
      const ip = request.ip || "Unknown IP";

      const { claims, idToken } = await handleCallback(request);
      const { provisionFromClaims } = require("../utils/oidc/provision");
      const { user, error } = await provisionFromClaims(claims, ip);
      if (error || !user) return frontendRedirect(response, { error });

      const { token, error: tokenError } = await TemporaryAuthToken.issue(
        user.id
      );
      if (tokenError || !token)
        return frontendRedirect(response, {
          error: "Failed to establish a session. Please try again.",
        });

      stashIdToken(token, idToken);

      await Telemetry.sendTelemetry(
        "login_event",
        { multiUserMode: true },
        user.id
      );
      await EventLogs.logEvent(
        "login_event",
        { ip, username: user.username || "Unknown user", via: "oidc" },
        user.id
      );

      return frontendRedirect(response, { token });
    } catch (e) {
      console.error("[OIDC] callback error:", e.message);
      return frontendRedirect(response, {
        error:
          "SSO login failed. Please try again or contact an administrator.",
      });
    }
  });

  // 3) Exchange the single-use temp token for a real session token.
  //    Called by the frontend /sso/oidc handoff page.
  app.get("/auth/oidc/exchange", async (request, response) => {
    try {
      if (!isOidcEnabled())
        return response
          .status(404)
          .json({ valid: false, token: null, message: "OIDC is not enabled." });

      const { token: tempAuthToken } = request.query;
      const { sessionToken, token, error } =
        await TemporaryAuthToken.validate(tempAuthToken);

      if (error) {
        await EventLogs.logEvent("failed_login_invalid_temporary_auth_token", {
          ip: request.ip || "Unknown IP",
          multiUserMode: true,
          via: "oidc",
        });
        return response.status(401).json({
          valid: false,
          token: null,
          message: `An error occurred while validating the session: ${error}`,
        });
      }

      return response.status(200).json({
        valid: true,
        user: User.filterFields(token.user),
        token: sessionToken,
        idToken: takeIdToken(tempAuthToken),
        message: null,
      });
    } catch (e) {
      console.error("[OIDC] exchange error:", e.message);
      return response
        .status(500)
        .json({ valid: false, token: null, message: "Internal error." });
    }
  });

  // 4) Optional RP-initiated logout passthrough.
  app.get("/auth/oidc/logout", async (request, response) => {
    try {
      if (!isOidcEnabled()) return response.redirect("/login");
      const config = oidcConfig();
      const postLogout =
        config.redirectUri?.replace(/\/api\/auth\/oidc\/callback$/, "/login") ||
        null;
      const idTokenHint = request.query.id_token_hint || null;
      const url = await endSessionUrl(postLogout, idTokenHint);
      return response.redirect(url || "/login");
    } catch (e) {
      console.error("[OIDC] logout error:", e.message);
      return response.redirect("/login");
    }
  });
}

module.exports = { oidcEndpoints };
