/**
 * Native OIDC (Keycloak) support.
 *
 * This module is intentionally isolated and additive. When `OIDC_ENABLED` is
 * not exactly "true", `isOidcEnabled()` returns false and every consumer
 * (routes, frontend flag, login button) short-circuits so the app behaves
 * EXACTLY as upstream AnythingLLM. This makes the feature trivial to disable
 * or remove for fork maintenance.
 */

/**
 * Whether native OIDC login is enabled for this instance.
 * @returns {boolean}
 */
function isOidcEnabled() {
  return process.env.OIDC_ENABLED === "true";
}

/**
 * Read a comma-separated env var into a normalized array of group names.
 * Empty/unset returns an empty array.
 * @param {string} key
 * @returns {string[]}
 */
function groupListFromEnv(key) {
  const raw = process.env[key];
  if (!raw || typeof raw !== "string") return [];
  return raw
    .split(",")
    .map((g) => normalizeGroup(g))
    .filter(Boolean);
}

/**
 * Normalize a single Keycloak group claim value for comparison.
 * Keycloak may emit groups as "staff", "/staff", "/parent/child", etc.
 * We lowercase, trim, and strip any leading slash so "/staff" and "staff"
 * compare equal.
 * @param {string} group
 * @returns {string}
 */
function normalizeGroup(group = "") {
  return String(group || "")
    .trim()
    .replace(/^\/+/, "")
    .toLowerCase();
}

/**
 * Normalize a list of group claims (tolerating non-array claim shapes).
 * @param {string[]|string|null} groups
 * @returns {string[]}
 */
function normalizeGroups(groups) {
  if (!groups) return [];
  const arr = Array.isArray(groups) ? groups : [groups];
  return arr.map((g) => normalizeGroup(g)).filter(Boolean);
}

/**
 * Returns true if any of the user's (already-normalizable) groups is present
 * in the target group list.
 * @param {string[]|string|null} userGroups
 * @param {string[]} targetGroups - assumed already normalized via groupListFromEnv
 * @returns {boolean}
 */
function hasAnyGroup(userGroups, targetGroups) {
  if (!Array.isArray(targetGroups) || targetGroups.length === 0) return false;
  const normalized = new Set(normalizeGroups(userGroups));
  return targetGroups.some((g) => normalized.has(g));
}

/**
 * Centralized, validated view of all OIDC_* configuration.
 * @returns {{
 *  enabled: boolean,
 *  providerName: string,
 *  issuer: string,
 *  clientId: string,
 *  clientSecret: string,
 *  redirectUri: string,
 *  scopes: string,
 *  autoCreateUsers: boolean,
 *  emailClaim: string,
 *  usernameClaim: string,
 *  groupsClaim: string,
 *  allowedGroups: string[],
 *  adminGroups: string[],
 *  managerGroups: string[],
 *  defaultRole: string,
 *  allowPatronLogin: boolean,
 *  patronGroups: string[],
 * }}
 */
function oidcConfig() {
  return {
    enabled: isOidcEnabled(),
    providerName: process.env.OIDC_PROVIDER_NAME || "SSO",
    issuer: process.env.OIDC_ISSUER || "",
    clientId: process.env.OIDC_CLIENT_ID || "",
    clientSecret: process.env.OIDC_CLIENT_SECRET || "",
    redirectUri: process.env.OIDC_REDIRECT_URI || "",
    scopes: process.env.OIDC_SCOPES || "openid email profile groups",
    autoCreateUsers: process.env.OIDC_AUTO_CREATE_USERS === "true",
    emailClaim: process.env.OIDC_EMAIL_CLAIM || "email",
    usernameClaim: process.env.OIDC_USERNAME_CLAIM || "preferred_username",
    groupsClaim: process.env.OIDC_GROUPS_CLAIM || "groups",
    allowedGroups: groupListFromEnv("OIDC_ALLOWED_GROUPS"),
    adminGroups: groupListFromEnv("OIDC_ADMIN_GROUPS"),
    managerGroups: groupListFromEnv("OIDC_MANAGER_GROUPS"),
    defaultRole: process.env.OIDC_DEFAULT_ROLE || "default",
    allowPatronLogin: process.env.OIDC_ALLOW_PATRON_LOGIN === "true",
    patronGroups: groupListFromEnv("OIDC_PATRON_GROUPS"),
    disableLocalLogin: process.env.OIDC_DISABLE_LOCAL_LOGIN === "true",
  };
}

/**
 * Force-SSO gate. When OIDC is enabled and local login is disabled, only
 * `admin` users may still authenticate / change passwords with local
 * credentials (break-glass). Everyone else must use SSO so the patron gate and
 * group -> role sync remain the single source of truth.
 * @param {string|null} role - the user's stored AnythingLLM role
 * @returns {boolean} true if local credential use should be blocked for this role
 */
function localLoginBlockedForRole(role = null) {
  if (!isOidcEnabled()) return false;
  if (process.env.OIDC_DISABLE_LOCAL_LOGIN !== "true") return false;
  return role !== "admin";
}

/**
 * Validate that the minimum config required to actually perform OIDC is set.
 * Used by routes to fail fast with a clear message instead of a cryptic
 * library error.
 * @returns {{ok: boolean, missing: string[]}}
 */
function validateOidcConfig() {
  const required = {
    OIDC_ISSUER: process.env.OIDC_ISSUER,
    OIDC_CLIENT_ID: process.env.OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET: process.env.OIDC_CLIENT_SECRET,
    OIDC_REDIRECT_URI: process.env.OIDC_REDIRECT_URI,
  };
  const missing = Object.entries(required)
    .filter(([, v]) => !v)
    .map(([k]) => k);
  return { ok: missing.length === 0, missing };
}

/**
 * Map normalized Keycloak groups to an AnythingLLM role.
 * Precedence: admin > manager > default. PoC only — no full RBAC.
 * @param {string[]|string|null} groups
 * @returns {"admin"|"manager"|"default"|string}
 */
function mapOidcGroupsToRole(groups) {
  const config = oidcConfig();
  if (hasAnyGroup(groups, config.adminGroups)) return "admin";
  if (hasAnyGroup(groups, config.managerGroups)) return "manager";
  return config.defaultRole || "default";
}

/**
 * Staff/patron gate.
 *
 * Returns whether the user should be REJECTED based on the patron policy:
 * a user is rejected when patron login is disabled AND they are a "patron-only"
 * user (in a configured patron group and NOT in any allowed staff/admin group).
 *
 * If OIDC_ALLOWED_GROUPS is configured, a user must be in at least one allowed
 * group OR an admin/manager group to be considered staff. If OIDC_ALLOWED_GROUPS
 * is empty, only the patron-group membership is used to gate.
 *
 * @param {string[]|string|null} groups
 * @returns {{rejected: boolean, reason: string|null}}
 */
function patronGate(groups) {
  const config = oidcConfig();
  const isPatron = hasAnyGroup(groups, config.patronGroups);

  // Staff = in an allowed/admin/manager group, EXCLUDING patron groups. Patron
  // groups are intentionally removed from the staff set even if an operator
  // lists them in OIDC_ALLOWED_GROUPS, so patron membership never by itself
  // counts as staff for the gate.
  const patronSet = new Set(config.patronGroups);
  const staffGroups = [
    ...config.allowedGroups,
    ...config.adminGroups,
    ...config.managerGroups,
  ].filter((g) => !patronSet.has(g));
  const isStaff = hasAnyGroup(groups, staffGroups);

  // A patron-only user is a patron who is not also staff.
  const patronOnly = isPatron && !isStaff;

  if (patronOnly && !config.allowPatronLogin) {
    return {
      rejected: true,
      reason: "Patron login is not enabled for this AnythingLLM instance.",
    };
  }

  // If allowed groups are configured, enforce that non-patron users still
  // belong to an allowed/admin/manager group. This blocks accounts that are
  // in neither staff nor patron groups from silently getting access.
  if (config.allowedGroups.length > 0 && !isStaff && !isPatron) {
    return {
      rejected: true,
      reason: "You are not a member of a group permitted to use this instance.",
    };
  }

  return { rejected: false, reason: null };
}

module.exports = {
  isOidcEnabled,
  oidcConfig,
  validateOidcConfig,
  normalizeGroup,
  normalizeGroups,
  hasAnyGroup,
  groupListFromEnv,
  mapOidcGroupsToRole,
  patronGate,
  localLoginBlockedForRole,
};
