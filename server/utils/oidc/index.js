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
 *  staffGroups: string[],
 *  adminGroups: string[],
 *  managerGroups: string[],
 *  defaultRole: string,
 *  allowPatronLogin: boolean,
 *  patronGroups: string[],
 *  disableLocalLogin: boolean,
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
    staffGroups: groupListFromEnv("OIDC_STAFF_GROUPS"),
    adminGroups: groupListFromEnv("OIDC_ADMIN_GROUPS"),
    managerGroups: groupListFromEnv("OIDC_MANAGER_GROUPS"),
    defaultRole: process.env.OIDC_DEFAULT_ROLE || "default",
    allowPatronLogin: process.env.OIDC_ALLOW_PATRON_LOGIN === "true",
    patronGroups: groupListFromEnv("OIDC_PATRON_GROUPS"),
    disableLocalLogin: process.env.OIDC_DISABLE_LOCAL_LOGIN === "true",
  };
}

/**
 * Force-SSO gate. When OIDC is enabled and OIDC_DISABLE_LOCAL_LOGIN=true, local
 * credential login and self-service password changes are disabled for EVERYONE
 * (no break-glass) so SSO is the single source of truth. Recovery during an IdP
 * outage is done at the host level (set OIDC_DISABLE_LOCAL_LOGIN=false and
 * restart, or edit the DB directly via the container).
 * @returns {boolean} true if local credential use is disabled
 */
function localLoginDisabled() {
  if (!isOidcEnabled()) return false;
  return process.env.OIDC_DISABLE_LOCAL_LOGIN === "true";
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
 * If OIDC_STAFF_GROUPS is configured, a user must be in at least one staff
 * group OR an admin/manager group to be considered staff. If OIDC_STAFF_GROUPS
 * is empty, only the patron-group membership is used to gate.
 *
 * @param {string[]|string|null} groups
 * @returns {{rejected: boolean, reason: string|null}}
 */
function patronGate(groups) {
  const config = oidcConfig();
  const isPatron = hasAnyGroup(groups, config.patronGroups);

  // Staff = in a staff/admin/manager group, EXCLUDING patron groups. Patron
  // groups are intentionally removed from the staff set even if an operator
  // lists them in OIDC_STAFF_GROUPS, so patron membership never by itself
  // counts as staff for the gate.
  const patronSet = new Set(config.patronGroups);
  const staffGroups = [
    ...config.staffGroups,
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

  // If staff groups are configured, enforce that non-patron users still
  // belong to a staff/admin/manager group. This blocks accounts that are
  // in neither staff nor patron groups from silently getting access.
  if (config.staffGroups.length > 0 && !isStaff && !isPatron) {
    return {
      rejected: true,
      reason: "You are not a member of a group permitted to use this instance.",
    };
  }

  return { rejected: false, reason: null };
}

/**
 * Parse OIDC_GROUP_WORKSPACES into a map of normalized group -> workspace slugs.
 *
 * Format: comma-separated `group:slug` entries; a group may map to several
 * workspaces with `|`. Example:
 *   OIDC_GROUP_WORKSPACES=staff:general,ai-admins:admin-kb|general,patrons:patron-space
 *
 * Groups are normalized (lowercased, leading slash stripped). Workspace slugs
 * are left as-is (they must match existing workspace slugs).
 * @returns {Map<string, string[]>}
 */
function groupWorkspaceMap() {
  const raw = process.env.OIDC_GROUP_WORKSPACES;
  const map = new Map();
  if (!raw || typeof raw !== "string") return map;

  for (const entry of raw.split(",")) {
    const idx = entry.indexOf(":");
    if (idx === -1) continue;
    const group = normalizeGroup(entry.slice(0, idx));
    const slugs = entry
      .slice(idx + 1)
      .split("|")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!group || slugs.length === 0) continue;
    const existing = map.get(group) || [];
    map.set(group, [...new Set([...existing, ...slugs])]);
  }
  return map;
}

/**
 * Given a user's groups, return the de-duplicated list of workspace slugs they
 * should be auto-assigned to (union across all matching group mappings).
 * @param {string[]|string|null} groups
 * @returns {string[]}
 */
function workspaceSlugsForGroups(groups) {
  const map = groupWorkspaceMap();
  if (map.size === 0) return [];
  const userGroups = new Set(normalizeGroups(groups));
  const slugs = new Set();
  for (const [group, list] of map.entries()) {
    if (userGroups.has(group)) list.forEach((s) => slugs.add(s));
  }
  return [...slugs];
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
  localLoginDisabled,
  groupWorkspaceMap,
  workspaceSlugsForGroups,
};
