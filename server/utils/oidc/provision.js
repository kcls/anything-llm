/**
 * OIDC user provisioning: turn validated OIDC claims into an AnythingLLM user.
 *
 * Matching strategy (PoC): the AnythingLLM `users` table has no email column,
 * so the natural key is `username`. We derive the username from the configured
 * username claim (default `preferred_username`), sanitize it to satisfy the
 * existing username regex, and match/create on that. Email is captured into the
 * user `bio` for reference only.
 */

const crypto = require("crypto");
const { User } = require("../../models/user");
const { EventLogs } = require("../../models/eventLogs");
const {
  oidcConfig,
  mapOidcGroupsToRole,
  patronGate,
  workspaceSlugsForGroups,
} = require("./index");

/**
 * Sanitize an arbitrary OIDC username claim into a value that passes
 * User.usernameRegex: ^[a-z][a-z0-9._@-]*$, 2-32 chars.
 * @param {string} raw
 * @returns {string}
 */
function sanitizeUsername(raw = "") {
  let username = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._@-]/g, "-"); // drop disallowed chars

  // Must start with a lowercase letter.
  if (!/^[a-z]/.test(username)) username = `u-${username}`;
  // Collapse any accidental empty/short result.
  username = username.slice(0, 32);
  if (username.length < 2) username = `${username}user`.slice(0, 32);
  return username;
}

/**
 * Generate a strong random password for OIDC-provisioned users. It is never
 * shown to anyone and never used for login (the user authenticates via OIDC),
 * but the schema requires a password. Guarantees upper/lower/number/symbol so
 * it satisfies any configured PASSWORD* complexity rules.
 * @returns {string}
 */
function generateUnusablePassword() {
  const rand = crypto.randomBytes(24).toString("base64url");
  return `Aa1!${rand}`;
}

/**
 * Extract normalized identity from claims.
 * @param {object} claims
 * @returns {{username: string|null, email: string|null, groups: string[]}}
 */
function extractIdentity(claims = {}) {
  const config = oidcConfig();
  const rawUsername = claims[config.usernameClaim] ?? claims.preferred_username;
  const email = claims[config.emailClaim] ?? claims.email ?? null;
  const groups = claims[config.groupsClaim] ?? claims.groups ?? [];
  return {
    username: rawUsername ? sanitizeUsername(rawUsername) : null,
    email: email ? String(email) : null,
    groups: Array.isArray(groups) ? groups : groups ? [groups] : [],
  };
}

/**
 * Resolve an OIDC login into an AnythingLLM user record.
 * Applies the patron gate, matches/creates the user, and maps the role.
 *
 * @param {object} claims - merged ID token + userinfo claims
 * @param {string} ip - request IP for event logging
 * @returns {Promise<{user: import("@prisma/client").users|null, error: string|null}>}
 */
async function provisionFromClaims(claims = {}, ip = "Unknown IP") {
  const config = oidcConfig();
  const { username, email, groups } = extractIdentity(claims);

  if (!username)
    return {
      user: null,
      error: "OIDC response did not include a usable username claim.",
    };

  // 1) Staff/patron gate.
  const gate = patronGate(groups);
  if (gate.rejected) {
    await EventLogs.logEvent("failed_login_oidc_gate_rejected", {
      ip,
      username,
      reason: gate.reason,
    });
    return { user: null, error: gate.reason };
  }

  const desiredRole = mapOidcGroupsToRole(groups);

  // 2) Match existing user by username (full record incl. role/suspended).
  let existing = await User._get({ username });

  // 3) Auto-create if allowed.
  if (!existing) {
    if (!config.autoCreateUsers) {
      await EventLogs.logEvent("failed_login_oidc_unknown_user", {
        ip,
        username,
      });
      return {
        user: null,
        error:
          "No matching account exists and automatic account creation is disabled.",
      };
    }

    const { user: created, error } = await User.create({
      username,
      password: generateUnusablePassword(),
      role: desiredRole,
      bio: email ? `OIDC: ${email}` : "",
    });
    if (error || !created)
      return { user: null, error: error || "Failed to create OIDC user." };

    await EventLogs.logEvent(
      "oidc_user_created",
      { ip, username, role: desiredRole },
      created.id
    );
    // Re-read full record (create returns filtered fields).
    existing = await User._get({ username });
  }

  if (!existing)
    return { user: null, error: "Failed to resolve OIDC user record." };

  if (existing.suspended)
    return { user: null, error: "Account suspended by admin." };

  // 4) Keep role in sync with current group membership (PoC: groups are the
  // source of truth on each login).
  if (existing.role !== desiredRole) {
    await User._update(existing.id, { role: desiredRole });
    await EventLogs.logEvent(
      "oidc_user_role_synced",
      { ip, username, from: existing.role, to: desiredRole },
      existing.id
    );
    existing.role = desiredRole;
  }

  // 5) Auto-assign workspaces based on group membership (additive-only; never
  // removes memberships). No-op unless OIDC_GROUP_WORKSPACES is configured.
  await assignWorkspacesByGroups(existing, groups, ip);

  return { user: existing, error: null };
}

/**
 * Add the user to any workspaces mapped from their groups (OIDC_GROUP_WORKSPACES).
 * Idempotent: only adds memberships that don't already exist; never removes.
 * Workspaces must already exist (matched by slug); unknown slugs are skipped.
 * @param {import("@prisma/client").users} user
 * @param {string[]|string|null} groups
 * @param {string} ip
 * @returns {Promise<void>}
 */
async function assignWorkspacesByGroups(user, groups, ip = "Unknown IP") {
  const slugs = workspaceSlugsForGroups(groups);
  if (slugs.length === 0) return;

  const { Workspace } = require("../../models/workspace");
  const { WorkspaceUser } = require("../../models/workspaceUsers");

  // Resolve slugs -> workspace ids (skip slugs that don't exist).
  const targetIds = [];
  for (const slug of slugs) {
    const workspace = await Workspace.get({ slug: String(slug) });
    if (!workspace) {
      console.error(
        `[OIDC] group->workspace: workspace slug "${slug}" not found; skipping.`
      );
      continue;
    }
    targetIds.push(workspace.id);
  }
  if (targetIds.length === 0) return;

  // Only add memberships the user does not already have (table has no unique
  // constraint, so we must dedupe ourselves to avoid duplicate rows).
  const existingMemberships = await WorkspaceUser.where({ user_id: user.id });
  const existingIds = new Set(existingMemberships.map((m) => m.workspace_id));

  for (const workspaceId of targetIds) {
    if (existingIds.has(workspaceId)) continue;
    const ok = await WorkspaceUser.create(user.id, workspaceId);
    if (ok)
      await EventLogs.logEvent(
        "oidc_workspace_assigned",
        { ip, username: user.username, workspaceId },
        user.id
      );
  }
}

module.exports = {
  provisionFromClaims,
  sanitizeUsername,
  extractIdentity,
  generateUnusablePassword,
  assignWorkspacesByGroups,
};
