/**
 * DOM-free navigation helpers (SV-060).
 *
 * Pure functions only — no access to window/document/localStorage — so they can
 * be unit-tested in a bare Node environment and re-used by router.js. Keeping
 * them isolated from the rest of the UI module graph (which touches the DOM at
 * import time) is what makes the deep-link/rotation logic testable.
 *
 * Map #96 — the header is a clean 5-tab navbar (Secrets, Clients, Services,
 * Integrations, Settings). Users, Logs, 2FA/Passkey and Change Password live
 * as Settings sub-tabs. Legacy deep links (#users, #activity, #logs) alias into
 * the Settings area so existing bookmarks/support links keep working.
 */

/**
 * Map URL hash segment -> primary tab id.
 *
 * Top-level tabs are the only first-class navbar entries. Alias segments
 * (users / activity / logs) resolve to the Settings tab because their content
 * now lives under Settings sub-tabs; the matching sub-tab is resolved from
 * HASH_TO_SETTINGS_SUB by the router.
 */
export const HASH_TO_TAB = {
  secrets: "tab-secrets",
  clients: "tab-clients",
  services: "tab-profiles",
  integrations: "tab-integrations",
  settings: "tab-settings",
  // Legacy deep-link aliases — content consolidated under Settings (Map #96).
  users: "tab-settings",
  activity: "tab-settings",
  logs: "tab-settings",
};

/** Reverse map: tab id -> URL hash segment (canonical segments only). */
export const TAB_TO_HASH = {
  "tab-secrets": "secrets",
  "tab-clients": "clients",
  "tab-profiles": "services",
  "tab-integrations": "integrations",
  "tab-settings": "settings",
};

/**
 * Known Settings sub-tab segments eligible for #settings/<segment> deep links.
 * The four consolidated sub-tabs (Map #96):
 *   security -> 2FA & Passkey
 *   users    -> Users (admin) + open-registration toggle
 *   logs     -> Audit trail / activity
 *   password -> Change password
 */
export const SETTINGS_SUBHASHES = new Set(["security", "users", "logs", "password"]);

/**
 * Legacy hash segments that alias to a Settings sub-tab. A bare #users /
 * #activity / #logs bookmark resolves to Settings and the named sub-tab, so
 * existing support links keep working after the consolidation.
 */
export const HASH_TO_SETTINGS_SUB = {
  users: "users",
  activity: "logs",
  logs: "logs",
};

/**
 * Determine which primary tab a URL hash refers to.
 * @param {string} hash  raw location.hash (with or without leading #)
 * @returns {string|null} tab id, or null if the hash is unknown/absent
 */
export function tabKeyFromHash(hash) {
  if (!hash) return null;
  const clean = String(hash).replace(/^#/, "").trim();
  if (!clean) return null;
  const segment = clean.split("/")[0];
  return HASH_TO_TAB[segment] || null;
}

/**
 * Resolve a Settings sub-tab from a URL hash, if any.
 *
 * Honors both explicit `#settings/<sub>` links and the legacy bare aliases
 * (`#users`, `#activity`, `#logs`) so consolidated content is reachable from
 * old bookmarks.
 * @param {string} hash  raw location.hash (with or without leading #)
 * @returns {string|null} sub-tab segment, or null
 */
export function settingsSubFromHash(hash) {
  if (!hash) return null;
  const clean = String(hash).replace(/^#/, "").trim();
  if (!clean) return null;
  const [segment, sub] = clean.split("/");
  if (segment === "settings" && sub && SETTINGS_SUBHASHES.has(sub)) return sub;
  return HASH_TO_SETTINGS_SUB[segment] || null;
}

/**
 * Build a URL hash from a tab id plus an optional sub-segment.
 * @param {string} tabId
 * @param {string} [segment]  e.g. settings sub-tab name
 * @returns {string} a hash string beginning with "#"
 */
export function buildHash(tabId, segment) {
  const base = TAB_TO_HASH[tabId];
  if (!base) return "";
  // Only the Settings tab supports a sub-segment deep link.
  if (segment && base === "settings" && SETTINGS_SUBHASHES.has(segment)) {
    return `#${base}/${segment}`;
  }
  return `#${base}`;
}

/**
 * Pick the next tab id when rotating through a (visible) tab list.
 * @param {string[]} visibleTabIds
 * @param {string} currentId
 * @param {number} delta  +1 for next, -1 for previous
 * @returns {string|null}
 */
export function rotateTab(visibleTabIds, currentId, delta) {
  if (!Array.isArray(visibleTabIds) || visibleTabIds.length === 0) return null;
  const idx = visibleTabIds.indexOf(currentId);
  if (idx === -1) return visibleTabIds[0] || null;
  const next = (idx + delta + visibleTabIds.length) % visibleTabIds.length;
  return visibleTabIds[next] || null;
}
