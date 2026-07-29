/**
 * Cached current-user / factor / passkey model (SV-071).
 *
 * The dashboard previously fetched `/v1/me` from both loadUserMe() and
 * loadPasskeys(), and re-fetched the whole identity/security model every time
 * the user opened Settings or its Security sub-panel. This module fetches the
 * user object and the WebAuthn credential list once per session and serves
 * them from cache until a mutation explicitly invalidates it.
 *
 * Invalidation is opt-in: after any factor/account change (TOTP enroll/disable,
 * passkey add/delete, backup-code regen, password change, key reveal step-up)
 * callers call invalidateSecurityModel() and then refreshSecurityModel() so the
 * next read sees fresh data.
 */

import { apiGet } from "./api.js";
import { getState, setState } from "./state.js";

let cached = null; // { user, passkeys, fetchedAt }
let inflight = null; // shared promise so concurrent callers don't double-fetch

/**
 * Fetch the security model (user + passkeys) in parallel and cache it.
 *
 * @param {{ force?: boolean }} [opts]  force bypasses the cache
 * @returns {Promise<{user: object|null, passkeys: Array}>}
 */
export async function fetchSecurityModel(opts = {}) {
  if (!opts.force && cached) return cached;
  if (!opts.force && inflight) return inflight;

  const promise = (async () => {
    const [meRes, passRes] = await Promise.all([
      apiGet("/v1/me"),
      apiGet("/v1/auth/webauthn/credentials"),
    ]);
    const user = meRes?.data || null;
    const passkeys = Array.isArray(passRes?.data) ? passRes.data : [];
    cached = { user, passkeys };
    return cached;
  })();

  inflight = promise;
  // Clear the shared inflight marker once settled either way, so a later call
  // after a failure can retry instead of forever awaiting a rejected promise.
  const clear = () => { if (inflight === promise) inflight = null; };
  promise.then(clear, clear);
  return promise;
}

/** Return the cached model without fetching, or null if none. */
export function getCachedSecurityModel() {
  return cached;
}

/**
 * Mark the cached model stale. The next fetchSecurityModel() call (or a
 * refreshSecurityModel()) will re-fetch. Use after any mutation that can change
 * the user's factors, passkeys, or account state.
 */
export function invalidateSecurityModel() {
  cached = null;
}

/**
 * Force-refresh the model and apply it to global state. Returns the model.
 * @returns {Promise<{user: object|null, passkeys: Array}>}
 */
export async function refreshSecurityModel() {
  const model = await fetchSecurityModel({ force: true });
  applyModelToState(model);
  return model;
}

/** Push the cached model into the shared state object. */
export function applyModelToState(model = cached) {
  if (!model) return;
  const { user, passkeys } = model;
  if (user) {
    setState({ currentUser: user });
    const factors = user.factors || {};
    const hasTotp = Boolean(user.has_totp ?? factors.totp);
    const hasPasskey =
      user.has_passkey !== undefined || factors.passkey !== undefined
        ? Boolean(user.has_passkey ?? factors.passkey)
        : passkeys.length > 0;
    setState({ currentUserHasTotp: hasTotp });
    setState({ currentUserHasPasskey: hasPasskey });
    setState({ currentBackupCodesRemaining: Number(factors.backup_codes_remaining ?? 0) });
  }
}

/** Test hook: reset all module state. */
export function __resetSecurityCache() {
  cached = null;
  inflight = null;
}

void getState;
