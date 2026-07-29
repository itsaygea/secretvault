/**
 * Top-level Activity panel (SV-068).
 *
 * Promotes the account audit trail out of the per-client modal into a
 * first-class section reachable by URL (#activity). Loads the user's audit log
 * page from /v1/user/logs and renders it with an outcome filter. Rendering is
 * kept in DOM text nodes / controlled attributes to avoid injecting untrusted
 * log fields as HTML.
 */

import { apiGet } from "../api.js";
import { setState, getState, setResourceState } from "../state.js";
import { escapeHtml } from "../utils.js";

let activityLoaded = false;

function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? escapeHtml(String(ts)) : escapeHtml(d.toLocaleString());
}

function fmtOutcome(outcome) {
  const o = outcome || "unknown";
  const color = o === "success" ? "var(--accent-emerald)" : o === "denied" || o === "failed" ? "var(--accent-rose)" : "var(--text-muted)";
  return `<span style="color: ${color}; font-weight: 600;">${escapeHtml(o)}</span>`;
}

export async function loadActivity() {
  const tbody = document.getElementById("activity-table-body");
  if (!tbody) return;
  setResourceState("logs", { loading: true, error: null });
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">Loading activity…</td></tr>`;

  const result = await apiGet("/v1/user/logs", { resourceKey: "activity" });
  if (result.error) {
    setResourceState("logs", { loading: false, error: result.error.message });
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--accent-rose);">Failed to load activity: ${escapeHtml(result.error.message)}</td></tr>`;
    return;
  }
  // The endpoint may return either a bare array or a paginated { data, next } envelope.
  const rows = Array.isArray(result.data) ? result.data : Array.isArray(result.data?.logs) ? result.data.logs : Array.isArray(result.data?.data) ? result.data.data : [];
  setState({ activityRows: rows });
  activityLoaded = true;
  setResourceState("logs", { loading: false, error: null });
  renderActivity(document.getElementById("activity-outcome-filter")?.value || "all");
}

export function renderActivity(outcome = "all") {
  const tbody = document.getElementById("activity-table-body");
  if (!tbody) return;
  const rows = getState().activityRows || [];
  const filtered = outcome === "all" ? rows : rows.filter((r) => (r.outcome || "").toLowerCase() === outcome);

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">No activity${outcome !== "all" ? ` for "${escapeHtml(outcome)}"` : ""}.</td></tr>`;
    return;
  }
  tbody.innerHTML = filtered
    .map(
      (r) => `
      <tr>
        <td style="white-space: nowrap;">${fmtTime(r.created_at || r.timestamp)}</td>
        <td>${escapeHtml(r.access_type || r.action || "—")}</td>
        <td>${escapeHtml(r.secret_name || r.target || "—")}</td>
        <td>${fmtOutcome(r.outcome)}</td>
        <td>${escapeHtml(r.actor_username || r.caller || "—")}</td>
        <td><code class="code-tag">${escapeHtml((r.request_id || "").slice(0, 12))}</code></td>
      </tr>`,
    )
    .join("");
}

/** Has the activity panel been loaded at least once this session? */
export function isActivityLoaded() {
  return activityLoaded;
}
