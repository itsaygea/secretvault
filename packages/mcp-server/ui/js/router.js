import { loadPasskeys } from "./auth.js";
import { updateDocsSnippets, renderIntegrationsPanel } from "./features/settings.js";
import { loadUsers, loadAdminStats } from "./features/users.js";
import { loadActivity } from "./features/activity.js";
import { getState } from "./state.js";
import {
  HASH_TO_TAB,
  TAB_TO_HASH,
  SETTINGS_SUBHASHES,
  tabKeyFromHash,
  settingsSubFromHash,
  buildHash,
  rotateTab,
} from "./navHelpers.js";

/**
 * Primary navigation as an accessible tablist (SV-060).
 *
 * The header nav uses the WAI-ARIA tabs pattern: a [role="tablist"] container
 * with [role="tab"] buttons that own a roving tabindex, and matching
 * [role="tabpanel"] regions. Tab selection is reflected in the URL hash so
 * that reload, back/forward, bookmarks, and support links all preserve the
 * active section (and the Settings sub-tab when present).
 *
 * Map #96 — the navbar is a clean 5 tabs (Secrets, Clients, Services,
 * Integrations, Settings). Users / Logs / 2FA / Change Password are Settings
 * sub-tabs; legacy deep links (#users, #activity, #logs) alias into Settings.
 *
 * Pure helpers (tabKeyFromHash, settingsSubFromHash, buildHash, rotateTab) live
 * in navHelpers.js so they can be unit-tested without a DOM; they are
 * re-exported here for callers.
 */

export { tabKeyFromHash, settingsSubFromHash, buildHash, rotateTab };

export function switchSettingsTab(subName, btn) {
  document.querySelectorAll(".settings-subpanel").forEach((el) => (el.style.display = "none"));
  document.querySelectorAll(".subnav-btn").forEach((el) => {
    el.classList.remove("active");
    el.setAttribute("aria-selected", "false");
    el.tabIndex = -1;
  });

  const target = document.getElementById(`setpanel-${subName}`);
  if (target) target.style.display = "block";
  if (btn) {
    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");
    btn.tabIndex = 0;
  }

  // Reflect the sub-tab in the URL so reload/back-forward preserve it.
  if (window.location.hash.replace(/^#/, "").split("/")[0] === "settings") {
    const next = `#settings/${subName}`;
    if (`#${window.location.hash.replace(/^#/, "")}` !== next) {
      history.replaceState({ tab: "settings", sub: subName }, "", next);
    }
  }

  // Load lazy content for the revealed sub-tab.
  if (subName === "security") loadPasskeys();
  if (subName === "users" && getState().currentUser?.is_admin) {
    loadUsers();
    loadAdminStats();
  }
  if (subName === "logs") loadActivity();
}

function visibleTabIds() {
  return Array.from(document.querySelectorAll(".nav-tab"))
    .filter((t) => t.offsetParent !== null || t.style.display !== "none")
    .map((t) => t.id);
}

function setRovingTabindex(activeTab) {
  document.querySelectorAll(".nav-tab").forEach((t) => {
    const isActive = t === activeTab;
    t.setAttribute("aria-selected", String(isActive));
    t.tabIndex = isActive ? 0 : -1;
    t.classList.toggle("active", isActive);
  });
}

/** Activate a tab by id, update URL hash, run panel hooks. */
function activateTab(tabId, { updateHash = true } = {}) {
  const tab = document.getElementById(tabId);
  if (!tab) return;
  if (tab.offsetParent === null && tab.style.display === "none") return; // hidden tab

  setRovingTabindex(tab);

  document.querySelectorAll(".view-panel").forEach((p) => p.classList.remove("active"));
  const target = document.getElementById(tab.dataset.target);
  if (target) target.classList.add("active");

  const hashBase = TAB_TO_HASH[tabId] || "";
  if (tab.dataset.target === "panel-settings") {
    // Map #96: Settings now hosts security/passkey, users, logs, password.
    // Passkeys load when the security sub-tab is the landing target; docs
    // snippets feed the Integrations tab and are refreshed there.
    updateDocsSnippets();
  }
  if (tab.dataset.target === "panel-integrations") {
    // SV-068: Integrations is the single home for client docs/snippets.
    updateDocsSnippets();
    renderIntegrationsPanel();
  }

  if (updateHash && hashBase) {
    const current = window.location.hash.replace(/^#/, "");
    // Preserve a settings sub-segment when staying on settings, otherwise reset.
    const seg = current.startsWith("settings/") ? current.split("/")[1] : "";
    const next = seg && hashBase === "settings" ? `#settings/${seg}` : `#${hashBase}`;
    if (`#${current}` !== next) {
      history.pushState({ tab: hashBase }, "", next);
    }
  }

  // Move focus to the panel for screen-reader users following the tab.
  if (target && target.getAttribute("role") === "tabpanel") {
    target.focus({ preventScroll: true });
  }
}

function activateByHash() {
  const tabId = tabKeyFromHash(window.location.hash);
  if (!tabId) return;
  activateTab(tabId, { updateHash: false });

  // Resolve a Settings sub-tab from either #settings/<sub> or the legacy bare
  // aliases (#users / #activity / #logs) and reveal it (Map #96).
  const sub = settingsSubFromHash(window.location.hash);
  if (sub && SETTINGS_SUBHASHES.has(sub)) {
    const btn = document.querySelector(`.subnav-btn[data-settings-tab="${sub}"]`);
    if (btn) switchSettingsTab(sub, btn);
  }
}

export function setupNavigation() {
  const tablist = document.getElementById("primary-tablist");
  if (tablist) {
    tablist.addEventListener("click", (event) => {
      const tab = event.target.closest?.(".nav-tab");
      if (!tab || !tablist.contains(tab)) return;
      activateTab(tab.id);
    });

    tablist.addEventListener("keydown", (event) => {
      const tab = event.target.closest?.(".nav-tab");
      if (!tab) return;
      const ids = visibleTabIds();
      let nextId = null;
      switch (event.key) {
        case "ArrowRight":
        case "ArrowDown":
          nextId = rotateTab(ids, tab.id, 1);
          break;
        case "ArrowLeft":
        case "ArrowUp":
          nextId = rotateTab(ids, tab.id, -1);
          break;
        case "Home":
          nextId = ids[0] || null;
          break;
        case "End":
          nextId = ids[ids.length - 1] || null;
          break;
        default:
          return;
      }
      if (nextId) {
        event.preventDefault();
        activateTab(nextId);
        const nextEl = document.getElementById(nextId);
        if (nextEl) nextEl.focus({ preventScroll: true });
      }
    });
  }

  // Back/forward navigation and reload restore the active tab from the hash.
  window.addEventListener("popstate", () => activateByHash());
  window.addEventListener("hashchange", () => activateByHash());

  // Settings sub-tablist keyboard navigation (same arrows pattern).
  const settingsTablist = document.getElementById("settings-tablist");
  if (settingsTablist) {
    settingsTablist.addEventListener("keydown", (event) => {
      const tab = event.target.closest?.(".subnav-btn");
      if (!tab) return;
      const ids = Array.from(settingsTablist.querySelectorAll(".subnav-btn"))
        .filter((t) => t.style.display !== "none")
        .map((t) => t.id);
      let nextId = null;
      switch (event.key) {
        case "ArrowRight":
        case "ArrowDown":
          nextId = rotateTab(ids, tab.id, 1);
          break;
        case "ArrowLeft":
        case "ArrowUp":
          nextId = rotateTab(ids, tab.id, -1);
          break;
        case "Home":
          nextId = ids[0] || null;
          break;
        case "End":
          nextId = ids[ids.length - 1] || null;
          break;
        default:
          return;
      }
      if (nextId) {
        event.preventDefault();
        const nextEl = document.getElementById(nextId);
        if (nextEl) {
          switchSettingsTab(nextEl.dataset.settingsTab, nextEl);
          nextEl.focus({ preventScroll: true });
        }
      }
    });
  }

  // On first load, honor any deep link; otherwise default to secrets.
  if (window.location.hash) {
    activateByHash();
  }
}

/** Programmatic activation used by callers that don't have a tab id handy. */
export function activatePanel(panelId) {
  const tab = document.querySelector(`.nav-tab[data-target="${panelId}"]`);
  if (tab) activateTab(tab.id);
}
