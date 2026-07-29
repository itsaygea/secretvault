import { getState, setState } from "../state.js";
import { getActiveToken, apiGet, apiPost, apiPatch, apiDelete, withMutationGuard } from "../api.js";
import { showToast } from "../notifications.js";
import { escapeHtml, apiErrorMessage, extractList } from "../utils.js";
import { closeModal, openModal, promptConfirmAction } from "../dialog.js";
import { setResourceState } from "../state.js";
import { updateDocsSnippets } from "./settings.js";

function setFormBusy(formId, busy) {
  const form = document.getElementById(formId);
  if (form) form.setAttribute("aria-busy", String(busy));
  (form?.querySelectorAll("button[type=submit]") || []).forEach((btn) => {
    btn.disabled = busy;
  });
}

export async function loadClients() {
  const tbody = document.getElementById("clients-table-body");
  if (!tbody) return;
  setResourceState("clients", { loading: true, error: null });

  const result = await apiGet("/v1/clients", { resourceKey: "clients" });
  if (result.error) {
    setResourceState("clients", { loading: false, error: result.error.message });
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--accent-rose);">Failed to load clients: ${escapeHtml(result.error.message)}</td></tr>`;
    return;
  }

  const data = extractList(result.data);
  setState({ clientAppsList: data });
  setResourceState("clients", { loading: false, error: null });
  updateDocsSnippets();

  if (data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No client apps registered yet. Click "+ Register Client App".</td></tr>`;
    return;
  }
  tbody.innerHTML = data
    .map((c) => {
      const cId = escapeHtml(c.id);
      const cName = escapeHtml(c.app_name);
      const cPrefix = escapeHtml(c.key_prefix);
      const scopesStr = escapeHtml((c.scopes || []).join(", "));
      const lastUsed = c.last_used_at ? escapeHtml(new Date(c.last_used_at).toLocaleString()) : "Never";
      return `
    <tr>
      <td style="font-weight: 600; color: #fff;">${cName}</td>
      <td id="client-key-cell-${cId}"><code class="code-tag">${cPrefix}...</code></td>
      <td><span class="code-tag">${scopesStr}</span></td>
      <td style="color: var(--text-muted); font-size: 0.8rem;">${lastUsed}</td>
      <td style="text-align: right;">
        <div class="btn-action-group">
          <button class="btn btn-secondary btn-sm" data-action="reveal-client-key" data-client-id="${cId}" data-app-name="${cName}">Reveal</button>
          <button class="btn btn-secondary btn-sm" data-action="edit-client" data-client-id="${cId}">Edit</button>
          <button class="btn btn-secondary btn-sm" data-action="client-logs" data-client-id="${cId}" data-app-name="${cName}">Logs</button>
          <button class="btn btn-danger btn-sm" data-action="revoke-client" data-client-id="${cId}">Revoke</button>
        </div>
      </td>
    </tr>
  `;
    })
    .join("");
}

export function openCreateClientModal() {
  const form = document.getElementById("form-create-client");
  if (form) form.reset();
  const nameEl = document.getElementById("new-client-name");
  if (nameEl) nameEl.value = "";

  const checkboxes = document.querySelectorAll(".scope-checkbox");
  checkboxes.forEach((cb) => {
    cb.checked = cb.value === "proxy:*" || cb.value === "mcp:read";
  });

  document.getElementById("client-key-result").style.display = "none";
  document.getElementById("created-client-key").value = "";
  openModal("modal-create-client", { focusSelector: "#new-client-name" });
}

export async function submitCreateClient() {
  await withMutationGuard("create-client", async () => {
    setFormBusy("form-create-client", true);
    const app_name = document.getElementById("new-client-name").value;
    const scopeBoxes = document.querySelectorAll(".scope-checkbox:checked");
    const scopes = Array.from(scopeBoxes).map((b) => b.value);

    if (!app_name) {
      showToast("Enter client application name", true);
      setFormBusy("form-create-client", false);
      return;
    }

    const result = await apiPost("/v1/clients", { app_name, scopes });
    if (result.error) {
      showToast(result.error.message || "Failed to register client", true);
      setFormBusy("form-create-client", false);
      return;
    }

    document.getElementById("created-client-key").value = result.data.linking_key || result.data.key || "";
    closeModal("modal-create-client");
    document.getElementById("client-key-result").style.display = "block";
    openModal("modal-create-client", { focusSelector: "#copy-created-key" });
    loadClients();
    setFormBusy("form-create-client", false);
  });
}

export function openEditClientModal(clientId) {
  const clientApp = getState().clientAppsList.find((c) => c.id === clientId);
  if (!clientApp) return showToast("Client application not found", true);

  document.getElementById("edit-client-id").value = clientApp.id;
  document.getElementById("edit-client-name").value = clientApp.app_name;

  const currentScopes = clientApp.scopes || [];
  const editBoxes = document.querySelectorAll(".edit-scope-checkbox");
  editBoxes.forEach((cb) => {
    cb.checked = currentScopes.includes(cb.value);
  });

  openModal("modal-edit-client", { focusSelector: "#edit-client-name" });
}

export async function submitUpdateClient() {
  await withMutationGuard("update-client", async () => {
    setFormBusy("form-edit-client", true);
    const id = document.getElementById("edit-client-id").value;
    const app_name = document.getElementById("edit-client-name").value;
    const scopeBoxes = document.querySelectorAll(".edit-scope-checkbox:checked");
    const scopes = Array.from(scopeBoxes).map((b) => b.value);

    if (!app_name) {
      showToast("Enter application name", true);
      setFormBusy("form-edit-client", false);
      return;
    }

    const result = await apiPatch(`/v1/clients/${encodeURIComponent(id)}`, { app_name, scopes });
    if (result.error) {
      showToast(result.error.message || "Failed to update client", true);
      setFormBusy("form-edit-client", false);
      return;
    }

    if (result.data?.id) {
      showToast(`Client application '${result.data.app_name}' updated successfully!`);
      closeModal("modal-edit-client");
      loadClients();
    } else {
      showToast("Failed to update client", true);
    }
    setFormBusy("form-edit-client", false);
  });
}

export async function viewClientLogs(id, appName) {
  document.getElementById("client-logs-title").innerText = `Audit history for '${appName}'`;
  setResourceState("logs", { loading: true, error: null });

  const result = await apiGet(`/v1/clients/${encodeURIComponent(id)}/logs`, { resourceKey: "logs" });
  if (result.error) {
    setResourceState("logs", { loading: false, error: result.error.message });
    showToast(result.error.message || "Failed to load logs", true);
    return;
  }

  setState({ activeClientLogs: Array.isArray(result.data) ? result.data : [] });
  setResourceState("logs", { loading: false, error: null });
  const filter = document.getElementById("client-logs-outcome-filter");
  if (filter) filter.value = "all";
  renderClientLogs("all");
  openModal("modal-client-logs");
}

export function renderClientLogs(outcome) {
  const tbody = document.getElementById("client-logs-table-body");
  if (!tbody) return;
  const logs = outcome === "all" ? getState().activeClientLogs : getState().activeClientLogs.filter((log) => log.outcome === outcome);
  if (logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No matching access events recorded for this client.</td></tr>`;
    return;
  }
  tbody.innerHTML = logs
    .map(
      (l) => `
    <tr>
      <td style="color: var(--text-muted); font-size: 0.78rem;">${escapeHtml(new Date(l.created_at).toLocaleString())}</td>
      <td><span class="code-tag">${escapeHtml(l.access_type)}</span></td>
      <td><span class="code-tag">${escapeHtml(l.outcome || "unknown")}</span></td>
      <td>${escapeHtml(l.caller || "client")}</td>
      <td><code class="code-tag">${escapeHtml(l.secret_name || "N/A")}</code></td>
    </tr>
  `,
    )
    .join("");
}

export function revokeClient(id) {
  promptConfirmAction("\u26A0\uFE0F Revoke Client Key", "Are you sure you want to revoke this client linking key? Connected applications will immediately lose access.", "Yes, Revoke Key", async () => {
    const result = await apiDelete(`/v1/clients/${encodeURIComponent(id)}`);
    if (result.error) {
      showToast(result.error.message || "Failed to revoke client key", true);
      return;
    }
    if (result.data?.revoked) {
      showToast("Client linking key revoked successfully!");
      loadClients();
    } else {
      showToast("Failed to revoke client key", true);
    }
  });
}
