import { getState, setState, getResourceState, setResourceState } from "../state.js";
import { getActiveToken, apiGet, apiPost, apiPatch, apiDelete, withMutationGuard } from "../api.js";
import { showToast } from "../notifications.js";
import { escapeHtml, apiErrorMessage, extractList } from "../utils.js";
import { closeModal, openModal, promptConfirmAction } from "../dialog.js";
import { updateDocsSnippets } from "./settings.js";

const CLIENT_PAGE_SIZE = 25;
const clientView = {
  cursor: null,
  nextCursor: null,
  cursorHistory: [],
  search: "",
};
let clientSearchTimer = null;

function setFormBusy(formId, busy) {
  const form = document.getElementById(formId);
  if (form) form.setAttribute("aria-busy", String(busy));
  (form?.querySelectorAll("button[type=submit]") || []).forEach((btn) => {
    btn.disabled = busy;
  });
}

function syncClientFilters() {
  const searchInput = document.getElementById("search-clients");
  if (searchInput) clientView.search = String(searchInput.value || "").trim().slice(0, 128);
}

function renderClientsPagination(itemCount) {
  const status = document.getElementById("clients-page-status");
  const previousButton = document.querySelector('[data-action="previous-clients-page"]');
  const nextButton = document.querySelector('[data-action="next-clients-page"]');
  const loading = getResourceState("clients").loading;
  const pageNumber = clientView.cursorHistory.length + 1;

  if (status) {
    if (loading) {
      status.textContent = "Loading client applications…";
    } else if (itemCount === 0) {
      status.textContent = "No matching client applications.";
    } else {
      const countLabel = `${itemCount} client application${itemCount === 1 ? "" : "s"}`;
      status.textContent = `Page ${pageNumber} · ${countLabel}${clientView.nextCursor ? " · more available" : ""}`;
    }
  }

  if (previousButton) {
    previousButton.disabled = loading || clientView.cursorHistory.length === 0;
    previousButton.setAttribute("aria-disabled", String(previousButton.disabled));
  }
  if (nextButton) {
    nextButton.disabled = loading || !clientView.nextCursor;
    nextButton.setAttribute("aria-disabled", String(nextButton.disabled));
  }
}

export async function loadClients({ reset = true, direction = "current" } = {}) {
  const tbody = document.getElementById("clients-table-body");
  if (!tbody) return;

  syncClientFilters();

  const previousView = {
    cursor: clientView.cursor,
    nextCursor: clientView.nextCursor,
    cursorHistory: [...clientView.cursorHistory],
  };

  if (reset) {
    clientView.cursor = null;
    clientView.nextCursor = null;
    clientView.cursorHistory = [];
  } else if (direction === "next" && clientView.nextCursor) {
    clientView.cursorHistory.push(clientView.cursor);
    clientView.cursor = clientView.nextCursor;
    clientView.nextCursor = null;
  } else if (direction === "previous" && clientView.cursorHistory.length > 0) {
    clientView.cursor = clientView.cursorHistory.pop();
    clientView.nextCursor = null;
  }

  setResourceState("clients", { loading: true, error: null });
  renderClientsPagination(0);

  const params = new URLSearchParams({ page_size: String(CLIENT_PAGE_SIZE) });
  if (clientView.cursor) params.set("cursor", clientView.cursor);
  if (clientView.search) params.set("search", clientView.search);
  const result = await apiGet(`/v1/clients?${params.toString()}`, { resourceKey: "clients" });
  if (result.error) {
    clientView.cursor = previousView.cursor;
    clientView.nextCursor = previousView.nextCursor;
    clientView.cursorHistory = previousView.cursorHistory;
    setResourceState("clients", { loading: false, error: result.error.message });
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--accent-rose);">Failed to load clients: ${escapeHtml(result.error.message)}</td></tr>`;
    renderClientsPagination(0);
    return;
  }

  const responsePage = result.data && typeof result.data === "object" && !Array.isArray(result.data)
    ? result.data
    : { data: result.data };
  const data = extractList(responsePage);
  clientView.nextCursor = typeof responsePage.next_cursor === "string" && responsePage.next_cursor.length > 0
    ? responsePage.next_cursor
    : null;
  setState({
    clientAppsList: data,
    clientPagination: {
      pageSize: CLIENT_PAGE_SIZE,
      page: clientView.cursorHistory.length + 1,
      hasNext: Boolean(clientView.nextCursor),
    },
  });
  setResourceState("clients", { loading: false, error: null });
  updateDocsSnippets();

  if (data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No matching client applications. Click "+ Register Client App" to create one.</td></tr>`;
    renderClientsPagination(0);
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
  renderClientsPagination(data.length);
}

export function handleClientSearchInput(value) {
  clientView.search = String(value || "").trim().slice(0, 128);
  if (clientSearchTimer) clearTimeout(clientSearchTimer);
  clientSearchTimer = setTimeout(() => {
    clientSearchTimer = null;
    void loadClients({ reset: true });
  }, 250);
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
