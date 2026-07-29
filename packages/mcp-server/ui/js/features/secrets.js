import { getState, setState } from "../state.js";
import { getActiveToken, apiGet, apiPost, apiDelete, withMutationGuard, isMutationLocked } from "../api.js";
import { showToast } from "../notifications.js";
import { escapeHtml, apiErrorMessage, extractList } from "../utils.js";
import { closeModal, openModal, promptConfirmAction } from "../dialog.js";
import { setResourceState, getResourceState } from "../state.js";
import { loadAdminStats } from "./users.js";

function renderSecretsTable(filtered, tbody) {
  if (!Array.isArray(filtered) || filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No secrets found in this environment. Click "+ Add New Secret".</td></tr>`;
    return;
  }
  tbody.innerHTML = filtered
    .map((s) => {
      const sName = escapeHtml(s.name);
      const sDisplayName = escapeHtml(s.display_name || s.name);
      const envStr = (s.environment || "development").toLowerCase();
      let envBadge = `<span class="code-tag" style="color: #3b82f6; border-color: rgba(59,130,246,0.3);">Development</span>`;
      if (envStr === "production") envBadge = `<span class="badge-admin">Production</span>`;
      if (envStr === "staging") envBadge = `<span class="code-tag" style="color: #f59e0b; border-color: rgba(245,158,11,0.3);">Staging</span>`;

      const tagsList = Array.isArray(s.tags) ? s.tags : [];
      const tagsHtml = tagsList.length > 0
        ? tagsList
            .map(
              (t) =>
                `<span class="code-tag" style="font-size: 0.68rem; padding: 0.08rem 0.35rem; color: var(--text-muted); border-color: rgba(255,255,255,0.12); margin-right: 0.2rem; margin-top: 0.2rem; display: inline-block;">${escapeHtml(t)}</span>`,
            )
            .join("")
        : "";

      return `
    <tr>
      <td>
        <div style="font-weight: 600; color: #fff;">${sDisplayName}</div>
        ${tagsHtml ? `<div style="margin-top: 0.2rem;">${tagsHtml}</div>` : ""}
      </td>
      <td>${envBadge}</td>
      <td id="secret-val-${sName}"><code class="code-tag">${escapeHtml(s.masked_preview || s.preview || "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022")}</code></td>
      <td style="color: var(--text-muted); font-size: 0.8rem;">${escapeHtml(new Date(s.created_at).toLocaleDateString())}</td>
      <td style="text-align: right;">
        <div class="btn-action-group">
          <button class="btn btn-secondary btn-sm" data-action="reveal-secret" data-secret-name="${sName}">Reveal</button>
          <button class="btn btn-secondary btn-sm" data-action="rotate-secret" data-secret-name="${sName}">Update</button>
          <button class="btn btn-danger btn-sm" data-action="delete-secret" data-secret-name="${sName}">Delete</button>
        </div>
      </td>
    </tr>
  `;
    })
    .join("");
}

export async function loadSecrets() {
  const tbody = document.getElementById("secrets-table-body");
  if (!tbody) return;
  setResourceState("secrets", { loading: true, error: null });

  const result = await apiGet("/v1/secrets", { resourceKey: "secrets" });
  if (result.error) {
    setResourceState("secrets", { loading: false, error: result.error.message });
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--accent-rose);">Failed to load secrets: ${escapeHtml(result.error.message)}</td></tr>`;
    return;
  }

  const secretsList = extractList(result.data);
  setState({ secretsList });
  setResourceState("secrets", { loading: false, error: null });

  const tagsSet = new Set();
  secretsList.forEach((s) => {
    if (Array.isArray(s.tags)) {
      s.tags.forEach((t) => { if (t && t.trim()) tagsSet.add(t.trim()); });
    }
  });
  setState({ allUniqueTags: Array.from(tagsSet).sort() });
  updateTagsUi();

  const filterSelect = document.getElementById("filter-secret-env");
  const filterEnv = filterSelect?.value || "all";
  const filtered = filterEnv === "all" ? secretsList : secretsList.filter((s) => (s.environment || "development").toLowerCase() === filterEnv);
  renderSecretsTable(filtered, tbody);
}

export function updateTagsUi() {
  const allUniqueTags = getState().allUniqueTags;
  const datalist = document.getElementById("existing-tags-datalist");
  if (datalist) {
    datalist.innerHTML = allUniqueTags.map((t) => `<option value="${escapeHtml(t)}"></option>`).join("");
  }
  const pillsContainer = document.getElementById("existing-tags-pills-container");
  if (pillsContainer) {
    if (allUniqueTags.length === 0) {
      pillsContainer.innerHTML = `<span style="font-size: 0.75rem; color: var(--text-muted);">No existing tags yet. Type to create new tags!</span>`;
    } else {
      pillsContainer.innerHTML = allUniqueTags
        .map(
          (t) =>
            `<button type="button" class="btn btn-secondary" data-action="add-tag-pill" data-tag-val="${escapeHtml(t)}" style="padding: 0.15rem 0.45rem; font-size: 0.72rem; border-radius: 12px; background: rgba(255,255,255,0.04);">+ ${escapeHtml(t)}</button>`,
        )
        .join("");
    }
  }
}

export function addTagPill(tag) {
  const input = document.getElementById("new-secret-tags");
  if (!input) return;
  const current = input.value.split(",").map((t) => t.trim()).filter(Boolean);
  if (!current.includes(tag)) {
    current.push(tag);
    input.value = current.join(", ");
  }
}

function setFormBusy(formId, busy) {
  const form = document.getElementById(formId);
  if (form) form.setAttribute("aria-busy", String(busy));
  (form?.querySelectorAll("button[type=submit]") || []).forEach((btn) => {
    btn.disabled = busy;
  });
}

export function openAddSecretModal() {
  const form = document.querySelector("#modal-create-secret form");
  if (form) form.reset();
  const nameEl = document.getElementById("new-secret-name");
  const valEl = document.getElementById("new-secret-value");
  const tagsEl = document.getElementById("new-secret-tags");
  if (nameEl) nameEl.value = "";
  if (valEl) valEl.value = "";
  if (tagsEl) tagsEl.value = "";
  openModal("modal-create-secret", { focusSelector: "#new-secret-name" });
}

export async function submitAddSecret() {
  await withMutationGuard("create-secret", async () => {
    setFormBusy("form-create-secret", true);
    const name = document.getElementById("new-secret-name").value;
    const value = document.getElementById("new-secret-value").value;
    const environment = document.getElementById("new-secret-env").value;
    const rawTags = document.getElementById("new-secret-tags")?.value || "";
    const tags = rawTags.split(",").map((t) => t.trim()).filter(Boolean);

    const result = await apiPost("/v1/secrets", { name, value, environment, tags });
    if (result.error) {
      showToast(result.error.message || "Failed to create secret", true);
      setFormBusy("form-create-secret", false);
      return;
    }

    showToast(`Secret '${result.data.display_name || result.data.name}' created successfully!`);
    const form = document.querySelector("#modal-create-secret form");
    if (form) form.reset();
    closeModal("modal-create-secret");
    loadSecrets();
    loadAdminStats();
    setFormBusy("form-create-secret", false);
  });
}

export function openRotateSecretModal(name) {
  setState({ currentRotateSecretName: name });
  document.getElementById("rotate-secret-name-label").textContent = name;
  document.getElementById("rotate-secret-value").value = "";
  openModal("modal-rotate-secret", { focusSelector: "#rotate-secret-value" });
}

export async function submitRotateSecret() {
  await withMutationGuard("rotate-secret", async () => {
    setFormBusy("form-rotate-secret", true);
    const newValue = document.getElementById("rotate-secret-value").value;
    if (!newValue) {
      showToast("Enter new secret value", true);
      setFormBusy("form-rotate-secret", false);
      return;
    }

    const result = await apiPost(`/v1/secrets/${encodeURIComponent(getState().currentRotateSecretName)}/rotate`, { new_value: newValue });
    if (result.error) {
      showToast(result.error.message || "Failed to update secret", true);
      setFormBusy("form-rotate-secret", false);
      return;
    }

    if (result.data?.rotated) {
      showToast(`Secret '${getState().currentRotateSecretName}' updated successfully!`);
      closeModal("modal-rotate-secret");
      loadSecrets();
    } else {
      showToast("Failed to update secret", true);
    }
    setFormBusy("form-rotate-secret", false);
  });
}

export function deleteSecret(name) {
  promptConfirmAction("\uD83D\uDDD1\uFE0F Delete Secret", `Are you sure you want to delete secret '${name}'? Applications attempting to proxy credentials using this secret will fail.`, "Yes, Delete Secret", async () => {
    const result = await apiDelete(`/v1/secrets/${encodeURIComponent(name)}`);
    if (result.error) {
      showToast(result.error.message || "Failed to delete secret", true);
      return;
    }
    if (result.data?.deleted) {
      showToast(`Secret '${name}' deleted successfully!`);
      loadSecrets();
      loadAdminStats();
    } else {
      showToast("Failed to delete secret", true);
    }
  });
}
