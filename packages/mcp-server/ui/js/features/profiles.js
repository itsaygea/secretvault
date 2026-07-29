import { getState, setState } from "../state.js";
import { getActiveToken, apiGet, apiPost, apiDelete, withMutationGuard } from "../api.js";
import { showToast } from "../notifications.js";
import { escapeHtml, apiErrorMessage, extractList } from "../utils.js";
import { closeModal, openModal, promptConfirmAction } from "../dialog.js";
import { setResourceState } from "../state.js";
import { loadSecrets } from "./secrets.js";

function setFormBusy(formId, busy) {
  const form = document.getElementById(formId);
  if (form) form.setAttribute("aria-busy", String(busy));
  (form?.querySelectorAll("button[type=submit]") || []).forEach((btn) => {
    btn.disabled = busy;
  });
}

export async function loadProfiles() {
  const tbody = document.getElementById("profiles-table-body");
  if (!tbody) return;
  setResourceState("profiles", { loading: true, error: null });

  const result = await apiGet("/v1/service-profiles", { resourceKey: "profiles" });
  if (result.error) {
    setResourceState("profiles", { loading: false, error: result.error.message });
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--accent-rose);">Failed to load profiles: ${escapeHtml(result.error.message)}</td></tr>`;
    return;
  }

  const data = extractList(result.data);
  setResourceState("profiles", { loading: false, error: null });

  if (data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No service profiles configured yet. Click "+ Create Profile".</td></tr>`;
    return;
  }
  tbody.innerHTML = data
    .map((p) => {
      const pId = escapeHtml(p.id);
      const pName = escapeHtml(p.name);
      const pTarget = escapeHtml(p.target_url);
      const pAuth = escapeHtml(p.auth_method);
      const pHeader = p.header_name ? ` (${escapeHtml(p.header_name)})` : "";
      const mappedSecret = p.user_secret_name ? `${escapeHtml(p.user_secret_name)} / ${escapeHtml(p.pass_secret_name)}` : escapeHtml(p.pass_secret_name);
      return `
    <tr>
      <td style="font-weight: 600; color: #fff;">${pName}</td>
      <td><code class="code-tag">${pTarget}</code></td>
      <td><span class="code-tag">${pAuth}${pHeader}</span></td>
      <td><code class="code-tag">${mappedSecret}</code></td>
      <td style="text-align: right;">
        <div class="btn-action-group">
          <button class="btn btn-danger btn-sm" data-action="delete-profile" data-profile-id="${pId}">Delete</button>
        </div>
      </td>

    </tr>
  `;
    })
    .join("");
}

export function openCreateProfileModal() {
  const form = document.querySelector("#modal-create-profile form");
  if (form) form.reset();
  const authMethodEl = document.getElementById("new-profile-auth-method");
  if (authMethodEl) authMethodEl.value = "bearer";
  renderProfileAuthFields("bearer");
  openModal("modal-create-profile", { focusSelector: "#modal-create-profile .form-input" });
}

export function toggleInlineUserSecret(val) {
  const newBox = document.getElementById("inline-user-secret-container");
  if (newBox) newBox.style.display = val === "__create_new__" ? "block" : "none";
}

export function toggleInlinePassSecret(val) {
  const newBox = document.getElementById("inline-pass-secret-container");
  if (newBox) newBox.style.display = val === "__create_new__" ? "block" : "none";
}

export function renderProfileAuthFields(method) {
  const container = document.getElementById("profile-auth-fields");
  if (!container) return;

  const secretOptions = getState().secretsList
    .map((s) => `<option value="${escapeHtml(s.name)}">${escapeHtml(s.display_name || s.name)}</option>`)
    .join("");
  const userSecretOptionsHtml = secretOptions
    ? `<option value="">— Select a username secret —</option>${secretOptions}<option value="__create_new__">➕ Create New Username Secret...</option>`
    : `<option value="__create_new__" selected>➕ Create New Username Secret...</option>`;
  const passSecretOptionsHtml = secretOptions
    ? `${secretOptions}<option value="__create_new__">➕ Create New Secret...</option>`
    : `<option value="__create_new__" selected>➕ Create New Secret...</option>`;

  let fieldsHtml = "";

  if (method === "basic") {
    fieldsHtml += `
      <div class="form-group">
        <label class="form-label">Basic Auth Username Secret</label>
        <select id="new-profile-user-secret-select" class="form-select" data-change-action="inline-user-secret">
          ${userSecretOptionsHtml}
        </select>
      </div>
      <div id="inline-user-secret-container" class="form-group" style="display: none; background: rgba(255,255,255,0.03); border: 1px dashed var(--card-border); padding: 0.75rem; border-radius: 8px;">
        <label class="form-label" style="color: var(--accent-cyan); font-size: 0.78rem; margin-bottom: 0.35rem;">✨ Create New Username Secret</label>
        <input type="text" id="inline-user-secret-name" class="form-input" placeholder="Secret Name (e.g. QBIT_USER)" style="margin-bottom: 0.5rem; font-size: 0.8rem;">
        <input type="text" id="inline-user-secret-value" class="form-input" placeholder="Username Value (e.g. admin)" style="font-size: 0.8rem;">
      </div>
    `;
  } else if (method === "header") {
    fieldsHtml += `
      <div class="form-group">
        <label class="form-label">Header Name (e.g. X-API-Key)</label>
        <input type="text" id="new-profile-header-name" class="form-input" required placeholder="X-API-Key">
      </div>
    `;
  } else if (method === "cookie") {
    fieldsHtml += `
      <div class="form-group">
        <label class="form-label">Cookie Name (e.g. session)</label>
        <input type="text" id="new-profile-cookie-name" class="form-input" required placeholder="session">
      </div>
    `;
  }

  const labelText = method === "basic" ? "Basic Auth Password Secret" : method === "header" ? "Header Value Secret" : method === "cookie" ? "Cookie Value Secret" : "Bearer Token Secret";
  const isPassNewDefault = !secretOptions;

  fieldsHtml += `
    <div class="form-group">
      <label class="form-label">${labelText}</label>
      <select id="new-profile-pass-secret-select" class="form-select" data-change-action="inline-pass-secret">
        ${passSecretOptionsHtml}
      </select>
    </div>
    <div id="inline-pass-secret-container" class="form-group" style="${isPassNewDefault ? "display: block;" : "display: none;"} background: rgba(255,255,255,0.03); border: 1px dashed var(--card-border); padding: 0.75rem; border-radius: 8px;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.35rem;">
        <label class="form-label" style="color: var(--accent-cyan); font-size: 0.78rem; margin: 0;">✨ Create New Secret</label>
        <button type="button" class="btn btn-secondary" data-action="random-password" data-target-id="inline-pass-secret-value" style="padding: 0.15rem 0.4rem; font-size: 0.72rem;">🎲 Random Password</button>
      </div>
      <div style="display: flex; gap: 0.3rem;">
        <input type="password" id="inline-pass-secret-value" class="form-input" placeholder="Secret Value (e.g. sk-...)" style="font-size: 0.8rem;" autocomplete="off" autocorrect="off" spellcheck="false">
        <button type="button" class="btn btn-secondary" data-action="toggle-password" data-target-id="inline-pass-secret-value" aria-label="Show password" style="padding: 0.15rem 0.4rem; font-size: 0.72rem; min-width: 38px;">Show</button>
      </div>
    </div>
  `;

  container.innerHTML = fieldsHtml;
}

export async function submitCreateProfile() {
  await withMutationGuard("create-profile", async () => {
    setFormBusy("form-create-profile", true);
    const name = document.getElementById("new-profile-service").value.trim();
    const target_url = document.getElementById("new-profile-target").value.trim();
    const auth_method = document.getElementById("new-profile-auth-method").value;
    const header_name = document.getElementById("new-profile-header-name")?.value.trim() || null;
    const cookie_name = document.getElementById("new-profile-cookie-name")?.value.trim() || null;

    const create_secrets = [];
    let user_secret_name = null;
    let pass_secret_name = "";

    if (auth_method === "basic") {
      const userSel = document.getElementById("new-profile-user-secret-select")?.value;
      if (userSel === "__create_new__") {
        const sName = document.getElementById("inline-user-secret-name")?.value.trim();
        const sVal = document.getElementById("inline-user-secret-value")?.value;
        if (!sName || !sVal) { showToast("Please enter name & value for the new username secret", true); setFormBusy("form-create-profile", false); return; }
        create_secrets.push({ name: sName, value: sVal, environment: "production" });
        user_secret_name = sName;
      } else if (userSel) {
        user_secret_name = userSel;
      }
    }

    const passSel = document.getElementById("new-profile-pass-secret-select")?.value;
    if (passSel === "__create_new__") {
      const sName = document.getElementById("inline-pass-secret-name")?.value.trim();
      const sVal = document.getElementById("inline-pass-secret-value")?.value;
      if (!sName || !sVal) { showToast("Please enter name & value for the new credential secret", true); setFormBusy("form-create-profile", false); return; }
      create_secrets.push({ name: sName, value: sVal, environment: "production" });
      pass_secret_name = sName;
    } else {
      pass_secret_name = passSel;
    }

    if (!pass_secret_name) { showToast("Please select or create a credential secret", true); setFormBusy("form-create-profile", false); return; }

    const allowed_methods_raw = document.getElementById("new-profile-allowed-methods")?.value.trim() || "";
    const allowed_paths_raw = document.getElementById("new-profile-allowed-paths")?.value.trim() || "";
    const allow_private_network = !!document.getElementById("new-profile-allow-private-network")?.checked;
    const payload = { name, target_url, auth_method, user_secret_name, pass_secret_name, header_name, cookie_name, allow_private_network };
    if (allowed_methods_raw) payload.allowed_methods = allowed_methods_raw.split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
    if (allowed_paths_raw) payload.allowed_path_prefixes = allowed_paths_raw.split(",").map((s) => s.trim()).filter(Boolean);
    if (create_secrets.length > 0) payload.create_secrets = create_secrets;

    const result = await apiPost("/v1/service-profiles", payload);
    if (result.error) {
      showToast(result.error.message || "Failed to create service profile", true);
      setFormBusy("form-create-profile", false);
      return;
    }

    if (result.data?.name) {
      const note = result.data.created_secrets && result.data.created_secrets.length ? ` (created ${result.data.created_secrets.length} secret(s))` : "";
      showToast(`Service profile '${result.data.name}' created successfully!${note}`);
      closeModal("modal-create-profile");
      loadSecrets();
      loadProfiles();
    } else {
      showToast("Failed to create service profile", true);
    }
    setFormBusy("form-create-profile", false);
  });
}

export function deleteProfile(id) {
  promptConfirmAction("\uD83D\uDDD1\uFE0F Delete Service Profile", "Are you sure you want to delete this service proxy profile?", "Yes, Delete Profile", async () => {
    const result = await apiDelete(`/v1/service-profiles/${encodeURIComponent(id)}`);
    if (result.error) {
      showToast(result.error.message || "Failed to delete profile", true);
      return;
    }
    if (result.data?.deleted) {
      showToast("Service profile deleted successfully!");
      loadProfiles();
    } else {
      showToast("Failed to delete profile", true);
    }
  });
}
