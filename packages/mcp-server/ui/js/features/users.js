import { getState, setState } from "../state.js";
import { getActiveToken, apiGet, apiPost, apiDelete, withMutationGuard } from "../api.js";
import { showToast } from "../notifications.js";
import { escapeHtml, apiErrorMessage, extractList } from "../utils.js";
import { closeModal, openModal, promptConfirmAction } from "../dialog.js";
import { setResourceState } from "../state.js";

function setFormBusy(formId, busy) {
  const form = document.getElementById(formId);
  if (form) form.setAttribute("aria-busy", String(busy));
  (form?.querySelectorAll("button[type=submit]") || []).forEach((btn) => {
    btn.disabled = busy;
  });
}

export async function loadUsers() {
  const tbody = document.getElementById("users-table-body");
  if (!tbody) return;
  setResourceState("users", { loading: true, error: null });

  const result = await apiGet("/v1/users", { resourceKey: "users" });
  if (result.error) {
    setResourceState("users", { loading: false, error: result.error.message });
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--accent-rose);">Failed to load users: ${escapeHtml(result.error.message)}</td></tr>`;
    return;
  }

  const data = extractList(result.data);
  setResourceState("users", { loading: false, error: null });

  if (data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">No users found.</td></tr>`;
    return;
  }
  tbody.innerHTML = data
    .map((u) => {
      const uId = escapeHtml(u.id);
      const uName = escapeHtml(u.username);
      const isCurrent = u.username === getState().currentUser?.username;
      return `
    <tr>
      <td style="font-weight: 600; color: #fff;">${uName}</td>
      <td><span class="${u.is_admin ? "badge-admin" : "badge-user"}">${u.is_admin ? "Admin" : "User"}</span></td>
      <td><span class="code-tag">${u.has_passkey ? "Registered" : "None"}</span></td>
      <td><span class="code-tag">${u.has_totp ? "Active" : "None"}</span></td>
      <td style="color: var(--text-muted); font-size: 0.8rem;">${escapeHtml(new Date(u.created_at).toLocaleDateString())}</td>
      <td style="text-align: right;">
        <div class="btn-action-group">
          <button class="btn btn-secondary btn-sm" data-action="reset-user-password" data-user-id="${uId}" data-username="${uName}">Update</button>
          <button class="btn btn-secondary btn-sm" data-action="reset-user-2fa" data-user-id="${uId}" data-username="${uName}">Reset 2FA</button>
          ${!isCurrent ? `<button class="btn btn-danger btn-sm" data-action="delete-user" data-user-id="${uId}" data-username="${uName}">Delete</button>` : ""}
        </div>
      </td>
    </tr>
  `;
    })
    .join("");
}

export async function loadAdminStats() {
  const result = await apiGet("/v1/admin/stats");
  const render = (value, available) => (available === false ? "\u2014" : value ?? 0);

  if (result.error || result.status === 503) {
    if (result.status === 503) {
      document.getElementById("stat-total-users").innerText = "\u2014";
      document.getElementById("stat-total-secrets").innerText = "\u2014";
      document.getElementById("stat-total-clients").innerText = "\u2014";
      document.getElementById("stat-total-logs").innerText = "\u2014";
      showToast("Admin statistics unavailable");
    } else {
      showToast(result.error?.message || "Failed to load stats", true);
    }
    return;
  }

  const data = result.data;
  if (data && typeof data === "object") {
    document.getElementById("stat-total-users").innerText = render(data.totalUsers, data.totalUsersAvailable);
    document.getElementById("stat-total-secrets").innerText = render(data.totalSecrets, data.totalSecretsAvailable);
    document.getElementById("stat-total-clients").innerText = render(data.totalClientApps, data.totalClientAppsAvailable);
    document.getElementById("stat-total-logs").innerText = render(data.totalLogs, data.totalLogsAvailable);
    if (data.status === "partial") {
      showToast(`Some statistics unavailable: ${(data.unavailable || []).join(", ")}`);
    }
  }
}

export function openAddUserModal() {
  openModal("modal-add-user", { focusSelector: "#new-user-username" });
}

export async function submitAddUser() {
  await withMutationGuard("add-user", async () => {
    setFormBusy("form-add-user", true);
    const username = document.getElementById("new-user-username").value;
    const password = document.getElementById("new-user-password").value;
    const is_admin = document.getElementById("new-user-is-admin").checked;

    const result = await apiPost("/v1/users", { username, password, is_admin });
    if (result.error) {
      showToast(result.error.message || "Failed to create user", true);
      setFormBusy("form-add-user", false);
      return;
    }

    if (result.data?.id) {
      showToast(`User '${result.data.username}' created successfully!`);
      closeModal("modal-add-user");
      loadUsers();
      loadAdminStats();
    } else {
      showToast("Failed to create user", true);
    }
    setFormBusy("form-add-user", false);
  });
}

export function deleteUser(userId, username) {
  promptConfirmAction("\uD83D\uDDD1\uFE0F Delete User Account", `Are you sure you want to delete user account '${username}'? This action cannot be undone.`, "Yes, Delete User", async () => {
    const result = await apiDelete(`/v1/users/${encodeURIComponent(userId)}`);
    if (result.error) {
      showToast(result.error.message || "Failed to delete user", true);
      return;
    }
    if (result.data?.deleted) {
      showToast(`User '${username}' deleted successfully!`);
      loadUsers();
      loadAdminStats();
    } else {
      showToast("Failed to delete user", true);
    }
  });
}

export function openAdminResetPassModal(userId, username) {
  setState({ activeResetUserId: userId });
  const usernameEl = document.getElementById("admin-reset-pass-username");
  if (usernameEl) usernameEl.innerText = username;
  const passEl = document.getElementById("admin-reset-pass-new");
  if (passEl) passEl.value = "";
  openModal("modal-admin-reset-pass", { focusSelector: "#admin-reset-pass-new" });
}

export async function submitAdminResetPassword() {
  await withMutationGuard("reset-password", async () => {
    setFormBusy("form-admin-reset-pass", true);
    const newPassword = document.getElementById("admin-reset-pass-new")?.value || "";
    if (!newPassword) { showToast("Enter new password", true); setFormBusy("form-admin-reset-pass", false); return; }

    const result = await apiPost(`/v1/users/${encodeURIComponent(getState().activeResetUserId)}/reset-password`, { new_password: newPassword, password: newPassword });
    if (result.error) {
      showToast(result.error.message || "Password reset failed", true);
      setFormBusy("form-admin-reset-pass", false);
      return;
    }

    if (result.data?.reset) {
      showToast("Password reset successfully!");
      closeModal("modal-admin-reset-pass");
    } else {
      showToast("Password reset failed", true);
    }
    setFormBusy("form-admin-reset-pass", false);
  });
}

export function resetUser2FA(userId, username) {
  promptConfirmAction("\uD83D\uDEE1\uFE0F Reset 2FA Credentials", `Are you sure you want to reset 2FA (Passkeys & TOTP) for user '${username}'?`, "Yes, Reset 2FA", async () => {
    const result = await apiPost(`/v1/users/${encodeURIComponent(userId)}/reset-2fa`);
    if (result.error) {
      showToast(result.error.message || "2FA reset failed", true);
      return;
    }
    if (result.data?.reset_2fa) {
      showToast(`2FA reset successfully for user '${username}'!`);
      loadUsers();
    } else {
      showToast("2FA reset failed", true);
    }
  });
}
