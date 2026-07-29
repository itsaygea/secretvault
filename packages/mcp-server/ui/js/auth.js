import { getState, setState } from "./state.js";
import { setActiveToken, getActiveToken, apiGet, apiPost, apiDelete, apiPostStepUp, apiFetch, authHeaders } from "./api.js";
import { showToast } from "./notifications.js";
import { escapeHtml, apiErrorMessage, base64UrlToBuffer, bufferToBase64Url } from "./utils.js";
import { closeModal, openModal, openRevealModal, promptConfirmAction } from "./dialog.js";
import { clearSensitiveState } from "./sensitive.js";
import { loadSecrets } from "./features/secrets.js";
import { loadClients } from "./features/clients.js";
import { loadProfiles } from "./features/profiles.js";
import { fetchSecurityModel, applyModelToState } from "./securityCache.js";

export function showAuthCard(type) {
  document.getElementById("login-card").style.display = type === "login" ? "block" : "none";
  document.getElementById("register-card").style.display = type === "register" ? "block" : "none";
  document.getElementById("setup-card").style.display = type === "setup" ? "block" : "none";
}

export async function submitLogin() {
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;

  try {
    const res = await fetch("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (data.token) {
      setActiveToken(data.token);
      localStorage.setItem("sv_session_token", data.token);
      initDashboard();
      showToast("Signed in successfully!");
    } else {
      showToast(typeof data?.error === "string" ? data.error : (data?.error?.message || "Login failed"), true);
    }
  } catch {
    showToast("Login failed: Network or server error", true);
  }
}

export async function submitRegister() {
  const username = document.getElementById("register-username").value;
  const password = document.getElementById("register-password").value;

  try {
    const res = await fetch("/v1/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (data.id) {
      showToast(`Account '${data.username}' created! Please sign in.`);
      showAuthCard("login");
      document.getElementById("login-username").value = data.username;
      document.getElementById("login-password").value = "";
    } else {
      showToast(typeof data?.error === "string" ? data.error : (data?.error?.message || "Registration failed"), true);
    }
  } catch {
    showToast("Registration failed: Network error", true);
  }
}

export async function submitSetup() {
  const setup_code = document.getElementById("setup-code").value;
  const username = document.getElementById("setup-username").value;
  const password = document.getElementById("setup-password").value;

  try {
    const res = await fetch("/v1/auth/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ setup_code, username, password }),
    });
    const data = await res.json();
    if (data.token) {
      setActiveToken(data.token);
      localStorage.setItem("sv_session_token", data.token);
      initDashboard();
      showToast("Vault initialized successfully!");
    } else {
      showToast(typeof data?.error === "string" ? data.error : (data?.error?.message || "Setup failed"), true);
    }
  } catch {
    showToast("Setup failed: Network error", true);
  }
}

export function initDashboard() {
  document.getElementById("auth-view").style.display = "none";
  document.getElementById("app-header").style.display = "block";
  document.getElementById("dashboard-view").style.display = "block";

  loadUserMe();
  loadSecrets();
  loadClients();
  loadProfiles();
  loadPasskeys();
}

export async function loadUserMe() {
  // SV-071: the user + factor model is fetched once per session via the shared
  // security cache; loadUserMe() applies the cached model rather than issuing a
  // fresh /v1/me on every call. Force-refresh only on explicit mutation.
  let model;
  try {
    model = await fetchSecurityModel();
  } catch {
    return;
  }
  if (!model || !model.user) {
    // A missing user from /me typically means an expired session.
    if (getState().activeToken) logout();
    return;
  }
  applyModelToState(model);
  renderUserChrome(model.user);
}

/** Update the header user pill + admin-only navigation from a user object. */
function renderUserChrome(user) {
  if (!user || !user.username) return;
  const nameEl = document.getElementById("user-display-name");
  if (nameEl) nameEl.innerText = user.username;
  const roleEl = document.getElementById("user-role-badge");
  if (roleEl) {
    roleEl.innerText = user.is_admin ? "Admin" : "User";
    roleEl.className = user.is_admin ? "badge-admin" : "badge-user";
  }

  if (user.is_admin) {
    // Map #96: Users management + the open-registration toggle now live as the
    // admin-only Users sub-tab inside Settings. Show the sub-tab button and the
    // System Config card it contains.
    const subnavUsers = document.getElementById("subnav-users");
    if (subnavUsers) subnavUsers.style.display = "inline-flex";
    const sysconfigCard = document.getElementById("sysconfig-card");
    if (sysconfigCard) sysconfigCard.style.display = "";
    loadSystemSettings();
  }
}

function loadSystemSettings() {
  apiGet("/v1/settings")
    .then((result) => result.data)
    .then((data) => {
      if (data && data.open_registration_enabled !== undefined) {
        const toggle = document.getElementById("setting-open-reg-toggle");
        if (toggle) toggle.checked = data.open_registration_enabled;
      }
    });
}

export async function toggleOpenRegistration(enabled) {
  const result = await apiFetch("/v1/settings", { method: "PATCH", body: { open_registration_enabled: enabled } });
  if (result.error) {
    showToast(result.error.message || "Failed to update registration setting", true);
    return;
  }
  showToast(`Public registration ${result.data?.open_registration_enabled ? "ENABLED" : "DISABLED"}`);
}

export async function loadPasskeys(force = false) {
  // SV-071: render passkey + TOTP/factor state from the shared cached security
  // model instead of issuing separate /v1/me and webauthn requests on every
  // Settings/Security visit. Pass force=true after a factor mutation to bypass
  // the cache and re-fetch fresh data.
  const model = await fetchSecurityModel({ force });
  applyModelToState(model);
  renderPasskeyTable(model.passkeys);
  renderTotpBadge(model);
}

/** Render the WebAuthn credential table + status badge from a passkey list. */
function renderPasskeyTable(passkeys) {
  const list = Array.isArray(passkeys) ? passkeys : [];
  setState({ currentUserHasPasskey: list.length > 0 });

  const badge = document.getElementById("passkey-status-badge");
  if (badge) {
    badge.innerText = list.length > 0 ? `${list.length} Registered` : "Not Registered";
    badge.style.color = list.length > 0 ? "var(--accent-emerald)" : "var(--text-muted)";
  }

  const tbody = document.getElementById("passkey-table-body");
  if (tbody) {
    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No passkeys registered yet. Click Add Passkey above.</td></tr>`;
    } else {
      tbody.innerHTML = list
        .map(
          (p) => `
        <tr>
          <td style="font-weight: 600; color: #fff;"><span aria-hidden="true">\uD83D\uDD11</span> ${escapeHtml(p.device_name || "Passkey")}</td>
          <td style="color: var(--text-muted); font-size: 0.8rem;">${p.last_used_at ? escapeHtml(new Date(p.last_used_at).toLocaleString()) : "Never"}</td>
          <td style="text-align: right;">
            <div class="btn-action-group">
              <button class="btn btn-danger btn-sm" data-action="delete-passkey" data-passkey-id="${escapeHtml(p.id)}" data-device-name="${escapeHtml(p.device_name || "Passkey")}">Delete</button>
            </div>
          </td>

        </tr>
      `,
        )
        .join("");
    }
  }
}

/** Update the TOTP status badge + recovery-code hint from the cached model. */
function renderTotpBadge(model) {
  const user = model?.user;
  if (!user) return;
  const factors = user.factors || {};
  const hasTotp = Boolean(user.has_totp ?? factors.totp);
  setState({ currentUserHasTotp: hasTotp });
  setState({ currentBackupCodesRemaining: Number(factors.backup_codes_remaining ?? 0) });

  const totpBadge = document.getElementById("totp-status-badge");
  const btnDisable = document.getElementById("btn-disable-totp");
  const btnOpen = document.getElementById("btn-open-totp");
  const btnRegen = document.getElementById("btn-regen-backup");
  const backupStatus = document.getElementById("totp-backup-status");

  if (totpBadge) {
    totpBadge.innerText = hasTotp ? "Active" : "Not Configured";
    totpBadge.style.color = hasTotp ? "var(--accent-emerald)" : "var(--text-muted)";
  }
  if (btnDisable) btnDisable.style.display = hasTotp ? "inline-flex" : "none";
  if (btnOpen) btnOpen.innerText = hasTotp ? "Reconfigure 2FA App" : "Configure Authenticator App";
  if (btnRegen) btnRegen.style.display = hasTotp ? "inline-flex" : "none";
  if (backupStatus) {
    if (hasTotp) {
      backupStatus.style.display = "block";
      backupStatus.textContent = `Recovery codes remaining: ${getState().currentBackupCodesRemaining}. Codes are shown only once at creation or regeneration.`;
    } else {
      backupStatus.style.display = "none";
    }
  }
}
export function logout() {
  clearSensitiveState();
  localStorage.removeItem("sv_session_token");
  setState({ activeToken: "" });
  location.reload();
}

export function openStepUpChooser() {
  const s = getState();
  const passkeyEl = document.getElementById("stepup-factor-passkey");
  const totpEl = document.getElementById("stepup-factor-totp");
  const backupEl = document.getElementById("stepup-factor-backup");
  const noneEl = document.getElementById("stepup-no-factors");
  if (passkeyEl) passkeyEl.style.display = s.currentUserHasPasskey ? "block" : "none";
  if (totpEl) totpEl.style.display = s.currentUserHasTotp ? "block" : "none";
  if (backupEl) backupEl.style.display = s.currentUserHasTotp ? "block" : "none";
  if (noneEl) noneEl.style.display = !s.currentUserHasPasskey && !s.currentUserHasTotp ? "block" : "none";
  const backupInput = document.getElementById("stepup-backup-code");
  if (backupInput) backupInput.value = "";
  openModal("modal-stepup", { focusSelector: "#stepup-factor-passkey .btn-primary, #stepup-factor-totp .totp-pin-box, #stepup-no-factors" });
}

export async function registerPasskey() {
  if (!window.isSecureContext || !navigator.credentials) {
    return showToast("Passkeys require HTTPS or http://localhost (Secure Context). When accessing via HTTP IP/hostname, use Authenticator 2FA (TOTP) instead.", true);
  }

  try {
    const optRes = await apiPost("/v1/auth/webauthn/register-options");
    const options = await optRes.json();
    if (!optRes.ok || options.error) return showToast(apiErrorMessage(options, "Passkey options failed"), true);

    options.challenge = base64UrlToBuffer(options.challenge);
    options.user.id = base64UrlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((c) => ({ ...c, id: base64UrlToBuffer(c.id) }));
    }

    const credential = await navigator.credentials.create({ publicKey: options });
    const responseData = {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64Url(credential.response.attestationObject),
        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
      },
    };

    const verRes = await apiPost("/v1/auth/webauthn/register-verify", { response: responseData });
    const verData = await verRes.json();

    if (verData.verified) {
      showToast("Passkey registered successfully!");
      loadPasskeys(true);
    } else {
      showToast(apiErrorMessage(verData, "Passkey verification failed"), true);
    }
  } catch (err) {
    showToast("Passkey error: " + err.message, true);
  }
}

export async function verifyStepUpPasskey() {
  if (!window.isSecureContext || !navigator.credentials) {
    return showToast("Passkey requires HTTPS or http://localhost", true);
  }

  try {
    const optRes = await apiPost("/v1/auth/webauthn/authenticate-options");
    const options = await optRes.json();
    if (!optRes.ok || options.error) return showToast(apiErrorMessage(options, "Passkey auth options failed"), true);

    options.challenge = base64UrlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((c) => ({ ...c, id: base64UrlToBuffer(c.id) }));
    }

    const credential = await navigator.credentials.get({ publicKey: options });
    const responseData = {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
        signature: bufferToBase64Url(credential.response.signature),
        userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : undefined,
      },
    };

    const verRes = await apiPost("/v1/auth/webauthn/authenticate-verify", {
      response: responseData,
      resource: getState().pendingStepUpResource || undefined,
    });
    const verData = await verRes.json();

    if (verData.stepUpToken) {
      setState({ stepUpToken: verData.stepUpToken });
      closeModal("modal-stepup");
      showToast("Passkey verification succeeded!");
      resumePendingAfterStepUp();
    } else {
      showToast(apiErrorMessage(verData, "Passkey step-up verification failed"), true);
      openStepUpChooser();
    }
  } catch (err) {
    showToast("Passkey cancelled or failed — choose another factor", true);
    openStepUpChooser();
  }
}

export function resumePendingAfterStepUp() {
  const s = getState();
  if (s.pendingRevealSecretName) {
    const sName = s.pendingRevealSecretName;
    setState({ pendingRevealSecretName: null, pendingStepUpResource: "" });
    executeSecretReveal(sName);
  }
  if (s.pendingRevealClientId) {
    const cId = s.pendingRevealClientId;
    setState({ pendingRevealClientId: null });
    executeClientKeyReveal(cId);
  }
  if (s.pendingRegenerateClientId) {
    const cId = s.pendingRegenerateClientId;
    const cName = s.pendingRegenerateAppName;
    setState({ pendingRegenerateClientId: "", pendingRegenerateAppName: "" });
    executeRegenerateClientKey(cId, cName);
  }
}

export async function completeStepUpWithCode(code) {
  if (!code) return showToast("Enter a verification code", true);
  const result = await apiPost("/v1/auth/totp/authenticate", { code, resource: getState().pendingStepUpResource || undefined });
  if (result.error) {
    showToast(result.error.message || "Step-up verification failed", true);
    return;
  }
  if (result.data?.stepUpToken) {
    setState({ stepUpToken: result.data.stepUpToken });
    closeModal("modal-stepup");
    showToast("Step-up authentication verified!");
    resumePendingAfterStepUp();
  } else {
    showToast("Step-up verification failed", true);
  }
}

export function verifyStepUpTotp() {
  completeStepUpWithCode(document.getElementById("stepup-totp-code")?.value || "");
}

export function verifyStepUpBackup() {
  completeStepUpWithCode((document.getElementById("stepup-backup-code")?.value || "").trim());
}

export async function executeSecretReveal(name) {
  const result = await apiPostStepUp(`/v1/secrets/${encodeURIComponent(name)}/reveal`);
  if (result.error) {
    if (result.error.code === "STEP_UP_REQUIRED") {
      setState({ stepUpToken: "" });
      openStepUpChooser();
    } else {
      showToast(result.error.message || "Failed to reveal secret", true);
    }
    return;
  }
  if (result.data?.plaintext !== undefined) {
    setState({ pendingRevealSecretName: null });
    openRevealModal(`\uD83D\uDD10 Secret Value: ${name}`, `Decrypted secret value for '${name}'. Copy value to clipboard below.`, "Secret Plaintext", result.data.plaintext);
  } else {
    showToast("Failed to reveal secret", true);
  }
}

export function triggerSecretReveal(secretName) {
  setState({ pendingRevealSecretName: secretName });
  executeSecretReveal(secretName);
}

export async function executeClientKeyReveal(clientId) {
  const clientApp = getState().clientAppsList.find((c) => c.id === clientId);
  const appName = clientApp ? clientApp.app_name : "Client Application";

  const result = await apiPostStepUp(`/v1/clients/${encodeURIComponent(clientId)}/reveal`);
  if (result.error) {
    if (result.error.code === "STEP_UP_REQUIRED") {
      setState({ stepUpToken: "" });
      openStepUpChooser();
    } else {
      showToast(result.error.message || "Failed to reveal key", true);
    }
    return;
  }
  if (result.data?.linking_key !== undefined) {
    setState({ pendingRevealClientId: null });
    openRevealModal(`\uD83D\uDCBB Linking Key: ${appName}`, `Decrypted client linking key for application '${appName}'. Use the 1-click copy buttons below.`, "Linking Key (sv_...)", result.data.linking_key, true);
  } else {
    showToast("Failed to reveal key", true);
  }
}

export function triggerClientKeyReveal(clientId, appName) {
  setState({ pendingRevealClientId: clientId });
  if (getState().stepUpToken && getState().pendingStepUpResource === clientId) {
    executeClientKeyReveal(clientId);
  } else {
    setState({ stepUpToken: "", pendingStepUpResource: clientId });
    openStepUpChooser();
  }
}

export async function executeRegenerateClientKey(clientId, appName) {
  const result = await apiPostStepUp(`/v1/clients/${encodeURIComponent(clientId)}/regenerate`);
  if (result.error) {
    if (result.error.code === "STEP_UP_REQUIRED") {
      setState({ stepUpToken: "" });
      setState({ pendingRegenerateClientId: clientId, pendingRegenerateAppName: appName, pendingStepUpResource: clientId });
      openStepUpChooser();
    } else if (result.error.code === "KEY_REGENERATE_CONFLICT") {
      showToast("Key was regenerated concurrently; refresh and retry.", true);
      loadClients();
    } else {
      showToast(result.error.message || "Failed to regenerate client key", true);
    }
    return;
  }
  if (result.data?.linking_key) {
    document.getElementById("created-client-key").value = result.data.linking_key;
    closeModal("modal-create-client");
    document.getElementById("client-key-result").style.display = "block";
    openModal("modal-create-client", { focusSelector: "#copy-created-key" });
    showToast(`Linking key for '${appName}' regenerated!`);
    loadClients();
  } else {
    showToast("Failed to regenerate client key", true);
  }
}

export function regenerateClientKey(clientId, appName) {
  promptConfirmAction("\uD83D\uDD04 Regenerate Client Linking Key", `Are you sure you want to regenerate the linking key for '${appName}'? The previous key will be immediately revoked. A fresh step-up bound to this client is required.`, "Yes, Regenerate Key", () => {
    if (!getState().stepUpToken || getState().pendingStepUpResource !== clientId) {
      setState({ stepUpToken: "", pendingRegenerateClientId: clientId, pendingRegenerateAppName: appName, pendingStepUpResource: clientId });
      openStepUpChooser();
      return;
    }
    executeRegenerateClientKey(clientId, appName);
  });
}
