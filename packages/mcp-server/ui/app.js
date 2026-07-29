import { showAuthCard, submitLogin, submitRegister, submitSetup, initDashboard, loadUserMe, logout, registerPasskey, verifyStepUpPasskey, verifyStepUpTotp, verifyStepUpBackup, triggerSecretReveal, triggerClientKeyReveal, regenerateClientKey, loadPasskeys, openStepUpChooser, toggleOpenRegistration } from "./js/auth.js";
import { updateDocsSnippets, openTotpSetupModal, cancelTotpSetup, verifyTotpSetup, copyBackupCodes, downloadBackupCodes, printBackupCodes, acknowledgeBackupCodes, regenerateBackupCodes, disableTotp, deletePasskey, submitChangePassword } from "./js/features/settings.js";
import { openAddSecretModal, submitAddSecret, openRotateSecretModal, submitRotateSecret, deleteSecret, addTagPill, loadSecrets } from "./js/features/secrets.js";
import { openCreateClientModal, submitCreateClient, openEditClientModal, submitUpdateClient, viewClientLogs, renderClientLogs, revokeClient, loadClients } from "./js/features/clients.js";
import { openCreateProfileModal, renderProfileAuthFields, toggleInlineUserSecret, toggleInlinePassSecret, submitCreateProfile, deleteProfile, loadProfiles } from "./js/features/profiles.js";
import { loadActivity, renderActivity } from "./js/features/activity.js";
import { loadUsers, loadAdminStats, openAddUserModal, submitAddUser, deleteUser, openAdminResetPassModal, submitAdminResetPassword, resetUser2FA } from "./js/features/users.js";
import { switchSettingsTab, setupNavigation } from "./js/router.js";
import { closeModal, setupDialogKeyboard } from "./js/dialog.js";
import { showToast } from "./js/notifications.js";
import { setActiveToken, getActiveToken } from "./js/api.js";
import { getState } from "./js/state.js";
import { copySnippetText, copySnippet, copyMcpCliConfig, copyMcpJsonConfig, copySdkConfig, generateRandomPassword, togglePasswordVisibility } from "./js/utils.js";
import { setupSensitiveCleanup } from "./js/sensitive.js";
import { setupAccessibility } from "./js/a11y.js";
import { checkPublicSettings } from "./js/boot.js";

window.addEventListener("DOMContentLoaded", () => {
  fetch("/v1/auth/status")
    .then((r) => r.json())
    .then((data) => {
      const isInitialized = data.initialized !== undefined ? data.initialized : data.is_setup;
      if (!isInitialized) {
        showAuthCard("setup");
      } else if (getActiveToken()) {
        initDashboard();
      } else {
        checkPublicSettings();
      }
    })
    .catch(() => {
      if (getActiveToken()) initDashboard();
    });
});

setupNavigation();
setupSensitiveCleanup();
setupDialogKeyboard();
setupAccessibility();

document.addEventListener("click", (event) => {
  const target = event.target.closest?.("[data-action]");
  if (!target) return;
  const action = target.dataset.action;
  switch (action) {
    case "logout": logout(); break;
    case "show-auth": event.preventDefault(); showAuthCard(target.dataset.authCard); break;
    case "skip-to-content": {
      event.preventDefault();
      const main = document.getElementById("dashboard-view") || document.getElementById("auth-view");
      if (main) {
        main.setAttribute("tabindex", "-1");
        main.focus({ preventScroll: false });
      }
      break;
    }
    case "open-create-secret": openAddSecretModal(); break;
    case "open-create-client": openCreateClientModal(); break;
    case "open-create-profile": openCreateProfileModal(); break;
    case "reload-activity": loadActivity(); break;
    case "switch-settings": switchSettingsTab(target.dataset.settingsTab, target); break;
    case "copy-snippet": copySnippet(target.dataset.snippetId); break;
    case "register-passkey": registerPasskey(); break;
    case "open-totp": openTotpSetupModal(); break;
    case "open-add-user": openAddUserModal(); break;
    case "verify-stepup-passkey": verifyStepUpPasskey(); break;
    case "verify-stepup-totp": verifyStepUpTotp(); break;
    case "verify-stepup-backup": verifyStepUpBackup(); break;
    case "verify-totp-setup": verifyTotpSetup(); break;
    case "cancel-totp-setup": cancelTotpSetup(); break;
    case "copy-backup-codes": copyBackupCodes(); break;
    case "download-backup-codes": downloadBackupCodes(); break;
    case "print-backup-codes": printBackupCodes(); break;
    case "ack-backup-codes": acknowledgeBackupCodes(); break;
    case "regen-backup-codes": regenerateBackupCodes(); break;
    case "random-password": generateRandomPassword(target.dataset.targetId); break;
    case "toggle-password": togglePasswordVisibility(target); break;
    case "close-modal": closeModal(target.dataset.modalId); break;
    case "copy-created-key": copySnippetText(document.getElementById("created-client-key")?.value || "", "Linking key copied!"); break;
    case "copy-created-mcp-cli": copyMcpCliConfig(document.getElementById("created-client-key")?.value || ""); break;
    case "copy-created-antigravity": copyMcpJsonConfig(document.getElementById("created-client-key")?.value || ""); break;
    case "copy-created-mcp-json": copyMcpJsonConfig(document.getElementById("created-client-key")?.value || ""); break;
    case "copy-created-sdk": copySdkConfig(document.getElementById("created-client-key")?.value || ""); break;
    case "copy-revealed-value": copySnippetText(document.getElementById("reveal-modal-input")?.value || "", "Copied to clipboard!"); break;
    case "copy-quick-mcp-cli": copyMcpCliConfig(getState().currentRevealedKey); break;
    case "copy-quick-antigravity": copyMcpJsonConfig(getState().currentRevealedKey); break;
    case "copy-quick-mcp-json": copyMcpJsonConfig(getState().currentRevealedKey); break;
    case "copy-quick-sdk": copySdkConfig(getState().currentRevealedKey); break;
    case "copy-quick-raw": copySnippetText(getState().currentRevealedKey, "Raw linking key copied!"); break;
    case "reset-user-password": openAdminResetPassModal(target.dataset.userId, target.dataset.username); break;
    case "reset-user-2fa": resetUser2FA(target.dataset.userId, target.dataset.username); break;
    case "delete-user": deleteUser(target.dataset.userId, target.dataset.username); break;
    case "reveal-secret": triggerSecretReveal(target.dataset.secretName); break;
    case "rotate-secret": openRotateSecretModal(target.dataset.secretName); break;
    case "delete-secret": deleteSecret(target.dataset.secretName); break;
    case "reveal-client-key": triggerClientKeyReveal(target.dataset.clientId, target.dataset.appName); break;
    case "edit-client": openEditClientModal(target.dataset.clientId); break;
    case "regenerate-from-edit": regenerateClientKey(document.getElementById("edit-client-id")?.value || "", document.getElementById("edit-client-name")?.value || ""); closeModal("modal-edit-client"); break;
    case "regenerate-client-key": regenerateClientKey(target.dataset.clientId, target.dataset.appName); break;
    case "client-logs": viewClientLogs(target.dataset.clientId, target.dataset.appName); break;
    case "revoke-client": revokeClient(target.dataset.clientId); break;
    case "delete-profile": deleteProfile(target.dataset.profileId); break;
    case "delete-passkey": deletePasskey(target.dataset.passkeyId, target.dataset.deviceName); break;
    case "disable-totp": disableTotp(); break;
    case "add-tag-pill": addTagPill(target.dataset.tagVal); break;
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest?.("form[data-submit-action]");
  if (!form) return;
  const action = form.dataset.submitAction;
  event.preventDefault();
  switch (action) {
    case "login": submitLogin(); break;
    case "register":
    case "self-register": submitRegister(); break;
    case "setup": submitSetup(); break;
    case "create-secret": submitAddSecret(); break;
    case "rotate-secret": submitRotateSecret(); break;
    case "create-client": submitCreateClient(); break;
    case "update-client": submitUpdateClient(); break;
    case "create-profile": submitCreateProfile(); break;
    case "add-user": submitAddUser(); break;
    case "change-password": submitChangePassword(); break;
    case "admin-reset-password":
    case "admin-reset-user-pass": submitAdminResetPassword(); break;
  }
});

document.addEventListener("change", (event) => {
  const select = event.target.closest?.("[data-change-action]");
  if (!select) return;
  const action = select.dataset.changeAction;
  switch (action) {
    case "reload-secrets": loadSecrets(); break;
    case "inline-user-secret": toggleInlineUserSecret(select.value); break;
    case "inline-pass-secret": toggleInlinePassSecret(select.value); break;
    case "profile-auth-fields": renderProfileAuthFields(select.value); break;
    case "private-network-warning": {
      const warn = document.getElementById("private-network-warning");
      if (warn) warn.style.display = select.checked ? "block" : "none";
      break;
    }
    case "filter-client-logs": renderClientLogs(select.value); break;
    case "filter-activity": renderActivity(select.value); break;
    case "docs-client-key": updateDocsSnippets(); break;
    case "toggle-registration": toggleOpenRegistration(select.checked); break;
  }
});

document.addEventListener("change", (event) => {
  if (event.target?.id === "backup-codes-ack") {
    const done = document.getElementById("btn-backup-codes-done");
    if (done) done.disabled = !event.target.checked;
  }
});

let totpAutoSubmitTimers = {};
document.addEventListener("input", (event) => {
  const box = event.target.closest?.(".totp-pin-box");
  if (!box) return;
  const container = box.closest(".totp-pin-container");
  if (!container) return;

  const boxes = Array.from(container.querySelectorAll(".totp-pin-box"));
  const val = box.value.replace(/\D/g, "");
  box.value = val.slice(0, 1);

  if (box.value && boxes.indexOf(box) < boxes.length - 1) {
    boxes[boxes.indexOf(box) + 1].focus();
  }
  updateTotpHiddenInput(container);
});

document.addEventListener("keydown", (event) => {
  const box = event.target.closest?.(".totp-pin-box");
  if (!box) return;
  const container = box.closest(".totp-pin-container");
  if (!container) return;

  const boxes = Array.from(container.querySelectorAll(".totp-pin-box"));
  const idx = boxes.indexOf(box);

  if (event.key === "Backspace") {
    if (!box.value && idx > 0) {
      boxes[idx - 1].focus();
      boxes[idx - 1].value = "";
      event.preventDefault();
    }
  } else if (event.key === "ArrowLeft" && idx > 0) {
    boxes[idx - 1].focus();
  } else if (event.key === "ArrowRight" && idx < boxes.length - 1) {
    boxes[idx + 1].focus();
  }
  updateTotpHiddenInput(container);
});

document.addEventListener("paste", (event) => {
  const box = event.target.closest?.(".totp-pin-box");
  if (!box) return;
  const container = box.closest(".totp-pin-container");
  if (!container) return;

  const pasted = (event.clipboardData || window.clipboardData)?.getData("text");
  if (!pasted) return;

  const digits = pasted.replace(/\D/g, "").slice(0, 6);
  if (!digits) return;

  event.preventDefault();
  const boxes = Array.from(container.querySelectorAll(".totp-pin-box"));
  boxes.forEach((b, i) => {
    b.value = digits[i] || "";
  });

  const nextFocus = Math.min(digits.length, boxes.length - 1);
  boxes[nextFocus].focus();
  updateTotpHiddenInput(container);

  if (digits.length === 6) {
    const parentModal = container.closest(".modal");
    const submitBtn = parentModal?.querySelector('[data-action="verify-stepup-totp"], [data-action="verify-totp-setup"]');
    if (submitBtn) submitBtn.click();
  }
});

function updateTotpHiddenInput(container) {
  const targetId = container.dataset.pinTarget;
  if (!targetId) return;
  const hiddenInput = document.getElementById(targetId);
  const boxes = Array.from(container.querySelectorAll(".totp-pin-box"));
  const code = boxes.map((b) => b.value).join("");
  if (hiddenInput) hiddenInput.value = code;
}
