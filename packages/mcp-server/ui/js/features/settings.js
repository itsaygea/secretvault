import { getState, setState } from "../state.js";
import { getActiveToken, apiGet, apiPost, apiDelete, apiPostStepUp, withMutationGuard } from "../api.js";
import { showToast } from "../notifications.js";
import { escapeHtml, apiErrorMessage, copySnippetText } from "../utils.js";
import { closeModal, openModal, promptConfirmAction } from "../dialog.js";
import { loadPasskeys, openStepUpChooser } from "../auth.js";
import { invalidateSecurityModel } from "../securityCache.js";

/**
 * Compute the client-integration snippets for the current server origin.
 *
 * Pure data — no DOM writes — so the Integrations panel and any standalone
 * snippet blocks can both consume it. (Map #96 removed the Settings→Docs
 * subpanel; Integrations is now the single home for these snippets.)
 */
export function buildDocsSnippets() {
  const keyVal = "<YOUR_LINKING_KEY>";
  const hostUrl = `${window.location.protocol}//${window.location.host}`;
  const allowInsecureHttp = hostUrl.startsWith("http://");

  const mcpRemoteArgs = [
    "-y",
    "mcp-remote",
    `${hostUrl}/mcp`,
    "--header",
    `Authorization: Bearer ${keyVal}`,
  ];
  if (allowInsecureHttp) {
    mcpRemoteArgs.push("--allow-http");
  }

  const mcpRemoteJson = JSON.stringify(
    {
      mcpServers: {
        secretvault: {
          command: "npx",
          args: mcpRemoteArgs,
        },
      },
    },
    null,
    2,
  );

  return {
    "snippet-claude-code": `claude mcp add secretvault ${hostUrl}/mcp --header "Authorization: Bearer ${keyVal}"`,
    "snippet-antigravity": mcpRemoteJson,
    "snippet-vscode": mcpRemoteJson,

    "snippet-bridge": [
      `import { SecretVaultClient } from "@secretvault/client";`,
      "",
      `const vault = new SecretVaultClient({`,
      `  baseUrl: "${hostUrl}",`,
      `  clientKey: "${keyVal}",`,
      `  allowInsecureHttp: ${allowInsecureHttp}`,
      `});`,
      "",
      `const res = await vault.proxy("qbittorrent", "/api/v2/torrents/info");`,
    ].join("\n"),
    "snippet-mcp-stdio-runner": JSON.stringify(
      {
        mcpServers: {
          "example-stdio-mcp": {
            "command": "secretvault",
            "args": [
              "run",
              "--secret",
              "EXAMPLE_API_KEY",
              "--",
              "npx",
              "-y",
              "@example/mcp-server"
            ]
          }
        }
      },
      null,
      2
    ),
    "snippet-mcp-http-proxy": JSON.stringify(
      {
        mcpServers: {
          "example-remote-mcp": {
            "type": "http",
            "url": `${hostUrl}/proxy/example-service/mcp/tool`,
            "headers": {
              "Authorization": `Bearer ${keyVal}`
            }
          }
        }
      },
      null,
      2
    ),
    "snippet-curl": [
      `# 1. Reverse Proxy:`,
      `curl -s -H "Authorization: Bearer ${keyVal}" \\`,
      `  "${hostUrl}/proxy/example-service/api/v1/resource"`,
      "",
      `# 2. Zero-Leak CLI Runner (uses ~/.secretvault/credential.json):`,
      `secretvault run --secret EXAMPLE_API_KEY -- my-command`,
    ].join("\n"),
  };
}

/**
 * Populate any standalone snippet <code> blocks (by id) with the current
 * origin's text. Kept for backward compatibility with external/legacy mounts.
 */
export function updateDocsSnippets() {
  const snippets = buildDocsSnippets();
  for (const [id, text] of Object.entries(snippets)) {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
  }
}

/**
 * Render the client-integration snippets into the top-level Integrations panel
 * (Map #96: Integrations is the single home for client setup & docs). Builds
 * a label + code + copy-button row per snippet directly from the computed
 * snippet data — no dependency on a separate source panel. Idempotent.
 */
export function renderIntegrationsPanel() {
  const host = document.getElementById("integrations-snippets");
  if (!host) return;
  const snippets = buildDocsSnippets();
  // Clear previous render using safe DOM (no innerHTML) and rebuild.
  host.replaceChildren();
  for (const [id, text] of Object.entries(snippets)) {
    const row = document.createElement("div");
    row.style.marginBottom = "1rem";
    const head = document.createElement("div");
    head.style.display = "flex";
    head.style.alignItems = "center";
    head.style.justifyContent = "space-between";
    head.style.gap = "0.5rem";
    head.style.marginBottom = "0.3rem";
    const label = document.createElement("span");
    label.style.fontSize = "0.8rem";
    label.style.color = "var(--text-muted)";
    label.textContent = prettySnippetLabel(id);
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-secondary";
    copyBtn.style.padding = "0.25rem 0.6rem";
    copyBtn.style.fontSize = "0.75rem";
    copyBtn.style.flexShrink = "0";
    copyBtn.dataset.action = "copy-snippet";
    copyBtn.dataset.snippetId = id;
    copyBtn.textContent = "📋 Copy";
    head.appendChild(label);
    head.appendChild(copyBtn);
    const pre = document.createElement("pre");
    pre.style.margin = "0";
    const code = document.createElement("code");
    code.id = id;
    code.className = "code-block";
    code.innerText = text;
    pre.appendChild(code);
    row.appendChild(head);
    row.appendChild(pre);
    host.appendChild(row);
  }
}

function prettySnippetLabel(id) {
  const map = {
    "snippet-claude-code": "Claude Code (Streamable HTTP)",
    "snippet-antigravity": "Antigravity & Agentic MCP Clients (npx mcp-remote)",
    "snippet-vscode": "VS Code & Claude Desktop (npx mcp-remote)",
    "snippet-bridge": "@secretvault/client (TypeScript / Node.js SDK)",
    "snippet-mcp-stdio-runner": "Stdio MCP Servers (Zero-Leak CLI Runner via secretvault run)",
    "snippet-mcp-http-proxy": "HTTP Remote MCP Servers (Zero-Leak Reverse Proxy via /proxy/<service>/...)",
    "snippet-curl": "curl & Shell (Egress Proxy + CLI Runner)",
  };
  return map[id] || id;
}


function setFormBusy(formId, busy) {
  const form = document.getElementById(formId);
  if (form) form.setAttribute("aria-busy", String(busy));
  (form?.querySelectorAll("button[type=submit]") || []).forEach((btn) => {
    btn.disabled = busy;
  });
}

export async function submitChangePassword() {
  await withMutationGuard("change-password", async () => {
    setFormBusy("form-change-password", true);
    const current_password = document.getElementById("change-current-pass")?.value || "";
    const new_password = document.getElementById("change-new-pass")?.value || "";
    const confirm_password = document.getElementById("change-confirm-pass")?.value || "";

    if (!current_password || !new_password) {
      showToast("Please enter current and new password", true);
      setFormBusy("form-change-password", false);
      return;
    }
    if (new_password !== confirm_password) {
      showToast("New passwords do not match", true);
      setFormBusy("form-change-password", false);
      return;
    }

    const result = await apiPost("/v1/auth/change-password", { current_password, new_password });
    if (result.error) {
      showToast(result.error.message || "Password change failed", true);
      setFormBusy("form-change-password", false);
      return;
    }

    if (result.data?.changed) {
      // The server revokes all sessions on password change, so the next API
      // call will 401. Tell the user clearly and invalidate the security cache
      // before the forced logout so no stale identity is reused.
      invalidateSecurityModel();
      showToast("Password updated. All sessions were revoked — you will be signed out.");
      ["change-current-pass", "change-new-pass", "change-confirm-pass"].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.value = "";
      });
    } else {
      showToast("Password change failed", true);
    }
    setFormBusy("form-change-password", false);
  });
}

export async function openTotpSetupModal() {
  setFormBusy("form-totp-setup", true);
  const result = await apiPost("/v1/auth/totp/setup");
  if (result.error) {
    showToast(result.error.message || "Failed to setup TOTP", true);
    setFormBusy("form-totp-setup", false);
    return;
  }

  if (result.data?.qr_code) {
    document.getElementById("totp-qr-img").src = result.data.qr_code;
    const setupCode = document.getElementById("totp-setup-code");
    if (setupCode) setupCode.value = "";
    document.querySelectorAll("#modal-totp .totp-pin-box").forEach((el) => { el.value = ""; });
    openModal("modal-totp", { focusSelector: "#modal-totp .totp-pin-box" });
  } else {
    showToast(result.data?.error || "Failed to setup TOTP", true);
  }
  setFormBusy("form-totp-setup", false);
}

export async function cancelTotpSetup() {
  await apiPost("/v1/auth/totp/cancel-setup");
  closeModal("modal-totp");
  loadPasskeys(true);
}

export async function verifyTotpSetup() {
  await withMutationGuard("verify-totp", async () => {
    setFormBusy("form-totp-setup", true);
    const code = document.getElementById("totp-setup-code").value;
    if (!code || code.length !== 6) { showToast("Enter 6-digit TOTP code", true); setFormBusy("form-totp-setup", false); return; }

    const result = await apiPost("/v1/auth/totp/verify-setup", { code });
    if (result.error) {
      showToast(result.error.message || "Invalid code", true);
      setFormBusy("form-totp-setup", false);
      return;
    }

    if (result.data?.verified) {
      closeModal("modal-totp");
      setState({ currentUserHasTotp: true });
      showBackupCodesOnce(Array.isArray(result.data.backup_codes) ? result.data.backup_codes : []);
      loadPasskeys(true);
    } else {
      showToast("Invalid code", true);
    }
    setFormBusy("form-totp-setup", false);
  });
}

export function showBackupCodesOnce(codes) {
  setState({ pendingBackupCodes: codes.slice() });
  const list = document.getElementById("backup-codes-list");
  const ack = document.getElementById("backup-codes-ack");
  const done = document.getElementById("btn-backup-codes-done");
  if (list) list.textContent = getState().pendingBackupCodes.join("\n");
  if (ack) ack.checked = false;
  if (done) done.disabled = true;
  openModal("modal-backup-codes", { focusSelector: "#backup-codes-ack" });
}

export function copyBackupCodes() {
  const codes = getState().pendingBackupCodes;
  if (!codes.length) return;
  copySnippetText(codes.join("\n"), "Recovery codes copied");
}

export function downloadBackupCodes() {
  const codes = getState().pendingBackupCodes;
  if (!codes.length) return;
  const blob = new Blob([`SecretVault recovery codes\nGenerated: ${new Date().toISOString()}\n\n${codes.join("\n")}\n`], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "secretvault-recovery-codes.txt";
  a.click();
  URL.revokeObjectURL(url);
}

export function printBackupCodes() {
  const codes = getState().pendingBackupCodes;
  if (!codes.length) return;
  const w = window.open("", "_blank", "noopener,noreferrer,width=480,height=640");
  if (!w) return showToast("Pop-up blocked — allow pop-ups to print", true);
  w.document.write(`<pre style="font:16px/1.6 monospace;padding:2rem;">SecretVault recovery codes\n\n${codes.join("\n")}</pre>`);
  w.document.close();
  w.focus();
  w.print();
}

export function acknowledgeBackupCodes() {
  const ack = document.getElementById("backup-codes-ack");
  if (!ack?.checked) return showToast("Confirm you saved the recovery codes first", true);
  setState({ pendingBackupCodes: [] });
  const list = document.getElementById("backup-codes-list");
  if (list) list.textContent = "";
  closeModal("modal-backup-codes");
  showToast("TOTP 2FA enabled. Recovery codes saved offline.");
  loadPasskeys(true);
}

export function disableTotp() {
  promptConfirmAction("\uD83D\uDCF1 Disable Authenticator 2FA", "Are you sure you want to disable Authenticator App 2FA for your account?", "Yes, Disable 2FA", async () => {
    const result = await apiDelete("/v1/auth/totp");
    if (result.error) {
      showToast(result.error.message || "Failed to disable 2FA", true);
      return;
    }
    if (result.data?.disabled) {
      showToast("Authenticator 2FA disabled");
      loadPasskeys(true);
    } else {
      showToast("Failed to disable 2FA", true);
    }
  });
}

export async function regenerateBackupCodes() {
  if (!getState().stepUpToken) {
    setState({ pendingRevealSecretName: null, pendingRevealClientId: null });
    openStepUpChooser();
    showToast("Complete step-up authentication, then click Regenerate again", true);
    return;
  }
  promptConfirmAction("\uD83D\uDEE1\uFE0F Regenerate Recovery Codes", "This immediately invalidates all unused recovery codes and shows a new set once.", "Regenerate Codes", async () => {
    const result = await apiPostStepUp("/v1/auth/totp/regenerate-backup-codes", {});
    if (result.error) {
      if (result.error.code === "STEP_UP_REQUIRED") {
        setState({ stepUpToken: "" });
        openStepUpChooser();
      } else {
        showToast(result.error.message || "Failed to regenerate codes", true);
      }
      return;
    }
    if (Array.isArray(result.data?.backup_codes)) {
      showBackupCodesOnce(result.data.backup_codes);
      loadPasskeys(true);
    } else {
      showToast("Failed to regenerate codes", true);
    }
  });
}

export function deletePasskey(passkeyId, deviceName) {
  promptConfirmAction("\uD83D\uDDD1\uFE0F Delete Passkey", `Are you sure you want to remove passkey '${deviceName}'?`, "Yes, Delete Passkey", async () => {
    const result = await apiDelete(`/v1/auth/webauthn/credentials/${encodeURIComponent(passkeyId)}`);
    if (result.error) {
      showToast(result.error.message || "Failed to delete passkey", true);
      return;
    }
    if (result.data?.deleted) {
      showToast(`Passkey '${deviceName}' deleted!`);
      loadPasskeys(true);
    } else {
      showToast("Failed to delete passkey", true);
    }
  });
}
