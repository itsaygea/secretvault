import { showToast } from "./notifications.js";

export function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function extractList(resData) {
  if (Array.isArray(resData)) return resData;
  if (Array.isArray(resData?.data)) return resData.data;
  if (Array.isArray(resData?.logs)) return resData.logs;
  return [];
}

export function apiErrorMessage(data, fallback) {
  if (data?.error && typeof data.error === "object") {
    return data.error.message || fallback;
  }
  return typeof data?.error === "string" ? data.error : fallback;
}

export function base64UrlToBuffer(base64url) {
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/\-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  const buffer = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) buffer[i] = rawData.charCodeAt(i);
  return buffer.buffer;
}

export function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  const base64 = window.btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function fallbackCopyText(text, successMsg = "Copied to clipboard!") {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.top = "-9999px";
  textArea.style.left = "-9999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    if (document.execCommand("copy")) {
      showToast(successMsg);
    } else {
      showToast("Failed to copy", true);
    }
  } catch (err) {
    showToast("Copy failed: " + err.message, true);
  }
  document.body.removeChild(textArea);
}

export function copySnippetText(text, successMsg = "Copied to clipboard!") {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => showToast(successMsg)).catch(() => fallbackCopyText(text, successMsg));
  } else {
    fallbackCopyText(text, successMsg);
  }
}

export function copySnippet(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const textToCopy = el.innerText || el.textContent;
  copySnippetText(textToCopy, "Snippet copied to clipboard!");
}

export function togglePasswordVisibility(btn) {
  const inputId = btn?.dataset?.targetId;
  if (!inputId) return;
  const input = document.getElementById(inputId);
  if (!input) return;
  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";
  btn.textContent = isPassword ? "Hide" : "Show";
  btn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
}

export function generateRandomPassword(targetId) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=";
  let pass = "";
  const array = new Uint32Array(24);
  window.crypto.getRandomValues(array);
  for (let i = 0; i < 24; i++) {
    pass += chars[array[i] % chars.length];
  }
  const input = document.getElementById(targetId);
  if (input) input.value = pass;
}

export function copyMcpCliConfig(key) {
  if (!key) return showToast("No key available to copy", true);
  const hostUrl = `${window.location.protocol}//${window.location.host}`;
  const cmd = `claude mcp add secretvault ${hostUrl}/mcp --header "Authorization: Bearer ${key}"`;
  copySnippetText(cmd, "Claude CLI command copied to clipboard!");
}

export function copyMcpJsonConfig(key) {
  if (!key) return showToast("No key available to copy", true);
  const hostUrl = `${window.location.protocol}//${window.location.host}`;
  const json = JSON.stringify({ mcpServers: { secretvault: { url: `${hostUrl}/mcp`, headers: { Authorization: `Bearer ${key}` } } } }, null, 2);
  copySnippetText(json, "MCP JSON config copied to clipboard!");
}

export function copySdkConfig(key) {
  if (!key) return showToast("No key available to copy", true);
  const hostUrl = `${window.location.protocol}//${window.location.host}`;
  const allowInsecureHttp = hostUrl.startsWith("http://");
  const code = [
    `import { SecretVaultClient } from "@secretvault/client";`,
    ``,
    `const vault = new SecretVaultClient({`,
    `  baseUrl: "${hostUrl}",`,
    `  clientKey: "${key}",`,
    `  allowInsecureHttp: ${allowInsecureHttp}`,
    `});`,
    ``,
    `const res = await vault.proxy("qbittorrent", "/api/v2/torrents/info");`,
  ].join("\n");
  copySnippetText(code, "@secretvault/client code snippet copied!");
}
