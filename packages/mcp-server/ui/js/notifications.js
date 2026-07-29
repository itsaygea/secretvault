/**
 * Toast notifications with live-region semantics (SV-061).
 *
 * Error toasts become role="alert" (assertive, announced immediately) while
 * success/info toasts become role="status" (polite). The container itself is
 * marked aria-live="polite" aria-atomic="true" as a fallback for AT that reads
 * the region rather than individual toasts.
 */
export function showToast(msg, isError = false) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${isError ? "toast-error" : "toast-success"}`;
  toast.setAttribute("role", isError ? "alert" : "status");
  toast.setAttribute("aria-live", isError ? "assertive" : "polite");

  const icon = document.createElement("span");
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = isError ? "⚠️" : "✅";
  toast.appendChild(icon);

  const msgSpan = document.createElement("span");
  msgSpan.textContent = msg;
  toast.appendChild(msgSpan);

  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}
