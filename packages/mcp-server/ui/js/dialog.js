import { getState, setState } from "./state.js";
import { showToast } from "./notifications.js";
import { copySnippetText, copyMcpCliConfig, copyMcpJsonConfig, copySdkConfig } from "./utils.js";
import { clearSensitiveState, clearSensitiveDomElements } from "./sensitive.js";
import { nextFocusIndex } from "./focusTrap.js";

/**
 * Accessible dialog controller (SV-059).
 *
 * Every modal shares the markup convention
 *   <div id="modal-..." class="modal-overlay"> <div class="modal"> ... </div> </div>
 * where the inner .modal carries an .modal-title (h3) and optional .modal-desc.
 *
 * openModal()/closeModal() make each overlay a real dialog:
 *   - role="dialog" aria-modal="true"
 *   - aria-labelledby / aria-describedby pointing at title/desc
 *   - initial focus on a chosen element (or the dialog / first focusable)
 *   - focus trap (Tab/Shift+Tab stay inside), Escape to close
 *   - background made inert + hidden from assistive tech
 *   - focus restored to the opener on close
 *
 * openStack is kept so a confirm dialog opened from within another dialog
 * restores focus through the chain. In practice SecretVault opens one modal
 * at a time, but the stack is cheap insurance.
 */

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  'input:not([disabled]):not([type="hidden"])',
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
  "[contenteditable]:not([contenteditable='false'])",
].join(",");

/** Stack of { overlay, opener, onAfterClose } for nested dialogs. */
const stack = [];

/** @returns {readonly {overlay: HTMLElement, opener: HTMLElement|null, onAfterClose?: () => void}[]} */
export function getDialogStack() {
  return stack;
}

function getOverlayEl(idOrEl) {
  if (!idOrEl) return null;
  if (typeof idOrEl === "string") return document.getElementById(idOrEl);
  return idOrEl;
}

function queryFocusable(root) {
  if (!root) return [];
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
    (el) => el.offsetParent !== null || el === document.activeElement || el.getAttribute("tabindex") === "0",
  );
}

function setTitleDescriptionRoles(overlay) {
  const dialog = overlay.querySelector(".modal");
  if (!dialog) return;
  const title = overlay.querySelector(".modal-title");
  const desc = overlay.querySelector(".modal-desc");

  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");

  // Give the dialog an implicit id-backed label/description so screen readers
  // announce the title and description when it opens.
  if (title) {
    if (!title.id) title.id = `${overlay.id}-title`;
    dialog.setAttribute("aria-labelledby", title.id);
  }
  if (desc) {
    if (!desc.id) desc.id = `${overlay.id}-desc`;
    dialog.setAttribute("aria-describedby", desc.id);
  }
}

/**
 * Open an accessible dialog.
 *
 * @param {string|HTMLElement} idOrEl  overlay id or element
 * @param {{ focusSelector?: string, opener?: HTMLElement|null, onAfterClose?: () => void }} [opts]
 */
export function openModal(idOrEl, opts = {}) {
  const overlay = getOverlayEl(idOrEl);
  if (!overlay) return;

  setTitleDescriptionRoles(overlay);

  // Record where focus should return to. Prefer the explicit opener (the
  // element that triggered the dialog), else the currently focused element.
  const opener = opts.opener || document.activeElement;

  // Push onto the stack FIRST so setBackdropInert() treats this overlay as
  // protected (it must remain focusable while open).
  stack.push({ overlay, opener, onAfterClose: opts.onAfterClose });

  // Inert everything behind the topmost dialog so the background cannot
  // receive focus or be reached via Tab/Shift+Tab.
  setBackdropInert(true);

  overlay.classList.add("active");
  overlay.style.display = "flex";

  // Re-show previously hidden siblings (the overlay was possibly display:none)
  overlay.removeAttribute("aria-hidden");

  // Place initial focus: explicit selector → dialog wrapper → first focusable.
  let target = null;
  if (opts.focusSelector) {
    target = overlay.querySelector(opts.focusSelector);
  }
  if (!target) {
    target = overlay.querySelector(".modal") || overlay;
  }
  const focusables = queryFocusable(overlay);
  if (focusables.length && (!opts.focusSelector || !target || target.tabIndex < 0)) {
    target = focusables[0];
  }

  // Defer focus until after the display flip so the browser honors it.
  requestAnimationFrame(() => {
    try {
      target.focus({ preventScroll: false });
    } catch {
      target.focus();
    }
  });
}

/**
 * Close a dialog, restoring focus and re-enabling the background.
 *
 * @param {string|HTMLElement} idOrEl
 * @param {{ restoreFocus?: boolean }} [opts]
 */
export function closeModal(idOrEl, opts = {}) {
  const overlay = getOverlayEl(idOrEl);
  if (!overlay) return;

  overlay.classList.remove("active");
  overlay.style.display = "none";

  // Modal-specific cleanup hooks (kept from the original behaviour).
  if (overlay.id === "modal-reveal-value") {
    clearSensitiveState();
    clearSensitiveDomElements();
  }
  if (overlay.id === "modal-backup-codes") {
    overlay.querySelectorAll(".totp-pin-box").forEach((el) => {
      el.value = "";
    });
  }
  // Clear all TOTP pin boxes in any closing modal so a reopened dialog starts fresh.
  overlay.querySelectorAll(".totp-pin-box").forEach((el) => {
    el.value = "";
  });

  // Remove this dialog (and anything stacked above it) from the stack.
  const idx = stack.findIndex((entry) => entry.overlay === overlay);
  const removed = idx >= 0 ? stack.splice(idx, stack.length - idx) : [];
  const top = removed[0];

  // If a deeper dialog remains open, keep its backdrop inerted; otherwise free the page.
  if (stack.length > 0) {
    // Re-show the new top dialog if it was hidden by stacking display rules.
    stack[stack.length - 1].overlay.style.display = "flex";
  } else {
    setBackdropInert(false);
  }

  if (opts.restoreFocus !== false && top?.opener && typeof top.opener.focus === "function") {
    requestAnimationFrame(() => top.opener.focus());
  }
  if (typeof top?.onAfterClose === "function") top.onAfterClose();
}

/** Close the topmost dialog (used by the global Escape handler). */
export function closeTopDialog() {
  if (stack.length === 0) return null;
  const top = stack[stack.length - 1];
  closeModal(top.overlay);
  return top.overlay;
}

/**
 * Make every top-level sibling of the active dialog(s) inert/aria-hidden so
 * background content is neither focusable nor announced. The dialog overlays
 * themselves are never inerted.
 */
function setBackdropInert(inert) {
  const protectedEls = new Set(stack.map((e) => e.overlay));
  const bodyChildren = Array.from(document.body.children);
  bodyChildren.forEach((child) => {
    if (protectedEls.has(child)) {
      child.inert = false;
      child.removeAttribute("aria-hidden");
      return;
    }
    // Auth view + dashboard are siblings; only toggle when a dialog is open.
    child.inert = inert;
    if (inert) child.setAttribute("aria-hidden", "true");
    else child.removeAttribute("aria-hidden");
  });
}

function clearRevealTimer() {
  const s = getState();
  if (s.revealTimerInterval) {
    clearInterval(s.revealTimerInterval);
    setState({ revealTimerInterval: null });
  }
}

export function openRevealModal(title, desc, label, value, isClientKey = false) {
  clearRevealTimer();
  setState({ currentRevealedKey: value });

  document.getElementById("reveal-modal-title").textContent = title;
  document.getElementById("reveal-modal-desc").textContent = desc;
  document.getElementById("reveal-modal-label").textContent = label;
  document.getElementById("reveal-modal-input").value = value;

  const quickCopyBox = document.getElementById("reveal-quick-copy-container");
  if (quickCopyBox) {
    quickCopyBox.style.display = isClientKey ? "block" : "none";
  }

  let secondsLeft = 15;
  const timerBadge = document.getElementById("reveal-modal-timer");
  if (timerBadge) {
    timerBadge.textContent = `Auto-closing in ${secondsLeft}s`;
    timerBadge.setAttribute("aria-live", "polite");
  }

  const interval = setInterval(() => {
    secondsLeft--;
    if (timerBadge) timerBadge.textContent = `Auto-closing in ${secondsLeft}s`;
    if (secondsLeft <= 0) {
      clearInterval(interval);
      setState({ revealTimerInterval: null, currentRevealedKey: "" });
      const valInput = document.getElementById("reveal-modal-input");
      if (valInput) valInput.value = "";
      closeModal("modal-reveal-value");
    }
  }, 1000);
  setState({ revealTimerInterval: interval });

  openModal("modal-reveal-value", { focusSelector: "#reveal-modal-input" });
}

export function promptConfirmAction(title, message, confirmBtnText, onConfirm) {
  document.getElementById("confirm-modal-title").textContent = title;
  document.getElementById("confirm-modal-desc").textContent = message;
  const btn = document.getElementById("confirm-modal-submit-btn");
  btn.textContent = confirmBtnText;
  btn.onclick = () => {
    closeModal("modal-confirm-action");
    onConfirm();
  };
  openModal("modal-confirm-action", { focusSelector: "#confirm-modal-submit-btn" });
}

/**
 * Global keyboard handling for open dialogs:
 *   - Escape closes the topmost dialog
 *   - Tab/Shift+Tab is constrained to the active dialog
 *
 * Installed once at app boot.
 */
export function setupDialogKeyboard() {
  document.addEventListener("keydown", (event) => {
    if (stack.length === 0) return;
    const top = stack[stack.length - 1];
    const dialog = top.overlay.querySelector(".modal") || top.overlay;

    if (event.key === "Escape") {
      // Ignore Escape while a passkey/WebAuthn prompt or autofill has focus.
      const cancelBtn = top.overlay.querySelector('[data-action="close-modal"], [data-action="cancel-totp-setup"]');
      event.preventDefault();
      if (cancelBtn) {
        cancelBtn.click();
      } else {
        closeModal(top.overlay);
      }
      return;
    }

    if (event.key === "Tab") {
      const focusables = queryFocusable(top.overlay);
      if (focusables.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const active = document.activeElement;
      const currentIndex = focusables.indexOf(active);
      // If focus is outside the dialog (shouldn't happen while trapped), pull it
      // back to the first focusable.
      if (currentIndex === -1) {
        event.preventDefault();
        focusables[0].focus();
        return;
      }
      // Only intercept when the natural Tab would escape the trap (boundary).
      const atStart = currentIndex === 0;
      const atEnd = currentIndex === focusables.length - 1;
      if ((event.shiftKey && atStart) || (!event.shiftKey && atEnd)) {
        const targetIndex = nextFocusIndex(currentIndex, focusables.length, event.shiftKey);
        event.preventDefault();
        focusables[targetIndex].focus();
      }
    }
  });
}

/** Backwards-compatible aliases for callers that still import open/close. */
export { openModal as openDialog, closeModal as closeDialog };
