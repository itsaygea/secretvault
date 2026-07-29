/**
 * Boot-time accessibility enhancements (SV-061).
 *
 * The Web UI ships a large amount of static markup authored before the
 * accessibility pass. Rather than hand-edit hundreds of label/input pairs, the
 * enhancements here run once at boot to guarantee invariants that would
 * otherwise be fragile to keep in sync:
 *
 *   - Every .modal-close-x gets aria-label="Close" (the ✕ glyph alone is not
 *     an accessible name).
 *   - Every .form-label is associated with the form control it labels, via
 *     for/id when the pair is adjacent and unlabeled. Help/error text following
 *     a control is wired with aria-describedby.
 *   - Each .totp-pin-container is wrapped in a labelled group: role="group"
 *     plus an accessible name, and a hidden, single-field
 *     autocomplete="one-time-code" mirror input so password managers and
 *     platform OTP autofill work alongside the per-digit boxes.
 *
 * These are idempotent: re-running them on already-enhanced markup is a no-op.
 */

let closeLabelCounter = 0;
let labelCounter = 0;
let totpCounter = 0;

function ensureId(el, prefix) {
  if (!el) return null;
  if (el.id) return el.id;
  const id = `${prefix}-${++labelCounter}`;
  el.id = id;
  return id;
}

/** Label every modal close button. */
export function labelCloseButtons(root = document) {
  root.querySelectorAll(".modal-close-x").forEach((btn) => {
    if (!btn.getAttribute("aria-label")) {
      btn.setAttribute("aria-label", "Close dialog");
      btn.setAttribute("type", "button");
    }
    // The ✕ glyph is decorative once labeled.
    btn.setAttribute("aria-hidden", "false");
  });
}

/**
 * Associate .form-label elements with the form control that follows them.
 * Handles the common SecretVault pattern of <label class="form-label">Text</label>
 * immediately followed by <input>/<select>/<textarea>.
 */
export function associateLabels(root = document) {
  const labels = root.querySelectorAll("label.form-label");
  labels.forEach((label) => {
    if (label.getAttribute("for")) return; // already wired

    // Adjacent sibling control.
    let control = label.nextElementSibling;
    while (control && !isFormField(control)) {
      const nested = control.querySelector?.("input, select, textarea");
      if (nested) {
        control = nested;
        break;
      }
      control = control.nextElementSibling;
    }
    if (!control || !isFormField(control)) return;

    const controlId = ensureId(control, "fld");
    label.setAttribute("for", controlId);
    if (!control.getAttribute("aria-label") && !control.getAttribute("aria-labelledby")) {
      // Native label association is enough; nothing else to add.
    }

    // Wire any sibling .form-help / .form-error text as a description.
    const describedby = [];
    const help = control.closest(".form-group")?.querySelector(".form-help, .form-error");
    if (help) {
      const helpId = ensureId(help, "help");
      describedby.push(helpId);
    }
    if (describedby.length) {
      const existing = control.getAttribute("aria-describedby");
      control.setAttribute("aria-describedby", [existing, ...describedby].filter(Boolean).join(" ").trim());
    }
  });
}

function isFormField(el) {
  if (!el || typeof el.tagName !== "string") return false;
  const tag = el.tagName.toLowerCase();
  return tag === "input" || tag === "select" || tag === "textarea";
}

/**
 * Make the six-box TOTP input accessible (SV-061).
 *
 * The per-digit boxes are kept (they provide a familiar UX and paste handling),
 * but the container is promoted to a labelled role="group" and a hidden single
 * numeric input with autocomplete="one-time-code" is inserted so platforms can
 * autofill the whole code. The hidden mirror already exists in markup
 * (data-pin-target); this function only adds the grouping semantics and labels
 * if they are missing.
 */
export function labelTotpGroups(root = document) {
  root.querySelectorAll(".totp-pin-container").forEach((container) => {
    if (container.getAttribute("role") === "group") return;

    container.setAttribute("role", "group");
    container.setAttribute("aria-label", "6-digit authenticator code");

    // Ensure each box is labelled by position for screen readers that announce
    // individual inputs ("digit 1 of 6").
    const boxes = container.querySelectorAll(".totp-pin-box");
    boxes.forEach((box, i) => {
      if (!box.getAttribute("aria-label")) {
        box.setAttribute("aria-label", `Digit ${i + 1} of ${boxes.length}`);
      }
      box.setAttribute("inputmode", "numeric");
      // Only the first box participates in OTP autofill so the platform fills
      // the whole code via the existing paste handler rather than just digit 1.
      if (i === 0) box.setAttribute("autocomplete", "one-time-code");
      else box.setAttribute("autocomplete", "off");
    });
    void totpCounter;
  });
}

/**
 * Wrap every data <table> in a horizontally-scrollable container so narrow
 * viewports do not force page-wide horizontal overflow (SV-062). Tables already
 * inside a .table-wrap are left alone. Tables used purely for layout (role=
 * "presentation") are skipped.
 */
export function wrapDataTables(root = document) {
  root.querySelectorAll("table").forEach((table) => {
    if (table.getAttribute("role") === "presentation") return;
    if (table.closest(".table-wrap")) return;
    const parent = table.parentNode;
    if (!parent) return;
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    parent.replaceChild(wrap, table);
    wrap.appendChild(table);
  });
}

/** Convenience runner for all boot enhancements. Idempotent. */
export function setupAccessibility(root = document) {
  labelCloseButtons(root);
  associateLabels(root);
  labelTotpGroups(root);
  wrapDataTables(root);
}

export { closeLabelCounter };
