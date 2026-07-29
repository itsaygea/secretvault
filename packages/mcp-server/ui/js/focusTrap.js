/**
 * DOM-free focus-trap math (SV-059).
 *
 * The dialog controller constrains Tab/Shift+Tab to the open dialog. The
 * decision of which focusable to move to is pure arithmetic on the focusable
 * count, the current index, and whether Shift is held. Extracting it here keeps
 * the boundary logic unit-testable without a DOM.
 */

/**
 * Compute the next focus index inside a focus trap, wrapping at the edges.
 *
 * @param {number} currentIndex  index of the currently focused element (-1 if outside)
 * @param {number} count         number of focusable elements
 * @param {boolean} shift        true for Shift+Tab (reverse)
 * @returns {number} the index to move focus to, or -1 when there is nowhere to go
 */
export function nextFocusIndex(currentIndex, count, shift) {
  if (!Number.isFinite(count) || count <= 0) return -1;
  const base = currentIndex < 0 || currentIndex >= count ? 0 : currentIndex;
  if (shift) {
    return base <= 0 ? count - 1 : base - 1;
  }
  return base >= count - 1 ? 0 : base + 1;
}

/**
 * Whether a Tab from the given index would escape the trap without wrapping.
 * Useful for deciding if the controller must preventDefault + refocus.
 *
 * @param {number} currentIndex
 * @param {number} count
 * @param {boolean} shift
 * @returns {boolean}
 */
export function wouldEscape(currentIndex, count, shift) {
  if (!Number.isFinite(count) || count <= 0) return true;
  if (currentIndex < 0 || currentIndex >= count) return true;
  if (shift) return currentIndex === 0;
  return currentIndex === count - 1;
}
