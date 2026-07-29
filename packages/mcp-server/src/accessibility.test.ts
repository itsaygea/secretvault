import { describe, it, expect } from "vitest";
// The UI ships as plain ESM JavaScript that is copied verbatim into dist/ — it
// is never compiled by tsc, so it has no type declarations. The DOM-free pure
// helpers underpinning accessible navigation (SV-060) and the dialog focus trap
// (SV-059) are imported here directly; they perform no DOM access at load.
// @ts-expect-error — plain JS module outside the typed src/ tree.
import { tabKeyFromHash, settingsSubFromHash, buildHash, rotateTab } from "../ui/js/navHelpers.js";
// @ts-expect-error — plain JS module outside the typed src/ tree.
import { nextFocusIndex, wouldEscape } from "../ui/js/focusTrap.js";

// The imports are typed as `any` (no declarations), so runtime-guard probes that
// pass non-string values are exercised via these untyped aliases.
const _tabKeyFromHash = tabKeyFromHash as (hash: unknown) => string | null;
const _rotateTab = rotateTab as (ids: unknown, currentId: string, delta: number) => string | null;
const _nextFocusIndex = nextFocusIndex as (i: number, c: unknown, s: boolean) => number;

describe("Accessible navigation — URL hash helpers (SV-060)", () => {
  describe("tabKeyFromHash", () => {
    it("maps each of the 5 primary navbar tabs to its tab id (Map #96)", () => {
      expect(tabKeyFromHash("#secrets")).toBe("tab-secrets");
      expect(tabKeyFromHash("#clients")).toBe("tab-clients");
      expect(tabKeyFromHash("#services")).toBe("tab-profiles");
      expect(tabKeyFromHash("#integrations")).toBe("tab-integrations");
      expect(tabKeyFromHash("#settings")).toBe("tab-settings");
    });

    it("uses only the first segment so settings sub-tabs resolve to settings", () => {
      expect(tabKeyFromHash("#settings/security")).toBe("tab-settings");
      expect(tabKeyFromHash("#settings/users")).toBe("tab-settings");
      expect(tabKeyFromHash("#settings/logs")).toBe("tab-settings");
    });

    it("aliases the consolidated legacy deep links onto the Settings tab (Map #96)", () => {
      // Users, Activity, and Logs content now live under Settings sub-tabs, so
      // old #users / #activity / #logs bookmarks route into the Settings area.
      expect(tabKeyFromHash("#users")).toBe("tab-settings");
      expect(tabKeyFromHash("#activity")).toBe("tab-settings");
      expect(tabKeyFromHash("#logs")).toBe("tab-settings");
    });

    it("tolerates a missing leading hash", () => {
      expect(tabKeyFromHash("secrets")).toBe("tab-secrets");
    });

    it("returns null for unknown, empty, or undefined hashes", () => {
      expect(tabKeyFromHash("#unknown")).toBeNull();
      expect(tabKeyFromHash("")).toBeNull();
      expect(tabKeyFromHash("#")).toBeNull();
      expect(_tabKeyFromHash(undefined)).toBeNull();
    });
  });

  describe("settingsSubFromHash", () => {
    it("resolves an explicit #settings/<sub> deep link", () => {
      expect(settingsSubFromHash("#settings/security")).toBe("security");
      expect(settingsSubFromHash("#settings/users")).toBe("users");
      expect(settingsSubFromHash("#settings/logs")).toBe("logs");
      expect(settingsSubFromHash("#settings/password")).toBe("password");
    });

    it("maps the legacy bare aliases onto their consolidated sub-tab (Map #96)", () => {
      expect(settingsSubFromHash("#users")).toBe("users");
      expect(settingsSubFromHash("#activity")).toBe("logs");
      expect(settingsSubFromHash("#logs")).toBe("logs");
    });

    it("returns null when no sub-tab applies", () => {
      expect(settingsSubFromHash("#secrets")).toBeNull();
      expect(settingsSubFromHash("#settings")).toBeNull();
      expect(settingsSubFromHash("#settings/nonsense")).toBeNull();
      expect(settingsSubFromHash("")).toBeNull();
    });
  });

  describe("buildHash", () => {
    it("builds a section hash from a tab id", () => {
      expect(buildHash("tab-secrets")).toBe("#secrets");
      expect(buildHash("tab-profiles")).toBe("#services");
      expect(buildHash("tab-integrations")).toBe("#integrations");
      expect(buildHash("tab-settings")).toBe("#settings");
    });

    it("appends a settings sub-segment when valid", () => {
      expect(buildHash("tab-settings", "security")).toBe("#settings/security");
      expect(buildHash("tab-settings", "users")).toBe("#settings/users");
      expect(buildHash("tab-settings", "logs")).toBe("#settings/logs");
      expect(buildHash("tab-settings", "password")).toBe("#settings/password");
    });

    it("ignores a sub-segment that is not a known settings sub-tab", () => {
      expect(buildHash("tab-settings", "nonsense")).toBe("#settings");
    });

    it("ignores a sub-segment on non-settings tabs", () => {
      expect(buildHash("tab-secrets", "security")).toBe("#secrets");
    });

    it("returns empty string for an unknown tab id", () => {
      expect(buildHash("tab-nope")).toBe("");
    });
  });

  describe("rotateTab", () => {
    const ids = ["tab-secrets", "tab-clients", "tab-profiles"];

    it("moves forward by one, wrapping at the end", () => {
      expect(rotateTab(ids, "tab-secrets", 1)).toBe("tab-clients");
      expect(rotateTab(ids, "tab-clients", 1)).toBe("tab-profiles");
      expect(rotateTab(ids, "tab-profiles", 1)).toBe("tab-secrets");
    });

    it("moves backward by one, wrapping at the start", () => {
      expect(rotateTab(ids, "tab-clients", -1)).toBe("tab-secrets");
      expect(rotateTab(ids, "tab-secrets", -1)).toBe("tab-profiles");
    });

    it("falls back to the first id when the current id is not in the list", () => {
      expect(rotateTab(ids, "tab-missing", 1)).toBe("tab-secrets");
    });

    it("returns null for an empty list", () => {
      expect(rotateTab([], "tab-secrets", 1)).toBeNull();
      expect(_rotateTab(null, "tab-secrets", 1)).toBeNull();
    });
  });
});

describe("Accessible dialog focus trap — math (SV-059)", () => {
  describe("nextFocusIndex", () => {
    it("moves forward through the list", () => {
      expect(nextFocusIndex(0, 3, false)).toBe(1);
      expect(nextFocusIndex(1, 3, false)).toBe(2);
    });

    it("wraps from last to first on forward Tab", () => {
      expect(nextFocusIndex(2, 3, false)).toBe(0);
    });

    it("moves backward through the list", () => {
      expect(nextFocusIndex(2, 3, true)).toBe(1);
      expect(nextFocusIndex(1, 3, true)).toBe(0);
    });

    it("wraps from first to last on Shift+Tab", () => {
      expect(nextFocusIndex(0, 3, true)).toBe(2);
    });

    it("clamps an out-of-range current index to 0", () => {
      expect(nextFocusIndex(-1, 3, false)).toBe(1);
      expect(nextFocusIndex(99, 3, false)).toBe(1);
    });

    it("returns -1 when there is nothing focusable", () => {
      expect(nextFocusIndex(0, 0, false)).toBe(-1);
      expect(_nextFocusIndex(0, NaN, false)).toBe(-1);
    });
  });

  describe("wouldEscape", () => {
    it("flags forward Tab from the last element", () => {
      expect(wouldEscape(2, 3, false)).toBe(true);
      expect(wouldEscape(1, 3, false)).toBe(false);
    });

    it("flags Shift+Tab from the first element", () => {
      expect(wouldEscape(0, 3, true)).toBe(true);
      expect(wouldEscape(1, 3, true)).toBe(false);
    });

    it("escapes when focus is outside the list", () => {
      expect(wouldEscape(-1, 3, false)).toBe(true);
      expect(wouldEscape(5, 3, false)).toBe(true);
    });

    it("escapes when the list is empty", () => {
      expect(wouldEscape(0, 0, false)).toBe(true);
    });
  });
});
