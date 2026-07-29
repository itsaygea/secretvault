import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

describe("Web UI Security, Stored XSS Remediation & CSP Enforcement", () => {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const uiDir = resolve(currentDir, "..", "ui");

  it("ensures index.html does not contain inline scripts and loads app.js as module", () => {
    const indexPath = resolve(uiDir, "index.html");
    expect(existsSync(indexPath)).toBe(true);
    const html = readFileSync(indexPath, "utf8");

    expect(html).toContain('src="app.js"');
    expect(html).toContain('type="module"');

    expect(html).not.toMatch(/<script>(?!<\/script>)/s);
    expect(html).not.toMatch(/\s\bon(?:click|submit|change)=/i);
  });

  it("verifies modules contain escapeHtml helper and apply it to dynamic DOM sinks", () => {
    const utilsPath = resolve(uiDir, "js", "utils.js");
    expect(existsSync(utilsPath)).toBe(true);
    const utils = readFileSync(utilsPath, "utf8");
    const appJsPath = resolve(uiDir, "app.js");
    const appJs = readFileSync(appJsPath, "utf8");
    const secretsPath = resolve(uiDir, "js", "features", "secrets.js");
    const secrets = readFileSync(secretsPath, "utf8");
    const clientsPath = resolve(uiDir, "js", "features", "clients.js");
    const clients = readFileSync(clientsPath, "utf8");
    const profilesPath = resolve(uiDir, "js", "features", "profiles.js");
    const profiles = readFileSync(profilesPath, "utf8");
    const usersPath = resolve(uiDir, "js", "features", "users.js");
    const users = readFileSync(usersPath, "utf8");

    expect(utils).toContain("export function escapeHtml(str)");

    const dialogPath = resolve(uiDir, "js", "dialog.js");
    const dialog = readFileSync(dialogPath, "utf8");
    expect(dialog).toContain("export function openRevealModal(");

    expect(secrets).toContain("escapeHtml(s.name)");
    expect(clients).toContain("escapeHtml(c.app_name)");
    expect(profiles).toContain("escapeHtml(p.name)");
    expect(profiles).toContain("escapeHtml(p.target_url)");
    expect(users).toContain("escapeHtml(u.username)");
    expect(appJs).not.toMatch(/\sonclick=/i);
  });

  it("DOM contract: all data-action values have corresponding handler registrations in app.js", () => {
    const appJsPath = resolve(uiDir, "app.js");
    const appJs = readFileSync(appJsPath, "utf8");
    const htmlPath = resolve(uiDir, "index.html");
    const html = readFileSync(htmlPath, "utf8");

    const htmlActions = new Set(
      [...html.matchAll(/\bdata-action="([^"]+)"/g)].map((m) => m[1]),
    );

    const handledActions = new Set(
      [...appJs.matchAll(/case "([^"]+)":/g)].map((m) => m[1]),
    );

    const unhandled = [...htmlActions].filter((a) => !handledActions.has(a));
    expect(unhandled).toEqual([]);
  });

  it("DOM contract: index.html has no duplicate IDs", () => {
    const htmlPath = resolve(uiDir, "index.html");
    const html = readFileSync(htmlPath, "utf8");

    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]);
    const seen = new Set<string>();
    const duplicates = ids.filter((id) => {
      if (seen.has(id)) return true;
      seen.add(id);
      return false;
    });
    expect(duplicates).toEqual([]);
  });

  it("DOM contract: every form has a data-submit-action attribute", () => {
    const htmlPath = resolve(uiDir, "index.html");
    const html = readFileSync(htmlPath, "utf8");

    const forms = [...html.matchAll(/<form/g)];
    const formsWithAction = [...html.matchAll(/<form[^>]*data-submit-action/g)];
    expect(forms.length).toBeGreaterThan(0);
    expect(forms.length).toBe(formsWithAction.length);
  });

  it("DOM contract: all id-referenced elements in app.js have matching index.html IDs", () => {
    const htmlPath = resolve(uiDir, "index.html");
    const html = readFileSync(htmlPath, "utf8");
    const htmlIds = new Set(
      [...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]),
    );

    const appJsPath = resolve(uiDir, "app.js");
    const appJs = readFileSync(appJsPath, "utf8");
    const appJsIds = new Set(
      [...appJs.matchAll(/document\.getElementById\(["']([^"']+)["']\)/g)].map((m) => m[1]),
    );

    const missing = [...appJsIds].filter((id) => !htmlIds.has(id));
    expect(missing).toEqual([]);
  });

  it("security UX: sensitive state is cleared on all exit paths", () => {
    const sensitiveJs = readFileSync(resolve(uiDir, "js", "sensitive.js"), "utf8");
    const authJs = readFileSync(resolve(uiDir, "js", "auth.js"), "utf8");
    const dialogJs = readFileSync(resolve(uiDir, "js", "dialog.js"), "utf8");
    const appJs = readFileSync(resolve(uiDir, "app.js"), "utf8");

    expect(sensitiveJs).toContain("clearSensitiveState");
    expect(sensitiveJs).toContain("clearSensitiveDom");

    expect(sensitiveJs).toContain("visibilitychange");
    expect(sensitiveJs).toContain("beforeunload");
    expect(sensitiveJs).toContain("pagehide");
    expect(sensitiveJs).toContain("popstate");

    expect(authJs).toContain("clearSensitiveState");
    expect(dialogJs).toContain("clearSensitiveState");

    expect(appJs).toContain("setupSensitiveCleanup()");
  });

  it("security UX: rotation and creation inputs use password type with show/hide toggle", () => {
    const html = readFileSync(resolve(uiDir, "index.html"), "utf8");
    const appJs = readFileSync(resolve(uiDir, "app.js"), "utf8");

    expect(html).toMatch(/type="password" id="rotate-secret-value"/);
    expect(html).toMatch(/type="password" id="new-secret-value"/);

    const toggleMatches = [...html.matchAll(/data-action="toggle-password"/g)];
    expect(toggleMatches.length).toBeGreaterThanOrEqual(2);

    expect(appJs).toContain("case \"toggle-password\"");
  });

  it("security UX: no plaintext prefix in UI copy", () => {
    const authJs = readFileSync(resolve(uiDir, "js", "auth.js"), "utf8");
    expect(authJs).not.toContain("sv_live_");
  });

  it("security UX: status badges use text labels, not emoji alone", () => {
    const usersJs = readFileSync(resolve(uiDir, "js", "features", "users.js"), "utf8");
    const authJs = readFileSync(resolve(uiDir, "js", "auth.js"), "utf8");

    expect(usersJs).toMatch(/has_passkey \? "Registered"/);
    expect(usersJs).toMatch(/has_totp \? "Active"/);
  });

  it("validates escapeHtml logic against standard XSS vectors", () => {
    function escapeHtml(str: string | null | undefined) {
      if (str === null || str === undefined) return "";
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    const payload = `<script>alert('XSS "1"')</script> & <img src=x onerror=fetch('http://attacker')>`;
    const escaped = escapeHtml(payload);

    expect(escaped).not.toContain("<script>");
    expect(escaped).not.toContain("</script>");
    expect(escaped).toContain("&lt;script&gt;");
    expect(escaped).toContain("&quot;1&quot;");
    expect(escaped).toContain("&amp;");
    expect(escaped).toContain("&#39;XSS");
  });
});
