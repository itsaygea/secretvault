import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "@secretvault/testing";

const installer = readFileSync(
  resolve(import.meta.dirname, "..", "..", "..", "install-server.sh"),
  "utf8",
);

describe("SV-057 installer hardening — no eval", () => {
  it("contains no eval statement", () => {
    const evalLines = installer
      .split("\n")
      .filter((line) => /^\s*eval\s/.test(line) && !/^\s*#/.test(line));
    expect(evalLines).toHaveLength(0);
  });

  it("uses $(...) command substitution instead of eval for variable capture", () => {
    const lines = installer.split("\n");
    const promptCalls = lines.filter(
      (l) => l.includes("$(prompt_with_default") || l.includes("$(prompt_password"),
    );
    expect(promptCalls.length).toBeGreaterThan(0);

    const evalCalls = lines.filter(
      (l) => l.includes("prompt_with_default") || l.includes("prompt_password"),
    );
    for (const line of evalCalls) {
      if (line.trimStart().startsWith("#")) continue;
      if (line.includes("function") || line.includes("()")) continue;
      expect(line).not.toMatch(/prompt_(with_default|password)\s+"[^"]+"\s+\w+$/);
    }
  });
});

describe("SV-057 installer hardening — safe .env encoding", () => {
  it("writes values inside single-quoted shell literals", () => {
    // Anchor on the .env-write block by its stable banner, not a step number
    // (the backend selector added in #94 shifts step indices).
    const envSection = installer.split("Writing .env configuration file")[1] || installer;
    const keyLines = envSection
      .split("\n")
      .filter(
        (l) =>
          /^SECRETVAULT_/.test(l.trim()) &&
          !/^SECRETVAULT_DATABASE_SSL\b/.test(l.trim()) &&
          !/^SECRETVAULT_PROXY_TIMEOUT_MS\b/.test(l.trim()),
      );
    for (const line of keyLines) {
      expect(line).toMatch(/='.*'/);
    }
  });

  it("does not use heredoc for .env output", () => {
    expect(installer).not.toMatch(/cat\s+<<\s*EOF\b/);
  });
});

describe("SV-057 installer hardening — percent-encoding", () => {
  it("defines a url_encode function", () => {
    expect(installer).toMatch(/url_encode\(\)/);
  });

  it("uses url_encode for database URI user and password", () => {
    // Anchor on the guided external-PostgreSQL block (option 2) where
    // url_encode is applied to DB_USER/DB_PASS/DB_NAME. The backend selector
    // added in #94 moved this off a fixed step number, so anchor on content.
    const dbSection =
      installer.split("Guided setup")[1]?.split("Admin Bootstrap Password")[0] || installer;
    expect(dbSection).toMatch(/url_encode\s+"\$\{?DB_USER\}?"/);
    expect(dbSection).toMatch(/url_encode\s+"\$\{?DB_PASS\}?"/);
    expect(dbSection).toMatch(/url_encode\s+"\$\{?DB_NAME\}?"/);
  });
});

describe("SV-057 installer hardening — input validation", () => {
  it("validates numeric port range", () => {
    expect(installer).toMatch(/validate_port/);
  });

  it("validates boolean values for SSL toggle", () => {
    expect(installer).toMatch(/validate_boolean/);
  });
});

describe("SV-057 installer hardening — atomic write and cleanup", () => {
  it("writes to a temporary file first", () => {
    expect(installer).toMatch(/\$\{?ENV_FILE\}?\.tmp/);
  });

  it("uses mv for atomic replacement", () => {
    expect(installer).toMatch(/mv\s+"?\$ENV_TMP"?\s+"?\$ENV_FILE"?/);
  });

  it("sets restrictive umask before writing secrets", () => {
    expect(installer).toMatch(/umask 077/);
  });

  it("cleans up temporary files on exit", () => {
    expect(installer).toMatch(/trap.*cleanup.*EXIT/);
  });

  it("backs up existing .env before overwriting", () => {
    expect(installer).toMatch(/\.env\.backup/);
  });
});
