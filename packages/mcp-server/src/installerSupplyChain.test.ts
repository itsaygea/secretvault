import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "@secretvault/testing";

const root = resolve(import.meta.dirname, "..", "..", "..");
const server = readFileSync(resolve(root, "install-server.sh"), "utf8");
const client = readFileSync(resolve(root, "install-client.sh"), "utf8");

// SV-AUD-012: installers must be fail-closed and verify immutable artifacts.
describe.each([
  ["install-server.sh", server],
  ["install-client.sh", client],
])("%s supply-chain posture (SV-AUD-012)", (_name, text) => {
  it("runs fail-closed with set -euo pipefail", () => {
    expect(text).toMatch(/set\s+-euo\s+pipefail/);
  });

  it("defines a fail-closed verify_sha256 helper", () => {
    expect(text).toMatch(/verify_sha256\s*\(\)/);
    // The helper must abort on mismatch, not warn-and-continue.
    const fn = text.split("verify_sha256()")[1] ?? "";
    expect(fn).toMatch(/exit\s+1/);
    expect(fn).toMatch(/Integrity verification FAILED/);
  });

  it("supports an immutable release ref (SECRETVAULT_RELEASE_TAG)", () => {
    expect(text).toMatch(/SECRETVAULT_RELEASE_TAG/);
    expect(text).toMatch(/SECRETVAULT_TARBALL_SHA256/);
  });

  it("clones a pinned ref with --branch/--checkout rather than unconditionally mutable main", () => {
    expect(text).toMatch(/--branch "\$RELEASE_REF"/);
  });

  it("refuses an immutable ref when no checksum is supplied (fail-closed)", () => {
    expect(text).toMatch(/without SECRETVAULT_TARBALL_SHA256 .* fail-closed|requested without SECRETVAULT_TARBALL_SHA256 .* Aborting/s);
  });
});

describe("install-client.sh fail-closed install (SV-AUD-012)", () => {
  it("does not swallow the global npm CLI install with || true", () => {
    // The critical install line must NOT end in `|| true`. It may keep a
    // best-effort fallback (`|| npm install -g ... --prefix=...`), which is a
    // genuine alternate path, not a silent swallow. Find the line and assert it
    // is not terminated by a bare `|| true`.
    const lines = client.split("\n");
    const installLine = lines.find((l) => /npm install -g \.\/packages\/mcp-server/.test(l));
    expect(installLine, "npm install -g line should exist").toBeDefined();
    expect(installLine!).not.toMatch(/\|\|\s*true\s*$/);
  });
});

describe("SV-AUD-012 mutable-branch URL containment", () => {
  // When a release tag is set, the mutable main tarball URL is only reached via
  // the RELEASE_REF=main branch. The archive URL must be parameterized through
  // ARCHIVE_REF, not hardcoded into the execute path for tagged installs.
  it("parameterizes the archive URL through ARCHIVE_REF", () => {
    expect(server).toMatch(/\$\{ARCHIVE_REF\}\.tar\.gz/);
    expect(client).toMatch(/\$\{ARCHIVE_REF\}\.tar\.gz/);
  });

  it("prints a warning when falling back to mutable main", () => {
    expect(server).toMatch(/fetching mutable 'main'/i);
    expect(client).toMatch(/fetching mutable 'main'/i);
  });
});
