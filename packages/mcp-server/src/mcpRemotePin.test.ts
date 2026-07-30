import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const setupSrc = readFileSync(
  resolve(__dirname, "cli", "setup.ts"),
  "utf8",
);

// SV-AUD-012: the generated client launcher must pin mcp-remote to an audited
// exact version — it runs with the client key, so resolving "latest" at runtime
// is unverified remote code execution.
describe("mcp-remote version pinning (SV-AUD-012)", () => {
  it("declares a pinned MCP_REMOTE_VERSION constant", () => {
    expect(setupSrc).toMatch(/MCP_REMOTE_VERSION\s*=\s*"[\d.]+"/);
    expect(setupSrc).toMatch(/MCP_REMOTE_SPEC\s*=\s*`mcp-remote@\$\{MCP_REMOTE_VERSION\}`/);
  });

  it("the POSIX launcher execs the pinned spec, not bare mcp-remote", () => {
    expect(setupSrc).toMatch(/exec npx -y \$\{MCP_REMOTE_SPEC\}/);
  });

  it("the Windows launcher spawns the pinned spec, not bare mcp-remote", () => {
    expect(setupSrc).toMatch(/spawn\("npx", \["-y",\s*\$\{JSON\.stringify\(MCP_REMOTE_SPEC\)\}/);
  });

  it("does not emit an unpinned 'npx -y mcp-remote ' anywhere", () => {
    // Any remaining bare `mcp-remote` (no @version) in an npx invocation is a pinning leak.
    expect(setupSrc).not.toMatch(/npx\s+-y\s+"?mcp-remote"?(?!@)/);
  });
});
