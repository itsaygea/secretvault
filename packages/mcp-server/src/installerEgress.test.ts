import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * SV-058: the installer must not advertise "empty for all" for the egress
 * allowlist (that implied unrestricted access, when an empty allowlist is
 * actually default-deny for non-admins). It must explain the real semantics
 * and confirm the resulting boundary before writing the config.
 */
describe("SV-058 installer egress prompt", () => {
  const installer = readFileSync(resolve(__dirname, "..", "..", "..", "install-server.sh"), "utf8");

  it("no longer claims empty input means allow-all", () => {
    expect(installer).not.toMatch(/empty for all/i);
  });

  it("states the default-deny semantics for an empty allowlist", () => {
    expect(installer).toMatch(/default-deny/i);
    expect(installer).toMatch(/empty = default-deny/i);
  });

  it("warns separately about the administrator override / private-network mode", () => {
    expect(installer).toMatch(/Administrators can ALWAYS create a destination/i);
    expect(installer).toMatch(/private-network/i);
  });

  it("shows the resulting egress boundary and asks for confirmation", () => {
    expect(installer).toMatch(/Resulting egress boundary/i);
    expect(installer).toMatch(/Proceed with this egress boundary/i);
  });
});
