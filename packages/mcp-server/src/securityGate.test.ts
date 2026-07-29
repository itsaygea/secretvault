import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Security-gate contract tests (SV-026 / SV-056).
 *
 * These do not run a live Trivy scan. They assert the workflows that gate on
 * findings are configured to fail CI, that accepted risk is deliberate and
 * time-boxed, and that the gate self-test and action-pin linters pass.
 *
 * The repo root is two levels above this package's src directory.
 */
const repoRoot = resolve(__dirname, "..", "..", "..");
const workflowsDir = join(repoRoot, ".github", "workflows");

function runNode(script: string): string {
  return execFileSync("node", [join(repoRoot, script)], {
    encoding: "utf8",
    cwd: repoRoot,
  });
}

function workflowFiles(): string[] {
  if (!existsSync(workflowsDir)) return [];
  return readdirSync(workflowsDir).filter(
    (f) => f.endsWith(".yml") || f.endsWith(".yaml"),
  );
}

describe("security gate (SV-026)", () => {
  it("pins every GitHub Actions workflow to immutable commit SHAs", () => {
    expect(() => runNode("scripts/check-workflow-pins.mjs")).not.toThrow();
  });

  it("the Trivy gate self-test passes", () => {
    expect(() => runNode("scripts/test-trivy-gate.mjs")).not.toThrow();
  });

  it("no workflow references a mutable action tag", () => {
    const mutable = /uses:\s+[\w./-]+@(master|main|latest|v\d+(?:\.\d+)*)(?!\S)/;
    for (const file of workflowFiles()) {
      const text = readFileSync(join(workflowsDir, file), "utf8");
      // Strip the trailing tag-comment so "uses: ...@<sha> # v4" is not matched.
      const stripped = text.replace(/(#.*)$/gm, "");
      expect(
        mutable.test(stripped),
        `${file} contains a mutable action ref`,
      ).toBe(false);
    }
  });

  it("at least one workflow runs the Trivy container gate with exit-code 1", () => {
    const gated = workflowFiles().some((file) => {
      const text = readFileSync(join(workflowsDir, file), "utf8");
      const blocks = text.split(/(?=\n\s*-\s*(?:name|uses):)/);
      return blocks.some(
        (b) =>
          /aquasecurity\/trivy-action@/.test(b) &&
          /^\s*severity:\s*\S/m.test(b) &&
          /^\s*exit-code:\s*"?1"?\s*$/m.test(b),
      );
    });
    expect(gated).toBe(true);
  });

  it("accepted-risk register is well-formed YAML-list-shaped", () => {
    const register = join(repoRoot, ".github", "trivy", "accepted-risk.yml");
    expect(existsSync(register)).toBe(true);
    const text = readFileSync(register, "utf8");
    // Header documents the four required fields a real entry must carry.
    expect(text).toMatch(/owner/);
    expect(text).toMatch(/rationale/);
    expect(text).toMatch(/scope/);
    expect(text).toMatch(/expiration/);
  });
});

describe("security reporting policy (SV-056)", () => {
  it("SECURITY.md no longer points at the placeholder contact", () => {
    const policy = readFileSync(join(repoRoot, "SECURITY.md"), "utf8");
    expect(policy).not.toMatch(/security@example\.com/);
    // Preferred path is GitHub Private Vulnerability Reporting.
    expect(policy.toLowerCase()).toMatch(/private vulnerabilit|security advisory/);
  });

  it("SECURITY.md documents supported versions and response expectations", () => {
    const policy = readFileSync(join(repoRoot, "SECURITY.md"), "utf8").toLowerCase();
    expect(policy).toMatch(/supported version/);
    expect(policy).toMatch(/response|acknowledge|sla/);
    expect(policy).toMatch(/disclos/);
  });
});
