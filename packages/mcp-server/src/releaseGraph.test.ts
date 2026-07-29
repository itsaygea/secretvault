import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

describe("Release Graph — Build Integrity (SV-050, SV-051, SV-052, SV-074)", () => {
  const packages = ["shared", "client", "admin", "bridge", "sdk", "mcp-server"];

  describe("Package declarations", () => {
    for (const pkg of packages) {
      it(`${pkg} has "type": "module"`, () => {
        const pkgJson = JSON.parse(
          readFileSync(join(root, "packages", pkg, "package.json"), "utf8")
        );
        // All packages emit ESM via tsconfig module=esnext
        expect(pkgJson.type).toBe("module");
      });

      it(`${pkg} has "files" field excluding tests`, () => {
        const pkgJson = JSON.parse(
          readFileSync(join(root, "packages", pkg, "package.json"), "utf8")
        );
        expect(pkgJson.files).toBeDefined();
        expect(Array.isArray(pkgJson.files)).toBe(true);
        // No positive file entry should include test artifacts for publish
        for (const entry of pkgJson.files) {
          // Negation patterns (starting with !) are fine — they exclude test files
          if (entry.startsWith("!")) continue;
          expect(entry).not.toMatch(/\.test\./);
        }
      });

      it(`${pkg} has "clean" script`, () => {
        const pkgJson = JSON.parse(
          readFileSync(join(root, "packages", pkg, "package.json"), "utf8")
        );
        expect(pkgJson.scripts?.clean).toBeDefined();
      });

      it(`${pkg} "build" script cleans first`, () => {
        const pkgJson = JSON.parse(
          readFileSync(join(root, "packages", pkg, "package.json"), "utf8")
        );
        expect(pkgJson.scripts?.build).toContain("clean");
      });
    }
  });

  describe("Deprecated compatibility surfaces", () => {
    it("@secretvault/bridge emits deprecation warning at module scope", () => {
      const src = readFileSync(
        join(root, "packages", "bridge", "src", "index.ts"),
        "utf8"
      );
      expect(src).toContain("console.warn");
      expect(src).toContain("deprecation");
      expect(src).toContain("@secretvault/bridge");
    });

    it("@secretvault/sdk emits deprecation warning at module scope", () => {
      const src = readFileSync(
        join(root, "packages", "sdk", "src", "index.ts"),
        "utf8"
      );
      expect(src).toContain("console.warn");
      expect(src).toContain("deprecation");
      expect(src).toContain("@secretvault/sdk");
    });

    it("SSE endpoint has deprecation headers", () => {
      const src = readFileSync(
        join(root, "packages", "mcp-server", "src", "index.ts"),
        "utf8"
      );
      expect(src).toContain("Legacy SSE endpoints (deprecated)");
      expect(src).toContain('"Deprecation"');
      expect(src).toContain('"successor-version"');
    });

    it("runnerBin.ts is marked DEPRECATED (dead entrypoint)", () => {
      const src = readFileSync(
        join(root, "packages", "mcp-server", "src", "runnerBin.ts"),
        "utf8"
      );
      expect(src).toContain("DEPRECATED");
      expect(src).toContain("dead entrypoint");
    });
  });

  describe("Root build configuration", () => {
    it("root package.json has clean and check scripts", () => {
      const pkgJson = JSON.parse(
        readFileSync(join(root, "package.json"), "utf8")
      );
      expect(pkgJson.scripts?.clean).toBeDefined();
      expect(pkgJson.scripts?.prebuild).toBeDefined();
      expect(pkgJson.scripts?.["check:build-reproducibility"]).toBeDefined();
    });
  });
});
