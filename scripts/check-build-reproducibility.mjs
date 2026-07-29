// SV-050, SV-051, SV-052: Build reproducibility and artifact integrity
// Run after `npm run build` to ensure:
//   1. No nested/stale UI artifacts (repeatable build)
//   2. All ESM packages declare type:module
//   3. No stale test files in dist (files field excludes them)
//   4. Deprecated surfaces emit warnings

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];

// 1. Check that dist/ui/ has no nested ui/ directory (stale artifact)
const distUi = join(root, "packages", "mcp-server", "dist", "ui");
if (existsSync(distUi)) {
  const distUiIndex = join(distUi, "index.html");
  if (!existsSync(distUiIndex)) {
    errors.push("mcp-server/dist/ui/index.html missing — UI was not copied correctly");
  }
  const nestedUi = join(distUi, "ui");
  if (existsSync(nestedUi) && statSync(nestedUi).isDirectory()) {
    errors.push("nested stale UI artifact detected: dist/ui/ui/ exists — clean build should remove this");
  }
}

// 2. Verify all ESM-emitting packages declare type:module
const packages = ["shared", "client", "admin", "bridge", "sdk", "mcp-server"];
for (const pkg of packages) {
  const pkgJsonPath = join(root, "packages", pkg, "package.json");
  if (!existsSync(pkgJsonPath)) {
    errors.push(`packages/${pkg}/package.json not found`);
    continue;
  }
  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
  // All packages emit ESM (tsconfig uses "module": "esnext")
  if (pkgJson.type !== "module") {
    errors.push(`packages/${pkg} is missing "type": "module"`);
  }
  // Verify files field excludes test artifacts (check only positive patterns, not negations)
  if (!pkgJson.files) {
    errors.push(`packages/${pkg} is missing "files" field`);
  } else {
    const positivePatterns = pkgJson.files.filter((f) => !f.startsWith("!"));
    const includesTest = positivePatterns.some((f) => f.includes("test"));
    if (includesTest) {
      errors.push(`packages/${pkg} "files" field includes test artifacts`);
    }
  }
}

// 3. Verify runtime dist files exist for all packages
for (const pkg of packages) {
  const distDir = join(root, "packages", pkg, "dist");
  if (!existsSync(distDir)) {
    errors.push(`packages/${pkg}/dist does not exist — build may not have run`);
    continue;
  }
  const indexJs = join(distDir, "index.js");
  if (pkg !== "mcp-server" && !existsSync(indexJs)) {
    errors.push(`packages/${pkg}/dist/index.js missing`);
  }
}

// 4. Verify deprecated bridge/sdk modules emit warnings
try {
  const bridgeSrc = readFileSync(join(root, "packages", "bridge", "src", "index.ts"), "utf8");
  if (!bridgeSrc.includes("console.warn") || !bridgeSrc.includes("deprecation")) {
    errors.push("bridge/src/index.ts missing runtime deprecation warning");
  }
} catch { errors.push("could not read bridge/src/index.ts"); }

try {
  const sdkSrc = readFileSync(join(root, "packages", "sdk", "src", "index.ts"), "utf8");
  if (!sdkSrc.includes("console.warn") || !sdkSrc.includes("deprecation")) {
    errors.push("sdk/src/index.ts missing runtime deprecation warning");
  }
} catch { errors.push("could not read sdk/src/index.ts"); }

// 5. Verify SSE endpoint has deprecation headers
try {
  const indexSrc = readFileSync(join(root, "packages", "mcp-server", "src", "index.ts"), "utf8");
  if (!indexSrc.includes("Legacy SSE endpoints (deprecated)")) {
    errors.push("mcp-server/src/index.ts missing SSE deprecation notice");
  }
  if (!indexSrc.includes("Deprecation")) {
    errors.push("mcp-server/src/index.ts missing Deprecation header on SSE endpoint");
  }
  if (!indexSrc.includes("successor-version")) {
    errors.push("mcp-server/src/index.ts missing successor-version Link header on SSE endpoint");
  }
} catch { errors.push("could not read mcp-server/src/index.ts"); }

// 6. Verify dead entrypoint (runnerBin.ts) is marked deprecated
try {
  const runnerBin = readFileSync(join(root, "packages", "mcp-server", "src", "runnerBin.ts"), "utf8");
  if (!runnerBin.includes("DEPRECATED")) {
    errors.push("runnerBin.ts is not marked as DEPRECATED");
  }
} catch { errors.push("could not read runnerBin.ts"); }

if (errors.length > 0) {
  console.error("Build reproducibility checks failed:");
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log(`Build reproducibility check passed (${packages.length} packages, ${errors.length} errors).`);
}
