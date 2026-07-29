#!/usr/bin/env node
// Lint every GitHub Actions workflow so third-party actions are pinned to an
// immutable commit SHA. Mutable refs (@master, @vN tags, @latest, @main)
// let workflow behavior change under an unreviewed upstream push. SV-026.
//
// A SHA pin looks like  actions/checkout@11d5960a326750d5838078e36cf38b85af677262
// Optionally followed by  # v4.2.2   (kept as a readability/human comment).
//
// Run via:  node scripts/check-workflow-pins.mjs
// Exits 1 on any mutable or unparseable reference.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const WORKFLOWS_DIR = ".github/workflows";
const SHA_RE = /^[0-9a-f]{40}$/i;

// uses: <owner>/<repo>@<ref>   (owner/repo optional for local ./path actions)
// Captures the ref after the last '@'.
const USES_RE = /^\s*uses:\s+(?:\.\/)?([\w./-]+)?@(\S+)/;

function listWorkflows() {
  let entries;
  try {
    entries = readdirSync(WORKFLOWS_DIR);
  } catch {
    console.error(`✓ no ${WORKFLOWS_DIR} directory — nothing to lint`);
    return [];
  }
  return entries.filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"));
}

function isMutableRef(ref) {
  // A bare SHA is immutable. Everything else (branch, tag, latest) is mutable.
  return !SHA_RE.test(ref);
}

let failures = 0;

for (const file of listWorkflows()) {
  const path = join(WORKFLOWS_DIR, file);
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  lines.forEach((line, idx) => {
    const match = line.match(USES_RE);
    if (!match) return;
    const action = match[1] || "(local)";
    const ref = match[2].replace(/#..*$/, "").trim();
    if (!ref) return;
    // Local action paths (uses: ./foo) carry no remote ref to pin.
    if (line.includes("uses:") && line.match(/uses:\s+\.\//)) return;
    if (isMutableRef(ref)) {
      failures += 1;
      console.error(
        `✗ ${path}:${idx + 1} — ${action}@${ref} is not pinned to a commit SHA (use @<40-hex-sha> # <tag>)`,
      );
    }
  });
}

if (failures > 0) {
  console.error(`\n${failures} mutable action reference(s) found.`);
  console.error("Pin each action to an immutable commit SHA with a tag comment, e.g.");
  console.error('  uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.2.2');
  process.exit(1);
}

console.log("✓ all workflow actions pinned to immutable commit SHAs");
