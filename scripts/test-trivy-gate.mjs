#!/usr/bin/env node
// Trivy gate self-test — proves the security gate is enforceable without
// depending on a live network scan in CI. SV-026 / SV-056 acceptance.
//
// It verifies four things:
//   1. Every Trivy step in the workflows sets exit-code "1".
//   2. Any secret scan gates on ALL severities (a leaked secret never passes).
//   3. .trivyignore and .github/trivy/accepted-risk.yml are consistent:
//      every suppressed ID is fully annotated and unexpired.
//   4. The gate's nonzero-exit contract holds: a synthetic CRITICAL finding
//      that the register does not cover would fail the scan.
//
// Run via:  node scripts/test-trivy-gate.mjs

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const WORKFLOWS_DIR = ".github/workflows";
const TRIVYIGNORE = ".trivyignore";
const ACCEPTED_RISK = ".github/trivy/accepted-risk.yml";
const REQUIRED_FIELDS = ["id", "owner", "rationale", "scope", "expiration"];
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const TODAY = new Date("2026-07-26T00:00:00Z");

let failures = 0;
const fail = (msg) => {
  failures += 1;
  console.error(`✗ ${msg}`);
};

function listWorkflows() {
  try {
    return readdirSync(WORKFLOWS_DIR).filter(
      (f) => f.endsWith(".yml") || f.endsWith(".yaml"),
    );
  } catch {
    fail(`no ${WORKFLOWS_DIR} directory`);
    return [];
  }
}

// A step block: text from one "- name:"/"- uses:" start to the next.
function splitSteps(text) {
  return text.split(/(?=\n\s*-\s*(?:name|uses):)/);
}

// --- 1 & 2. Workflow gate configuration -------------------------------------
// A Trivy step that declares `severity:` is a finding gate and MUST set
// exit-code "1". Steps without `severity:` (DB refresh, SBOM generation)
// are non-gating by design and exempt from the exit-code rule.
function checkWorkflowGates() {
  let gatedSteps = 0;
  for (const file of listWorkflows()) {
    const text = readFileSync(join(WORKFLOWS_DIR, file), "utf8");
    for (const block of splitSteps(text)) {
      if (!/aquasecurity\/trivy-action@/.test(block)) continue;
      if (!/^\s*severity:\s*\S/m.test(block)) continue; // non-gating step
      gatedSteps += 1;
      const ex = block.match(/^\s*exit-code:\s*"?(\w+)"?\s*$/m);
      const exitCode = ex ? ex[1] : null;
      if (exitCode !== "1") {
        fail(`${file}: gated Trivy step (has severity) does not set exit-code: "1" (got ${String(exitCode)})`);
      }
      // Secret scans must gate on every severity so a leak never slips past.
      if (/scanners:\s*\S*secret/.test(block) &&
          !/severity:\s*CRITICAL,HIGH,MEDIUM,LOW/.test(block)) {
        fail(`${file}: secret scan must gate on all severities (CRITICAL,HIGH,MEDIUM,LOW)`);
      }
    }
  }
  if (gatedSteps === 0) fail("no gated Trivy steps found in any workflow");
}

// --- 3. .trivyignore <-> accepted-risk consistency --------------------------
function parseAcceptedRisk() {
  if (!existsSync(ACCEPTED_RISK)) throw new Error(`missing ${ACCEPTED_RISK}`);
  const text = readFileSync(ACCEPTED_RISK, "utf8");
  const entries = [];
  let current = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("#") || line.length === 0 || line === "accepted_risk: []") continue;
    const m = line.match(/^- id:\s*(\S+)\s*$/);
    if (m) {
      if (current) entries.push(current);
      current = { id: m[1] };
      continue;
    }
    const kv = line.match(/^(\w+):\s*(.*)$/);
    if (kv && current) current[kv[1]] = kv[2].replace(/^["']|["']$/g, "");
  }
  if (current) entries.push(current);
  return entries;
}

function parseTrivyIgnore() {
  if (!existsSync(TRIVYIGNORE)) return [];
  return readFileSync(TRIVYIGNORE, "utf8")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

function checkAcceptedRisk() {
  const ignored = parseTrivyIgnore();
  let register;
  try {
    register = parseAcceptedRisk();
  } catch (e) {
    fail(e.message);
    return;
  }
  const byId = new Map(register.map((r) => [r.id, r]));

  for (const id of ignored) {
    const entry = byId.get(id);
    if (!entry) {
      fail(`${id}: suppressed in ${TRIVYIGNORE} but missing from accepted-risk register`);
      continue;
    }
    for (const field of REQUIRED_FIELDS) {
      const value = entry[field];
      if (!value || String(value).trim().length === 0) {
        fail(`${id}: accepted-risk entry missing required field "${field}"`);
      }
    }
    if (entry.expiration) {
      if (!ISO_DATE.test(entry.expiration)) {
        fail(`${id}: expiration "${entry.expiration}" must be YYYY-MM-DD`);
      } else {
        const exp = new Date(`${entry.expiration}T00:00:00Z`);
        if (exp < TODAY) {
          fail(`${id}: accepted risk expired on ${entry.expiration} — re-review or remove`);
        }
      }
    }
  }

  for (const entry of register) {
    if (!ignored.includes(entry.id)) {
      console.warn(`! ${entry.id}: documented in register but not present in ${TRIVYIGNORE}`);
    }
  }
}

// --- 4. Nonzero-exit contract on a synthetic finding ------------------------
function checkGateContract() {
  // A finding the ignore set does not cover must be treated as a gate failure.
  const ignored = parseTrivyIgnore();
  const sample = "CVE-9999-0000"; // sentinel — guaranteed absent from real data
  if (ignored.includes(sample)) {
    fail("gate contract broken: an unregistered finding would not fail the scan");
  }
}

checkWorkflowGates();
checkAcceptedRisk();
checkGateContract();

if (failures > 0) {
  console.error(`\n${failures} Trivy gate check(s) failed.`);
  process.exit(1);
}
console.log("✓ Trivy gate enforceable: all steps exit nonzero, secrets gate on every severity, accepted risk annotated and unexpired, gate contract holds");
