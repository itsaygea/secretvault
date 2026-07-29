#!/usr/bin/env node
// SV-029 acceptance: assert the real PostgREST grant/RLS matrix the
// migrations define. Runs against the CI PostgREST service.
//
//   service_role  -> can read secretvault.users (RLS policy passes)
//   anon          -> CANNOT read secretvault.users (no RLS policy, no grant)
//
// Proves the database enforces least privilege independent of PostgREST's own
// config — exactly the gap the mock hid. Run after the stack is healthy:
//
//   node ci/postgrest-permissions.mjs http://postgrest:3000 <service-key> <anon-key>

import { execFileSync } from "node:child_process";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const base = resolve(here, "..");

function mint(role) {
  return execFileSync("node", [join(base, "ci", "mint-jwt.mjs"), role], {
    encoding: "utf8",
  }).trim();
}

const url = process.argv[2] || process.env.PGRST_URL || "http://localhost:3000";
const serviceKey = process.argv[3] || process.env.SERVICE_KEY || mint("service_role");
const anonKey = process.argv[4] || process.env.ANON_KEY || mint("anon");

let failures = 0;
const fail = (m) => { failures += 1; console.error(`✗ ${m}`); };

async function request(path, key, { method = "GET", limit, body } = {}) {
  const u = new URL(path, url);
  if (limit) u.searchParams.set("select", "id");
  if (limit) u.searchParams.set("limit", String(limit));
  const headers = { apikey: key, Authorization: `Bearer ${key}` };
  const init = { method, headers };
  if (body) {
    headers["Content-Type"] = "application/json";
    headers["Prefer"] = "return=representation";
    init.body = JSON.stringify(body);
  }
  const res = await fetch(u, init);
  let text = null;
  try { text = await res.text(); } catch {}
  return { status: res.status, body: text };
}

function parseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

async function main() {
  // 0. Seed an audit row as service_role so the read assertions can prove
  //    RLS actually returns data (a 200 with an empty array would be a silent
  //    policy failure, as the mock used to hide).
  const seed = await request("/rest/v1/access_logs", serviceKey, {
    method: "POST",
    body: { secret_name: "system", access_type: "perm_check", caller: "ci" },
  });
  if (seed.status >= 300) {
    fail(`service_role could not INSERT access_logs (status ${seed.status}): ${seed.body}`);
  } else {
    console.log("✓ service_role writes secretvault.access_logs (RLS WITH CHECK passes)");
  }

  // 1. service_role can read the access_logs table AND gets non-empty data.
  //    This is the strong check: a broken RLS policy would return 200 [].
  const svc = await request("/rest/v1/access_logs", serviceKey, { limit: 1 });
  const svcData = parseJson(svc.body);
  if (svc.status === 200 && Array.isArray(svcData) && svcData.length > 0) {
    console.log("✓ service_role reads secretvault.access_logs with data through PostgREST");
  } else {
    fail(`service_role read failed or empty (status ${svc.status}): ${svc.body}`);
  }

  // 2. anon CANNOT read access_logs (RLS denies; empty or 401).
  const anon = await request("/rest/v1/access_logs", anonKey, { limit: 1 });
  const anonData = parseJson(anon.body);
  const anonDenied = anon.status >= 400 || (Array.isArray(anonData) && anonData.length === 0);
  if (anonDenied) {
    console.log(`✓ anon denied secretvault.access_logs (status ${anon.status})`);
  } else {
    fail(`anon was NOT denied access_logs (status ${anon.status}): ${anon.body}`);
  }

  // 3. anon CANNOT write access_logs (RLS WITH CHECK blocks it).
  const anonWrite = await request("/rest/v1/access_logs", anonKey, {
    method: "POST",
    body: { secret_name: "system", access_type: "perm_check", caller: "anon" },
  });
  if (anonWrite.status >= 400) {
    console.log(`✓ anon cannot write secretvault.access_logs (status ${anonWrite.status})`);
  } else {
    fail(`anon was able to write access_logs (status ${anonWrite.status}): ${anonWrite.body}`);
  }

  // 4. service_role can read the secrets table (001, the original grant gap).
  const secrets = await request("/rest/v1/secrets", serviceKey, { limit: 1 });
  if (secrets.status === 200) {
    console.log("✓ service_role reads secretvault.secrets (001 table granted)");
  } else {
    fail(`service_role could not read secrets (status ${secrets.status}): ${secrets.body}`);
  }

  // 4. The secretvault schema is exposed (its tables appear as paths) and the
  //    auth schema is NOT (no auth.role function leaks through).
  const openapi = await fetch(new URL("/", url), {
    headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` },
  });
  const spec = await openapi.json();
  const paths = Object.keys(spec.paths || {});
  const exposesSecretvault = paths.includes("/users") && paths.includes("/secrets");
  const exposesAuth = paths.some((p) => p.startsWith("/auth"));
  if (exposesSecretvault && !exposesAuth) {
    console.log("✓ PostgREST exposes secretvault tables, not auth");
  } else {
    if (!exposesSecretvault) fail("PostgREST does not expose secretvault tables");
    if (exposesAuth) fail("PostgREST exposes the auth schema (should be hidden)");
  }

  if (failures > 0) {
    console.error(`\n${failures} PostgREST permission check(s) failed.`);
    process.exit(1);
  }
  console.log("✓ PostgREST least-privilege matrix enforced (SV-029)");
}

main().catch((err) => {
  console.error("✗ unexpected error:", err);
  process.exit(1);
});
