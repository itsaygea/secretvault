#!/usr/bin/env node
// SV-029 acceptance: assert the real PostgREST grant/RLS matrix the
// migrations define. Runs against the CI PostgREST service.
//
//   service_role  -> can use only global/pre-auth tables and RPCs
//   sv_runtime   -> can use tenant tables only with a tenant claim
//   anon         -> CANNOT read or write tenant data
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

function mint(role, tenantUserId) {
  const env = { ...process.env };
  if (tenantUserId) {
    // ci/mint-jwt.mjs translates this into the signed tenant_user_id claim.
    env.JWT_TENANT_USER_ID = tenantUserId;
    env.JWT_IS_ADMIN = "0";
  } else {
    delete env.JWT_TENANT_USER_ID;
    delete env.JWT_CLIENT_ID;
    delete env.JWT_IS_ADMIN;
  }
  return execFileSync("node", [join(base, "ci", "mint-jwt.mjs"), role], {
    encoding: "utf8",
    env,
  }).trim();
}

const url = process.argv[2] || process.env.PGRST_URL || "http://localhost:3000";
const serviceKey = process.argv[3] || process.env.SERVICE_KEY || mint("service_role");
const anonKey = process.argv[4] || process.env.ANON_KEY || mint("anon");
const permissionCheckUserId = process.env.PERMISSION_CHECK_USER_ID || "00000000-0000-0000-0000-00000000000c";
const runtimeKey = process.argv[5] || process.env.RUNTIME_KEY || mint("sv_runtime", permissionCheckUserId);

let failures = 0;
const fail = (m) => { failures += 1; console.error(`✗ ${m}`); };

async function request(path, key, { method = "GET", limit, body, prefer = "return=representation" } = {}) {
  const u = new URL(path, url);
  if (limit) u.searchParams.set("select", "id");
  if (limit) u.searchParams.set("limit", String(limit));
  const headers = { apikey: key, Authorization: `Bearer ${key}` };
  const init = { method, headers };
  if (body) {
    headers["Content-Type"] = "application/json";
    headers["Prefer"] = prefer;
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
  // 0. Seed a tenant user through the global service_role path. This is the
  //    only tenant-adjacent operation service_role should need here; direct
  //    tenant-table access is intentionally denied below.
  const seedUser = await request("/rest/v1/users", serviceKey, {
    method: "POST",
    body: {
      id: permissionCheckUserId,
      username: "ci-permission-check",
      password_hash: "ci-test-placeholder",
      is_admin: false,
    },
    prefer: "resolution=merge-duplicates,return=minimal",
  });
  if (seedUser.status >= 300) {
    fail(`service_role could not seed the permission-check user (status ${seedUser.status}): ${seedUser.body}`);
  } else {
    console.log("✓ service_role can use the global users path needed for pre-auth setup");
  }

  // 1. service_role MUST NOT read or write tenant tables directly. Migration
  //    029 removes even residual TRUNCATE/REFERENCES/TRIGGER privileges; the
  //    application uses narrow pre-auth RPCs until it can mint sv_runtime.
  const serviceWrite = await request("/rest/v1/access_logs", serviceKey, {
    method: "POST",
    body: { user_id: permissionCheckUserId, secret_name: "system", access_type: "perm_check", caller: "service_role" },
  });
  if (serviceWrite.status >= 400) {
    console.log(`✓ service_role is denied tenant-table INSERT (status ${serviceWrite.status})`);
  } else {
    fail(`service_role was able to INSERT access_logs (status ${serviceWrite.status}): ${serviceWrite.body}`);
  }
  const serviceRead = await request("/rest/v1/access_logs", serviceKey, { limit: 1 });
  if (serviceRead.status >= 400) {
    console.log(`✓ service_role is denied tenant-table SELECT (status ${serviceRead.status})`);
  } else {
    fail(`service_role was able to SELECT access_logs (status ${serviceRead.status}): ${serviceRead.body}`);
  }

  // 2. sv_runtime can write/read its own tenant row. The non-empty read is
  //    important: a 200 [] could otherwise hide a broken RLS policy.
  const runtimeSeed = await request("/rest/v1/access_logs", runtimeKey, {
    method: "POST",
    body: {
      user_id: permissionCheckUserId,
      secret_name: "system",
      access_type: "perm_check",
      caller: "sv_runtime",
    },
  });
  if (runtimeSeed.status >= 300) {
    fail(`sv_runtime could not INSERT its tenant row (status ${runtimeSeed.status}): ${runtimeSeed.body}`);
  } else {
    console.log("✓ sv_runtime writes its own tenant-scoped access log");
  }
  const runtimeRead = await request("/rest/v1/access_logs", runtimeKey, { limit: 1 });
  const runtimeData = parseJson(runtimeRead.body);
  if (runtimeRead.status === 200 && Array.isArray(runtimeData) && runtimeData.length > 0) {
    console.log("✓ sv_runtime reads tenant access logs with a tenant claim");
  } else {
    fail(`sv_runtime tenant read failed or empty (status ${runtimeRead.status}): ${runtimeRead.body}`);
  }

  // 3. anon CANNOT read access_logs (RLS denies; empty or 401).
  const anon = await request("/rest/v1/access_logs", anonKey, { limit: 1 });
  const anonData = parseJson(anon.body);
  const anonDenied = anon.status >= 400 || (Array.isArray(anonData) && anonData.length === 0);
  if (anonDenied) {
    console.log(`✓ anon denied secretvault.access_logs (status ${anon.status})`);
  } else {
    fail(`anon was NOT denied access_logs (status ${anon.status}): ${anon.body}`);
  }

  // 4. anon CANNOT write access_logs (RLS WITH CHECK blocks it).
  const anonWrite = await request("/rest/v1/access_logs", anonKey, {
    method: "POST",
    body: { secret_name: "system", access_type: "perm_check", caller: "anon" },
  });
  if (anonWrite.status >= 400) {
    console.log(`✓ anon cannot write secretvault.access_logs (status ${anonWrite.status})`);
  } else {
    fail(`anon was able to write access_logs (status ${anonWrite.status}): ${anonWrite.body}`);
  }

  // 5. service_role is denied on secrets too; this catches a partial revoke.
  const serviceSecrets = await request("/rest/v1/secrets", serviceKey, { limit: 1 });
  if (serviceSecrets.status >= 400) {
    console.log(`✓ service_role is denied tenant-table SELECT on secrets (status ${serviceSecrets.status})`);
  } else {
    fail(`service_role was able to SELECT secrets (status ${serviceSecrets.status}): ${serviceSecrets.body}`);
  }

  // 6. The role-specific OpenAPI views expose global users to service_role
  //    and tenant tables to sv_runtime. The auth schema is never exposed.
  const serviceOpenapi = await fetch(new URL("/", url), {
    headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` },
  });
  const serviceSpec = await serviceOpenapi.json();
  const servicePaths = Object.keys(serviceSpec.paths || {});
  const serviceExposesGlobal = servicePaths.includes("/users");
  const serviceExposesTenant = servicePaths.includes("/secrets") || servicePaths.includes("/access_logs");
  const serviceExposesAuth = servicePaths.some((p) => p.startsWith("/auth"));
  if (serviceExposesGlobal && !serviceExposesTenant && !serviceExposesAuth) {
    console.log("✓ service_role OpenAPI exposes global paths only, not tenant tables or auth");
  } else {
    if (!serviceExposesGlobal) fail("PostgREST does not expose the service_role users path");
    if (serviceExposesTenant) fail("PostgREST exposes tenant tables to service_role");
    if (serviceExposesAuth) fail("PostgREST exposes the auth schema (should be hidden)");
  }

  const runtimeOpenapi = await fetch(new URL("/", url), {
    headers: { apikey: runtimeKey, Authorization: `Bearer ${runtimeKey}` },
  });
  const runtimeSpec = await runtimeOpenapi.json();
  const runtimePaths = Object.keys(runtimeSpec.paths || {});
  const runtimeExposesTenant =
    runtimePaths.includes("/users") &&
    runtimePaths.includes("/secrets") &&
    runtimePaths.includes("/access_logs");
  const runtimeExposesAuth = runtimePaths.some((p) => p.startsWith("/auth"));
  if (runtimeExposesTenant && !runtimeExposesAuth) {
    console.log("✓ sv_runtime OpenAPI exposes tenant paths, not auth");
  } else {
    if (!runtimeExposesTenant) fail("PostgREST does not expose the sv_runtime tenant paths");
    if (runtimeExposesAuth) fail("PostgREST exposes the auth schema (should be hidden)");
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
