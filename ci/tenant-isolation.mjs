#!/usr/bin/env node
// SV-AUD-013 acceptance: prove the DATABASE enforces tenant isolation.
//
// Mints two tenant-scoped sv_runtime JWTs (User A, User B), seeds a secrets row
// for each through PostgREST, and asserts neither can see/mutate the other's
// row — including an INSERT with the other tenant's user_id (blocked by
// WITH CHECK) and a SELECT with NO user_id filter (must still return only the
// caller's rows). This is the test a mock cannot satisfy: a missed application
// .eq("user_id") must NOT become a cross-tenant breach.
//
// Runs against the CI PostgREST service after the stack is healthy:
//   node ci/tenant-isolation.mjs http://127.0.0.1:3001

import { execFileSync } from "node:child_process";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const base = resolve(here, "..");

const url = process.argv[2] || process.env.PGRST_URL || "http://localhost:3000";
let failures = 0;
const fail = (m) => { failures += 1; console.error(`✗ ${m}`); };
const ok = (m) => console.log(`✓ ${m}`);

// Mint a tenant token: role=sv_runtime + tenant_user_id claim, via the extended
// ci/mint-jwt.mjs (reads JWT_TENANT_USER_ID).
function tenantToken(role, userId, { clientId, isAdmin } = {}) {
  const env = { ...process.env, JWT_TENANT_USER_ID: userId };
  if (clientId !== undefined) env.JWT_CLIENT_ID = clientId;
  env.JWT_IS_ADMIN = isAdmin ? "1" : "0";
  return execFileSync("node", [join(base, "ci", "mint-jwt.mjs"), role], { encoding: "utf8", env }).trim();
}

async function request(path, key, { method = "GET", body, query } = {}) {
  const u = new URL(path, url);
  if (query) for (const [k, v] of Object.entries(query)) u.searchParams.set(k, v);
  const init = { method, headers: { Authorization: `Bearer ${key}`, apikey: key } };
  if (body) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
  const res = await fetch(u, init);
  let text = null;
  try { text = await res.text(); } catch {}
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch {}
  return { status: res.status, body: text, json };
}

// Two pre-created tenants. In CI these are seeded by the test setup; their UUIDs
// are deterministic enough to pass via env, or default to fixed test UUIDs.
const USER_A = process.env.TENANT_A_ID || "00000000-0000-0000-0000-00000000000a";
const USER_B = process.env.TENANT_B_ID || "00000000-0000-0000-0000-00000000000b";
const SECRET_A = "ci-tenant-a-secret";
const SECRET_B = "ci-tenant-b-secret";

async function main() {
  const tokenA = tenantToken("sv_runtime", USER_A);
  const tokenB = tenantToken("sv_runtime", USER_B);

  // Seed one secret per tenant as that tenant (WITH CHECK admits own user_id).
  const seedA = await request("/rest/v1/secrets", tokenA, {
    method: "POST",
    body: { name: SECRET_A, user_id: USER_A, encrypted_blob: "x", masked_preview: "••", key_prefix: "a", key_suffix: "b", tags: [] },
  });
  if (seedA.status >= 300) fail(`User A could not seed its own secret (${seedA.status}): ${seedA.body}`);
  else ok("User A seeds its own secret (WITH CHECK admits own tenant)");

  const seedB = await request("/rest/v1/secrets", tokenB, {
    method: "POST",
    body: { name: SECRET_B, user_id: USER_B, encrypted_blob: "x", masked_preview: "••", key_prefix: "a", key_suffix: "b", tags: [] },
  });
  if (seedB.status >= 300) fail(`User B could not seed its own secret (${seedB.status}): ${seedB.body}`);
  else ok("User B seeds its own secret (WITH CHECK admits own tenant)");

  // 1. User A cannot SELECT User B's secret by name (no .eq leak — query B's row).
  const crossRead = await request("/rest/v1/secrets", tokenA, { query: { name: `eq.${SECRET_B}`, select: "name" } });
  if (crossRead.status === 200 && Array.isArray(crossRead.json) && crossRead.json.length === 0) {
    ok("User A cannot read User B's secret (RLS hides other tenants)");
  } else {
    fail(`User A saw User B's secret (status ${crossRead.status}): ${crossRead.body}`);
  }

  // 2. User A's unfiltered SELECT returns ONLY its own rows (the acceptance
  //    criterion: a dropped .eq("user_id") still returns only the caller's rows).
  const ownOnly = await request("/rest/v1/secrets", tokenA, { query: { select: "name" } });
  const names = Array.isArray(ownOnly.json) ? ownOnly.json.map((r) => r.name) : [];
  if (ownOnly.status === 200 && names.includes(SECRET_A) && !names.includes(SECRET_B)) {
    ok("User A unfiltered SELECT returns only its own rows (DB enforces tenant scope)");
  } else {
    fail(`Unfiltered SELECT did not isolate tenant: ${JSON.stringify(names)}`);
  }

  // 3. User A cannot INSERT a secret under User B's user_id (WITH CHECK blocks).
  const crossInsert = await request("/rest/v1/secrets", tokenA, {
    method: "POST",
    body: { name: "ci-cross-insert", user_id: USER_B, encrypted_blob: "x", masked_preview: "••", key_prefix: "a", key_suffix: "b", tags: [] },
  });
  if (crossInsert.status >= 400) ok(`User A cannot insert under User B's tenant (${crossInsert.status})`);
  else fail(`Cross-tenant INSERT succeeded (${crossInsert.status}): ${crossInsert.body}`);

  // 4. User A cannot UPDATE User B's secret.
  const crossUpdate = await request("/rest/v1/secrets", tokenA, {
    method: "PATCH",
    query: { name: `eq.${SECRET_B}` },
    body: { masked_preview: "hax" },
  });
  // PostgREST reports 204 even when RLS matched zero rows, so — exactly like
  // the DELETE check below — the proof is that B's row is unchanged afterward,
  // not the PATCH status code.
  const bAfterUpdate = await request("/rest/v1/secrets", tokenB, {
    query: { name: `eq.${SECRET_B}`, select: "masked_preview" },
  });
  const rowUntouched =
    bAfterUpdate.status === 200 && Array.isArray(bAfterUpdate.json) &&
    bAfterUpdate.json.length === 1 && bAfterUpdate.json[0].masked_preview !== "hax";
  const statusAcceptable =
    crossUpdate.status >= 400 ||
    crossUpdate.status === 204 ||
    (crossUpdate.status === 200 && Array.isArray(crossUpdate.json) && crossUpdate.json.length === 0);
  if (statusAcceptable && rowUntouched) {
    ok("User A cannot update User B's secret (B's row untouched)");
  } else {
    fail(`Cross-tenant UPDATE mutated B's row (PATCH ${crossUpdate.status}; re-read: ${bAfterUpdate.status} ${bAfterUpdate.body})`);
  }

  // 5. User A cannot DELETE User B's secret.
  const crossDelete = await request("/rest/v1/secrets", tokenA, { method: "DELETE", query: { name: `eq.${SECRET_B}` } });
  // PostgREST returns 200 always; the proof is that B's row still exists afterward.
  const bStillThere = await request("/rest/v1/secrets", tokenB, { query: { name: `eq.${SECRET_B}`, select: "name" } });
  if (bStillThere.status === 200 && Array.isArray(bStillThere.json) && bStillThere.json.length === 1) {
    ok("User A cannot delete User B's secret (B's row survives)");
  } else {
    fail(`Cross-tenant DELETE removed B's row: ${crossDelete.status} / ${bStillThere.body}`);
  }

  // 6. anon JWT sees nothing.
  const anonToken = execFileSync("node", [join(base, "ci", "mint-jwt.mjs"), "anon"], { encoding: "utf8" }).trim();
  const anonRead = await request("/rest/v1/secrets", anonToken, { query: { select: "name" } });
  if ((anonRead.status === 200 && Array.isArray(anonRead.json) && anonRead.json.length === 0) || anonRead.status === 401) {
    ok("anon JWT sees no secrets");
  } else {
    fail(`anon saw secrets (${anonRead.status}): ${anonRead.body}`);
  }

  if (failures > 0) { console.error(`\n${failures} tenant-isolation check(s) failed`); process.exit(1); }
  console.log("\nAll tenant-isolation checks passed — the database enforces tenant scope.");
}

main().catch((e) => { console.error(e); process.exit(1); });
