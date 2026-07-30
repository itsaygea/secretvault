#!/usr/bin/env node
// Mint the HS256 JWT that real PostgREST accepts as the SecretVault service
// key in CI. The token carries role=service_role so PostgREST sets
// request.jwt.claim.role and the 001 RLS policies pass, exactly as Supabase
// Cloud does in production. Used by ci/secretvault.env generation.
//
//   node ci/mint-jwt.mjs <role>            -> prints the JWT
//   SERVICE_DATE_EPOCH / PGRST_JWT_SECRET env override defaults below

import { createHmac, timingSafeEqual } from "node:crypto";

const DEFAULT_SECRET = "ci-postgrest-jwt-secret-do-not-use-in-production";
const secret = process.env.PGRST_JWT_SECRET || DEFAULT_SECRET;
const role = process.argv[2] || "service_role";
// Deterministic timestamps so the token is reproducible in CI. iat is fixed
// in the past; exp is fixed far enough in the future (2099-01-01) that the
// committed token never expires during CI runs.
const iat = Number(process.env.SOURCE_DATE_EPOCH || 1735689600); // 2025-01-01
const exp = Number(process.env.CI_JWT_EXP || 4070908800); // 2099-01-01

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=+$/, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

const header = { alg: "HS256", typ: "JWT" };
const payload = {
  role,
  iss: "secretvault-ci",
  iat,
  exp,
  ref: "ci",
};
// SV-AUD-013: optional tenant claims for the cross-tenant isolation test. When
// JWT_TENANT_USER_ID is set, the token carries tenant_user_id / client_id /
// is_admin so PostgREST exposes them as request.jwt.claims and the tenant RLS
// policies (migration 022) bind. Absent = the legacy global token.
if (process.env.JWT_TENANT_USER_ID) {
  payload.tenant_user_id = process.env.JWT_TENANT_USER_ID;
  if (process.env.JWT_CLIENT_ID) payload.client_id = process.env.JWT_CLIENT_ID;
  payload.is_admin = process.env.JWT_IS_ADMIN === "1" || process.env.JWT_IS_ADMIN === "true";
}
const encHeader = b64url(JSON.stringify(header));
const encPayload = b64url(JSON.stringify(payload));
const signingInput = `${encHeader}.${encPayload}`;
const sig = createHmac("sha256", secret).update(signingInput).digest();
const token = `${signingInput}.${b64url(sig)}`;

// Quick self-check so a bad secret is caught at mint time, not in the app.
const re = createHmac("sha256", secret).update(signingInput).digest();
if (re.length !== sig.length || !timingSafeEqual(re, sig)) {
  console.error("jwt self-verification failed");
  process.exit(1);
}

console.log(token);
