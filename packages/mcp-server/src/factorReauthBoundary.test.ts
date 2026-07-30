import { createServer, type Server } from "node:http";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { authenticator } from "otplib";
import { encryptSecret, ENCRYPTION_PURPOSE, buildContextAad } from "@secretvault/shared";

process.env.NODE_ENV = "test";
process.env.SECRETVAULT_SUPABASE_URL = "http://supabase.test";
process.env.SECRETVAULT_SUPABASE_SERVICE_KEY = "test-service-key";
process.env.SECRETVAULT_MASTER_KEY = Buffer.alloc(32, 9).toString("hex");

type Row = Record<string, any>;

// ── Minimal in-memory Supabase (mirrors httpConformance.test.ts harness) ────

class FakeQuery {
  private operation: "select" | "insert" | "update" | "delete" = "select";
  private payload: Row | Row[] | null = null;
  private filters: Array<[string, unknown]> = [];
  private singleResult = false;
  private maybeSingleResult = false;
  constructor(private readonly db: FakeSupabase, private readonly table: string) {}
  select(): this { return this; }
  insert(p: Row | Row[]): this { this.operation = "insert"; this.payload = p; return this; }
  upsert(p: Row | Row[]): this { this.operation = "insert"; this.payload = p; return this; }
  update(p: Row): this { this.operation = "update"; this.payload = p; return this; }
  delete(): this { this.operation = "delete"; return this; }
  eq(c: string, v: unknown): this { this.filters.push([c, v]); return this; }
  order(): this { return this; }
  single(): Promise<{ data: Row | null; error: Row | null }> { this.singleResult = true; return this.execute(); }
  maybeSingle(): Promise<{ data: Row | null; error: Row | null }> { this.maybeSingleResult = true; return this.execute(); }
  then<T1 = { data: unknown; error: Row | null }, T2 = never>(
    onf?: ((v: { data: unknown; error: Row | null }) => T1 | PromiseLike<T1>) | null,
    onr?: ((r: unknown) => T2 | PromiseLike<T2>) | null,
  ): Promise<T1 | T2> { return this.execute().then(onf as any, onr as any); }
  private async execute(): Promise<{ data: any; error: Row | null }> {
    const rows = this.db.rows(this.table);
    const matches = rows.filter((r) => this.filters.every(([c, v]) => r[c] === v));
    if (this.operation === "insert") {
      const ins = Array.isArray(this.payload) ? this.payload : [this.payload ?? {}];
      const created = ins.map((p) => { const row = { id: `id-${Math.random().toString(36).slice(2)}`, ...p }; rows.push(row); return row; });
      return { data: this.singleResult ? created[0] : created, error: null };
    }
    if (this.operation === "update") { for (const r of matches) Object.assign(r, this.payload ?? {}); return { data: null, error: null }; }
    if (this.operation === "delete") { this.db.remove(this.table, matches); return { data: null, error: null }; }
    if (this.singleResult || this.maybeSingleResult) {
      if (matches.length === 0) return { data: null, error: this.singleResult ? { message: "not found" } : null };
      return { data: matches[0], error: null };
    }
    return { data: matches, error: null };
  }
}

class FakeSupabase {
  tables: Record<string, Row[]>;
  constructor(seed: Record<string, Row[]>) { this.tables = seed; }
  from(t: string): FakeQuery { return new FakeQuery(this, t); }
  rows(t: string): Row[] { return this.tables[t] ?? (this.tables[t] = []); }
  remove(t: string, removed: Row[]): void { const rows = this.rows(t); for (const r of removed) { const i = rows.indexOf(r); if (i >= 0) rows.splice(i, 1); } }
}

// ── Fixture ─────────────────────────────────────────────────────────────────

const masterKey = Buffer.alloc(32, 9);
const USER_ID = "user-victim";
const PASSWORD = "correct-horse-battery-staple";
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";

let fakeSupabase: FakeSupabase;
let appServer: Server | null = null;
let appBaseUrl = "";
let requestListener: any;
let configureServerForTests: any;

beforeAll(async () => {
  ({ requestListener, configureServerForTests } = await import("./index.js"));
});

afterEach(async () => {
  if (appServer) { await new Promise<void>((r) => appServer!.close(() => r())); appServer = null; }
});
afterAll(async () => {
  if (appServer) { await new Promise<void>((r) => appServer!.close(() => r())); }
});

async function seedDb(withExistingTotp: boolean): Promise<FakeSupabase> {
  // bcryptjs is loaded lazily so the test file stays standalone; the server
  // verifies the password against this hash via the real authenticateUser path.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const bcrypt = require("bcryptjs");
  const { encrypted } = await encryptSecret(TOTP_SECRET, masterKey, {
    purpose: ENCRYPTION_PURPOSE.TOTP_PENDING,
    aad: buildContextAad(ENCRYPTION_PURPOSE.TOTP_PENDING, { userId: USER_ID, recordId: USER_ID }),
  });
  return new FakeSupabase({
    users: [{ id: USER_ID, username: "victim", is_admin: false, password_hash: bcrypt.hashSync(PASSWORD, 4), session_epoch: 0 }],
    totp_secrets: withExistingTotp ? [{ id: "totp-1", user_id: USER_ID, secret_encrypted: encrypted, verified: true }] : [],
    totp_pending_enrollments: [],
    totp_backup_codes: [],
    webauthn_credentials: [],
    access_logs: [],
  });
}

async function boot(withExistingTotp: boolean): Promise<void> {
  // Import the compiled dispatcher (dist) so the running server and the tokens
  // it mints share one module instance / HMAC key. Tokens and grants are then
  // obtained FROM the server via its own endpoints — never minted locally — so
  // this is a faithful reproduction of an attacker who holds only a session.
  ({ requestListener, configureServerForTests } = await import("./index.js"));
  fakeSupabase = await seedDb(withExistingTotp);
  configureServerForTests(fakeSupabase as any, masterKey);
  appServer = createServer(requestListener);
  await new Promise<void>((resolve) => appServer!.listen(0, "127.0.0.1", resolve));
  const address = appServer.address();
  appBaseUrl = `http://127.0.0.1:${(address as any).port}`;
}

interface ReqOpts {
  method?: string;
  session?: string;
  reauth?: string;
  body?: unknown;
}
async function jsonRequest(path: string, opts: ReqOpts = {}): Promise<{ response: Response; body: any }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.session) headers.authorization = `Bearer ${opts.session}`;
  if (opts.reauth) headers["x-secretvault-reauth"] = opts.reauth;
  const response = await fetch(`${appBaseUrl}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const text = await response.text();
  return { response, body: text ? JSON.parse(text) : undefined };
}

/** Log in as the victim via the real login endpoint → dist-signed session token. */
async function loginSession(password = PASSWORD): Promise<string> {
  const r = await jsonRequest("/v1/auth/login", { method: "POST", body: { username: "victim", password } });
  if (r.response.status !== 200) throw new Error(`login failed: ${r.response.status} ${JSON.stringify(r.body)}`);
  return r.body.token as string;
}

/** Mint a server-signed grant for `operation` via the password-reauth endpoint. */
async function passwordGrant(operation: string, session: string, password = PASSWORD): Promise<string | null> {
  const pw = await jsonRequest("/v1/auth/reauth/password", { method: "POST", session, body: { password, operation } });
  return pw.response.status === 200 ? (pw.body.grant as string) : null;
}

/**
 * Mint a server-signed grant for an existing-factor operation (totp:replace /
 * totp:disable) by performing a real TOTP step-up with the victim's enrolled
 * secret. This is the legitimate existing-factor reauth path; an attacker with
 * only a stolen session cannot produce this grant because they cannot generate
 * a valid TOTP code.
 */
async function factorGrant(operation: string, session: string): Promise<string | null> {
  const code = authenticator.generate(TOTP_SECRET);
  const r = await jsonRequest("/v1/auth/totp/authenticate", { method: "POST", session, body: { code, operation } });
  return r.response.status === 200 ? (r.body.grant as string) : null;
}

describe("SV-AUD-002 — factor operations fail closed without a purpose-bound reauth grant", () => {
  it("TOTP setup with a session alone is rejected (PoC step 1-2 blocked, no seed returned)", async () => {
    await boot(false);
    const session = await loginSession();
    const { response, body } = await jsonRequest("/v1/auth/totp/setup", { method: "POST", session });
    expect(response.status).toBe(403);
    expect(body.error.code ?? body.code).toBe("REAUTH_REQUIRED");
    // No seed/qr leaked — the response must not contain enrollment material.
    expect(JSON.stringify(body)).not.toMatch(/qr_code|"secret"|otpauth/);
  });

  it("passkey register-options with a session alone is rejected", async () => {
    await boot(false);
    const session = await loginSession();
    const { response, body } = await jsonRequest("/v1/auth/webauthn/register-options", { method: "POST", session });
    expect(response.status).toBe(403);
    expect(body.error.code ?? body.code).toBe("REAUTH_REQUIRED");
    // The challenge must not be issued: no pending registration state recorded.
    expect(JSON.stringify(body)).not.toMatch(/challenge|excludeCredentials|webauthn/);
  });

  it("a current-password grant for totp:add permits setup (first enrollment)", async () => {
    await boot(false);
    const session = await loginSession();
    const grant = await passwordGrant("totp:add", session);
    expect(grant).not.toBeNull();
    const setup = await jsonRequest("/v1/auth/totp/setup", { method: "POST", session, reauth: grant! });
    expect(setup.response.status).toBe(200);
    expect(setup.body.secret).toBeDefined();
  });

  it("a wrong password does not mint a grant", async () => {
    await boot(false);
    const session = await loginSession();
    const grant = await passwordGrant("totp:add", session, "wrong-password");
    expect(grant).toBeNull();
  });

  it("a totp:add grant is single-use and cannot be replayed for a second setup", async () => {
    await boot(false);
    const session = await loginSession();
    const grant = await passwordGrant("totp:add", session);
    const setup = await jsonRequest("/v1/auth/totp/setup", { method: "POST", session, reauth: grant! });
    expect(setup.response.status).toBe(200);
    const again = await jsonRequest("/v1/auth/totp/setup", { method: "POST", session, reauth: grant! });
    expect(again.response.status).toBe(403);
  });
});

describe("SV-AUD-002 — existing-factor changes & session revocation", () => {
  it("disabling TOTP requires an existing-factor totp:disable grant and revokes prior sessions", async () => {
    await boot(true);
    const oldSession = await loginSession();
    // Session alone is rejected.
    expect((await jsonRequest("/v1/auth/totp", { method: "DELETE", session: oldSession })).response.status).toBe(403);
    // A grant minted for a DIFFERENT existing-factor op (totp:replace) must not
    // authorise disable — operation binding.
    const replaceGrant = await factorGrant("totp:replace", oldSession);
    expect(replaceGrant).not.toBeNull();
    expect((await jsonRequest("/v1/auth/totp", { method: "DELETE", session: oldSession, reauth: replaceGrant! })).response.status).toBe(403);
    // The correct existing-factor grant authorises disable.
    const disableGrant = await factorGrant("totp:disable", oldSession);
    expect(disableGrant).not.toBeNull();
    const ok = await jsonRequest("/v1/auth/totp", { method: "DELETE", session: oldSession, reauth: disableGrant! });
    expect(ok.response.status).toBe(200);
    // Prior session is revoked: the bumped epoch invalidates the old token.
    const userRow = fakeSupabase.rows("users")[0];
    expect(userRow.session_epoch).toBeGreaterThan(0);
    const stillValid = await jsonRequest("/api/me", { session: oldSession });
    expect(stillValid.response.status).toBe(401);
  });

  it("replacement requires the totp:replace operation; a totp:add grant is rejected for an existing factor", async () => {
    await boot(true);
    const session = await loginSession();
    // An attacker who knows the password can mint a totp:add grant, but with an
    // existing factor the route demands totp:replace — so add is rejected and no
    // pending enrollment is created.
    const addGrant = await passwordGrant("totp:add", session);
    const wrong = await jsonRequest("/v1/auth/totp/setup", { method: "POST", session, reauth: addGrant! });
    expect(wrong.response.status).toBe(403);
    expect(fakeSupabase.rows("totp_pending_enrollments")).toHaveLength(0);
    // The correct existing-factor grant is permitted and starts enrollment.
    const replaceGrant = await factorGrant("totp:replace", session);
    const ok = await jsonRequest("/v1/auth/totp/setup", { method: "POST", session, reauth: replaceGrant! });
    expect(ok.response.status).toBe(200);
    expect(fakeSupabase.rows("totp_pending_enrollments").length).toBeGreaterThanOrEqual(1);
  });
});
