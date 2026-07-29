import { describe, it, expect, beforeEach } from "vitest";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import { encryptSecret } from "@secretvault/shared";
import {
  initStepUpAuth,
  handleTotpSetup,
  handleTotpCancelSetup,
  handleTotpVerifySetup,
  handleTotpAuthenticate,
  consumeBackupCode,
  wipeUserTotpState,
} from "./stepup.js";

const MASTER = Buffer.alloc(32, "f");
const SECRET = "JBSWY3DPEHPK3PXP";

type Row = Record<string, any>;

function createFactorStore() {
  const store: {
    totp_secrets: Row[];
    totp_pending_enrollments: Row[];
    totp_backup_codes: Row[];
    access_logs: Row[];
  } = {
    totp_secrets: [],
    totp_pending_enrollments: [],
    totp_backup_codes: [],
    access_logs: [],
  };

  let idSeq = 1;
  const nextId = () => `id-${idSeq++}`;

  const supabase: any = {
    from(table: string) {
      const rows = (store as any)[table] as Row[];
      if (!rows) throw new Error(`unknown table ${table}`);

      return {
        select(_cols?: string, opts?: { count?: string; head?: boolean }) {
          const filters: Array<[string, any]> = [];
          const chain: any = {
            eq(field: string, val: any) {
              filters.push([field, val]);
              return chain;
            },
            maybeSingle: async () => {
              const found = rows.find((r) => filters.every(([f, v]) => r[f] === v)) ?? null;
              return { data: found ? { ...found } : null };
            },
            single: async () => {
              const found = rows.find((r) => filters.every(([f, v]) => r[f] === v)) ?? null;
              return { data: found ? { ...found } : null, error: found ? null : { message: "not found" } };
            },
            then(resolve: any) {
              const matched = rows.filter((r) => filters.every(([f, v]) => r[f] === v));
              if (opts?.count === "exact") {
                return resolve({ count: matched.length, data: opts.head ? null : matched.map((r) => ({ ...r })) });
              }
              return resolve({ data: matched.map((r) => ({ ...r })), error: null });
            },
          };
          return chain;
        },
        insert(payload: Row | Row[]) {
          const items = Array.isArray(payload) ? payload : [payload];
          for (const item of items) {
            rows.push({ id: nextId(), created_at: new Date().toISOString(), ...item });
          }
          return {
            select: () => ({
              single: async () => ({ data: { ...rows[rows.length - 1] }, error: null }),
            }),
            error: null,
            then: (resolve: any) => resolve({ error: null }),
          };
        },
        upsert(payload: Row, _opts?: any) {
          const idx = rows.findIndex((r) => r.user_id === payload.user_id);
          if (idx >= 0) {
            rows[idx] = { ...rows[idx], ...payload };
          } else {
            rows.push({ id: nextId(), created_at: new Date().toISOString(), ...payload });
          }
          return { error: null };
        },
        update(payload: Row) {
          const filters: Array<[string, any]> = [];
          return {
            eq(field: string, val: any) {
              filters.push([field, val]);
              return this;
            },
            then(resolve: any) {
              for (const r of rows) {
                if (filters.every(([f, v]) => r[f] === v)) Object.assign(r, payload);
              }
              resolve({ error: null });
            },
            error: null,
          };
        },
        delete() {
          const filters: Array<[string, any]> = [];
          const chain: any = {
            eq(field: string, val: any) {
              filters.push([field, val]);
              return chain;
            },
            select(_cols?: string) {
              return {
                maybeSingle: async () => {
                  const idx = rows.findIndex((r) => filters.every(([f, v]) => r[f] === v));
                  if (idx < 0) return { data: null };
                  const [removed] = rows.splice(idx, 1);
                  return { data: { id: removed.id } };
                },
              };
            },
            then(resolve: any) {
              for (let i = rows.length - 1; i >= 0; i--) {
                if (filters.every(([f, v]) => rows[i][f] === v)) rows.splice(i, 1);
              }
              resolve({ error: null });
            },
            error: null,
          };
          return chain;
        },
      };
    },
  };

  return { store, supabase };
}

describe("Factor lifecycle (SV-013, SV-014, SV-015, SV-067)", () => {
  beforeEach(() => {
    initStepUpAuth(MASTER);
  });

  it("TOTP reconfigure stores pending enrollment without disabling verified factor (SV-013)", async () => {
    const { store, supabase } = createFactorStore();
    const { encrypted } = await encryptSecret(SECRET, MASTER);
    store.totp_secrets.push({
      id: "totp-live",
      user_id: "user-1",
      secret_encrypted: encrypted,
      verified: true,
    });

    const setup = await handleTotpSetup(supabase, MASTER, "user-1", "alice");
    expect(setup.status).toBe(200);
    expect(store.totp_secrets[0].verified).toBe(true);
    expect(store.totp_secrets[0].secret_encrypted).toBe(encrypted);
    expect(store.totp_pending_enrollments).toHaveLength(1);

    // Existing factor still authenticates while pending is open
    const code = authenticator.generate(SECRET);
    const auth = await handleTotpAuthenticate(supabase, MASTER, "user-1", { code });
    expect(auth.status).toBe(200);
    expect((auth.body as any).stepUpToken).toBeTruthy();

    // Cancel leaves verified factor intact
    const cancel = await handleTotpCancelSetup(supabase, "user-1");
    expect(cancel.status).toBe(200);
    expect(store.totp_pending_enrollments).toHaveLength(0);
    expect(store.totp_secrets[0].verified).toBe(true);
  });

  it("successful verify-setup atomically swaps pending into verified and issues backup codes once (SV-013/014)", async () => {
    const { store, supabase } = createFactorStore();
    const setup = await handleTotpSetup(supabase, MASTER, "user-2", "bob");
    expect(setup.status).toBe(200);
    const pendingSecret = await (async () => {
      // Secret is returned in body for authenticator enrollment
      return (setup.body as any).secret as string;
    })();

    const code = authenticator.generate(pendingSecret);
    const verify = await handleTotpVerifySetup(supabase, MASTER, "user-2", { code });
    expect(verify.status).toBe(200);
    const body = verify.body as any;
    expect(body.verified).toBe(true);
    expect(body.backup_codes).toHaveLength(8);
    expect(store.totp_pending_enrollments).toHaveLength(0);
    expect(store.totp_secrets[0].verified).toBe(true);
    expect(store.totp_backup_codes).toHaveLength(8);

    // Audit lifecycle events without secrets/codes
    const accessTypes = store.access_logs.map((l) => l.access_type);
    expect(accessTypes).toContain("totp_enroll_start");
    expect(accessTypes).toContain("totp_enroll_complete");
    for (const log of store.access_logs) {
      const blob = JSON.stringify(log);
      expect(blob).not.toContain(pendingSecret);
      for (const c of body.backup_codes) expect(blob).not.toContain(c);
    }
  });

  it("concurrent backup-code consumption yields exactly one success (SV-015)", async () => {
    const { store, supabase } = createFactorStore();
    const raw = "a1b2c3d4e5";
    const hash = await bcrypt.hash(raw, 10);
    store.totp_secrets.push({
      id: "totp-3",
      user_id: "user-3",
      secret_encrypted: (await encryptSecret(SECRET, MASTER)).encrypted,
      verified: true,
    });
    store.totp_backup_codes.push({ id: "bc-1", user_id: "user-3", code_hash: hash });

    const [a, b] = await Promise.all([
      handleTotpAuthenticate(supabase, MASTER, "user-3", { code: raw }),
      handleTotpAuthenticate(supabase, MASTER, "user-3", { code: raw }),
    ]);

    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 401]);
    expect(store.totp_backup_codes).toHaveLength(0);

    // Direct unit of atomic delete also holds under concurrency
    store.totp_backup_codes.push({ id: "bc-2", user_id: "user-3", code_hash: await bcrypt.hash("zzzzzzzzzz", 10) });
    const results = await Promise.all([
      consumeBackupCode(supabase, "user-3", "zzzzzzzzzz"),
      consumeBackupCode(supabase, "user-3", "zzzzzzzzzz"),
      consumeBackupCode(supabase, "user-3", "zzzzzzzzzz"),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("skips backup bcrypt scan for 6-digit TOTP inputs (SV-010 regression)", async () => {
    const { store, supabase } = createFactorStore();
    store.totp_secrets.push({
      id: "totp-4",
      user_id: "user-4",
      secret_encrypted: (await encryptSecret(SECRET, MASTER)).encrypted,
      verified: true,
    });
    // Intentionally unusable hash — would hang/fail if scanned on 6-digit path
    store.totp_backup_codes.push({ id: "bc-x", user_id: "user-4", code_hash: "$2a$12$notavalidhashxxxxxxxxxx" });

    const res = await handleTotpAuthenticate(supabase, MASTER, "user-4", { code: "000000" });
    expect(res.status).toBe(401);
  });

  it("wipeUserTotpState clears verified, pending, and backup rows", async () => {
    const { store, supabase } = createFactorStore();
    store.totp_secrets.push({ id: "t", user_id: "u", secret_encrypted: "x", verified: true });
    store.totp_pending_enrollments.push({ id: "p", user_id: "u", secret_encrypted: "y", expires_at: new Date().toISOString() });
    store.totp_backup_codes.push({ id: "b", user_id: "u", code_hash: "h" });
    await wipeUserTotpState(supabase, "u");
    expect(store.totp_secrets).toHaveLength(0);
    expect(store.totp_pending_enrollments).toHaveLength(0);
    expect(store.totp_backup_codes).toHaveLength(0);
  });
});

describe("Factor lifecycle UI contracts (SV-014, SV-067)", () => {
  it("browser UI exposes recovery-code confirmation and factor chooser fallback", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve, dirname } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const uiDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "ui");
    const html = readFileSync(resolve(uiDir, "index.html"), "utf8");
    const authJs = readFileSync(resolve(uiDir, "js", "auth.js"), "utf8");
    const settingsJs = readFileSync(resolve(uiDir, "js", "features", "settings.js"), "utf8");

    expect(html).toContain('id="modal-backup-codes"');
    expect(html).toContain('id="backup-codes-ack"');
    expect(html).toContain('id="stepup-factor-passkey"');
    expect(html).toContain('id="stepup-factor-totp"');
    expect(html).toContain('id="stepup-factor-backup"');
    expect(html).toContain('id="stepup-backup-code"');
    expect(html).toContain('data-action="cancel-totp-setup"');

    expect(authJs).toContain("export function openStepUpChooser");
    expect(settingsJs).toContain("export function showBackupCodesOnce");
    expect(settingsJs).toMatch(/export (async )?function cancelTotpSetup/);
    expect(authJs).toContain("export function verifyStepUpBackup");
    expect(authJs).toContain("Passkey cancelled or failed");
    expect(authJs).toContain("openStepUpChooser()");
    expect(authJs).not.toMatch(/else if \(currentUserHasPasskey\) \{\s*verifyStepUpPasskey\(\)/);
  });
});
