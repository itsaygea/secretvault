import { describe, it, expect } from "@secretvault/testing";
import { randomBytes } from "node:crypto";
import {
  encryptSecret,
  decryptSecret,
  envelopeKeyId,
  envelopeVersion,
  ENCRYPTION_PURPOSE,
  buildContextAad,
} from "@secretvault/shared";
import { rotateMasterKeyDatabase } from "./cli/rotateKey.js";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

/**
 * SV-AUD-006: master-key rotation is verified, resumable, and atomic per row.
 *
 * The fake supabase below supports exactly the query shapes the rotation engine
 * issues: keyset-paginated scans (`.select().order().gt().limit()`), compare-and-
 * swap updates (`.update().eq().eq().select("id")`), checkpoint CRUD, and the
 * central audit insert (`.insert().select("id").single()`).
 */
type Row = Record<string, unknown>;

interface Tables {
  secrets: Row[];
  client_applications: Row[];
  totp_secrets: Row[];
  totp_pending_enrollments: Row[];
  master_key_rotations: Row[];
  access_logs: Row[];
}

export function makeFake(initial: Partial<Tables> = {}): { supabase: any; tables: Tables } {
  const tables: Tables = {
    secrets: [],
    client_applications: [],
    totp_secrets: [],
    totp_pending_enrollments: [],
    master_key_rotations: [],
    access_logs: [],
    ...initial,
  };

  const selectCols = (row: Row, cols: string): Row => {
    const wanted = cols.split(",").map(c => c.trim());
    const out: Row = {};
    for (const c of wanted) out[c] = row[c];
    return out;
  };

  // A chainable query builder capturing filters then resolving.
  function chain(table: keyof Tables): any {
    const state: { col: string; op: string; val: any; limit?: number; order?: { col: string; asc: boolean } }[] = [];
    const api: any = {
      select: (cols: string) => { api._cols = cols; return api; },
      order: (col: string, opts?: { ascending?: boolean }) => { state.push({ col: "order", op: "", val: { col, asc: opts?.ascending ?? true } }); return api; },
      gt: (col: string, val: any) => { state.push({ col, op: "gt", val }); return api; },
      eq: (col: string, val: any) => { state.push({ col, op: "eq", val }); return api; },
      limit: (n: number) => { state.push({ col: "limit", op: "limit", val: n }); return api; },
      range: (a: number, b: number) => { state.push({ col: "range", op: "range", val: [a, b] }); return api; },
      maybeSingle: () => Promise.resolve({ data: null, error: null }),
      single: () => api,
      insert: (payload: Row | Row[]) => ({ select: (c: string) => ({ single: async () => {
        const rows = Array.isArray(payload) ? payload : [payload];
        for (const r of rows) (tables[table] as Row[]).push({ ...r, id: r.id ?? `gen-${Math.random().toString(36).slice(2)}` });
        const last = (tables[table] as Row[]).slice(-1)[0];
        return { data: last ? selectCols(last, c) : null, error: null };
      } }) }),
      update: (patch: Row) => {
        const filters: { col: string; val: any }[] = [];
        const apply = (): { data: null; error: null } => {
          let matched = (tables[table] as Row[]).filter(r => filters.every(f => r[f.col] === f.val));
          for (const r of matched) Object.assign(r, patch);
          return { data: null, error: null };
        };
        const eqChain: any = {
          eq: (col: string, val: any) => { filters.push({ col, val }); return eqChain; },
          // CAS path: .eq().eq().select("id") returns matched ids.
          select: (c: string) => {
            let matched = (tables[table] as Row[]).filter(r => filters.every(f => r[f.col] === f.val));
            for (const r of matched) Object.assign(r, patch);
            return Promise.resolve({ data: matched.map(r => selectCols(r, c)), error: null });
          },
          // Single/multi-eq update awaited directly (checkpoint): thenable.
          then: (resolve: (v: any) => void) => { resolve(apply()); },
        };
        return { eq: (col: string, val: any) => { filters.push({ col, val }); return eqChain; } };
      },
    };
    // Make the chain thenable for scans: resolves {data, error} applying filters.
    api.then = (resolve: (v: any) => void) => {
      let rows = [...(tables[table] as Row[])] as Row[];
      let limit: number | undefined;
      let order: { col: string; asc: boolean } | undefined;
      for (const f of state) {
        if (f.op === "gt") rows = rows.filter(r => String(r[f.col]) > String(f.val));
        else if (f.op === "eq") rows = rows.filter(r => r[f.col] === f.val);
        else if (f.op === "limit") limit = f.val;
        else if (f.op === "range") { const [a, b] = f.val; rows = rows.slice(a, b + 1); }
        else if (f.col === "order") order = f.val;
      }
      if (order) rows.sort((x, y) => {
        const cmp = String(x[order!.col]).localeCompare(String(y[order!.col]));
        return order!.asc ? cmp : -cmp;
      });
      if (limit !== undefined) rows = rows.slice(0, limit);
      const projected = api._cols ? rows.map(r => selectCols(r, api._cols)) : rows;
      resolve({ data: projected, error: null });
    };
    return api;
  }

  const supabase: any = { from: (t: keyof Tables) => chain(t) };
  return { supabase, tables };
}

// Build rows for each object type under the OLD key.
export async function seedAll(oldKey: Buffer): Promise<Tables> {
  const secretAad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "s1" });
  const clientAad = buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId: "u1", recordId: "c1", clientId: "c1" });
  const totpAad = buildContextAad(ENCRYPTION_PURPOSE.TOTP_PENDING, { userId: "u1", recordId: "u1" });
  const [s, c, t, p] = await Promise.all([
    encryptSecret("secret-val", oldKey, { purpose: ENCRYPTION_PURPOSE.SECRET, keyId: "k0", aad: secretAad }),
    encryptSecret("client-val", oldKey, { purpose: ENCRYPTION_PURPOSE.CLIENT_KEY, keyId: "k0", aad: clientAad }),
    encryptSecret("totp-val", oldKey, { purpose: ENCRYPTION_PURPOSE.TOTP_PENDING, keyId: "k0", aad: totpAad }),
    encryptSecret("pend-val", oldKey, { purpose: ENCRYPTION_PURPOSE.TOTP_PENDING, keyId: "k0", aad: totpAad }),
  ]);
  return {
    secrets: [{ id: "s1", user_id: "u1", encrypted_blob: s.encrypted }],
    client_applications: [{ id: "c1", user_id: "u1", encrypted_key: c.encrypted }],
    totp_secrets: [{ id: "t1", user_id: "u1", secret_encrypted: t.encrypted }],
    totp_pending_enrollments: [{ id: "p1", user_id: "u1", secret_encrypted: p.encrypted }],
    master_key_rotations: [],
    access_logs: [],
  };
}

describe("master-key rotation (SV-AUD-006)", () => {
  const oldKey = Buffer.from("1".repeat(64), "hex");
  const newKey = Buffer.from("2".repeat(64), "hex");

  it("rotates all four object types to the new key and verifies every row", async () => {
    const { supabase, tables } = makeFake(await seedAll(oldKey));
    const res = await rotateMasterKeyDatabase(supabase, oldKey, newKey, { oldKeyId: "k0", newKeyId: "k1" });
    expect(res.secrets).toBe(1);
    expect(res.clients).toBe(1);
    expect(res.totp).toBe(1);
    expect(res.pendingTotp).toBe(1);

    // Every row is now v2 under the new key and decrypts under newKey with AAD.
    const secretAad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "s1" });
    expect(envelopeKeyId(tables.secrets[0].encrypted_blob as string)).toBe("k1");
    await expect(decryptSecret(tables.secrets[0].encrypted_blob as string, newKey, { purpose: ENCRYPTION_PURPOSE.SECRET, aad: secretAad })).resolves.toBe("secret-val");
    const clientAad = buildContextAad(ENCRYPTION_PURPOSE.CLIENT_KEY, { userId: "u1", recordId: "c1", clientId: "c1" });
    await expect(decryptSecret(tables.client_applications[0].encrypted_key as string, newKey, { purpose: ENCRYPTION_PURPOSE.CLIENT_KEY, aad: clientAad })).resolves.toBe("client-val");

    // Completion audit recorded through the central API with valid fields.
    expect(tables.access_logs.some(l => l.access_type === "master_key_rotated")).toBe(true);
    expect(tables.master_key_rotations[0].status).toBe("completed");
  });

  it("is idempotent: a second run is a no-op and still verifies", async () => {
    const { supabase } = makeFake(await seedAll(oldKey));
    await rotateMasterKeyDatabase(supabase, oldKey, newKey, { oldKeyId: "k0", newKeyId: "k1" });
    // Second run reuses the completed checkpoint's resolution path; must not throw.
    const res = await rotateMasterKeyDatabase(supabase, oldKey, newKey, { oldKeyId: "k0", newKeyId: "k1" });
    expect(res.secrets + res.clients + res.totp + res.pendingTotp).toBe(4);
  });

  it("resumes after a failed update: no row is falsely counted", async () => {
    const { supabase, tables } = makeFake(await seedAll(oldKey));
    // Inject a failing CAS update on the first secrets row: the fake returns
    // zero matched rows, simulating a concurrent change / failed write.
    let sabotaged = false;
    const origFrom = supabase.from;
    supabase.from = (t: string) => {
      const c = origFrom(t);
      if (t === "secrets" && !sabotaged) {
        // Wrap update to force a zero-row match once, then restore.
        const origUpdate = c.update;
        c.update = (patch: Row) => ({
          eq: (col: string, val: any) => ({
            eq: (col2: string, val2: any) => ({
              select: async (cols: string) => {
                sabotaged = true;
                supabase.from = origFrom;
                return { data: [], error: null }; // CAS fails: 0 rows
              },
            }),
          }),
        });
      }
      return c;
    };

    // The row's ciphertext was NOT changed by the sabotage (it only failed the
    // CAS), so the verification scan finds an old-key row → rotation does not
    // complete. (The blob is still old-key.)
    await expect(rotateMasterKeyDatabase(supabase, oldKey, newKey, { oldKeyId: "k0", newKeyId: "k1" })).rejects.toThrow(/verification/);
    expect(tables.master_key_rotations[0].status).toBe("failed");
    expect(tables.secrets[0].encrypted_blob).not.toBe(undefined);

    // Now restore a clean supabase and resume — completes, no false count.
    const clean = makeFake({ ...tables });
    const res = await rotateMasterKeyDatabase(clean.supabase, oldKey, newKey, { oldKeyId: "k0", newKeyId: "k1" });
    expect(res.secrets).toBe(1);
    expect(clean.tables.master_key_rotations.at(-1)!.status).toBe("completed");
  });

  it("does not retry new-key rows with the old key (keyring selects by keyId)", async () => {
    // Seed a row ALREADY rotated to the new key (e.g. after a prior run).
    const secretAad = buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId: "u1", recordId: "s1" });
    const alreadyNew = (await encryptSecret("secret-val", newKey, { purpose: ENCRYPTION_PURPOSE.SECRET, keyId: "k1", aad: secretAad })).encrypted;
    const { supabase } = makeFake({
      secrets: [{ id: "s1", user_id: "u1", encrypted_blob: alreadyNew }],
      client_applications: [], totp_secrets: [], totp_pending_enrollments: [],
      master_key_rotations: [], access_logs: [],
    });
    const res = await rotateMasterKeyDatabase(supabase, oldKey, newKey, { oldKeyId: "k0", newKeyId: "k1" });
    expect(res.secrets).toBe(1); // counted, not re-encrypted
  });

  it("blocks completion when the completion audit write fails", async () => {
    const { supabase, tables } = makeFake(await seedAll(oldKey));
    // Make access_logs insert fail (audit unavailable).
    const origFrom = supabase.from;
    supabase.from = (t: string) => {
      if (t === "access_logs") {
        return { insert: () => ({ select: () => ({ single: async () => ({ data: null, error: { message: "audit down" } }) }) }) };
      }
      return origFrom(t);
    };
    await expect(rotateMasterKeyDatabase(supabase, oldKey, newKey, { oldKeyId: "k0", newKeyId: "k1" })).rejects.toThrow(/audit/);
    expect(tables.master_key_rotations[0].status).toBe("failed");
  });
});

describe("master-key rotation key safety (SV-AUD-006/007)", () => {
  it("the rotation module never reads keys from process.argv", () => {
    const src = require("node:fs").readFileSync(require("path").resolve("packages/mcp-server/src/cli/rotateKey.ts"), "utf8");
    // No key value is ever parsed out of argv: the only argv handling rejects
    // the legacy flags rather than consuming a following argument.
    expect(src).not.toMatch(/args\.includes\("--old-key"\)\s*&&\s*args\[|args\[i\s*\+\s*1\].*key|OLD_MASTER_KEY\s*=\s*process/);
    expect(src).toMatch(/OLD_MASTER_KEY_FILE|NEW_MASTER_KEY_FILE/);
    expect(src).toMatch(/readKeyStdin|readKeyFile/);
  });
});
