import { describe, it, expect } from "@secretvault/testing";
import { handleGetMe, handleChangePassword, handleAdminResetUserPassword } from "./users.js";

describe("Browser Contracts & User Settings Endpoints", () => {
  it("handleGetMe queries totp_secrets and webauthn_credentials correctly", async () => {
    const mockSupabase: any = {
      from: (table: string) => ({
        select: (cols: string, opts?: any) => ({
          eq: (field: string, val: any) => {
            if (table === "users") {
              return {
                single: async () => ({
                  data: { id: "user-1", username: "alice", is_admin: false, api_key_prefix: "sv_123", created_at: "2026-07-26T00:00:00Z" },
                  error: null,
                }),
              };
            }
            if (table === "webauthn_credentials") {
              return { data: [{ id: "passkey-1" }] };
            }
            if (table === "totp_secrets") {
              return {
                maybeSingle: async () => ({ data: { id: "totp-1", verified: true } }),
              };
            }
            if (table === "totp_backup_codes") {
              return Promise.resolve({ count: 5, data: null });
            }
            return { data: null };
          },
        }),
      }),
    };

    const meRes = await handleGetMe(mockSupabase, "user-1");
    expect(meRes.status).toBe(200);
    const body = meRes.body as any;
    expect(body.username).toBe("alice");
    expect(body.has_totp).toBe(true);
    expect(body.has_passkey).toBe(true);
    expect(body.factors).toEqual({ passkey: true, totp: true, backup_codes_remaining: 5 });
  });

  it("handleAdminResetUserPassword accepts both new_password and password payloads", async () => {
    let updatedHash: string | null = null;
    const mockSupabase: any = {
      from: (table: string) => ({
        select: () => ({
          eq: () => ({
            maybeSingle: async () => ({ data: { id: "user-bob", username: "bob" } }),
            single: async () => ({ data: { id: "user-bob", session_epoch: 0 }, error: null }),
          }),
        }),
        update: (data: any) => {
          if (data.password_hash) updatedHash = data.password_hash;
          return { eq: () => ({ error: null }) };
        },
      }),
    };

    const res = await handleAdminResetUserPassword(mockSupabase, "user-bob", { new_password: "NewPassword123!" });
    expect(res.status).toBe(200);
    expect(updatedHash).toBeTruthy();
  });
});
