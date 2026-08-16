import { describe, it, expect } from "@secretvault/testing";
import { handleCreateSecret, handleRotateSecret, handleDeleteSecret, handleRevealSecret } from "./api.js";
import { handleDeleteUser } from "./users.js";

describe("Data Model & Multi-User Isolation Safeguards", () => {
  it("allows different users to create secrets with identical canonical names", async () => {
    const secretsDb: any[] = [];

    const mockSupabase: any = {
      from: (table: string) => ({
        select: () => ({
          eq: (field: string, val: any) => ({
            eq: (field2: string, val2: any) => ({
              maybeSingle: async () => {
                const found = secretsDb.find(s => s[field] === val && s[field2] === val2);
                return { data: found || null };
              },
            }),
          }),
        }),
        insert: (data: any) => {
          if (table === "secrets") {
            secretsDb.push(data);
            return {
              select: () => ({
                single: async () => ({ data: { id: "sec-1" } }),
              }),
              error: null,
            };
          }
          return {
            select: () => ({
              single: async () => ({ data: { id: "audit-1" } }),
            }),
            error: null,
          };
        },
        update: () => ({
          eq: () => ({ error: null }),
        }),
      }),
    };

    const masterKey = Buffer.alloc(32, "a");

    // User A creates OPENAI_API_KEY
    const resA = await handleCreateSecret(
      mockSupabase,
      masterKey,
      { name: "OPENAI_API_KEY", value: "sk-user-a-1234567890123456" },
      "user-a",
    );
    expect(resA.status).toBe(201);

    // User B creates OPENAI_API_KEY (same canonical name, different owner)
    const resB = await handleCreateSecret(
      mockSupabase,
      masterKey,
      { name: "OPENAI_API_KEY", value: "sk-user-b-1234567890123456" },
      "user-b",
    );
    expect(resB.status).toBe(201);

    // User A attempts to create OPENAI_API_KEY again -> conflict
    const resAConflict = await handleCreateSecret(
      mockSupabase,
      masterKey,
      { name: "OPENAI_API_KEY", value: "sk-user-a-duplicate" },
      "user-a",
    );
    expect(resAConflict.status).toBe(409);
  });

  it("prevents self-deletion of active user and deletion of final administrator", async () => {
    const mockSupabase: any = {
      from: (table: string) => ({
        select: () => ({
          eq: (field: string, val: any) => ({
            maybeSingle: async () => {
              if (val === "admin-1") return { data: { id: "admin-1", username: "admin", is_admin: true } };
              if (val === "user-2") return { data: { id: "user-2", username: "bob", is_admin: false } };
              return { data: null };
            },
            select: () => ({
              eq: (f2: string, v2: any) => ({
                count: 1,
              }),
            }),
          }),
        }),
        update: () => ({ eq: () => ({}) }),
        delete: () => ({ eq: () => ({ error: null }) }),
      }),
    };

    // Attempt self-deletion of admin-1
    const selfDeleteRes = await handleDeleteUser(mockSupabase, "admin-1", "admin-1");
    expect(selfDeleteRes.status).toBe(409);
    expect((selfDeleteRes.body as any).error).toContain("Cannot delete your own active administrator account");

    // Attempt deletion of final admin-1 by another session
    const mockSupabaseFinalAdmin: any = {
      from: (table: string) => ({
        select: (cols: string, opts?: any) => {
          if (opts?.count === "exact") {
            return { eq: () => ({ count: 1 }) };
          }
          return {
            eq: () => ({
              maybeSingle: async () => ({ data: { id: "admin-1", username: "admin", is_admin: true } }),
            }),
          };
        },
        update: () => ({ eq: () => ({}) }),
        delete: () => ({ eq: () => ({ error: null }) }),
      }),
    };

    const finalAdminDeleteRes = await handleDeleteUser(mockSupabaseFinalAdmin, "admin-1", "admin-other");
    expect(finalAdminDeleteRes.status).toBe(409);
    expect((finalAdminDeleteRes.body as any).error).toContain("Cannot delete the final remaining administrator account");
  });
});
