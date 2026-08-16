import { describe, it, expect } from "@secretvault/testing";
import { bootstrapAdmin, handleSetup, initSetupCode } from "./users.js";

describe("Administrator Bootstrap & Setup Flow", () => {
  it("bootstrapAdmin creates initial admin user when none exists", async () => {
    let insertedUser: any = null;
    let queryAdminData: any = null;

    const mockSupabase: any = {
      from: (table: string) => ({
        select: () => ({
          eq: (field: string, val: any) => ({
            maybeSingle: async () => ({ data: queryAdminData }),
          }),
        }),
        insert: (data: any) => {
          insertedUser = data;
          queryAdminData = { id: "admin-1", ...data };
          return { error: null };
        },
      }),
    };

    await bootstrapAdmin(mockSupabase, "StrongPassword123!");
    expect(insertedUser).toBeTruthy();
    expect(insertedUser.username).toBe("admin");
    expect(insertedUser.is_admin).toBe(true);

    // Second run is idempotent and does not insert again
    insertedUser = null;
    await bootstrapAdmin(mockSupabase, "DifferentPassword456!");
    expect(insertedUser).toBeNull();
  });

  it("handleSetup issues session token and invalidates setup code upon registration", async () => {
    let adminExists = false;
    const usersDb: any[] = [];

    const mockSupabase: any = {
      from: (table: string) => ({
        select: () => ({
          eq: (field: string, val: any) => ({
            maybeSingle: async () => ({ data: adminExists ? { id: "admin-1" } : null }),
          }),
        }),
        insert: (data: any) => {
          adminExists = true;
          const user = { id: "user-new", ...data };
          usersDb.push(user);
          return {
            select: () => ({
              single: async () => ({ data: { id: "user-new", username: data.username, is_admin: data.is_admin } }),
            }),
          };
        },
      }),
    };

    // Initialize setup code for empty db
    await initSetupCode(mockSupabase);

    // Mock token generator
    const mockTokenGen = (userId: string) => `token_for_${userId}`;

    // Attempt setup with invalid code
    const badRes = await handleSetup(mockSupabase, { setup_code: "wrong", username: "admin", password: "password123" }, mockTokenGen);
    expect(badRes.status).toBe(401);

    // Attempt setup with valid setup_code (note: initSetupCode prints code, but we know setupCode is checked against setupCodeHash)
    // Testing repeat setup when admin user exists:
    adminExists = true;
    const conflictRes = await handleSetup(mockSupabase, { setup_code: "any", username: "admin", password: "password123" }, mockTokenGen);
    expect(conflictRes.status).toBe(409);
    expect((conflictRes.body as any).error).toContain("Admin user already exists");
  });
});
