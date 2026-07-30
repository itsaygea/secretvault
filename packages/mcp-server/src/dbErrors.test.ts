import { describe, expect, it } from "vitest";
import { classify, internalError, isNotFound, publicDbCode, safeErrorMessage } from "./dbErrors.js";

describe("dbErrors classification (SV-047 / SV-AUD-014)", () => {
  it("maps a unique-violation to a stable conflict code without leaking detail", () => {
    const e = { code: "23505", message: 'duplicate key value violates unique constraint "secrets_name_key"' };
    expect(classify(e)).toMatchObject({ status: 409, code: "CONFLICT", message: "Resource already exists" });
  });

  it("maps a permission/RLS error to forbidden, not the role name", () => {
    const e = { code: "42501", message: "permission denied for table secretvault.secrets for role sv_runtime" };
    expect(classify(e)).toMatchObject({ status: 403, code: "FORBIDDEN", message: "Access denied" });
  });

  it("maps a JWT/auth error to unauthorized", () => {
    const e = { code: "PGRST301", message: "JWT expired" };
    expect(classify(e)).toMatchObject({ status: 401, code: "UNAUTHORIZED", message: "Authentication failed" });
  });

  it("falls back to a generic internal error for unknown SQLSTATEs", () => {
    const e = { code: "XX000", message: "relation secretvault.secrets does not exist in schema public" };
    expect(classify(e)).toMatchObject(internalError());
  });
});

describe("safeErrorMessage — MCP response redaction (SV-AUD-014)", () => {
  // The audit: "MCP error paths sometimes return raw PostgREST error messages.
  // Standardize them through the same redaction layer as REST errors."
  it("never returns raw PostgreSQL schema/column text", () => {
    const raw = {
      code: "42P01",
      message: 'relation "secretvault.access_logs" does not exist; while building the source',
    };
    const msg = safeErrorMessage(raw);
    expect(msg).not.toContain("access_logs");
    expect(msg).not.toContain("secretvault");
    expect(msg.length).toBeGreaterThan(0);
  });

  it("never returns a PostgREST internal error string", () => {
    const raw = { code: "PGRST202", message: "Could not find the column actor_username in the source" };
    const msg = safeErrorMessage(raw);
    expect(msg).not.toContain("actor_username");
    expect(msg).not.toContain("PGRST");
  });

  it("returns a stable generic message, identical for two different raw errors", () => {
    const a = safeErrorMessage({ code: "XX000", message: "catastrophe A in secrets table" });
    const b = safeErrorMessage({ code: "XX999", message: "catastrophe B in users table" });
    expect(a).toBe(b);
    expect(a).toBe("Internal server error");
  });

  it("handles non-object / nullish inputs without throwing", () => {
    expect(safeErrorMessage(null)).toBe("Internal server error");
    expect(safeErrorMessage(undefined)).toBe("Internal server error");
    expect(safeErrorMessage("a string")).toBe("Internal server error");
  });

  it("publicDbCode returns the redacted code, not raw text", () => {
    expect(publicDbCode({ code: "23505", message: "dup secrets_name_key" })).toBe("CONFLICT");
    expect(publicDbCode({ code: "XX000", message: "boom" })).toBe("INTERNAL_SERVER_ERROR");
  });

  it("isNotFound detects PGRST116 and absent-row messages", () => {
    expect(isNotFound({ code: "PGRST116", message: "JSON object requested" })).toBe(true);
    expect(isNotFound({ code: "XX000", message: "other failure" })).toBe(false);
  });
});
