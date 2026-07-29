import { describe, expect, it } from "vitest";
import {
  LIMITS,
  ValidationError,
  validateUsername,
  validatePassword,
  validateBoundedString,
  rejectUnknownKeys,
  validationErrorResponse,
} from "./validation.js";
import { classify, isNotFound } from "./dbErrors.js";

describe("Centralized Validation & Limits (SV-048)", () => {
  it("validates username bounds and character set", () => {
    expect(() => validateUsername("ab")).toThrow(ValidationError);
    expect(() => validateUsername("a".repeat(LIMITS.USERNAME_MAX + 1))).toThrow(ValidationError);
    expect(() => validateUsername("invalid user!")).toThrow(ValidationError);
    expect(validateUsername("valid_user-123")).toBe("valid_user-123");
  });

  it("validates password length boundary", () => {
    expect(() => validatePassword("12345")).toThrow(ValidationError);
    expect(() => validatePassword("a".repeat(LIMITS.PASSWORD_MAX + 1))).toThrow(ValidationError);
    expect(validatePassword("validPassword123")).toBe("validPassword123");
  });

  it("validates bounded strings and unknown key rejection", () => {
    expect(() => validateBoundedString(123, "testField", 10)).toThrow(ValidationError);
    expect(validateBoundedString("hello", "testField", 10)).toBe("hello");

    expect(() => rejectUnknownKeys({ foo: 1, bar: 2 }, ["foo"], "testContext")).toThrow(
      ValidationError,
    );
    expect(rejectUnknownKeys({ foo: 1 }, ["foo"], "testContext")).toEqual({ foo: 1 });
  });

  it("formats validation error response with 400 status", () => {
    const err = new ValidationError("field is invalid");
    const resp = validationErrorResponse(err);
    expect(resp.status).toBe(400);
    expect(resp.body.code).toBe("VALIDATION_ERROR");
    expect(resp.body.error).toBe("field is invalid");
  });
});

describe("Database Error Mapping (SV-047)", () => {
  it("classifies unique constraint violation to conflict 409", () => {
    const error = { code: "23505", message: "duplicate key value violates unique constraint" };
    const mapped = classify(error);
    expect(mapped.status).toBe(409);
    expect(mapped.code).toBe("CONFLICT");
  });

  it("classifies foreign key violation to dependency violation 409", () => {
    const error = { code: "23503", message: "violates foreign key constraint" };
    const mapped = classify(error);
    expect(mapped.status).toBe(409);
    expect(mapped.code).toBe("DEPENDENCY_VIOLATION");
  });

  it("identifies PGRST116 as not found error", () => {
    const error = { code: "PGRST116", message: "JSON object requested, 0 rows returned" };
    expect(isNotFound(error)).toBe(true);
  });
});
