import { describe, it, expect } from "@secretvault/testing";
import { maskSecret } from "./masking.js";

describe("Masking Invariants", () => {
  it("should redact short secrets completely", () => {
    expect(maskSecret("1234567")).toBe("[REDACTED]");
  });

  it("should mask medium secrets preserving prefix/suffix", () => {
    expect(maskSecret("abcdefgh")).toBe("ab****gh");
    expect(maskSecret("sk-1234567890abcdef")).toBe("sk-1****cdef");
  });

  it("should mask long secrets preserving first 6 and last 4", () => {
    expect(maskSecret("sk-proj-1234567890abcdefghijklmnopqrstuvwxyz")).toBe("sk-pro****wxyz");
  });
});
