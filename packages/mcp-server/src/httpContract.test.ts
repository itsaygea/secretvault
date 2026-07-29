import { describe, expect, it } from "vitest";
import type { IncomingMessage } from "node:http";
import {
  getRequestId,
  legacyApiSuccessor,
  toErrorEnvelope,
  versionedApiPath,
} from "./httpContract.js";

describe("versioned HTTP contract", () => {
  it("maps versioned management paths to the existing handler seam", () => {
    expect(versionedApiPath("/v1/me")).toBe("/api/me");
    expect(versionedApiPath("/v1/auth/login")).toBe("/api/auth/login");
    expect(versionedApiPath("/api/me")).toBeNull();
    expect(legacyApiSuccessor("/api/me")).toBe("/v1/me");
  });

  it("normalizes invalid client request IDs before they reach a response envelope", () => {
    const request = { headers: { "x-request-id": "bad id with whitespace" } } as unknown as IncomingMessage;
    const requestId = getRequestId(request);
    expect(requestId).not.toBe("bad id with whitespace");
    expect(requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("preserves stable application codes and adds correlation metadata", () => {
    expect(toErrorEnvelope(503, { error: "Audit logging unavailable", code: "AUDIT_UNAVAILABLE" }, "req-123")).toEqual({
      error: {
        code: "AUDIT_UNAVAILABLE",
        message: "Audit logging unavailable",
        requestId: "req-123",
        status: 503,
      },
    });
  });
});
