import type { IncomingMessage } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ALLOW_PLAINTEXT_EXTERNAL_CONFIRM,
  applySecurityHeaders,
  bindHost,
  effectiveHost,
  effectiveOrigin,
  effectiveScheme,
  isLoopback,
  plaintextStartupError,
  securityHeaders,
} from "./transportSecurity.js";

function req(headers: Record<string, string> = {}): IncomingMessage {
  return { headers } as unknown as IncomingMessage;
}

describe("transport security — proxy-aware scheme and origin", () => {
  it("honours X-Forwarded-Proto from a TLS-terminating reverse proxy", () => {
    expect(effectiveScheme(req({ "x-forwarded-proto": "https" }), false)).toBe("https");
  });

  it("falls back to the native listener protocol without a proxy", () => {
    expect(effectiveScheme(req({}), false)).toBe("http");
    expect(effectiveScheme(req({}), true)).toBe("https");
  });

  it("computes the canonical origin from forwarded host + proto", () => {
    expect(effectiveOrigin(req({ "x-forwarded-proto": "https", "x-forwarded-host": "vault.example.com" }), false))
      .toBe("https://vault.example.com");
  });

  it("falls back to the direct Host header", () => {
    expect(effectiveHost(req({ host: "127.0.0.1:3004" }))).toBe("127.0.0.1:3004");
  });
});

describe("transport security — security headers", () => {
  it("always emits nosniff / frame-deny / referrer headers", () => {
    const h = securityHeaders(req({ "x-forwarded-proto": "https" }), true);
    expect(h["X-Content-Type-Options"]).toBe("nosniff");
    expect(h["X-Frame-Options"]).toBe("DENY");
    expect(h["Referrer-Policy"]).toBe("no-referrer");
  });

  it("emits HSTS only over TLS, never over plaintext", () => {
    expect(securityHeaders(req({ "x-forwarded-proto": "https" }), false)["Strict-Transport-Security"])
      .toMatch(/max-age=\d+/);
    expect(securityHeaders(req({}), false)["Strict-Transport-Security"]).toBeUndefined();
  });

  it("applies headers to a live response", () => {
    const setHeader = vi.fn();
    applySecurityHeaders(req({ "x-forwarded-proto": "https" }), { setHeader } as never, true);
    expect(setHeader).toHaveBeenCalledWith("Strict-Transport-Security", expect.stringMatching(/max-age=\d+/));
  });
});

describe("transport security — bind host and loopback detection", () => {
  const original: Record<string, string | undefined> = {};
  beforeEach(() => { original.SECRETVAULT_BIND_HOST = process.env.SECRETVAULT_BIND_HOST; delete process.env.SECRETVAULT_BIND_HOST; });
  afterEach(() => { if (original.SECRETVAULT_BIND_HOST === undefined) delete process.env.SECRETVAULT_BIND_HOST; else process.env.SECRETVAULT_BIND_HOST = original.SECRETVAULT_BIND_HOST; });

  it("defaults to loopback so the plaintext listener is not externally reachable", () => {
    expect(bindHost()).toBe("127.0.0.1");
    expect(isLoopback(bindHost())).toBe(true);
  });

  it("honours an explicit bind host", () => {
    process.env.SECRETVAULT_BIND_HOST = "0.0.0.0";
    expect(bindHost()).toBe("0.0.0.0");
    expect(isLoopback(bindHost())).toBe(false);
  });
});

describe("transport security — production plaintext refusal (SV-020)", () => {
  const envKeys = ["NODE_ENV", "SECRETVAULT_BIND_HOST", "SECRETVAULT_TLS_CERT", "SECRETVAULT_TLS_KEY", "SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL", "SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM"];
  const original: Record<string, string | undefined> = {};
  beforeEach(() => { for (const k of envKeys) { original[k] = process.env[k]; delete process.env[k]; } });
  afterEach(() => { for (const k of envKeys) { if (original[k] === undefined) delete process.env[k]; else process.env[k] = original[k]; } });

  it("allows native TLS regardless of bind host", () => {
    process.env.NODE_ENV = "production";
    process.env.SECRETVAULT_BIND_HOST = "0.0.0.0";
    process.env.SECRETVAULT_TLS_CERT = "/x"; process.env.SECRETVAULT_TLS_KEY = "/y";
    expect(plaintextStartupError(true)).toBeNull();
  });

  it("allows plaintext on loopback in production", () => {
    process.env.NODE_ENV = "production";
    process.env.SECRETVAULT_BIND_HOST = "127.0.0.1";
    expect(plaintextStartupError(false)).toBeNull();
  });

  it("allows plaintext anywhere outside production (local development)", () => {
    process.env.NODE_ENV = "development";
    process.env.SECRETVAULT_BIND_HOST = "0.0.0.0";
    expect(plaintextStartupError(false)).toBeNull();
  });

  it("refuses externally-exposed plaintext in production without the override", () => {
    process.env.NODE_ENV = "production";
    process.env.SECRETVAULT_BIND_HOST = "0.0.0.0";
    const err = plaintextStartupError(false);
    expect(err).not.toBeNull();
    expect(err).toMatch(/Refusing to start/);
  });

  it("refuses the override when the confirmation is missing (no accidental empty prompt)", () => {
    process.env.NODE_ENV = "production";
    process.env.SECRETVAULT_BIND_HOST = "0.0.0.0";
    process.env.SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL = "1";
    // confirmation unset
    expect(plaintextStartupError(false)).not.toBeNull();
    // wrong confirmation
    process.env.SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM = "yes";
    expect(plaintextStartupError(false)).not.toBeNull();
  });

  it("allows externally-exposed plaintext only with the explicit, noisy override", () => {
    process.env.NODE_ENV = "production";
    process.env.SECRETVAULT_BIND_HOST = "0.0.0.0";
    process.env.SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL = "1";
    process.env.SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM = ALLOW_PLAINTEXT_EXTERNAL_CONFIRM;
    expect(plaintextStartupError(false)).toBeNull();
  });
});
