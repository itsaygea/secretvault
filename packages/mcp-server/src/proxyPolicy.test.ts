import { describe, expect, it } from "vitest";
import { buildProxyTargetUrl, isProxyPathAllowed, isTargetOriginAllowed, isValidServiceName, isValidHeaderName, isValidCookieName, parseEgressAllowlist, safeDecodePathSegment, sanitizeRequestHeaders, sanitizeResponseHeaders, validateResolvedTarget, validateTargetUrl, validateProxyPathPrefixes } from "./proxyPolicy.js";

describe("proxy path policy", () => {
  it("keeps ordinary request paths on the configured origin", () => {
    const result = buildProxyTargetUrl(
      "/proxy/github/v1/user?verbose=true",
      "github",
      "https://api.github.test/",
    );
    expect(result.targetUrl.toString()).toBe("https://api.github.test/v1/user?verbose=true");
  });

  it.each([
    "/proxy/github//attacker.test/path",
    "/proxy/github/\\\\attacker.test/path",
    "/proxy/github/%2F%2Fattacker.test/path",
    "/proxy/github/%40attacker.test/path",
    "/proxy/github/path#fragment",
  ])("rejects authority-changing path %s", (requestUrl) => {
    expect(() => buildProxyTargetUrl(requestUrl, "github", "https://api.github.test/")).toThrow();
  });

  it("rejects invalid profile names before lookup", () => {
    expect(isValidServiceName("github")).toBe(true);
    expect(isValidServiceName("../attacker")).toBe(false);
    expect(isValidServiceName("github/profile")).toBe(false);
  });

  it("requires HTTPS and blocks local destinations by default", () => {
    expect(() => validateTargetUrl("http://api.example.test/")).toThrow();
    expect(() => validateTargetUrl("https://127.0.0.1/")).toThrow();
    expect(() => validateTargetUrl("https://[::1]/")).toThrow();
    expect(() => validateTargetUrl("https://[fd00::1]/")).toThrow();
    expect(() => validateTargetUrl("https://169.254.169.254/latest/meta-data")).toThrow();
    expect(() => validateTargetUrl("http://127.0.0.1/", true)).not.toThrow();
  });

  it("enforces explicit method and path policies", () => {
    expect(isProxyPathAllowed("/v1/users", ["/v1"])).toBe(true);
    expect(isProxyPathAllowed("/v2/users", ["/v1"])).toBe(false);
    expect(validateProxyPathPrefixes(["/v1", "/v2/"]).valid).toBe(true);
    expect(validateProxyPathPrefixes(["//attacker"]).valid).toBe(false);
  });

  it("matches exact configured egress origins", () => {
    expect(parseEgressAllowlist("https://api.example.test,https://other.example.test/")).toEqual([
      "https://api.example.test",
      "https://other.example.test",
    ]);
    expect(isTargetOriginAllowed(new URL("https://api.example.test/v1"), ["https://api.example.test"])).toBe(true);
    expect(isTargetOriginAllowed(new URL("https://api.example.test.evil/v1"), ["https://api.example.test"])).toBe(false);
  });

  it("returns a pinned address for an IP-literal destination", async () => {
    await expect(validateResolvedTarget(new URL("https://8.8.8.8/"))).resolves.toEqual({ address: "8.8.8.8", family: 4 });
  });
});

describe("injected header/cookie name validation (SV-022)", () => {
  it("accepts well-formed token header names", () => {
    expect(isValidHeaderName("X-Api-Key")).toBe(true);
    expect(isValidHeaderName("x-api-key")).toBe(true);
    expect(isValidHeaderName("X-Custom_Header.1")).toBe(true);
  });

  it.each([
    ["Connection", "hop-by-hop"],
    ["connection", "hop-by-hop (case-insensitive)"],
    ["Content-Length", "framing"],
    ["Transfer-Encoding", "framing"],
    ["Host", "routing"],
    ["Authorization", "credential"],
    ["Cookie", "credential"],
    ["X-Forwarded-For", "forwarding"],
    ["Keep-Alive", "hop-by-hop"],
    ["Proxy-Authorization", "hop-by-hop"],
    ["Upgrade", "hop-by-hop"],
    ["Via", "forwarding"],
  ])("rejects reserved header name %s (%s)", (name) => {
    expect(isValidHeaderName(name)).toBe(false);
  });

  it.each([
    "X-Evil\r\nInjected: yes",
    "X-CRLF\nHeader",
    "X-Nul\0Header",
    "Host Spoof",
    "a/b",
    "",
  ])("rejects malformed or smuggling header name %j", (name) => {
    expect(isValidHeaderName(name)).toBe(false);
  });

  it("accepts and rejects cookie-name tokens conservatively", () => {
    expect(isValidCookieName("session")).toBe(true);
    expect(isValidCookieName("API_TOKEN")).toBe(true);
    expect(isValidCookieName("session\r\n")).toBe(false);
    expect(isValidCookieName("a b")).toBe(false);
    expect(isValidCookieName("")).toBe(false);
  });
});

describe("hop-by-hop header policy (SV-023)", () => {
  it("strips standard hop-by-hop, caller credentials, host, and forwarding from outbound requests", () => {
    const out = sanitizeRequestHeaders({
      "X-Api-Key": "caller",
      "Connection": "keep-alive",
      "Keep-Alive": "timeout=5",
      "Transfer-Encoding": "chunked",
      "TE": "trailers",
      "Trailer": "X-Foo",
      "Upgrade": "h2c",
      "Proxy-Authorization": "Bearer x",
      "Authorization": "Bearer caller",
      "Cookie": "caller=1",
      "Host": "caller.test",
      "X-Forwarded-For": "1.2.3.4",
      "Forwarded": "for=1.2.3.4",
      "Via": "1.1 proxy",
      "X-Real-Ip": "1.2.3.4",
      "Accept": "application/json",
    }, { stripForwarding: true });

    expect(out["X-Api-Key"]).toBe("caller");
    expect(out["Accept"]).toBe("application/json");
    expect(out["Connection"]).toBeUndefined();
    expect(out["Keep-Alive"]).toBeUndefined();
    expect(out["Transfer-Encoding"]).toBeUndefined();
    expect(out["TE"]).toBeUndefined();
    expect(out["Trailer"]).toBeUndefined();
    expect(out["Upgrade"]).toBeUndefined();
    expect(out["Proxy-Authorization"]).toBeUndefined();
    expect(out["Authorization"]).toBeUndefined();
    expect(out["Cookie"]).toBeUndefined();
    expect(out["Host"]).toBeUndefined();
    expect(out["X-Forwarded-For"]).toBeUndefined();
    expect(out["Forwarded"]).toBeUndefined();
    expect(out["Via"]).toBeUndefined();
    expect(out["X-Real-Ip"]).toBeUndefined();
  });

  it.each([
    ["connection", "Connection"],
    ["CONNECTION", "Connection (mixed case)"],
    ["Connection", "duplicate-nominated custom field"],
  ])("removes every field nominated by a %s header", () => {
    const out = sanitizeRequestHeaders({
      "Connection": "X-Custom-Hop, Keep-Alive",
      "X-Custom-Hop": "drop-me",
      "Keep-Alive": "timeout=5",
      "Accept": "keep-me",
    });
    expect(out["X-Custom-Hop"]).toBeUndefined();
    expect(out["Keep-Alive"]).toBeUndefined();
    expect(out["Connection"]).toBeUndefined();
    expect(out["Accept"]).toBe("keep-me");
  });

  it("removes Connection-nominated fields with mixed-case header keys", () => {
    const out = sanitizeRequestHeaders({
      "connection": "X-Sensitive",
      "X-Sensitive": "leak",
      "Accept": "ok",
    });
    expect(out["X-Sensitive"]).toBeUndefined();
    expect(out["connection"]).toBeUndefined();
  });

  it("joins multi-valued array headers and forwards safe ones", () => {
    const out = sanitizeRequestHeaders({
      "Accept": ["application/json", "text/plain"],
      "X-Api-Key": "k",
    });
    expect(out["Accept"]).toBe("application/json, text/plain");
    expect(out["X-Api-Key"]).toBe("k");
  });

  it("strips credentials and hop-by-hop fields from upstream responses", () => {
    const out = sanitizeResponseHeaders({
      "Set-Cookie": "upstream=secret",
      "Www-Authenticate": "Basic",
      "Authorization": "Bearer upstream",
      "X-Request-Id": "upstream-id",
      "Connection": "close, X-Hop",
      "X-Hop": "drop",
      "Transfer-Encoding": "chunked",
      "Content-Type": "application/json",
    });
    expect(out["Set-Cookie"]).toBeUndefined();
    expect(out["Www-Authenticate"]).toBeUndefined();
    expect(out["Authorization"]).toBeUndefined();
    expect(out["X-Request-Id"]).toBeUndefined();
    expect(out["Connection"]).toBeUndefined();
    expect(out["X-Hop"]).toBeUndefined();
    expect(out["Transfer-Encoding"]).toBeUndefined();
    expect(out["Content-Type"]).toBe("application/json");
  });
});

describe("safe percent-decoding (SV-024)", () => {
  it("decodes valid sequences", () => {
    expect(safeDecodePathSegment("my%20secret")).toBe("my secret");
    expect(safeDecodePathSegment("plain-name")).toBe("plain-name");
  });

  it.each([
    "%",
    "%ZZ",
    "%2",
    "bad%",
    "a%b%c",
  ])("returns null instead of throwing for malformed encoding %j", (value) => {
    expect(safeDecodePathSegment(value)).toBeNull();
  });

  it("does not throw on any malformed input (process-survival)", () => {
    const nasty = ["%", "%2", "%ZZ", "%E0%A4%A", "�%"];
    for (const input of nasty) {
      expect(() => safeDecodePathSegment(input)).not.toThrow();
    }
  });
});
