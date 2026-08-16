import { describe, expect, it } from "@secretvault/testing";
import { buildProxyTargetUrl, isProxyPathAllowed, isTargetOriginAllowed, isValidServiceName, isValidHeaderName, isValidCookieName, parseEgressAllowlist, safeDecodePathSegment, sanitizeRequestHeaders, sanitizeResponseHeaders, validateResolvedTarget, validateTargetUrl, validateProxyPathPrefixes, createSensitiveValueSet, containsSensitiveValue } from "./proxyPolicy.js";

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

  // SV-AUD-004: IPv4-mapped IPv6 and benchmarking/docs ranges must be denied.
  it.each([
    ["::ffff:7f00:1", "hex-form mapped loopback"],
    ["::ffff:127.0.0.1", "dotted-form mapped loopback"],
    ["::ffff:a00:1", "hex-form mapped RFC1918"],
    ["::ffff:10.0.0.1", "dotted-form mapped RFC1918"],
    ["::1", "IPv6 loopback"],
    ["fc00::1", "unique-local"],
    ["fe80::1", "link-local v6"],
    ["ff02::1", "multicast"],
    ["198.18.0.1", "benchmarking band"],
    ["198.19.255.1", "benchmarking band upper"],
    ["192.0.2.1", "TEST-NET-1 docs"],
    ["100.64.0.1", "carrier-grade NAT"],
  ])("denies non-global-unicast destination %s (%s)", (addr) => {
    expect(() => validateTargetUrl(`https://[${addr}]/`)).toThrow();
  });

  it.each([
    ["https://8.8.8.8/", "public IPv4"],
    ["https://1.1.1.1/", "public IPv4"],
    ["https://[2606:4700::1]/", "public IPv6"],
  ])("allows public destination %s (%s)", (url) => {
    expect(() => validateTargetUrl(url)).not.toThrow();
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

describe("value-based response redaction (SV-AUD-003)", () => {
  it("drops a response header that echoes an injected bearer credential under any name", () => {
    const sensitive = createSensitiveValueSet(["vault-secret-123456"]);
    const out = sanitizeResponseHeaders(
      { "x-debug-auth": "Bearer vault-secret-123456", "x-trace": "ok" },
      { sensitiveValues: sensitive },
    );
    expect(out["x-debug-auth"]).toBeUndefined();
    expect(out["x-trace"]).toBe("ok");
  });

  it("drops a header echoing the Basic composite and its base64 rendering", () => {
    const raw = "vault-secret-123456";
    const encoded = Buffer.from(`user:${raw}`).toString("base64");
    const sensitive = createSensitiveValueSet([raw, `user:${raw}`, `Basic ${encoded}`]);
    sensitive.add(encoded);
    const out = sanitizeResponseHeaders(
      { "x-echo": encoded, "server": "nginx" },
      { sensitiveValues: sensitive },
    );
    expect(out["x-echo"]).toBeUndefined();
    expect(out["server"]).toBe("nginx");
  });

  it("drops a header echoing a cookie rendering", () => {
    const sensitive = createSensitiveValueSet(["vault-secret-123456"]);
    sensitive.add("session=vault-secret-123456");
    const out = sanitizeResponseHeaders(
      { "x-set-debug": "session=vault-secret-123456" },
      { sensitiveValues: sensitive },
    );
    expect(out["x-set-debug"]).toBeUndefined();
  });

  it("does not register trivially short values (false-positive guard)", () => {
    const sensitive = createSensitiveValueSet(["abc"]);
    expect(containsSensitiveValue("abc", sensitive)).toBe(false);
    expect(sensitive.values.size).toBe(0);
  });

  it("still drops named credential headers even without a sensitive set", () => {
    const out = sanitizeResponseHeaders({ "set-cookie": "leak", "www-authenticate": "Basic" });
    expect(out["set-cookie"]).toBeUndefined();
    expect(out["www-authenticate"]).toBeUndefined();
  });
});

