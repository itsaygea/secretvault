import { request as httpRequest, Agent as HttpAgent, type IncomingMessage, type ServerResponse, type RequestOptions } from "node:http";
import { request as httpsRequest, Agent as HttpsAgent } from "node:https";
import { PassThrough } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import { decryptSecret, canonicalName, ENCRYPTION_PURPOSE, buildContextAad } from "@secretvault/shared";
import { getProfileForProxy } from "./serviceProfiles.js";
import type { Principal } from "./authz.js";
import { buildProxyTargetUrl, isProxyPathAllowed, sanitizeRequestHeaders, sanitizeResponseHeaders, validateResolvedTarget, createSensitiveValueSet } from "./proxyPolicy.js";
import { finishAuditEvent, recordAuditEvent, startCriticalAuditEvent } from "./audit.js";
import { buildUpstreamErrorEnvelope, getRequestId, writeErrorResponse } from "./httpContract.js";

const PROXY_BODY_LIMIT = 10 * 1024 * 1024;
const configuredProxyTimeout = Number.parseInt(process.env.SECRETVAULT_PROXY_TIMEOUT_MS ?? "30000", 10);
const PROXY_TIMEOUT_MS = Number.isFinite(configuredProxyTimeout) && configuredProxyTimeout > 0
  ? configuredProxyTimeout
  : 30_000;

const configuredMaxSockets = Number.parseInt(process.env.SECRETVAULT_PROXY_MAX_SOCKETS ?? "256", 10);
const PROXY_MAX_SOCKETS = Number.isFinite(configuredMaxSockets) && configuredMaxSockets > 0
  ? configuredMaxSockets
  : 256;

const configuredMaxFreeSockets = Number.parseInt(process.env.SECRETVAULT_PROXY_MAX_FREE_SOCKETS ?? "256", 10);
const PROXY_MAX_FREE_SOCKETS = Number.isFinite(configuredMaxFreeSockets) && configuredMaxFreeSockets >= 0
  ? configuredMaxFreeSockets
  : 256;

// ── Origin-keyed HTTP/HTTPS keep-alive agents ──────────────────────

const proxyAgents = new Map<string, HttpAgent | HttpsAgent>();

function agentKey(target: URL): string {
  return `${target.protocol}//${target.hostname}:${target.port || (target.protocol === "https:" ? "443" : "80")}`;
}

function getAgent(target: URL): HttpAgent | HttpsAgent {
  const key = agentKey(target);
  let agent = proxyAgents.get(key);
  if (!agent) {
    const opts = {
      keepAlive: true,
      keepAliveMsecs: 1000,
      maxSockets: PROXY_MAX_SOCKETS,
      maxFreeSockets: PROXY_MAX_FREE_SOCKETS,
      timeout: PROXY_TIMEOUT_MS,
    };
    agent = target.protocol === "https:" ? new HttpsAgent(opts) : new HttpAgent(opts);
    proxyAgents.set(key, agent);
  }
  return agent;
}

export function destroyProxyAgents(): void {
  for (const agent of proxyAgents.values()) {
    agent.destroy();
  }
  proxyAgents.clear();
}

// ── Helper ──────────────────────────────────────────────────────────

function extractIp(req: IncomingMessage): string | null {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length > 0) {
    const first = fwd.split(",")[0]?.trim();
    if (first) return first.slice(0, 64);
  }
  if (req.socket?.remoteAddress) return req.socket.remoteAddress.slice(0, 64);
  return null;
}

function buildLookup(resolved: { address: string; family: 4 | 6 }) {
  return (hostname: string, options: unknown, callback: unknown) => {
    const cb = (typeof options === "function" ? options : callback) as Function;
    const opts = (typeof options === "object" && options !== null ? options : {}) as { all?: boolean };
    if (opts.all) {
      cb(null, [{ address: resolved.address, family: resolved.family }]);
    } else {
      cb(null, resolved.address, resolved.family);
    }
  };
}

// ── Main handler ────────────────────────────────────────────────────

export async function handleProxyRequest(
  req: IncomingMessage,
  res: ServerResponse,
  supabase: SupabaseClient<Database, "secretvault">,
  masterKey: Buffer,
  principal: Principal,
  serviceName: string,
): Promise<void> {
  const { userId } = principal;
  const requestId = getRequestId(req);

  // 1. Look up service profile
  const profile = await getProfileForProxy(supabase, userId, serviceName);
  if (!profile) {
    await startAndFinishDeniedAudit(supabase, principal, serviceName, req);
    writeErrorResponse(res, 404, `Service '${serviceName}' not found`, requestId, "SERVICE_PROFILE_NOT_FOUND");
    return;
  }

  const auditId = await startCriticalAuditEvent(supabase, {
    userId,
    clientId: principal.clientId,
    actorUsername: principal.username ?? null,
    secretName: profile.name || serviceName,
    accessType: "proxy",
    caller: `proxy:${req.method || "GET"}:${req.url || "/"}`,
    requestId: typeof req.headers["x-request-id"] === "string" ? req.headers["x-request-id"] : null,
    sourceIp: extractIp(req),
    sourceUserAgent: typeof req.headers["user-agent"] === "string" ? req.headers["user-agent"] : null,
  });
  if (!auditId) {
    writeErrorResponse(res, 503, "Audit logging unavailable; operation blocked", requestId, "AUDIT_UNAVAILABLE");
    return;
  }

  // 2. Batch-fetch required secrets in one query
  const secretNames = [profile.pass_secret_name!];
  if (profile.user_secret_name) secretNames.push(profile.user_secret_name);

  const canonicalNames = secretNames.map(n => canonicalName(n));
  const { data: rows, error: dbError } = await supabase
    .from("secrets")
    .select("id, name, encrypted_blob")
    .in("name", canonicalNames)
    .eq("user_id", userId);

  if (dbError || !rows || rows.length !== canonicalNames.length) {
    const missing = canonicalNames.filter(n => !rows?.find(r => r.name === n));
    await finishAuditEvent(supabase, auditId, "failed", { reason: "proxy_secret_missing", missing: missing.join(",") });
    writeErrorResponse(res, 500, `Required secrets not found`, requestId, "PROXY_SECRET_NOT_FOUND");
    return;
  }

  const secrets = new Map<string, string>();
  for (const row of rows) {
    try {
      secrets.set(row.name, await decryptSecret(row.encrypted_blob, masterKey, {
        purpose: ENCRYPTION_PURPOSE.SECRET,
        aad: buildContextAad(ENCRYPTION_PURPOSE.SECRET, { userId, recordId: row.id }),
      }));
    } catch {
      await finishAuditEvent(supabase, auditId, "failed", { reason: "proxy_secret_decrypt_failed", secret_name: row.name });
      writeErrorResponse(res, 500, `Failed to decrypt '${row.name}'`, requestId, "PROXY_SECRET_DECRYPT_FAILED");
      return;
    }
  }

  // 3. Build upstream URL
  let target: { targetUrl: URL; pathAndQuery: string };
  try {
    target = buildProxyTargetUrl(req.url, serviceName, profile.target_url);
  } catch (error) {
    await finishAuditEvent(supabase, auditId, "denied", { reason: "proxy_path_invalid" });
    writeErrorResponse(res, 400, error instanceof Error ? error.message : "Invalid proxy path", requestId, "INVALID_PROXY_PATH");
    return;
  }
  const { targetUrl } = target;

  // 4. Method / path / origin checks
  const allowedMethods = profile.allowed_methods ?? ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
  const allowedPathPrefixes = profile.allowed_path_prefixes ?? ["/"];
  const method = (req.method || "GET").toUpperCase();
  if (!allowedMethods.includes(method)) {
    await finishAuditEvent(supabase, auditId, "denied", { reason: "proxy_method_not_allowed" });
    writeErrorResponse(res, 405, "HTTP method is not allowed for this service profile", requestId, undefined, { "Allow": allowedMethods.join(", ") });
    return;
  }
  if (!isProxyPathAllowed(targetUrl.pathname, allowedPathPrefixes)) {
    await finishAuditEvent(supabase, auditId, "denied", { reason: "proxy_path_not_allowed" });
    writeErrorResponse(res, 403, "Request path is not allowed for this service profile", requestId, "PROXY_PATH_NOT_ALLOWED");
    return;
  }
  const configuredOrigin = new URL(profile.target_url).origin;
  if (targetUrl.origin !== configuredOrigin) {
    await finishAuditEvent(supabase, auditId, "denied", { reason: "proxy_origin_mismatch" });
    writeErrorResponse(res, 502, "Upstream origin validation failed", requestId, "UPSTREAM_ORIGIN_MISMATCH");
    return;
  }

  // 5. DNS resolution with IP pinning
  let resolvedTarget: { address: string; family: 4 | 6 };
  try {
    resolvedTarget = await validateResolvedTarget(targetUrl, profile.allow_private_network ?? false);
  } catch (error) {
    await finishAuditEvent(supabase, auditId, "denied", { reason: "proxy_destination_not_allowed" });
    writeErrorResponse(res, 502, error instanceof Error ? error.message : "Upstream destination validation failed", requestId, "UPSTREAM_DESTINATION_NOT_ALLOWED");
    return;
  }

  // 6. Build headers — sanitize before injecting credentials
  let headers = sanitizeRequestHeaders(req.headers as Record<string, string | string[] | undefined>, { stripForwarding: true });
  headers["host"] = new URL(profile.target_url).host;

  const passValue = secrets.get(canonicalName(profile.pass_secret_name!)) ?? "";
  const userValue = profile.user_secret_name ? secrets.get(canonicalName(profile.user_secret_name)) ?? "" : "";

  // SV-AUD-003: track every rendering of the injected credentials for the life
  // of this request so response headers/bodies echoing any of them are dropped.
  const sensitive = createSensitiveValueSet();
  if (passValue) sensitive.add(passValue);
  if (userValue && userValue !== passValue) sensitive.add(userValue);

  switch (profile.auth_method) {
    case "basic": {
      const encoded = Buffer.from(`${userValue}:${passValue}`).toString("base64");
      headers["authorization"] = `Basic ${encoded}`;
      // Track the composite Basic credential and its base64, both of which an
      // attacker-controlled upstream could reflect verbatim or in an error body.
      sensitive.add(`Basic ${encoded}`);
      sensitive.add(encoded);
      sensitive.add(`${userValue}:${passValue}`);
      break;
    }
    case "bearer":
      headers["authorization"] = `Bearer ${passValue}`;
      sensitive.add(`Bearer ${passValue}`);
      break;
    case "header":
      headers[profile.header_name ?? "x-api-key"] = passValue;
      break;
    case "cookie":
      headers["cookie"] = `${profile.cookie_name ?? "session"}=${passValue}`;
      sensitive.add(`${profile.cookie_name ?? "session"}=${passValue}`);
      break;
  }

  // 7. Content-length precheck — reject early if declared body exceeds limit
  const contentLength = headers["content-length"];
  if (contentLength) {
    const len = Number(contentLength);
    if (Number.isFinite(len) && len > PROXY_BODY_LIMIT) {
      await finishAuditEvent(supabase, auditId, "failed", { reason: "proxy_content_length_exceeded" });
      writeErrorResponse(res, 413, "Payload too large", requestId);
      return;
    }
  }

  // 8. Stream request body with byte counter — do not buffer entire bodies
  const bodyStream = new PassThrough({ highWaterMark: 65536 });
  let bodySize = 0;
  let bodyOverflow = false;

  req.on("data", (chunk: Buffer) => {
    if (bodyOverflow) return;
    bodySize += chunk.length;
    if (bodySize > PROXY_BODY_LIMIT) {
      bodyOverflow = true;
      req.destroy();
      bodyStream.destroy(new Error("Payload too large"));
      return;
    }
    bodyStream.write(chunk);
  });
  req.on("end", () => {
    if (!bodyOverflow && !bodyStream.destroyed) bodyStream.end();
  });
  req.on("error", () => {
    if (!bodyStream.destroyed) bodyStream.destroy(new Error("Request body error"));
  });

  // 9. Forward request with keep-alive agent
  const isGetOrHead = method === "GET" || method === "HEAD";
  const agent = getAgent(targetUrl);

  const requestOptions: RequestOptions = {
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    port: targetUrl.port || undefined,
    path: `${targetUrl.pathname}${targetUrl.search}`,
    method,
    headers,
    agent,
    lookup: buildLookup(resolvedTarget),
  };

  try {
    const upstreamReq = targetUrl.protocol === "https:"
      ? httpsRequest(requestOptions)
      : httpRequest(requestOptions);

    const upstreamResponse = new Promise<IncomingMessage>((resolve, reject) => {
      upstreamReq.on("response", resolve);
      upstreamReq.on("error", reject);
    });

    upstreamReq.setTimeout(PROXY_TIMEOUT_MS, () => {
      upstreamReq.destroy(new Error("Upstream request timed out"));
    });

    // Pipe body stream to upstream request
    if (!isGetOrHead) {
      pipeline(bodyStream, upstreamReq).catch((err) => {
        if (!upstreamReq.destroyed) upstreamReq.destroy(err);
      });
    } else {
      upstreamReq.end();
    }

    // Wait a microtick for initial body data in case it overflows immediately
    await new Promise(r => setImmediate(r));
    if (bodyOverflow) {
      upstreamReq.destroy(new Error("Payload too large"));
      await finishAuditEvent(supabase, auditId, "failed", { reason: "proxy_request_body_failed" });
      writeErrorResponse(res, 413, "Payload too large or unreadable", requestId);
      return;
    }

    const upstream = await upstreamResponse;

    // 10. Stream response back
    const upstreamStatus = upstream.statusCode ?? 502;
    const isUpstreamError = upstreamStatus >= 400;
    const statusHeaders = sanitizeResponseHeaders(
      upstream.headers as Record<string, string | string[] | undefined>,
      { sensitiveValues: sensitive },
    );
    statusHeaders["X-Request-ID"] = requestId;

    if (isUpstreamError) {
      // SV-AUD-003: an attacker-controlled upstream error body could echo an
      // injected credential. Discard its body entirely and substitute a stable
      // SecretVault envelope. The status code is preserved; no upstream-derived
      // bytes reach the caller. The upstream stream is drained then dropped.
      const envelope = buildUpstreamErrorEnvelope(upstreamStatus, requestId);
      statusHeaders["Content-Type"] = "application/json; charset=utf-8";
      statusHeaders["Content-Length"] = Buffer.byteLength(envelope).toString();
      delete statusHeaders["content-encoding"];
      delete statusHeaders["transfer-encoding"];
      res.writeHead(upstreamStatus, statusHeaders);
      upstream.resume(); // drain and discard the upstream error body
      res.end(envelope);
    } else {
      // Successful responses stream through unchanged (streaming + 10 MiB limit
      // preserved); only the value-redacted headers above are applied.
      res.writeHead(upstreamStatus, statusHeaders);
      await pipeline(upstream, res);
    }

    await finishAuditEvent(supabase, auditId, upstreamStatus < 400 ? "succeeded" : "failed", {
      upstream_status: upstreamStatus,
    });
  } catch (err) {
    if (bodyOverflow) {
      await finishAuditEvent(supabase, auditId, "failed", { reason: "proxy_request_body_failed" });
      if (!res.headersSent) writeErrorResponse(res, 413, "Payload too large or unreadable", requestId);
      return;
    }
    await finishAuditEvent(supabase, auditId, "failed", { reason: "proxy_upstream_failed" });
    console.error(`[proxy] Upstream error: ${err}`);
    if (!res.headersSent) {
      writeErrorResponse(res, 502, "Upstream connection failed", requestId, "UPSTREAM_CONNECTION_FAILED");
    }
  }
}

// ── Denied audit helper ────────────────────────────────────────────

async function startAndFinishDeniedAudit(
  supabase: SupabaseClient<Database, "secretvault">,
  principal: Principal,
  serviceName: string,
  req: IncomingMessage,
): Promise<void> {
  await recordAuditEvent(supabase, {
    userId: principal.userId,
    clientId: principal.clientId,
    secretName: "system",
    accessType: "proxy",
    caller: `proxy:${req.method || "GET"}:${serviceName}`,
    outcome: "denied",
    requestId: typeof req.headers["x-request-id"] === "string" ? req.headers["x-request-id"] : null,
    metadata: { reason: "service_profile_not_found" },
  }).catch(() => undefined);
}
