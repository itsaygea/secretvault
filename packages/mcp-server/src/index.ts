#!/usr/bin/env node
import { handleRunCli } from "./runner.js";

const arg = process.argv[2];

if (arg === "run") {
  await handleRunCli();
  process.exit(0);
}

if (arg === "setup") {
  const { handleSetupCli } = await import("./cli/setup.js");
  await handleSetupCli();
  process.exit(0);
}

if (arg === "secret") {
  const { handleSecretCli } = await import("./cli/secret.js");
  await handleSecretCli();
  process.exit(0);
}

if (arg === "rotate-master-key") {
  const { handleRotateMasterKeyCli } = await import("./cli/rotateKey.js");
  await handleRotateMasterKeyCli();
  process.exit(0);
}

if (arg === "--help" || arg === "-h" || arg === "help") {
  console.log(`
SecretVault CLI & MCP Server

Usage:
  secretvault-mcp setup                  Launch interactive developer tool setup wizard
  secretvault-mcp secret <subcommand>   Manage secrets (list, create, rotate, delete)
  secretvault-mcp run <args...>          Inject secrets into command execution
  secretvault-mcp rotate-master-key      Re-encrypt stored database secrets
  secretvault-mcp                        Start SecretVault MCP Server (requires environment vars)

Options:
  --help, -h     Show this help message
  --version, -v  Show version
`);
  process.exit(0);
}

if (arg === "--version" || arg === "-v") {
  console.log("0.1.0");
  process.exit(0);
}

import crypto from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { readdirSync, statSync } from "node:fs";
import { resolve, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@secretvault/shared";
import { resolveMasterKey } from "./keyLoader.js";
import { registerAllTools } from "./tools/index.js";
import {
  initAuth,
  generateToken,
  handleAuthLogin,
  handleListSecrets,
  handleCreateSecret,
  handleRotateSecret,
  handleDeleteSecret,
  handleRevealSecret,
  handleClientGetSecret,
  resolveAuthContext,
  handleGetAdminStats,
  handleGetUserLogs,
} from "./api.js";
import {
  initSetupCode,
  bootstrapAdmin,
  handleAuthStatus,
  handleSetup,
  handleListUsers,
  handleCreateUser,
  handleDeleteUser,
  handleGenerateLinkingKey,
  handleGetMe,
  handleChangePassword,
  authenticateLinkingKey,
  handleListClients,
  handleCreateClient,
  handleDeleteClient,
  handleGetClientLogs,
  handleRevealClientKey,
  handleRegenerateClientKey,
  handleUpdateClient,
  handleGetPublicSettings,
  handleGetSystemSettings,
  handleUpdateSystemSettings,
  handleSelfRegister,
  handleAdminResetUserPassword,
  handleAdminResetUser2FA,
} from "./users.js";
import {
  initStepUpAuth,
  handleWebAuthnRegisterOptions,
  handleWebAuthnRegisterVerify,
  handleWebAuthnAuthOptions,
  handleWebAuthnAuthVerify,
  handleListPasskeys,
  handleDeletePasskey,
  handleTotpSetup,
  handleTotpCancelSetup,
  handleTotpVerifySetup,
  handleTotpAuthenticate,
  handleTotpRegenerateBackupCodes,
  handleDisableTotp,
} from "./stepup.js";
import {
  handleListProfiles,
  handleCreateProfile,
  handleDeleteProfile,
} from "./serviceProfiles.js";
import { handleProxyRequest, destroyProxyAgents } from "./proxy.js";
import { canonicalServiceName, isValidServiceName, safeDecodePathSegment } from "./proxyPolicy.js";
import { resolveMcpAuth } from "./mcpAuth.js";
import { hasScope, hasRunnerScope, isSessionPrincipal, type Principal } from "./authz.js";
import { recordAuditEvent, setAuditAlertSink } from "./audit.js";
import { getRetentionPolicy, setRetentionPolicy, pruneOldAuditLogs, exportAuditLogs } from "./auditRetention.js";
import {
  applySecurityHeaders,
  bindHost,
  effectiveHost,
  effectiveOrigin,
  plaintextStartupError,
} from "./transportSecurity.js";
import {
  API_VERSION,
  SERVER_VERSION,
  getRequestId,
  initializeRequestContext,
  legacyApiSuccessor,
  versionedApiPath,
  writeApiResponse,
  writeErrorResponse,
} from "./httpContract.js";

export { resolveMcpAuth };

const SUPABASE_URL = process.env.SECRETVAULT_SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SECRETVAULT_SUPABASE_SERVICE_KEY;
const PORT = parseInt(process.env.PORT ?? "3004", 10);
const ALLOWED_ORIGINS = process.env.SECRETVAULT_ALLOWED_ORIGINS
  ? process.env.SECRETVAULT_ALLOWED_ORIGINS.split(",").map(s => s.trim()).filter(Boolean)
  : null;

if (process.argv[2] !== "run" && (!SUPABASE_URL || !SUPABASE_SERVICE_KEY)) {
  console.error(
    "ERROR: Missing required environment variables: SECRETVAULT_SUPABASE_URL, SECRETVAULT_SUPABASE_SERVICE_KEY",
  );
  process.exit(1);
}

let masterKey: Buffer;
try {
  masterKey = resolveMasterKey();
} catch (err: any) {
  if (process.argv[2] !== "run") {
    console.error(`ERROR: ${err?.message}`);
    process.exit(1);
  }
  masterKey = Buffer.alloc(32);
}

// Initialize auth module with deterministic HMAC key derived from master key
initAuth(masterKey);
initStepUpAuth(masterKey);

// Operational alerting for audit write/finalization failures, unknown rows,
// and suspicious activity. The alert sink is the single fan-out point; the
// default implementation logs to stderr so failures are never silent. A
// rolling in-memory counter escalates repeated denials and reveal bursts.
const denialWindow = new Map<string, { count: number; first: number }>();
const revealWindow = new Map<string, { count: number; first: number }>();
const WINDOW_MS = 60_000;
const DENIAL_THRESHOLD = 20;
const REVEAL_THRESHOLD = 50;

function bumpWindow(window: Map<string, { count: number; first: number }>, key: string, threshold: number, kind: "repeated_denials" | "suspicious_activity", detail: string): void {
  const now = Date.now();
  const entry = window.get(key);
  if (!entry || now - entry.first > WINDOW_MS) {
    window.set(key, { count: 1, first: now });
    return;
  }
  entry.count += 1;
  if (entry.count === threshold) {
    console.error(`[audit:alert] ${kind} ${key}: ${detail} (${threshold} in ${WINDOW_MS / 1000}s)`);
  }
}

setAuditAlertSink((alert) => {
  // Always log so the signal is observable even without a metrics backend.
  console.error(`[audit:alert] ${alert.kind} ${alert.accessType}: ${alert.detail}`);
  if (alert.kind === "suspicious_activity" && alert.detail.startsWith("denial:")) {
    bumpWindow(denialWindow, alert.detail, DENIAL_THRESHOLD, "repeated_denials", alert.detail);
  }
});

let supabase: SupabaseClient<Database, "secretvault"> = (SUPABASE_URL && SUPABASE_SERVICE_KEY)
  ? createClient<Database>(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      db: { schema: "secretvault" },
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    })
  : (null as unknown as SupabaseClient<Database, "secretvault">);

// Generate setup code if no admin user exists yet. Test harnesses inject a
// database adapter through configureServerForTests before making requests.
async function runStartupTasks(): Promise<void> {
  const uiPassword = process.env.SECRETVAULT_UI_PASSWORD;
  if (uiPassword && uiPassword.trim() !== "") {
    await bootstrapAdmin(supabase, uiPassword.trim());
  }
  await initSetupCode(supabase);
  startupComplete = true;
  console.error("[runtime] Server startup initialization complete");
}
if (process.env.NODE_ENV !== "test") {
  runStartupTasks().catch(err => console.error(`[runtime] Startup task failed: ${err}`));
}

// ── Server Runtime State ──────────────────────────────────────────────
const serverState = {
  started: false,
  shuttingDown: false,
};
let startupComplete = false;
const SHUTDOWN_FORCE_EXIT_MS = 10_000;

// ── Static Asset Cache ────────────────────────────────────────────────
interface CachedAsset {
  data: Buffer;
  contentType: string;
  etag: string;
}

function loadAssetCache(): { openapi: CachedAsset; ui: Map<string, CachedAsset> } {
  const openApiPath = resolve(process.cwd(), "docs/openapi.json");
  let openapi: CachedAsset;
  if (existsSync(openApiPath)) {
    const data = readFileSync(openApiPath);
    const hash = crypto.createHash("md5").update(data).digest("hex");
    openapi = { data, contentType: "application/vnd.oai.openapi+json; charset=utf-8", etag: `"${hash}"` };
  } else {
    openapi = { data: Buffer.from("{}"), contentType: "application/vnd.oai.openapi+json; charset=utf-8", etag: '""' };
  }

  const baseDir = dirname(fileURLToPath(import.meta.url));
  const uiDir = existsSync(resolve(baseDir, "ui"))
    ? resolve(baseDir, "ui")
    : resolve(baseDir, "..", "ui");
  const ui = new Map<string, CachedAsset>();

  if (existsSync(uiDir)) {
    const scanDir = (dir: string, prefix: string) => {
      let entries: string[];
      try { entries = readdirSync(dir); } catch { return; }
      for (const entry of entries) {
        const fullPath = resolve(dir, entry);
        let stat: ReturnType<typeof statSync>;
        try { stat = statSync(fullPath); } catch { continue; }
        if (stat.isDirectory()) {
          scanDir(fullPath, `${prefix}${entry}/`);
        } else if (stat.isFile()) {
          const data = readFileSync(fullPath);
          const hash = crypto.createHash("md5").update(data).digest("hex");
          const ext = extname(entry).toLowerCase();
          const contentType = ext === ".js" ? "application/javascript; charset=utf-8"
            : ext === ".css" ? "text/css; charset=utf-8"
            : ext === ".ico" ? "image/x-icon"
            : ext === ".png" ? "image/png"
            : ext === ".svg" ? "image/svg+xml"
            : ext === ".json" && entry === "openapi.json" ? "application/vnd.oai.openapi+json; charset=utf-8"
            : "text/html; charset=utf-8";
          ui.set(`${prefix}${entry}`, { data, contentType, etag: `"${hash}"` });
        }
      }
    };
    scanDir(uiDir, "");
  }

  return { openapi, ui };
}

const assetCache = process.env.NODE_ENV !== "test" ? loadAssetCache() : { openapi: { data: Buffer.from("{}"), contentType: "application/json", etag: '""' } as CachedAsset, ui: new Map<string, CachedAsset>() };

export function configureServerForTests(
  testSupabase: SupabaseClient<Database, "secretvault">,
  testMasterKey = masterKey,
): void {
  supabase = testSupabase;
  masterKey = testMasterKey;
  initAuth(masterKey);
  initStepUpAuth(masterKey);
}

// Factory: each connection gets its own McpServer instance scoped to a user
function createMcpServer(principal: Principal) {
  const server = new McpServer({
    name: "secretvault",
    version: "0.1.0",
  });
  registerAllTools(server, supabase, masterKey, principal);
  return server;
}

// Transport state
const transports: Record<string, SSEServerTransport | StreamableHTTPServerTransport> = {};
const sessionPrincipals: Record<string, Principal> = {};

const MAX_BODY_SIZE = 1024 * 1024; // 1MB

// Parse raw request body with size limit
function parseRequestBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        req.destroy();
        reject(new Error("Payload too large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const body = Buffer.concat(chunks).toString("utf8");
        resolve(body ? JSON.parse(body) : {});
      } catch (err) { reject(err); }
    });
    req.on("error", reject);
  });
}

// ── Streamable HTTP handler ────────────────────────────────────────
async function handleStreamableHttpRequest(req: IncomingMessage, res: ServerResponse, url: URL) {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  try {
    // Reuse existing transport for known session
    if (sessionId && transports[sessionId]) {
      const boundPrincipal = sessionPrincipals[sessionId];
      const currentPrincipal = await resolveMcpAuth(req, url, supabase);
      if (!boundPrincipal || !currentPrincipal ||
          boundPrincipal.userId !== currentPrincipal.userId ||
          boundPrincipal.clientId !== currentPrincipal.clientId ||
          !hasScope(currentPrincipal, "mcp:read")) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized MCP session" }, id: null }));
        return;
      }
      const transport = transports[sessionId];
      if (transport instanceof StreamableHTTPServerTransport) {
        await transport.handleRequest(req, res);
        return;
      }
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "Session exists but uses different transport" }, id: null }));
      return;
    }

    // New session: only valid for POST with initialize request
    if (req.method === "POST") {
      let body: unknown;
      try {
        body = await parseRequestBody(req);
      } catch (err) {
        const status = err instanceof Error && err.message === "Payload too large" ? 413 : 400;
        const message = status === 413 ? "Payload too large (max 1MB)" : "Invalid JSON body";
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: message }));
        return;
      }

      if (isInitializeRequest(body)) {
        // Auth check for new MCP connections
        const mcpAuth = await resolveMcpAuth(req, url, supabase);
        if (!mcpAuth) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized. Provide Authorization: Bearer <linking_key> header." }, id: null }));
          return;
        }

        if (!hasScope(mcpAuth, "mcp:read")) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32003, message: "Forbidden. The linking key lacks the mcp:read scope." }, id: null }));
          return;
        }

        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: (sid) => {
            console.error(`[streamable-http] session initialized: ${sid}`);
            transports[sid] = transport;
            sessionPrincipals[sid] = mcpAuth;
          },
        });

        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid) {
            console.error(`[streamable-http] session closed: ${sid}`);
            delete transports[sid];
            delete sessionPrincipals[sid];
          }
        };

        const clientServer = createMcpServer(mcpAuth);
        await clientServer.connect(transport);
        await transport.handleRequest(req, res, body);
        return;
      }
    }

    // No valid session and not an initialize request
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: No valid session ID provided" }, id: null }));
  } catch (err) {
    console.error(`[streamable-http] error: ${err}`);
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }
}

// ── REST API handler ────────────────────────────────────────────────

const VALID_OUTCOMES = new Set(["succeeded", "failed", "denied", "unknown"]);

function parsePaginationQuery(url: URL): { cursor?: string | null; pageSize?: number } {
  const sp = url.searchParams;
  const query: { cursor?: string | null; pageSize?: number } = {};
  const cursor = sp.get("cursor");
  if (cursor) query.cursor = cursor;
  const ps = sp.get("page_size");
  if (ps) {
    const n = parseInt(ps, 10);
    if (Number.isFinite(n) && n > 0) query.pageSize = n;
  }
  return query;
}

function parseAuditLogQuery(url: URL): {
  cursor?: string | null;
  pageSize?: number;
  from?: string | null;
  to?: string | null;
  accessType?: string | null;
  outcome?: string | null;
  secretName?: string | null;
} {
  const sp = url.searchParams;
  const query: Record<string, string | number | null> = {};
  const cursor = sp.get("cursor");
  if (cursor) query.cursor = cursor;
  const ps = sp.get("page_size");
  if (ps) {
    const n = parseInt(ps, 10);
    if (Number.isFinite(n) && n > 0) query.pageSize = n;
  }
  const from = sp.get("from");
  if (from) query.from = from;
  const to = sp.get("to");
  if (to) query.to = to;
  const accessType = sp.get("access_type");
  if (accessType && /^[a-z][a-z0-9_.:-]{0,63}$/.test(accessType)) query.accessType = accessType;
  const outcome = sp.get("outcome");
  if (outcome && VALID_OUTCOMES.has(outcome)) query.outcome = outcome;
  const secretName = sp.get("secret_name");
  if (secretName) query.secretName = secretName;
  return query;
}

async function handleApiRoute(req: IncomingMessage, res: ServerResponse, url: URL) {
  function sendResponse(result: { status: number; body: unknown }) {
    writeApiResponse(res, result.status, result.body, getRequestId(req));
  }

  async function parseBodyOr413(): Promise<unknown | null> {
    try {
      return await parseRequestBody(req);
    } catch (err) {
      if (err instanceof Error && err.message === "Payload too large") {
        sendResponse({ status: 413, body: { error: "Payload too large (max 1MB)" } });
        return null;
      }
      sendResponse({ status: 400, body: { error: "Invalid JSON body" } });
      return null;
    }
  }

  // POST /api/auth/login
  if (url.pathname === "/api/auth/login" && req.method === "POST") {
    const body = await parseBodyOr413() as { username?: string; password?: string } | null;
    if (!body) return;
    return sendResponse(await handleAuthLogin(supabase, body));
  }

  // GET /api/auth/status (public — no auth required)
  if (url.pathname === "/api/auth/status" && req.method === "GET") {
    return sendResponse(await handleAuthStatus(supabase));
  }

  // GET /api/version (public — describes the supported protocol seam)
  if (url.pathname === "/api/version" && req.method === "GET") {
    return sendResponse({
      status: 200,
      body: {
        name: "secretvault",
        version: SERVER_VERSION,
        api_version: API_VERSION,
        supported_api_versions: [API_VERSION],
        management_base_path: `/${API_VERSION}`,
        proxy_base_path: "/proxy/{profile}",
        openapi: "/docs/openapi.json",
      },
    });
  }

  // POST /v1/auth/setup or /api/auth/setup (public — creates first admin)
  if ((url.pathname === "/v1/auth/setup" || url.pathname === "/api/auth/setup") && req.method === "POST") {
    const body = await parseBodyOr413() as { setup_code?: string; username?: string; password?: string } | null;
    if (!body) return;
    return sendResponse(await handleSetup(supabase, body, generateToken));
  }

  // GET /api/settings/public (public — returns open registration status)
  if (url.pathname === "/api/settings/public" && req.method === "GET") {
    return sendResponse(await handleGetPublicSettings(supabase));
  }

  // POST /api/auth/register (public — self-service registration when enabled)
  if (url.pathname === "/api/auth/register" && req.method === "POST") {
    const body = await parseBodyOr413() as { username?: string; password?: string } | null;
    if (!body) return;
    return sendResponse(await handleSelfRegister(supabase, body));
  }

  // All other API routes require auth
  const authCtx = await resolveAuthContext(supabase, req);
  if (!authCtx) {
    void recordAuditEvent(supabase, {
      secretName: "system",
      accessType: "authorization_denied",
      caller: `rest:${req.method || "GET"}:${url.pathname}`,
      outcome: "denied",
      metadata: { reason: "missing_or_invalid_auth" },
    }).catch(() => undefined);
    return sendResponse({ status: 401, body: { error: "Unauthorized" } });
  }

  const recordDenied = (reason: string, metadata: Record<string, string> = {}) => {
    bumpWindow(denialWindow, `denial:${authCtx.userId}:${reason}`, DENIAL_THRESHOLD, "repeated_denials", `denial:${authCtx.userId}:${reason}`);
    void recordAuditEvent(supabase, {
      userId: authCtx.userId,
      clientId: authCtx.clientId,
      secretName: "system",
      accessType: "authorization_denied",
      caller: `rest:${req.method || "GET"}:${url.pathname}`,
      outcome: "denied",
      metadata: { reason, ...metadata },
    }).catch(() => undefined);
  };

  const requireScope = (scope: string): boolean => {
    if (hasScope(authCtx, scope)) return true;
    recordDenied("missing_scope", { required_scope: scope });
    void sendResponse({ status: 403, body: { error: "Forbidden" } });
    return false;
  };

  const requireSession = (): boolean => {
    if (isSessionPrincipal(authCtx)) return true;
    recordDenied("session_required");
    void sendResponse({ status: 403, body: { error: "Forbidden: this operation requires a user session" } });
    return false;
  };

  const requireAdminSession = (): boolean => {
    if (isSessionPrincipal(authCtx) && authCtx.isAdmin) return true;
    recordDenied("admin_session_required");
    void sendResponse({ status: 403, body: { error: "Forbidden" } });
    return false;
  };

  // GET /api/me
  if (url.pathname === "/api/me" && req.method === "GET") {
    return sendResponse(await handleGetMe(supabase, authCtx.userId));
  }

  // GET /api/user/logs
  if (url.pathname === "/api/user/logs" && req.method === "GET") {
    if (!requireScope("secrets:metadata:read")) return;
    const query = parseAuditLogQuery(url);
    return sendResponse(await handleGetUserLogs(supabase, authCtx.userId, query));
  }

  // POST /api/auth/change-password
  if (url.pathname === "/api/auth/change-password" && req.method === "POST") {
    if (!requireSession()) return;
    const body = await parseBodyOr413() as { current_password?: string; new_password?: string } | null;
    if (!body) return;
    return sendResponse(await handleChangePassword(supabase, authCtx.userId, body));
  }

  // ── System Settings & Admin Stats (admin only) ───────────────────
  if (url.pathname === "/api/settings" && req.method === "GET") {
    if (!requireAdminSession()) return;
    return sendResponse(await handleGetSystemSettings(supabase));
  }

  if (url.pathname === "/api/settings" && req.method === "PATCH") {
    if (!requireAdminSession()) return;
    const body = await parseBodyOr413() as { open_registration_enabled?: boolean } | null;
    if (!body) return;
    return sendResponse(await handleUpdateSystemSettings(supabase, authCtx.userId, body));
  }

  // GET /api/settings/audit-retention (admin)
  if (url.pathname === "/api/settings/audit-retention" && req.method === "GET") {
    if (!requireAdminSession()) return;
    return sendResponse({ status: 200, body: await getRetentionPolicy(supabase) });
  }

  // PATCH /api/settings/audit-retention (admin) — set bounded retention; the
  // floor is enforced server-side so a short retention can't erase fresh rows.
  if (url.pathname === "/api/settings/audit-retention" && req.method === "PATCH") {
    if (!requireAdminSession()) return;
    const body = await parseBodyOr413() as { retention_days?: number | null; floor_days?: number } | null;
    if (!body) return;
    try {
      const policy = await setRetentionPolicy(supabase, body.retention_days ?? null, body.floor_days ?? 7, authCtx.userId);
      void recordAuditEvent(supabase, {
        userId: authCtx.userId,
        secretName: "system",
        accessType: "audit_retention_change",
        caller: "rest:/api/settings/audit-retention",
        metadata: { retention_days: String(policy.retentionDays ?? "unbounded"), floor_days: String(policy.floorDays) },
      }).catch(() => undefined);
      // Apply the new policy immediately so the bound takes effect at
      // configuration time rather than waiting for the next scheduled prune.
      const pruned = await pruneOldAuditLogs(supabase as SupabaseClient<Database, "secretvault">, policy);
      return sendResponse({ status: 200, body: { ...policy, pruned } });
    } catch (err) {
      return sendResponse({ status: 400, body: { error: (err as Error).message } });
    }
  }

  // GET /api/user/logs/export — immutable audit snapshot for archival
  if (url.pathname === "/api/user/logs/export" && req.method === "GET") {
    if (!requireScope("secrets:metadata:read")) return;
    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    const limit = url.searchParams.get("limit");
    const rows = await exportAuditLogs(supabase as SupabaseClient<Database, "secretvault">, authCtx.userId, {
      from: from || null,
      to: to || null,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
    return sendResponse({ status: 200, body: { events: rows, count: rows.length } });
  }

  if (url.pathname === "/api/admin/stats" && req.method === "GET") {
    if (!requireAdminSession()) return;
    return sendResponse(await handleGetAdminStats(supabase));
  }

  // ── User management (admin only) ─────────────────────────────────
  if (url.pathname === "/api/users" && req.method === "GET") {
    if (!requireAdminSession()) return;
    const pagination = parsePaginationQuery(url);
    return sendResponse(await handleListUsers(supabase, pagination));
  }

  if (url.pathname === "/api/users" && req.method === "POST") {
    if (!requireAdminSession()) return;
    const body = await parseBodyOr413() as { username?: string; password?: string; is_admin?: boolean } | null;
    if (!body) return;
    return sendResponse(await handleCreateUser(supabase, body, { userId: authCtx.userId, username: authCtx.username }));
  }

  // DELETE /api/users/:id
  const userDeleteMatch = url.pathname.match(/^\/api\/users\/([^/]+)$/);
  if (userDeleteMatch && req.method === "DELETE") {
    if (!requireAdminSession()) return;
    return sendResponse(await handleDeleteUser(supabase, userDeleteMatch[1], authCtx.userId));
  }

  // POST /api/users/:id/reset-password
  const userResetPassMatch = url.pathname.match(/^\/api\/users\/([^/]+)\/reset-password$/);
  if (userResetPassMatch && req.method === "POST") {
    if (!requireAdminSession()) return;
    const body = await parseBodyOr413() as { new_password?: string } | null;
    if (!body) return;
    return sendResponse(await handleAdminResetUserPassword(supabase, userResetPassMatch[1], body, { userId: authCtx.userId, username: authCtx.username }));
  }

  // POST /api/users/:id/reset-2fa
  const userReset2FAMatch = url.pathname.match(/^\/api\/users\/([^/]+)\/reset-2fa$/);
  if (userReset2FAMatch && req.method === "POST") {
    if (!requireAdminSession()) return;
    return sendResponse(await handleAdminResetUser2FA(supabase, userReset2FAMatch[1], { userId: authCtx.userId, username: authCtx.username }));
  }

  // POST /api/users/:id/linking-key
  const linkingKeyMatch = url.pathname.match(/^\/api\/users\/([^/]+)\/linking-key$/);
  if (linkingKeyMatch && req.method === "POST") {
    if (!requireSession()) return;
    // Admin can generate for anyone, users for themselves
    if (!authCtx.isAdmin && linkingKeyMatch[1] !== authCtx.userId) {
      return sendResponse({ status: 403, body: { error: "Forbidden" } });
    }
    return sendResponse(await handleGenerateLinkingKey(supabase, linkingKeyMatch[1], authCtx.username));
  }

  // ── Service profiles ─────────────────────────────────────────────
  if (url.pathname === "/api/service-profiles" && req.method === "GET") {
    if (!requireScope("profiles:read")) return;
    const pagination = parsePaginationQuery(url);
    return sendResponse(await handleListProfiles(supabase, authCtx.userId, pagination));
  }

  if (url.pathname === "/api/service-profiles" && req.method === "POST") {
    if (!requireScope("profiles:write")) return;
    const body = await parseBodyOr413() as Parameters<typeof handleCreateProfile>[2] | null;
    if (!body) return;
    if (body.allow_private_network && !requireAdminSession()) return;
    return sendResponse(await handleCreateProfile(supabase, authCtx.userId, body, isSessionPrincipal(authCtx) && authCtx.isAdmin, masterKey));
  }

  const profileDeleteMatch = url.pathname.match(/^\/api\/service-profiles\/([^/]+)$/);
  if (profileDeleteMatch && req.method === "DELETE") {
    if (!requireScope("profiles:write")) return;
    return sendResponse(await handleDeleteProfile(supabase, authCtx.userId, profileDeleteMatch[1]));
  }

  // ── Client Applications ───────────────────────────────────────────
  if (url.pathname === "/api/clients" && req.method === "GET") {
    if (!requireSession()) return;
    const pagination = parsePaginationQuery(url);
    return sendResponse(await handleListClients(supabase, authCtx.userId, pagination));
  }

  if (url.pathname === "/api/clients" && req.method === "POST") {
    if (!requireSession()) return;
    const body = await parseBodyOr413() as { app_name?: string; scopes?: string[] } | null;
    if (!body) return;
    return sendResponse(await handleCreateClient(supabase, masterKey, authCtx.userId, body));
  }

  const clientRevealMatch = url.pathname.match(/^\/api\/clients\/([^/]+)\/reveal$/);
  if (clientRevealMatch && req.method === "POST") {
    if (!requireSession()) return;
    return sendResponse(await handleRevealClientKey(supabase, masterKey, authCtx.userId, clientRevealMatch[1], req));
  }

  const clientRegenMatch = url.pathname.match(/^\/api\/clients\/([^/]+)\/regenerate$/);
  if (clientRegenMatch && req.method === "POST") {
    if (!requireSession()) return;
    return sendResponse(await handleRegenerateClientKey(supabase, masterKey, authCtx.userId, clientRegenMatch[1], req));
  }

  const clientUpdateMatch = url.pathname.match(/^\/api\/clients\/([^/]+)$/);
  if (clientUpdateMatch && req.method === "PATCH") {
    if (!requireSession()) return;
    const body = await parseBodyOr413() as { app_name?: string; scopes?: string[] } | null;
    if (!body) return;
    return sendResponse(await handleUpdateClient(supabase, authCtx.userId, clientUpdateMatch[1], body));
  }

  const clientDeleteMatch = url.pathname.match(/^\/api\/clients\/([^/]+)$/);
  if (clientDeleteMatch && req.method === "DELETE") {
    if (!requireSession()) return;
    return sendResponse(await handleDeleteClient(supabase, authCtx.userId, clientDeleteMatch[1]));
  }

  const clientLogsMatch = url.pathname.match(/^\/api\/clients\/([^/]+)\/logs$/);
  if (clientLogsMatch && req.method === "GET") {
    if (!requireSession()) return;
    return sendResponse(await handleGetClientLogs(supabase, authCtx.userId, clientLogsMatch[1], parseAuditLogQuery(url)));
  }

  // ── Step-Up Authentication (WebAuthn & TOTP) ──────────────────────
  const rpID = effectiveHost(req).split(":")[0];
  const origin = req.headers.origin ?? effectiveOrigin(req, isHttps);

  if (url.pathname === "/api/auth/webauthn/credentials" && req.method === "GET") {
    if (!requireSession()) return;
    return sendResponse(await handleListPasskeys(supabase, authCtx.userId));
  }

  const passkeyDeleteMatch = url.pathname.match(/^\/api\/auth\/webauthn\/credentials\/([^/]+)$/);
  if (passkeyDeleteMatch && req.method === "DELETE") {
    if (!requireSession()) return;
    return sendResponse(await handleDeletePasskey(supabase, authCtx.userId, passkeyDeleteMatch[1]));
  }

  if (url.pathname === "/api/auth/webauthn/register-options" && req.method === "POST") {
    if (!requireSession()) return;
    return sendResponse(await handleWebAuthnRegisterOptions(supabase, authCtx.userId, authCtx.username, rpID));
  }

  if (url.pathname === "/api/auth/webauthn/register-verify" && req.method === "POST") {
    if (!requireSession()) return;
    const body = await parseBodyOr413() as { response?: any; device_name?: string } | null;
    if (!body) return;
    return sendResponse(await handleWebAuthnRegisterVerify(supabase, authCtx.userId, rpID, origin, body));
  }

  if (url.pathname === "/api/auth/webauthn/authenticate-options" && req.method === "POST") {
    if (!requireSession()) return;
    return sendResponse(await handleWebAuthnAuthOptions(supabase, authCtx.userId, rpID));
  }

  if (url.pathname === "/api/auth/webauthn/authenticate-verify" && req.method === "POST") {
    if (!requireSession()) return;
    const body = await parseBodyOr413() as { response?: any } | null;
    if (!body) return;
    return sendResponse(await handleWebAuthnAuthVerify(supabase, authCtx.userId, rpID, origin, body));
  }

  if (url.pathname === "/api/auth/totp/setup" && req.method === "POST") {
    if (!requireSession()) return;
    return sendResponse(await handleTotpSetup(supabase, masterKey, authCtx.userId, authCtx.username));
  }

  if (url.pathname === "/api/auth/totp/cancel-setup" && req.method === "POST") {
    if (!requireSession()) return;
    return sendResponse(await handleTotpCancelSetup(supabase, authCtx.userId));
  }

  if (url.pathname === "/api/auth/totp/verify-setup" && req.method === "POST") {
    if (!requireSession()) return;
    const body = await parseBodyOr413() as { code?: string } | null;
    if (!body) return;
    return sendResponse(await handleTotpVerifySetup(supabase, masterKey, authCtx.userId, body));
  }

  if (url.pathname === "/api/auth/totp/authenticate" && req.method === "POST") {
    if (!requireSession()) return;
    const body = await parseBodyOr413() as { code?: string } | null;
    if (!body) return;
    return sendResponse(await handleTotpAuthenticate(supabase, masterKey, authCtx.userId, body));
  }

  if (url.pathname === "/api/auth/totp/regenerate-backup-codes" && req.method === "POST") {
    if (!requireSession()) return;
    return sendResponse(await handleTotpRegenerateBackupCodes(supabase, authCtx.userId, req.headers["x-secretvault-stepup"]));
  }

  if (url.pathname === "/api/auth/totp" && req.method === "DELETE") {
    if (!requireSession()) return;
    return sendResponse(await handleDisableTotp(supabase, authCtx.userId));
  }

  // POST /api/secrets/:name/reveal
  const revealMatch = url.pathname.match(/^\/api\/secrets\/([^/]+)\/reveal$/);
  if (revealMatch && req.method === "POST") {
    if (!requireSession()) return;
    const name = safeDecodePathSegment(revealMatch[1]);
    if (name === null) return sendResponse({ status: 400, body: { error: "Malformed percent-encoding in secret name" } });
    return sendResponse(await handleRevealSecret(supabase, masterKey, name, req, authCtx.userId, authCtx.isAdmin && isSessionPrincipal(authCtx), authCtx.credentialType === "linking_key", authCtx.username));
  }

  // GET /api/secrets
  if (url.pathname === "/api/secrets" && req.method === "GET") {
    if (!requireScope("secrets:metadata:read")) return;
    const pagination = parsePaginationQuery(url);
    return sendResponse(await handleListSecrets(supabase, authCtx.userId, authCtx.isAdmin && isSessionPrincipal(authCtx), pagination));
  }

  // POST /api/secrets
  if (url.pathname === "/api/secrets" && req.method === "POST") {
    if (!requireScope("secrets:write")) return;
    const body = await parseBodyOr413() as Parameters<typeof handleCreateSecret>[2] | null;
    if (!body) return;
    return sendResponse(await handleCreateSecret(supabase, masterKey, body, authCtx.userId, authCtx.clientId, authCtx.username));
  }

  // POST /api/secrets/:name/rotate
  const rotateMatch = url.pathname.match(/^\/api\/secrets\/([^/]+)\/rotate$/);
  if (rotateMatch && req.method === "POST") {
    if (!requireScope("secrets:write")) return;
    const name = safeDecodePathSegment(rotateMatch[1]);
    if (name === null) return sendResponse({ status: 400, body: { error: "Malformed percent-encoding in secret name" } });
    const body = await parseBodyOr413() as { new_value?: string } | null;
    if (!body) return;
    return sendResponse(await handleRotateSecret(supabase, masterKey, name, body, authCtx.userId, authCtx.isAdmin && isSessionPrincipal(authCtx), authCtx.clientId, authCtx.username));
  }

  // DELETE /api/secrets/:name
  const deleteMatch = url.pathname.match(/^\/api\/secrets\/([^/]+)$/);
  if (deleteMatch && req.method === "DELETE") {
    if (!requireScope("secrets:write")) return;
    const name = safeDecodePathSegment(deleteMatch[1]);
    if (name === null) return sendResponse({ status: 400, body: { error: "Malformed percent-encoding in secret name" } });
    return sendResponse(await handleDeleteSecret(supabase, name, authCtx.userId, authCtx.isAdmin && isSessionPrincipal(authCtx), authCtx.clientId, authCtx.username));
  }

  // GET /v1/client/secrets/:name or /api/client/secrets/:name
  const clientSecretMatch = url.pathname.match(/^(?:\/v1|\/api)?\/client\/secrets\/([^/]+)$/);
  if (clientSecretMatch && req.method === "GET") {
    const name = safeDecodePathSegment(clientSecretMatch[1]);
    if (name === null) return sendResponse({ status: 400, body: { error: "Malformed percent-encoding in secret name" } });
    if (!hasRunnerScope(authCtx, name)) {
      return sendResponse({ status: 403, body: { error: "Forbidden: credential lacks explicit runner capability for secret" } });
    }
    return sendResponse(await handleClientGetSecret(supabase, masterKey, name, authCtx.userId, authCtx.clientId, authCtx.username));
  }

  return sendResponse({ status: 404, body: { error: "API route not found" } });
}

// ── CORS helper ──────────────────────────────────────────────────────
function setCORSHeaders(req: IncomingMessage, res: ServerResponse): void {
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, mcp-session-id, Authorization, X-Request-ID, X-SecretVault-StepUp, X-SecretVault-Client-Id");
  res.setHeader("Access-Control-Expose-Headers", "X-Request-ID");

  if (!ALLOWED_ORIGINS) {
    // No allowlist configured — allow all origins (backward-compatible)
    res.setHeader("Access-Control-Allow-Origin", "*");
    return;
  }

  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
}

// ── HTTP / HTTPS Server ───────────────────────────────────────────
const tlsCertPath = process.env.SECRETVAULT_TLS_CERT;
const tlsKeyPath = process.env.SECRETVAULT_TLS_KEY;
const isHttps = Boolean(tlsCertPath && tlsKeyPath && existsSync(tlsCertPath) && existsSync(tlsKeyPath));

export const requestListener = async (req: IncomingMessage, res: ServerResponse) => {
  try {
    await handleRequest(req, res);
  } catch (err) {
    // SV-024: terminal request-listener error boundary. Any rejection that
    // escapes routing (malformed encoding, a stray throw, broken transport)
    // becomes a redacted 500 and never reaches unhandledRejection or hangs the
    // socket. Request ID is ensured so callers can correlate.
    const requestId = getRequestId(req);
    console.error(`[server] Unhandled request error (requestId=${requestId}): ${err instanceof Error ? err.message : String(err)}`);
    if (!res.headersSent) {
      writeErrorResponse(res, 500, "Internal server error", requestId, "INTERNAL_SERVER_ERROR");
    } else {
      try { res.end(); } catch { /* socket already gone */ }
    }
  }
};

async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  initializeRequestContext(req, res);
  applySecurityHeaders(req, res, isHttps);
  const url = new URL(req.url || "", effectiveOrigin(req, isHttps));

  // CORS headers
  setCORSHeaders(req, res);

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(200);
    res.end();
    return;
  }

  // Liveness probe — always 200 while the process is running
  if (url.pathname === "/health/live" && (req.method === "GET" || req.method === "HEAD")) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  // Readiness probe — 200 when the server can serve traffic
  if (url.pathname === "/health/ready" && (req.method === "GET" || req.method === "HEAD")) {
    if (serverState.shuttingDown) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "shutting_down", startup_complete: startupComplete }));
      return;
    }
    try {
      await supabase.from("secrets").select("id").limit(1).maybeSingle();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", startup_complete: startupComplete }));
    } catch {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "database_unavailable", startup_complete: startupComplete }));
    }
    return;
  }

  // Legacy /health — backward-compatible aggregate
  if (url.pathname === "/health" && (req.method === "GET" || req.method === "HEAD")) {
    const sseCount = Object.values(transports).filter(t => t instanceof SSEServerTransport).length;
    const streamableCount = Object.values(transports).filter(t => t instanceof StreamableHTTPServerTransport).length;
    res.writeHead(serverState.shuttingDown ? 503 : 200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: serverState.shuttingDown ? "shutting_down" : "ok",
      live: true,
      ready: !serverState.shuttingDown && startupComplete,
      startup_complete: startupComplete,
      sse_connections: sseCount,
      streamable_http_connections: streamableCount,
      total_connections: sseCount + streamableCount,
    }));
    return;
  }

  // Publish the checked-in OpenAPI document at a stable URL — served from cache
  if (url.pathname === "/docs/openapi.json" && req.method === "GET") {
    res.writeHead(200, {
      "Content-Type": assetCache.openapi.contentType,
      "Cache-Control": "public, max-age=300",
      "ETag": assetCache.openapi.etag,
    });
    res.end(assetCache.openapi.data);
    return;
  }

  // ── Web UI (served from preloaded asset cache) ──────────────────────
  let assetKey = url.pathname.replace(/^\/ui\/?/, "");
  if (assetKey.startsWith("/")) assetKey = assetKey.slice(1);
  if (!assetKey) assetKey = "index.html";

  if (assetCache.ui.has(assetKey) || url.pathname === "/" || url.pathname === "/ui" || url.pathname.startsWith("/ui/") || url.pathname.startsWith("/js/")) {

    const asset = assetCache.ui.get(assetKey);
    if (asset) {
      const headers: Record<string, string> = {
        "Content-Type": asset.contentType,
        "Cache-Control": "public, max-age=300",
        "ETag": asset.etag,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
      };
      if (assetKey === "index.html") {
        // No external font origins: the UI uses system font stacks (SV-073),
        // so style-src/font-src can be 'self'-only — fully usable offline and
        // a smaller supply/CSP surface.
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none';";
      }
      if (req.headers["if-none-match"] === asset.etag) {
        res.writeHead(304, headers);
        res.end();
        return;
      }
      res.writeHead(200, headers);
      res.end(asset.data);
    } else {
      writeErrorResponse(res, 404, "UI asset not found", getRequestId(req), "UI_ASSET_NOT_FOUND");
    }
    return;
  }

  // ── Versioned REST API ──────────────────────────────────────────
  const legacyPath = versionedApiPath(url.pathname);
  if (legacyPath) {
    const apiUrl = new URL(url.href);
    apiUrl.pathname = legacyPath;
    await handleApiRoute(req, res, apiUrl);
    return;
  }

  // Legacy aliases remain available during the migration window. New
  // integrations must use /v1; the successor link makes that explicit.
  if (url.pathname.startsWith("/api/")) {
    const successor = legacyApiSuccessor(url.pathname);
    if (successor) {
      res.setHeader("Deprecation", "true");
      res.setHeader("Link", `<${successor}>; rel="successor-version"`);
    }
    await handleApiRoute(req, res, url);
    return;
  }

  // ── Reverse proxy ─────────────────────────────────────────────────
  if (url.pathname.startsWith("/proxy/")) {
    // Auth required for proxy — linking key or session token
    const proxyAuth = await resolveAuthContext(supabase, req);
    if (!proxyAuth) {
      void recordAuditEvent(supabase, {
        secretName: "system",
        accessType: "authorization_denied",
        caller: `proxy:${req.method || "GET"}:${url.pathname}`,
        outcome: "denied",
        metadata: { reason: "missing_or_invalid_auth" },
      }).catch(() => undefined);
      writeErrorResponse(res, 401, "Unauthorized", getRequestId(req));
      return;
    }
    const rawServiceName = url.pathname.split("/")[2];
    if (!rawServiceName) {
      writeErrorResponse(res, 400, "Service name required: /proxy/<service>/...", getRequestId(req), "SERVICE_NAME_REQUIRED");
      return;
    }
    if (!isValidServiceName(rawServiceName)) {
      writeErrorResponse(res, 400, "Invalid service profile name", getRequestId(req), "INVALID_SERVICE_PROFILE");
      return;
    }
    // SV-053: canonicalize the service segment so the scope check and profile
    // lookup match the lowercase names stored at creation. Without this, a
    // mixed-case URL could bypass or miss a lowercased scope/profile.
    const serviceName = canonicalServiceName(rawServiceName);
    if (!hasScope(proxyAuth, `proxy:${serviceName}`)) {
      void recordAuditEvent(supabase, {
        userId: proxyAuth.userId,
        clientId: proxyAuth.clientId,
        secretName: "system",
        accessType: "authorization_denied",
        caller: `proxy:${req.method || "GET"}:${url.pathname}`,
        outcome: "denied",
        metadata: { reason: "missing_proxy_scope", required_scope: `proxy:${serviceName}` },
      }).catch(() => undefined);
      writeErrorResponse(res, 403, "Linking key is not authorized for this service profile", getRequestId(req));
      return;
    }
    return handleProxyRequest(req, res, supabase, masterKey, proxyAuth, serviceName);
  }

  // Streamable HTTP endpoint
  if (url.pathname === "/mcp") {
    await handleStreamableHttpRequest(req, res, url);
    return;
  }

  // ── Legacy SSE endpoints (deprecated) ──────────────────────────
  if (url.pathname === "/sse" && req.method === "GET") {
    console.warn("[deprecation] SSE transport is deprecated; use Streamable HTTP at /mcp instead");
    res.setHeader("Deprecation", "true");
    res.setHeader("Sunset", "Sat, 01 Nov 2026 00:00:00 GMT");
    res.setHeader("Link", '</mcp>; rel="successor-version"');

    const mcpAuth = await resolveMcpAuth(req, url, supabase);
    if (!mcpAuth) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized. Provide Authorization: Bearer <linking_key> header." }));
      return;
    }

    if (!hasScope(mcpAuth, "mcp:read")) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Forbidden. The linking key lacks the mcp:read scope." }));
      return;
    }

    const transport = new SSEServerTransport("/message", res);
    transports[transport.sessionId] = transport;
    sessionPrincipals[transport.sessionId] = mcpAuth;

    const clientServer = createMcpServer(mcpAuth);
    clientServer.connect(transport)
      .then(() => console.error(`[sse] connected: ${transport.sessionId}`))
      .catch((err) => console.error(`[sse] connect failed: ${err}`));

    req.on("close", () => {
      console.error(`[sse] closed: ${transport.sessionId}`);
      delete transports[transport.sessionId];
      delete sessionPrincipals[transport.sessionId];
    });
    return;
  }

  if (url.pathname === "/message" && req.method === "POST") {
    const sessionId = url.searchParams.get("sessionId") || url.searchParams.get("transportId");

    if (!sessionId || !transports[sessionId]) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Transport not found" }));
      return;
    }

    const boundPrincipal = sessionPrincipals[sessionId];
    const currentPrincipal = await resolveMcpAuth(req, url, supabase);
    if (!boundPrincipal || !currentPrincipal ||
        boundPrincipal.userId !== currentPrincipal.userId ||
        boundPrincipal.clientId !== currentPrincipal.clientId ||
        !hasScope(currentPrincipal, "mcp:read")) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized MCP session" }));
      return;
    }

    const transport = transports[sessionId];
    if (transport instanceof SSEServerTransport) {
      await transport.handlePostMessage(req, res);
    } else {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Wrong transport type for this endpoint" }));
    }
    return;
  }

  // 404
  writeErrorResponse(res, 404, `Route not found: ${url.pathname}`, getRequestId(req));
};

if (process.env.NODE_ENV !== "test") {
  // SV-020: refuse to start a production plaintext listener on a non-loopback
  // interface. The default bind is loopback; external exposure must go through
  // a TLS-terminating reverse proxy or native cert files.
  const startupError = plaintextStartupError(isHttps);
  if (startupError) {
    console.error(`ERROR: ${startupError}`);
    process.exit(1);
  }

  const host = bindHost();
  const httpServer = isHttps
    ? createHttpsServer(
        {
          cert: readFileSync(tlsCertPath!),
          key: readFileSync(tlsKeyPath!),
        },
        requestListener,
      )
    : createServer(requestListener);

  httpServer.listen({ port: PORT, host }, () => {
    serverState.started = true;
    const protocol = isHttps ? "https" : "http";
    console.error(`[runtime] SecretVault MCP server listening on ${protocol}://${host}:${PORT}`);
    console.error(`[runtime]   Streamable HTTP endpoint: ${protocol}://${host}:${PORT}/mcp`);
    console.error(`[runtime]   Legacy SSE endpoint:      ${protocol}://${host}:${PORT}/sse`);
    console.error(`[runtime]   Liveness:                 ${protocol}://${host}:${PORT}/health/live`);
    console.error(`[runtime]   Readiness:                ${protocol}://${host}:${PORT}/health/ready`);
    console.error(`[runtime]   Web UI:                   ${protocol}://${host}:${PORT}/ui`);
    if (!isHttps) {
      console.error(
        `[runtime] NOTE: plaintext listener bound to ${host}. Use a TLS-terminating reverse proxy ` +
          "(see docs/install.md) or SECRETVAULT_TLS_CERT/KEY for native TLS before exposing externally.",
      );
    }
  });

  async function gracefulShutdown(signal: string): Promise<void> {
    if (serverState.shuttingDown) return;
    serverState.shuttingDown = true;
    console.error(`[runtime] Received ${signal}, starting graceful shutdown...`);

    const forceTimer = setTimeout(() => {
      console.error(`[runtime] Shutdown timeout (${SHUTDOWN_FORCE_EXIT_MS}ms) reached, forcing exit`);
      process.exit(1);
    }, SHUTDOWN_FORCE_EXIT_MS);
    forceTimer.unref();

    // Destroy all proxy keep-alive agents
    destroyProxyAgents();

    // Close all MCP transports
    for (const sessionId in transports) {
      try { await transports[sessionId].close(); } catch { /* ignore */ }
      delete transports[sessionId];
    }

    // Close HTTP server — stop accepting new connections
    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });

    clearTimeout(forceTimer);
    console.error(`[runtime] Graceful shutdown complete`);
    process.exit(0);
  }

  process.on("SIGINT", () => { void gracefulShutdown("SIGINT"); });
  process.on("SIGTERM", () => { void gracefulShutdown("SIGTERM"); });
}
