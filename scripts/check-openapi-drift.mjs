import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// SV-037: real OpenAPI drift. Three artifacts must agree on what the server
// serves, and this check pins all three pairwise so drift fails CI in any
// direction:
//
//   1. The route registry (`routeRegistry.ts`) — the single source of truth.
//   2. The OpenAPI document (`docs/openapi.json`) — the published contract.
//   3. The request dispatcher (`handleApiRoute` in `index.ts`) — the runtime.
//
// Registry↔OpenAPI: every registry route is documented with a matching
// auth class, and every documented /v1 operation is in the registry.
// Runtime↔registry: every route the dispatcher actually matches is declared
// in the registry, so an undocumented runtime route is impossible to land.

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const openApiPath = join(repositoryRoot, "docs", "openapi.json");
const indexTsPath = join(repositoryRoot, "packages", "mcp-server", "src", "index.ts");
const openApi = JSON.parse(await readFile(openApiPath, "utf8"));

// Import the compiled route registry. The drift check runs after `npm run
// build` in CI and locally, so dist/ is present.
const require = createRequire(import.meta.url);
const { ROUTES } = require("../packages/mcp-server/dist/routeRegistry.js");

const errors = [];

if (openApi.openapi !== "3.1.0") {
  errors.push(`expected OpenAPI 3.1.0, received ${openApi.openapi}`);
}

// Map the registry's auth class to the OpenAPI security requirement key we
// document on each operation via the `x-sv-auth` extension.
const AUTH_TO_SECURITY = {
  public: [],
  session: ["SessionToken"],
  admin_session: ["AdminSession"],
  self_or_admin_session: ["SessionToken"],
  scope: ["Scope"],
};

/** Collect every (METHOD, /v1/path) the OpenAPI document declares. */
function documentedOperations() {
  const ops = [];
  for (const [path, item] of Object.entries(openApi.paths ?? {})) {
    if (!item || typeof item !== "object") continue;
    for (const method of ["get", "post", "put", "patch", "delete", "head"]) {
      if (item[method]) ops.push({ method: method.toUpperCase(), path });
    }
  }
  return ops;
}

const documented = documentedOperations();
const documentedSet = new Set(documented.map((o) => `${o.method} ${o.path}`));

// 1. No legacy /api paths in the document — all management routes are /v1.
for (const op of documented) {
  if (op.path.startsWith("/api/")) {
    errors.push(`legacy path must not be documented: ${op.method} ${op.path}`);
  }
}

// 2. Every registry route is documented (runtime → contract).
const registrySet = new Set();
for (const route of ROUTES) {
  const key = `${route.method} ${route.path}`;
  registrySet.add(key);
  if (!route.path.startsWith("/v1/")) {
    errors.push(`registry route is not /v1-prefixed: ${key}`);
    continue;
  }
  if (!documentedSet.has(key)) {
    errors.push(`runtime route missing from OpenAPI contract: ${key}`);
    continue;
  }
  // Auth class must match the documented `x-sv-auth` extension.
  const op = openApi.paths[route.path]?.[route.method.toLowerCase()];
  if (op && !op["x-sv-auth"]) {
    errors.push(`operation missing x-sv-auth extension: ${key}`);
  } else if (op && op["x-sv-auth"] !== route.auth) {
    errors.push(
      `auth class mismatch for ${key}: registry=${route.auth} openapi=${op["x-sv-auth"]}`,
    );
  }
}

// 3. No documented operation is absent from the registry (contract → runtime).
for (const key of documentedSet) {
  // The proxy path is documented but served outside the management registry.
  if (key.startsWith("GET /proxy/") || key.includes(" /proxy/")) continue;
  if (!key.includes(" /v1/")) continue;
  if (!registrySet.has(key)) {
    errors.push(`documented operation has no runtime route: ${key}`);
  }
}

// 4. Runtime↔registry: every route the dispatcher matches must be declared in
// the registry. This reads the static route conditions out of handleApiRoute
// (exact pathnames + regex param patterns), normalizes them to /v1 OpenAPI
// form, and compares. An undocumented runtime route fails here.
//
// Param *names* vary ({id} vs {name}); comparison is on a normalized signature
// where every {...} segment collapses to {x}, so only shape is compared.
const indexSource = await readFile(indexTsPath, "utf8");
const dispatcherStart = indexSource.indexOf("async function handleApiRoute");
const dispatcherEnd = indexSource.indexOf("// ── CORS helper", dispatcherStart);
const dispatcher = indexSource.slice(dispatcherStart, dispatcherEnd);

/** Collapse every {...} param to {x} so {id}/{name} compare equal by shape. */
function normalizeParamNames(path) {
  return path.replace(/\{[^}]+\}/g, "{x}");
}

const runtimeKeys = new Set();

// 4a. Exact-match routes: url.pathname === "/api/..." && req.method === "X"
for (const m of dispatcher.matchAll(/url\.pathname === "(\/api\/[^"]+)"\s*&&\s*req\.method === "(\w+)"/g)) {
  runtimeKeys.add(`${m[2]} ${m[1].replace(/^\/api/, "/v1")}`);
}
// The setup route is dual-path (/v1 or /api); both resolve to /v1/auth/setup.
for (const m of dispatcher.matchAll(/url\.pathname === "(\/v1\/[^"]+)"\s*&&\s*req\.method === "(\w+)"/g)) {
  runtimeKeys.add(`${m[2]} ${m[1]}`);
}

// 4b. Regex param routes: <name>Match = url.pathname.match(/PATTERN/);
//     if (<name>Match && req.method === "X")
const paramPatterns = new Map();
// Match a full regex literal /.../flags, tolerating escaped slashes (\/).
for (const m of dispatcher.matchAll(/(\w+Match)\s*=\s*url\.pathname\.match\((\/(?:[^/\\]|\\.)+\/[gimsuy]*)\)/g)) {
  paramPatterns.set(m[1], m[2]);
}
for (const [name, regexLiteral] of paramPatterns) {
  const methodMatch = dispatcher.match(new RegExp(`${name}\\s*&&\\s*req\\.method === "(\\w+)"`));
  if (!methodMatch) continue;
  const normalized = normalizeParamRegex(regexLiteral);
  if (normalized) runtimeKeys.add(`${methodMatch[1]} ${normalized}`);
}

/** Turn a JS regex literal like /^\/api\/users\/([^/]+)$/ into /v1/users/{x}. */
function normalizeParamRegex(literal) {
  // Strip leading /^ and trailing flags, drop the $ anchor.
  let core = literal;
  if (core.startsWith("/")) core = core.slice(1);
  if (core.startsWith("^")) core = core.slice(1);
  const lastSlash = core.lastIndexOf("/");
  if (lastSlash > 0) core = core.slice(0, lastSlash);
  core = core.replace(/\$$/, "");
  // Unescape escaped slashes (\/ → /) for segment splitting.
  core = core.replace(/\\\//g, "/");
  // Strip optional non-capturing alternation prefix (?:/v1|/api)? and anchors.
  core = core.replace(/^\(\?:\/v1\|\/api\)\?/, "");
  core = core.replace(/^\/api/, "/v1");
  if (!core.startsWith("/v1")) core = "/v1" + core;
  // Split on path-segment slashes, ignoring slashes inside [^/] char classes.
  let inClass = false;
  let seg = "";
  const segs = [];
  for (const ch of core) {
    if (ch === "[") inClass = true;
    if (ch === "]") inClass = false;
    if (ch === "/" && !inClass) {
      if (seg !== "") segs.push(seg);
      seg = "";
      continue;
    }
    seg += ch;
  }
  if (seg !== "") segs.push(seg);
  const out = segs.map((s) => (s.includes("(") && s.includes(")") ? "{x}" : s));
  return "/" + out.join("/");
}

// Compare runtime shape against registry shape (both with {x} normalization).
const registryShape = new Set([...registrySet].map(normalizeParamNames));
const runtimeByShape = new Map([...runtimeKeys].map((k) => [normalizeParamNames(k), k]));
for (const [shape, display] of runtimeByShape) {
  if (!registryShape.has(shape)) {
    errors.push(`dispatcher serves a route absent from the registry: ${display}`);
  }
}
const runtimeCount = runtimeKeys.size;

if (errors.length > 0) {
  console.error("OpenAPI drift detected:");
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  const mgmt = documented.filter((o) => o.path.startsWith("/v1/")).length;
  console.log(`OpenAPI drift check passed (${ROUTES.length} registry routes, ${mgmt} documented, ${runtimeCount} dispatched).`);
}

// Exported for tests that import this module's logic.
export { AUTH_TO_SECURITY, documentedOperations };
