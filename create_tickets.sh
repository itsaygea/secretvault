#!/bin/bash
set -e

# Map issue is #40

echo "Creating Ticket 1..."
T1=$(gh issue create --title "[P0 Containment] Eliminate Unauthenticated MCP Admin Fallback & Implement Header Bearer Auth" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we eliminate the unauthenticated admin fallback in `resolveMcpAuth()` and enforce `Authorization: Bearer sv_...` header resolution for all MCP connections across HTTP Streamable and SSE transports?

## Specification

- Remove the fallback to admin user when no `?key=` query param is present.
- Parse `Authorization: Bearer <linking_key>` header from MCP request headers.
- Return `401 Unauthorized` when authentication is missing or invalid.
- Bind each MCP session strictly to its authenticated user principal.
- Add transport-level integration tests for valid, missing, malformed, revoked, and cross-user credentials.

## Parent Map

#40
INNER
)")
echo "Created: $T1"

echo "Creating Ticket 2..."
T2=$(gh issue create --title "[P0 Containment] Remediate Stored XSS in Web UI, Enforce textContent & Restrictive CSP" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we systematically eliminate stored XSS vulnerabilities in the Web UI, replace `innerHTML` sinks with safe DOM construction, and enforce a strict Content Security Policy?

## Specification

- Audit and replace all `innerHTML` assignments (especially secret reveal, username, profile names, client names, and target URLs) with `textContent` or safe DOM builders.
- Remove inline `onclick` string interpolation.
- Add a restrictive CSP header disallowing inline scripts (`script-src 'self'`).
- Add regression tests verifying that XSS payloads in database fields or revealed secret plaintexts do not execute script.

## Parent Map

#40
INNER
)")
echo "Created: $T2"

echo "Creating Ticket 3..."
T3=$(gh issue create --title "[P0 Containment] Update README, Docs & UI Security Claims to Bounded Egress Gateway Model" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we align all documentation, README, and UI text with the Bounded Egress Gateway security model and document the upstream response trust boundary?

## Specification

- Replace absolute claims ("raw credentials never reach agent streams") with bounded egress gateway claims.
- Document that SecretVault injects credentials into approved upstream requests, but upstream response bodies remain within the upstream service's trust boundary.
- Document response-body reflection risks and mitigation via destination allowlists and path/method scoping.

## Parent Map

#40
INNER
)")
echo "Created: $T3"

echo "Creating Ticket 4..."
T4=$(gh issue create --title "[P0 Containment] Upgrade Production Dependencies & Resolve npm Audit Vulnerabilities" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we update production dependencies across `@secretvault/mcp-server`, `@secretvault/bridge`, and root packages to eliminate high/moderate audit vulnerabilities?

## Specification

- Update `@modelcontextprotocol/sdk`, `express`, `ws`, `fast-uri`, and transitive dependencies.
- Re-run `npm audit --omit=dev` to verify 0 production vulnerabilities.
- Run build and test suite to ensure full backward compatibility.

## Parent Map

#40
INNER
)")
echo "Created: $T4"

echo "Creating Ticket 5..."
T5=$(gh issue create --title "[P0 Auth] Implement Unified Principal & Enforce Scoped Linking Keys Across REST, MCP, and Proxy" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we design a single authorization module (`resolveAuthContext`) that enforces fine-grained scopes (`proxy:<profile>`, `secrets:metadata:read`, `secrets:write`, `profiles:read`, `profiles:write`, `mcp:read`, `mcp:write`) across REST, MCP, and proxy endpoints?

## Specification

- Define a normalized principal object: `{ userId, clientId, credentialType, isAdmin, scopes }`.
- Restrict linking keys by default (`proxy:*` or `proxy:<profile>`); deny administrative and management actions unless explicitly scoped.
- Ensure linking keys cannot create/revoke credentials or alter 2FA.
- Write unit/integration tests verifying that scoped keys receive `403 Forbidden` on unauthorized routes.

## Parent Map

#40

## Blocked by

Blocked by Phase 0 tickets (#41, #42, #43, #44)
INNER
)")
echo "Created: $T5"

echo "Creating Ticket 6..."
T6=$(gh issue create --title "[P0 Audit] Repair Audit Logging Schema Drift & Propagate client_id Across Access Events" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we repair schema drift in `access_logs` (`timestamp` vs `created_at`), enforce required fields (`user_id`, `client_id`, `secret_name`), and build a unified audit module?

## Specification

- Standardize `access_logs` schema and generate database TypeScript types in CI.
- Propagate `client_id` into all proxy and REST audit log insertions.
- Sanitize logged URL paths so sensitive query parameters are redacted.
- Ensure audit failures fail closed on critical operations or alert properly on reads.

## Parent Map

#40

## Blocked by

Blocked by Ticket 5
INNER
)")
echo "Created: $T6"

echo "Creating Ticket 7..."
T7=$(gh issue create --title "[P0 Proxy] Prevent Service-Profile SSRF & Enforce Destination Egress Allowlists" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we prevent server-side request forgery (SSRF) via service-profile `target_url` definitions, restricting destinations to approved origins and IP ranges?

## Specification

- Restrict `target_url` creation to admins or explicit destination allowlists.
- Require `https:` by default with explicit opt-in for internal http targets.
- Block IPv4/IPv6 loopback, link-local, multicast, and cloud metadata (169.254.169.254) ranges.
- Validate DNS and protect against DNS rebinding at connection time.
- Enforce per-profile allowed HTTP methods and path prefixes.

## Parent Map

#40

## Blocked by

Blocked by Ticket 5
INNER
)")
echo "Created: $T7"

echo "Creating Ticket 8..."
T8=$(gh issue create --title "[P0 Proxy] Prevent Proxy Path Authority Hijacking & Validate Canonical Origin Matching" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we prevent proxy request path authority hijacking (e.g. scheme-relative `//attacker.example/` paths) and strictly validate canonical upstream origins before request dispatch?

## Specification

- Parse proxy request remainder strictly as path/query data, rejecting leading `//`, backslashes, fragments, or userinfo.
- Compare final constructed URL origin against approved profile canonical origin immediately before dispatch.
- Strictly validate and URL-encode profile/service names.
- Add regression tests for scheme-relative, backslash, and encoded URL inputs.

## Parent Map

#40

## Blocked by

Blocked by Ticket 5
INNER
)")
echo "Created: $T8"

echo "Creating Ticket 9..."
T9=$(gh issue create --title "[Phase 2 Contract] Version HTTP Management API, OpenAPI 3.1 Spec & Standardized Error Envelopes" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we define a versioned `/v1` HTTP management API, publish an OpenAPI 3.1 specification, and standardize error envelopes across all REST & proxy responses?

## Specification

- Version all management endpoints under `/v1/...`.
- Create and validate an OpenAPI 3.1 schema for all management/metadata routes.
- Define a standard JSON error envelope: `{ error: { code, message, requestId, status } }`.
- Document proxy contract and header/query pass-through semantics.

## Parent Map

#40

## Blocked by

Blocked by Phase 1 tickets
INNER
)")
echo "Created: $T9"

echo "Creating Ticket 10..."
T10=$(gh issue create --title "[Phase 2 Client] Refactor TypeScript SDK into @secretvault/client & @secretvault/admin Packages" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we refactor the TypeScript client library into clean, purpose-built packages (`@secretvault/client` for proxying and `@secretvault/admin` for management operations)?

## Specification

- Build `@secretvault/client` focusing solely on `proxy()`, `proxyUrl()`, and health/capabilities.
- Build `@secretvault/admin` for account, profile, and secret lifecycle management.
- Remove process-mutating `injectEnv()` and client-side resolution hacks.
- Support caller-provided `fetch`, `AbortSignal`, timeout, and typed `SecretVaultError`.

## Parent Map

#40

## Blocked by

Blocked by Ticket 9
INNER
)")
echo "Created: $T10"

echo "Creating Ticket 11..."
T11=$(gh issue create --title "[Phase 2 Test] Implement HTTP/MCP Black-Box Conformance & Transport Integration Test Suite" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we build a black-box HTTP & MCP conformance test suite that validates server behavior against real HTTP endpoints and mock upstream services?

## Specification

- Build an in-process mock upstream server and test through public HTTP and MCP endpoints.
- Test authentication, header injection, scope enforcement, error codes, timeouts, and streaming.
- Ensure the conformance suite can be re-used to validate SDKs in any language.

## Parent Map

#40

## Blocked by

Blocked by Ticket 9, Ticket 10
INNER
)")
echo "Created: $T11"

echo "Creating Ticket 12..."
T12=$(gh issue create --title "[Phase 3 Docker] Implement Automatic Startup Migrations & Multi-Stage Non-Root Docker Image" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we package SecretVault into a hardened multi-stage Docker image running as non-root with automatic database startup migrations?

## Specification

- Convert Dockerfile to a true multi-stage build (build stage + minimal runtime stage).
- Run container process as a non-root `node` / `appuser`.
- Add an automated migration runner on startup before accepting traffic.
- Update `docker-compose.yml` to bind port 3004 to `127.0.0.1` and support Caddy reverse-proxy profile out of the box.

## Parent Map

#40

## Blocked by

Blocked by Phase 2 tickets
INNER
)")
echo "Created: $T12"

echo "Creating Ticket 13..."
T13=$(gh issue create --title "[Phase 3 CI] Set Up CI Pipeline for Build, Schema Drift, Security Scans & E2E Docker Tests" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we establish a complete GitHub Actions CI pipeline covering build, unit tests, schema drift detection, OpenAPI drift, container security scanning, and end-to-end Docker integration tests?

## Specification

- Add CI workflow for `npm test`, `npm run build`, and `npm audit`.
- Add automated check comparing generated database TypeScript types with Supabase migrations.
- Add Trivy/Snyk container vulnerability scan.
- Add end-to-end Docker Compose test running the full stack in CI.

## Parent Map

#40

## Blocked by

Blocked by Ticket 12
INNER
)")
echo "Created: $T13"

rm create_tickets.sh
