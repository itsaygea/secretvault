#!/bin/bash
set -e

echo "Creating Ticket 6 (#46)..."
gh issue create --title "[P0 Audit] Repair Audit Logging Schema Drift & Propagate client_id Across Access Events" --label "wayfinder:task" --body "$(cat << 'INNER'
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

Blocked by #45
INNER
)"

echo "Creating Ticket 7 (#47)..."
gh issue create --title "[P0 Proxy] Prevent Service-Profile SSRF & Enforce Destination Egress Allowlists" --label "wayfinder:task" --body "$(cat << 'INNER'
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

Blocked by #45
INNER
)"

echo "Creating Ticket 8 (#48)..."
gh issue create --title "[P0 Proxy] Prevent Proxy Path Authority Hijacking & Validate Canonical Origin Matching" --label "wayfinder:task" --body "$(cat << 'INNER'
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

Blocked by #45
INNER
)"

echo "Creating Ticket 9 (#49)..."
gh issue create --title "[Phase 2 Contract] Version HTTP Management API, OpenAPI 3.1 Spec & Standardized Error Envelopes" --label "wayfinder:task" --body "$(cat << 'INNER'
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

Blocked by Phase 1 tickets (#45, #46, #47, #48)
INNER
)"

echo "Creating Ticket 10 (#50)..."
gh issue create --title "[Phase 2 Client] Refactor TypeScript SDK into @secretvault/client & @secretvault/admin Packages" --label "wayfinder:task" --body "$(cat << 'INNER'
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

Blocked by #49
INNER
)"

echo "Creating Ticket 11 (#51)..."
gh issue create --title "[Phase 2 Test] Implement HTTP/MCP Black-Box Conformance & Transport Integration Test Suite" --label "wayfinder:task" --body "$(cat << 'INNER'
## Question

How do we build a black-box HTTP & MCP conformance test suite that validates server behavior against real HTTP endpoints and mock upstream services?

## Specification

- Build an in-process mock upstream server and test through public HTTP and MCP endpoints.
- Test authentication, header injection, scope enforcement, error codes, timeouts, and streaming.
- Ensure the conformance suite can be re-used to validate SDKs in any language.

## Parent Map

#40

## Blocked by

Blocked by #49, #50
INNER
)"

echo "Creating Ticket 12 (#52)..."
gh issue create --title "[Phase 3 Docker] Implement Automatic Startup Migrations & Multi-Stage Non-Root Docker Image" --label "wayfinder:task" --body "$(cat << 'INNER'
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

Blocked by Phase 2 tickets (#49, #50, #51)
INNER
)"

echo "Creating Ticket 13 (#53)..."
gh issue create --title "[Phase 3 CI] Set Up CI Pipeline for Build, Schema Drift, Security Scans & E2E Docker Tests" --label "wayfinder:task" --body "$(cat << 'INNER'
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

Blocked by #52
INNER
)"

rm create_remaining_tickets.sh
