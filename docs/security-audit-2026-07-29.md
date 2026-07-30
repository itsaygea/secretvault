# SecretVault Zero-Trust Security Audit

Date: 2026-07-29  
Commit reviewed: `275ab850ca556051a3e245b7555fafdf3c406494`  
Scope: `packages/shared`, `packages/mcp-server`, `packages/client`, `packages/admin`, `packages/bridge`, `packages/sdk`, installers, Docker assets, and all Supabase migrations.

## Executive summary

The audit found 14 actionable findings: 9 High, 4 Medium, and 1 Low. No Critical issue was assigned because the highest-impact paths require either a network interception position, a stolen authenticated session/client credential, an allowlisted egress origin, local process visibility, or database access.

The strongest controls are the explicit runner scopes, user-scoped application queries, masked MCP projections, AES-256-GCM with random 96-bit IVs, server-side proxy injection, DNS pinning, request body limits, and fail-closed initial audit writes for most critical operations.

The highest-priority failures are:

1. The production image deliberately enables external plaintext HTTP and Compose publishes it on all interfaces.
2. A stolen session can enroll or replace its own second factor and then reveal plaintext secrets.
3. Proxy responses can reflect injected credentials through arbitrary response headers or upstream error bodies.
4. Ciphertexts are not bound to tenant/record context, enabling cross-tenant ciphertext transplant after database read/write compromise.
5. Master-key rotation is non-atomic, non-resumable, ignores database errors, and uses domain-separation purposes that do not match existing ciphertexts.

## Method and validation

- Traced every `decryptSecret()` call and every raw-value response/injection path.
- Reviewed every REST route, MCP transport, MCP tool, scope matcher, and tenant predicate.
- Reviewed all 19 migrations and the bundled PostgREST role model.
- Reviewed proxy URL construction, DNS pinning, IP classification, header handling, body limits, and audit behavior.
- Reviewed installer downloads, generated configuration, process arguments, Docker defaults, and image/runtime privileges.
- Ran `npm test -- --run`: 37 files and 356 tests passed.
- Ran `npm run build`: passed.
- Ran schema and OpenAPI drift checks: passed after the build completed.
- Ran `npm audit --omit=dev`: 0 known production dependency vulnerabilities across 191 production dependencies.
- Executed safe local PoCs for session revocation, response-header reflection, rotation purpose mismatch, cursor injection, and IPv4-mapped IPv6 SSRF classification.

## Findings

### SV-AUD-001 — Production deployment exposes plaintext HTTP externally

Severity: **High — CVSS 8.1** (`AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H`)

Affected locations:

- `Dockerfile:29-33`
- `docker-compose.yml:7-15`
- `install-server.sh:572-609`

Description and root cause:

The runtime image sets `SECRETVAULT_BIND_HOST=0.0.0.0` and permanently enables the explicit insecure override. Base Compose publishes port 3004 on `${SECRETVAULT_BIND_HOST:-0.0.0.0}`. As a result, the production guard in `transportSecurity.ts` is intentionally bypassed and the plaintext management API is reachable on every host interface. Adding Caddy does not close port 3004, so users can bypass TLS.

Passwords, session tokens, setup codes, client keys, step-up tokens, and plaintext reveal responses can traverse this listener.

PoC:

1. Build and start the documented base Compose stack.
2. From another host on the same reachable network, request `http://SERVER_IP:3004/health/live`.
3. Observe HTTP 200 without TLS.
4. Log in or reveal a secret while capturing traffic on-path; bearer and plaintext response data are visible.

Remediation:

```diff
-    SECRETVAULT_BIND_HOST=0.0.0.0 \
-    SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL=1 \
-    SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM=I-know-this-is-insecure
+    SECRETVAULT_BIND_HOST=0.0.0.0
```

Bind the published host port to loopback by default:

```diff
-      - "${SECRETVAULT_BIND_HOST:-0.0.0.0}:3004:3004"
+      - "${SECRETVAULT_PUBLISH_HOST:-127.0.0.1}:3004:3004"
```

When the Caddy overlay is enabled, use `expose: ["3004"]` and do not publish 3004. Add an integration test that asserts the generated default Compose configuration binds only to `127.0.0.1`.

### SV-AUD-002 — Stolen sessions can replace MFA and mint their own step-up

Severity: **High — CVSS 8.7** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`)

Affected locations:

- `packages/mcp-server/src/index.ts:808-874`
- `packages/mcp-server/src/stepup.ts:121-205`
- `packages/mcp-server/src/stepup.ts:374-412`
- `packages/mcp-server/src/stepup.ts:436-504`
- `packages/mcp-server/src/stepup.ts:619-665`

Description and root cause:

MFA enrollment, replacement, deletion, and disable routes require only a normal 24-hour session. TOTP setup returns a new seed to the caller, and verify-setup promotes that seed after verifying a code generated from the attacker-controlled seed. Existing-factor replacement does not require the old factor, password re-entry, or a recent step-up. Passkey enrollment has the same authorization class.

This defeats the reveal step-up boundary after any session theft.

PoC:

1. Obtain a victim session token.
2. `POST /v1/auth/totp/setup` with the token; record the returned TOTP seed.
3. Generate a valid six-digit code from that seed.
4. `POST /v1/auth/totp/verify-setup` with the code; the attacker's factor replaces or creates the victim factor.
5. `POST /v1/auth/totp/authenticate` and receive a step-up token.
6. `POST /v1/secrets/NAME/reveal` with the session and step-up token; plaintext is returned.

Remediation:

- Require a short-lived, purpose-bound reauthentication grant for all factor enrollment, replacement, disable, and deletion operations.
- Existing-factor changes must require the existing factor.
- First-factor enrollment must require current-password verification performed immediately before enrollment; a long-lived session alone is insufficient.
- Bind the reauthentication token to an operation such as `factor:totp:replace`.
- Revoke all sessions after factor replacement or removal, then issue a new session only after reauthentication.
- Add an end-to-end regression test that starts with only a session token and proves the full PoC is rejected.

### SV-AUD-003 — Proxy can reflect injected secrets in response headers and error bodies

Severity: **High — CVSS 7.5** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)

Affected locations:

- `packages/mcp-server/src/proxy.ts:194-216`
- `packages/mcp-server/src/proxy.ts:299-310`
- `packages/mcp-server/src/proxyPolicy.ts:170-185`

Description and root cause:

Credentials are injected correctly in server memory, but response sanitization is name-based only. An upstream can copy the received `Authorization`, cookie, basic credential, or custom header value into an arbitrary response header such as `X-Debug-Auth`; it passes unchanged. Upstream 4xx/5xx response bodies are also streamed unchanged and can echo the credential.

Local PoC:

```text
sanitizeResponseHeaders({
  "x-debug-auth": "Bearer vault-secret-123",
  "authorization": "Bearer vault-secret-123"
})
=> { "x-debug-auth": "Bearer vault-secret-123" }
```

Exploit scenario:

1. A proxy-authorized client calls an allowed diagnostic or attacker-controlled upstream path.
2. The upstream returns the received credential in `X-Debug-Auth` or a 401 JSON body.
3. SecretVault forwards it to the client, converting in-flight use into raw credential disclosure.

Remediation:

- Before dispatch, construct a `SensitiveValueSet` containing every injected raw and encoded credential form.
- Drop any upstream response header whose value contains a sensitive value.
- Do not relay upstream error bodies by default for credentialed proxy requests; return a stable SecretVault error envelope and audit the upstream status.
- If successful response bodies must be relayed, document that the upstream is a trusted secret recipient and add profile-specific response policies. Generic redaction of arbitrary streaming bodies is not a reliable sole control.
- Add tests for bearer, basic/base64, cookie, and custom-header reflection.

### SV-AUD-004 — IPv4-mapped IPv6 literals bypass private-address SSRF blocking

Severity: **Medium — CVSS 6.4** (`AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L`)

Affected location:

- `packages/mcp-server/src/proxyPolicy.ts:210-230`
- `packages/mcp-server/src/proxyPolicy.ts:239-271`

Description and root cause:

For `::ffff:` addresses, the classifier strips the prefix and recursively parses the remainder as dotted IPv4. Hex-form mapped addresses such as `::ffff:7f00:1` and `::ffff:a00:1` are valid IPv6 but the remainder is not recognized as IPv4, so loopback and RFC1918 destinations are accepted.

Local PoC:

```text
https://[::ffff:7f00:1] => ACCEPTED, address ::ffff:7f00:1
https://[::ffff:0a00:1] => ACCEPTED, address ::ffff:a00:1
https://198.18.0.1       => ACCEPTED
```

An allowlisted hostname returning an equivalent AAAA answer can also reach the same path.

Remediation:

- Parse IPs into bytes using a well-reviewed CIDR library and classify the normalized 128-bit address.
- Convert every IPv4-mapped IPv6 representation to canonical IPv4 before applying CIDR checks.
- Deny all non-global-unicast ranges by default, including `198.18.0.0/15`, documentation ranges, link-local, unique-local, multicast, unspecified, and reserved ranges.
- Test literal and DNS-returned compressed, expanded, dotted, and hex mapped forms.

### SV-AUD-005 — Ciphertexts are not bound to tenant or record context

Severity: **High — CVSS 8.1** (`AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H`)

Affected locations:

- `packages/shared/src/crypto.ts:47-71`
- `packages/shared/src/crypto.ts:78-105`
- All production `encryptSecret()` and `decryptSecret()` call sites

Description and root cause:

The crypto API supports AAD, but production callers do not use it. A single global master key protects every tenant and object. A database actor with ciphertext read/write access can copy User A's `encrypted_blob` into a row owned by User B; the server authenticates and decrypts it successfully in User B's authorized reveal/runner/proxy path.

This breaks the expected protection against a compromised or malicious storage layer.

PoC:

1. Read User A's encrypted blob through database access.
2. Replace User B's encrypted blob with User A's blob while retaining User B ownership metadata.
3. Authenticate as User B and reveal or resolve the row.
4. The server returns User A's plaintext because no tenant/name context is authenticated.

Remediation:

- Define versioned AAD:
  - secret: `secretvault:v2:secret:<userId>:<secretId>`
  - client key: `secretvault:v2:client-key:<userId>:<clientId>`
  - TOTP: `secretvault:v2:totp:<userId>`
- Authenticate envelope version and key ID as AAD too.
- Generate immutable IDs before encryption so AAD does not depend on mutable names.
- Add an online/offline migration with dual-read support for v1 and strict v2 writes.
- Add negative tests proving ciphertext transplant across user, row, and purpose fails GCM authentication.

### SV-AUD-006 — Master-key rotation can leave the vault partially unrecoverable

Severity: **High — CVSS 7.2** (`AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H`)

Affected locations:

- `packages/mcp-server/src/cli/rotateKey.ts:19-145`
- `packages/mcp-server/src/cli/rotateKey.ts:147-187`
- `packages/mcp-server/src/users.ts:723-724, 815-816, 851-852`
- `packages/mcp-server/src/stepup.ts:380-383, 465-466, 531-532`

Description and root cause:

Rotation rewrites rows one at a time without a transaction or dual-key read period. It ignores select/update errors and increments counters after failed updates. Resume is impossible because decryption ignores envelope key IDs and always starts with the old key.

Additionally, current client keys and TOTP seeds are encrypted with the default `secret` purpose, while rotation decrypts them with `client_key` and `totp_secret`. The first such row fails authentication after secret rows may already have been rewritten with the new key.

The completion audit insert uses nonexistent `details` and omits required `secret_name` and `caller`, so it cannot satisfy the audit schema.

Local PoC:

```text
encryptSecret("client", oldKey)  // default purpose "secret"
decryptSecret(blob, oldKey, { purpose: "client_key" })
=> authentication failure
```

Remediation:

- First ship consistent purpose constants at every write/read call site.
- Implement a keyring keyed by authenticated `key_id`; during rotation, serve both old and new IDs.
- Use resumable batches with compare-and-swap updates (`WHERE id=? AND encrypted_blob=?`), check every database error, and verify each rewritten row with the new key.
- Do not declare completion until a full verification scan reports zero old-key rows.
- Use the central critical audit API.
- Remove `--old-key` and `--new-key`; accept file descriptors, `*_KEY_FILE`, or hidden stdin only.

### SV-AUD-007 — Raw secrets and client keys are placed in process arguments

Severity: **High — CVSS 7.0** (`AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N`)

Affected locations:

- `packages/mcp-server/src/runner.ts:67-73`
- `packages/mcp-server/src/cli/setup.ts:326-335`
- `packages/mcp-server/src/cli/secret.ts:62-75, 119-148`
- `packages/mcp-server/src/cli/rotateKey.ts:147-159`
- `docker/break-glass.sh:73-95`
- `packages/mcp-server/src/cli.ts:11-18`

Description and root cause:

`secretvault run` substitutes `$SECRET` and `%SECRET%` directly into child arguments. Setup stores `Authorization: Bearer <client key>` in the `mcp-remote` argument list. Secret-manager, rotation, and break-glass commands accept credentials through flags; break-glass converts even stdin/file input back into a Node `--password` argument.

On common systems these values are visible through `/proc/<pid>/cmdline`, `ps`, process telemetry, crash reports, and shell history.

PoC:

1. Run `secretvault run --secret API_KEY -- long-running-command '$API_KEY'`.
2. From another permitted local account, read `/proc/CHILD_PID/cmdline`.
3. Observe the raw vault value in the command arguments.

Remediation:

- Runner: inject only through the environment or an inherited file descriptor. Remove argument substitution, or require an explicit unsafe compatibility flag with a warning.
- MCP setup: use an environment-variable reference supported by the launcher, a `0600` credential file, or a small wrapper that reads the key at runtime without putting it in argv.
- Break-glass/rotation/secret CLI: accept stdin or `0600` files only; never reconstruct a secret-bearing argv.
- Add `/proc/self/cmdline` regression helpers proving marker secrets never appear.

### SV-AUD-008 — Session revocation is never enforced

Severity: **High — CVSS 8.1** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`)

Affected locations:

- `packages/mcp-server/src/sessionRevocation.ts:1-19`
- `packages/mcp-server/src/api.ts:46-61`
- `packages/mcp-server/src/api.ts:93-111`
- Revocation callers in `packages/mcp-server/src/users.ts:493, 520, 607, 1030`

Description and root cause:

Password changes, admin resets, 2FA resets, and break-glass recovery call `revokeAllUserSessions()`, but `verifyToken()` never calls `isTokenRevoked()`. A local PoC generated a token, revoked the user, and received `postRevocationStillValid: true`.

The in-memory-only map would also fail across replicas and process restarts even if consulted.

Remediation:

- Persist a `session_epoch` or `sessions_invalid_before` value on each user.
- Include the epoch in the signed token and compare it on every authenticated request.
- Increment the epoch transactionally after password/factor/admin recovery events.
- Reject tokens with invalid/future timestamps and use exact fixed-length signature validation.
- Add tests through `resolveAuthContext()`, not only unit tests of the unused manager.

### SV-AUD-009 — Established MCP sessions retain revoked write scopes

Severity: **Medium — CVSS 6.5** (`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L`)

Affected locations:

- `packages/mcp-server/src/index.ts:325-328`
- `packages/mcp-server/src/index.ts:361-375`
- `packages/mcp-server/src/index.ts:404-430`
- `packages/mcp-server/src/index.ts:1172-1211`

Description and root cause:

MCP tool handlers close over the principal and scopes captured at initialization. Later requests re-authenticate the credential, but only check identity and current `mcp:read`. If `mcp:write` is removed while `mcp:read` remains, the established server still authorizes create/rotate/delete using the old principal.

Remediation:

- Bind a canonical scope set and `key_version`/authorization version to each MCP session.
- On every request, reject and close the session if scopes or version differ.
- Prefer request-scoped principal lookup inside tool authorization rather than a long-lived captured principal.
- Add streamable HTTP and SSE tests for mid-session scope downgrade.

### SV-AUD-010 — `profiles:write` can create secrets without `secrets:write` or critical auditing

Severity: **Medium — CVSS 6.5** (`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L`)

Affected locations:

- `packages/mcp-server/src/index.ts:744-750`
- `packages/mcp-server/src/serviceProfiles.ts:53-57`
- `packages/mcp-server/src/serviceProfiles.ts:127-220`
- `packages/mcp-server/src/serviceProfiles.ts:248-256`

Description and root cause:

The profile-create route checks only `profiles:write`, yet `create_secrets` inserts arbitrary encrypted secret rows. Those inserts do not use the `secret_create` critical audit lifecycle and are not rolled back if audit logging is unavailable. This is a scope and audit-policy bypass.

Remediation:

- If `create_secrets` is nonempty, require both `profiles:write` and `secrets:write`.
- Move the operation into a database transaction/RPC that creates the initial `unknown` audit rows, secrets, and profile atomically.
- Apply the same secret value, environment, tag, and size validators as `/v1/secrets`.
- Record and finalize one critical event per created secret plus the profile event.

### SV-AUD-011 — Authentication and step-up endpoints have no active rate limiting

Severity: **High — CVSS 7.5** (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`)

Affected locations:

- `packages/mcp-server/src/rateLimit.ts:1-50`
- `packages/mcp-server/src/index.ts:513-557`
- `packages/mcp-server/src/index.ts:819-869`
- `packages/mcp-server/src/stepup.ts:507-559`

Description and root cause:

A rate limiter exists but is never imported or called. Login performs bcrypt work for known users without throttling. Open registration performs bcrypt on every request. TOTP verification has a six-digit space and no per-user/IP attempt limit.

This enables credential stuffing, online TOTP guessing, and inexpensive CPU denial of service.

Remediation:

- Apply layered limits by normalized source IP, username/user ID, credential/client ID, and endpoint.
- Use a shared store with atomic increments for multi-replica deployments.
- Return `429` with `Retry-After`; use exponential backoff and temporary account/factor cooldowns without enabling permanent lockout DoS.
- Treat proxy-derived client IP headers as trusted only from configured reverse-proxy addresses.
- Add fake-clock tests and concurrent-limit tests.

### SV-AUD-012 — Install and client setup execute mutable, unverified remote code

Severity: **High — CVSS 7.8** (`AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H`)

Affected locations:

- `install-client.sh:42-65`
- `install-server.sh:172-190`
- `packages/mcp-server/src/cli/setup.ts:326-335`
- Unpinned image tags in `Dockerfile` and `docker-compose*.yml`

Description and root cause:

Both installers clone or download mutable `main` without a commit pin, checksum, signature, or provenance verification, then execute build/install steps. Client setup configures `npx -y mcp-remote` without a version, causing mutable package code to execute on every launch while receiving the client key. Container base images are tag-pinned but not digest-pinned.

Remediation:

- Install only immutable releases.
- Publish SHA-256 checksums and Sigstore/GitHub artifact attestations; verify before extraction/execution.
- Pin `mcp-remote` to an audited exact version and install it once from a verified lockfile/artifact.
- Pin production container images by digest and automate reviewed digest updates.
- Fail closed on installation failure; remove `|| true` from the global install chain.

### SV-AUD-013 — Database RLS does not enforce tenant isolation

Severity: **Medium — CVSS 6.8** (`AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L`)

Affected locations:

- `supabase/migrations/001_create_tables.sql:34-43`
- `supabase/migrations/003_multi_user.sql:24-29`
- `supabase/migrations/004_service_profiles.sql:17-20`
- `supabase/migrations/006_client_applications.sql:28-31`
- `supabase/migrations/018_postgrest_grants.sql:15-83`
- `bundled/postgres-init.sql:22-24`

Description and root cause:

Tenant isolation is implemented only in application queries. Runtime queries use `service_role`, which has global table access and commonly bypasses RLS. Several policies are `USING (true)` without `TO service_role`, so any future or accidental table grant exposes every tenant. The bundled `authenticator` password is static and public; a compromised sibling container can connect directly and `SET ROLE service_role`.

The shipped grants keep anonymous access closed, so this is defense-in-depth rather than an unauthenticated current exploit.

Remediation:

- Create a dedicated least-privileged runtime role without `BYPASSRLS`.
- Set an authenticated tenant/client context per transaction and enforce `user_id = current_setting(...)::uuid` in RLS for tenant tables.
- Use a separate tightly scoped migration role; do not run normal traffic as `service_role`.
- Add explicit `TO` clauses to every policy and revoke explicit grants from `anon`, `authenticated`, and `PUBLIC`.
- Generate the bundled authenticator password per install and isolate PostgREST/database networks.
- Add real-Postgres integration tests that attempt cross-tenant select/insert/update/delete as the runtime role.

### SV-AUD-014 — Untrusted pagination cursors are interpolated into PostgREST filter grammar

Severity: **Low — CVSS 3.7** (`AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L`)

Affected locations:

- `packages/mcp-server/src/pagination.ts:18-65`
- `packages/mcp-server/src/api.ts:166-170`
- `packages/mcp-server/src/audit.ts:230-275`
- Equivalent cursor use in users, profiles, and MCP list/search handlers

Description and root cause:

Cursors are unsigned base64 strings. Decoded values are interpolated into `.or()` filter grammar without validating UUID/timestamp/name formats or escaping PostgREST reserved syntax. Existing top-level `user_id` filters prevent a demonstrated cross-tenant escape, but callers can alter the cursor predicate or trigger parser failures.

PoC:

```text
after:name),user_id.neq.victim|00000000-0000-0000-0000-000000000000
```

produces attacker-controlled filter grammar.

Remediation:

- Use an HMAC-authenticated opaque JSON cursor.
- Validate each decoded field against its exact type and maximum length.
- Escape PostgREST filter values or replace string grammar with a parameterized database RPC.
- Return 400 for invalid cursors rather than silently treating them as the first page.

## Informational observations

- `deriveMasterKey()` uses PBKDF2-HMAC-SHA-512 with 600,000 iterations, not Argon2id. It is not used by current production call sites, so this is a documentation/API mismatch rather than an active master-key weakness. If passphrase-derived keys become supported, use a versioned Argon2id envelope with calibrated memory, iterations, and parallelism.
- `get_secret_reference` and search/list tools project only metadata and `masked_preview`; no encrypted or raw value is selected. However, `get_secret_reference` does not return the declared `reference` token, and `generateReference()` is unused and uses a public nonce as its HMAC key. Do not deploy that token as an authorization capability; replace it with a server-keyed, tenant-bound, expiring token.
- MCP error paths sometimes return raw PostgREST error messages. Standardize them through the same redaction layer as REST errors.
- Master-key files with group/world permissions only produce a warning. Production should fail closed unless an explicit development override is present.

## Controls verified

- `mcp:read`, `mcp:write`, `proxy:*`, `secrets:metadata:read`, and `secrets:write` do not satisfy `hasRunnerScope()`.
- `/v1/client/secrets/:name` requires an explicit exact or wildcard runner capability and scopes the row by `user_id`.
- Linking-key `is_admin` flags do not bypass scopes; admin-only routes require a human session.
- MCP list/search/reference projections omit `encrypted_blob` and return masked metadata only.
- REST secret CRUD, client CRUD, profiles, proxy resolution, and audit-log reads include user ownership predicates.
- AES-256-GCM uses random 96-bit IVs and 128-bit authentication tags; HKDF purposes separate derived keys when callers use them consistently.
- Proxy request headers strip inbound credentials, hop-by-hop headers, `Connection`-nominated headers, and spoofed forwarding headers before injection.
- Proxy dispatch pins the validated DNS address for the outbound connection and does not automatically follow redirects.
- Proxy request bodies have declared-length and streaming 10 MiB enforcement.
- `.env` writes use restrictive `umask 077`, atomic replacement, and `chmod 0600`.
- Runtime container executes as the non-root `node` user.

## Remediation order

1. Close the plaintext listener and block session-driven factor takeover.
2. Fix proxy credential reflection and SSRF classification.
3. Repair cryptographic context binding and rotation before using rotation in production.
4. Eliminate process-argument secrets and mutable installer execution.
5. Enforce durable session/scope revocation and active rate limiting.
6. Close the profile inline-secret scope bypass.
7. Add database-enforced tenant isolation.
8. Harden cursors, MCP errors, reference-token semantics, and key-file policy.
