# SecretVault Security Architecture & Threat Model

SecretVault is designed specifically to prevent credential exposure in AI agent workflows, LLM context streams, and log outputs by operating as a Bounded Egress Gateway.

---

## Bounded Egress Gateway Trust Model & Core Invariants

1. **No Plaintext Secret Retrieval Endpoints for Agents**: AI agents, MCP tool responses, and client SDKs cannot retrieve raw secret plaintexts. All API and MCP responses return masked previews (e.g. `sk-live-***1234`) or opaque proxy references.
2. **Server-Side Injection**: Credentials are decrypted strictly in-memory on the SecretVault server and injected into outbound HTTP headers by the reverse proxy.
3. **Stripping Sensitive Outbound Headers**: The reverse proxy applies a complete hop-by-hop header policy in both directions. Outbound requests drop the caller's credentials (`Authorization`, `Cookie`), framing/routing headers (`Host`, `Connection`, `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive`, `Proxy-Authorization`), spoofable forwarding headers (`Forwarded`, `X-Forwarded-*`, `Via`, `X-Real-Ip`), and every field nominated by a caller-supplied `Connection` header. Inbound responses additionally drop the complete hop-by-hop set and credential headers (`Authorization`, `Cookie`, `Set-Cookie`, `WWW-Authenticate`) before returning to the client. Service-profile injected `header_name` and `cookie_name` are validated against the HTTP field-name / cookie token grammars and may not name a reserved header.

---

## Upstream Response Trust Boundary & Response Reflection Model

SecretVault acts as a credentialed proxy gateway between client applications/agents and upstream HTTP APIs.

- **Egress Header Injection**: SecretVault injects authorized credentials into the headers of outbound requests dispatched to configured upstream target URLs.
- **Upstream Response Trust Boundary**: Once an outbound request leaves SecretVault, the response returned by the target service enters the upstream service's trust boundary. SecretVault does not claim universal AI response-body regex sanitization for arbitrary third-party payloads.
- **Reflection Risk & Mitigations**:
  - *Risk*: An upstream API returning its own echo/debug response containing reflected credential data.
  - *Mitigation*: Service profiles require HTTPS by default, restrict non-admin destination creation to exact configured origins, reject local/private destinations unless explicitly enabled by an administrator, pin the DNS result used by each upstream connection, validate the canonical origin before dispatch, and record the calling client. Transparent response-body sanitization remains outside the generic proxy guarantee.

---

## Cryptographic Architecture

### Authenticated Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode) authenticated symmetric encryption.
- **Key Derivation**: HKDF-SHA256 per-purpose Data Encryption Keys (DEKs) derived from the 32-byte master key (`SECRETVAULT_MASTER_KEY` or `SECRETVAULT_MASTER_KEY_FILE`) with explicit context domain separation (`secretvault:dek:v1:<purpose>`).
- **Envelope Format**: Ciphertext is stored in versioned `v1:key_id:iv:ciphertext:authTag` format with a 12-byte (96-bit) random IV and 16-byte GCM authentication tag. Legacy `iv:ciphertext:authTag` blobs remain readable via fallback decryption.

---

## Master Key Protection

### Storage Options
- **Standard Storage**: `SECRETVAULT_MASTER_KEY` environment variable set in `.env` with strict file permissions:
  ```bash
  chmod 600 .env
  ```
- **Docker / Kubernetes Secrets (Recommended for Production)**: Pass key via secret file path:
  ```env
  SECRETVAULT_MASTER_KEY_FILE=/run/secrets/master_key
  ```
  This mounts the key strictly in RAM (`tmpfs`) without persisting it to host disk.

---

## Scoped Linking Keys & Client Identity

Linking keys (`sv_<48-hex>`) authenticate client applications and AI agents without providing master key access.

- **Storage**: Stored in PostgreSQL as SHA-256 hashes (`key_hash`). A client key's plaintext is displayed once at creation. Keys are also recoverable: SecretVault retains a master-key-encrypted copy (`encrypted_key`) so an enrolled operator can re-reveal a key without rotating it. Re-reveal and regeneration are both **critical operations** that require a recent, client-bound step-up (Passkey or TOTP) — a step-up minted for one client cannot be replayed against another. If you do not need recoverability, regenerate the key (which rotates it) and discard the plaintext; only the hash is authoritative for authentication.
- **Atomic regeneration**: Regeneration writes the new key, increments `key_version`, and invalidates the prior key in one conditional update. Concurrent regenerations are safe — only the winner's key is persisted; the loser gets a `409` and retries, so at most one key is ever valid.
- **Client Identity**: Bound to `(user_id, client_id)` pairs in `client_applications`.
- **Granular Revocation**: Revoking a client application revokes its specific linking key instantly without affecting other integrations.

---

## Step-Up Authentication (Passkeys & TOTP)

Human operations in the Web UI (such as raw secret reveal) are strictly protected by **Step-Up Authentication**:

- **WebAuthn / Passkeys**: Hardware biometric assertion (Touch ID, Face ID, Windows Hello, YubiKey).
- **TOTP Fallback**: Standard authenticator app 6-digit codes (`otplib`).
- **Recovery codes**: Eight one-time backup codes issued exactly once at TOTP enrollment (or regeneration). Shown in the UI with copy/download/print and an acknowledgment gate; never retrievable later. Consumed with an atomic compare-and-delete so concurrent use yields a single success.
- **Safe TOTP replacement**: Reconfigure writes a short-lived pending enrollment only. The verified factor stays active until the new code is confirmed, then the pending secret is swapped in atomically. Cancel discards the pending record only.
- **Factor chooser**: The UI lists enrolled factors only. Cancelling a passkey prompt returns to the chooser without dropping the pending high-risk action, so TOTP/recovery remain available.
- **Short-Lived Step-Up Tokens**: Successful assertion yields a 5-minute signed HMAC step-up token (`X-SecretVault-StepUp`). High-risk human actions require an active step-up token.

## Transport & Database TLS Defaults

SecretVault is designed to sit behind a TLS-terminating reverse proxy (Caddy, Nginx Proxy Manager, Tailscale Serve, Cloudflare Tunnel, …) in production. The defaults enforce that posture rather than ship an accidentally-exposed plaintext listener.

**Inbound HTTP (SV-020 / SV-AUD-001):**
- Two addresses govern exposure. `SECRETVAULT_BIND_HOST` is the interface the Node listener binds to *inside* its runtime (default `127.0.0.1`; the published image sets `0.0.0.0` so a proxy on the Compose network can reach it — this bind is container-internal and does not by itself expose plaintext). `SECRETVAULT_PUBLISH_HOST` is the *host-side* address port 3004 is published on (the Compose `ports:` left side); it defaults to **loopback (`127.0.0.1`)**, which is what keeps the plaintext listener off the network.
- The bundled `docker-compose.yml` therefore publishes port 3004 on the host loopback only; external exposure happens through the Caddy overlay (`docker-compose.caddy.yml`, ports 80/443 — which nulls out the app's host-side port 3004 entirely) or your own proxy.
- In production, a **plaintext listener published on a non-loopback host interface refuses to start** unless the operator sets the explicit, noisy override `SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL=1` together with `SECRETVAULT_ALLOW_PLAINTEXT_EXTERNAL_CONFIRM=I-know-this-is-insecure`. An empty prompt can never reach the unsafe path. The guard keys on the publish host, not the in-container bind host, so a legitimate container topology (bind `0.0.0.0`, publish `127.0.0.1`) is safe by default.
- Native TLS termination is available with `SECRETVAULT_TLS_CERT` / `SECRETVAULT_TLS_KEY`.
- Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and — only when the request arrived over TLS (natively or via `X-Forwarded-Proto: https`) — `Strict-Transport-Security`. HSTS is never emitted over plaintext, so it cannot pin an insecure origin.
- The WebAuthn RP ID and origin are derived proxy-aware (`X-Forwarded-Host` / `X-Forwarded-Proto`), so passkey enrollment works correctly behind the supported reverse proxy.
- Session credentials are bearer tokens returned in the JSON login body and sent as `Authorization: Bearer …`; there is no server-issued session cookie. The reverse proxy must terminate TLS end-to-end so these tokens never traverse the network in plaintext.

**Database TLS (SV-021):**
- The startup migration runner connects to PostgreSQL with **TLS on and certificate verification on by default**.
- Pin a CA bundle with `SECRETVAULT_DATABASE_SSL_CA_FILE` (path) or `SECRETVAULT_DATABASE_SSL_CA` (inline PEM), and override the SNI/hostname check with `SECRETVAULT_DATABASE_SSL_SERVERNAME`.
- Disabling verification is a deliberate, two-key dev action: `SECRETVAULT_DATABASE_SSL_INSECURE=1` **and** `SECRETVAULT_DATABASE_SSL_INSECURE_CONFIRM=I-know-this-is-insecure`. Set `SECRETVAULT_DATABASE_SSL=false` only for a local plaintext PostgreSQL instance. A database MITM presenting an untrusted certificate is rejected by default.

## Database-Enforced Tenant Isolation (SV-AUD-013)

Tenant isolation is enforced **in the database**, not only in application query filters. A missed application `.eq("user_id", ...)` predicate cannot become a cross-tenant breach.

- **Runtime role `sv_runtime` (NOLOGIN / NOBYPASSRLS).** Authenticated application traffic is switched into `sv_runtime` by PostgREST per request. Because it cannot bypass RLS and the tenant tables have `FORCE ROW LEVEL SECURITY`, the per-request tenant claim is the real boundary.
- **Per-request tenant JWT (internal-only).** For each authenticated request the app mints a short-lived (60s) HS256 JWT carrying `{ role: "sv_runtime", tenant_user_id, client_id, is_admin }`, stamped onto the shared PostgREST client's requests via an `AsyncLocalStorage`-bound `fetch`. This token is **never returned to clients**; it is distinct from the session HMAC token. PostgREST exposes it as the `request.jwt.claims` GUC.
- **Tenant RLS policies.** `secrets`, `access_logs`, `service_profiles`, `client_applications`, `webauthn_credentials`, `totp_secrets`, `totp_pending_enrollments`, `totp_backup_codes` admit a row only when `user_id = current_tenant_id()` (or `is_admin`). Application `.eq("user_id")` filters remain as defense-in-depth, not the boundary.
- **Non-tenant tables.** `users` (global auth lookup by username), `system_settings`, and `master_key_rotations` are scoped to `service_role` only (used by the pre-auth/global and admin paths); `sv_runtime` has no grant on them. `rate_limit_buckets` is `sv_runtime`-only and keyed by bucket.
- **Least privilege + revokes.** Every policy carries an explicit `TO` clause; `PUBLIC`, `anon`, and `authenticated` are revoked across the schema.
- **Network isolation (bundled stack).** Two Docker networks: `backend` (postgres + the `migrate` one-shot) and `frontend` (postgrest, postgrest-proxy, the app). PostgREST bridges both. The runtime app has **no direct `SECRETVAULT_DATABASE_URL`** — it reaches the database only through PostgREST, so a compromised app container cannot bypass RLS.
- **Per-install credentials.** `install-server.sh` generates the PostgREST↔Postgres `authenticator` password and the JWT secret per install; there is no fixed bundled authenticator password.
- **Threat boundary.** PostgREST is a trusted, in-process mediator on an isolated network. The JWT secret (`SECRETVAULT_PGRST_JWT_SECRET`) must be protected: anyone holding it can mint tenant tokens. On Supabase Cloud, where `service_role` is provisioned `BYPASSRLS` out-of-band, isolation depends on the `sv_runtime` role existing there and the app minting per-request tenant tokens into it.
- **Proof.** A real PostgreSQL/PostgREST integration test (`ci/tenant-isolation.mjs`, run in the CI `docker-e2e` job) mints two tenant tokens and asserts cross-tenant SELECT/INSERT/UPDATE/DELETE are denied, including that an unfiltered SELECT returns only the caller's rows.

