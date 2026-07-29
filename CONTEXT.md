# SecretVault Security Context

This context defines the security vocabulary used by SecretVault’s audit and credentialed egress boundary.

## Authorization and Audit

**Critical operation**:
An operation that can disclose, inject, create, rotate, or delete secret material; it must fail closed when its audit event cannot be recorded.
_Avoid_: Sensitive operation, privileged operation

**Metadata read**:
An operation that returns secret metadata without plaintext or credential injection; it may continue when audit recording fails, provided the failure is alerted.
_Avoid_: Secret read

**Audit event**:
A sortable and filterable record of an operation attempt, including who or what initiated it, what it targeted, and whether it succeeded, failed, or was denied.
_Avoid_: Access row, success log

**Audit outcome**:
One of `succeeded`, `failed`, `denied`, or `unknown`; `unknown` means the attempt was recorded but its terminal result could not be finalized.
_Avoid_: Status, result code

**Audit event lifecycle**:
Critical operations create one `unknown` audit event before execution, fail closed if that write fails, and finalize the same event afterward; metadata reads record their terminal outcome afterward and alert rather than block when logging fails.
_Avoid_: Dual-row audit, best-effort critical logging

**Audit actor fields**:
`user_id` identifies the user for user-initiated events, `client_id` identifies registered API/linking-key/MCP/proxy credentials, and both are null only for system events or browser-session activity where no client credential exists; `secret_name` is always populated, using `system` for non-secret events.
_Avoid_: Synthetic client IDs, blank secret targets

## Audit-operation matrix

Every security-relevant route maps to exactly one audit access_type. Critical operations (secret material disclosure/injection/mutation) fail closed when the initial `unknown` event cannot be written and finalize the same row afterward. Metadata reads record the terminal outcome after the fact and alert rather than block when logging fails. The acting actor is recorded separately from the target (admin resets attribute the admin, not the reset user). `actor_username`, `source_ip`, and `source_user_agent` are immutable snapshots taken at event time.

| Route / tool | access_type | Actor fields | Fail policy |
|---|---|---|---|
| POST /api/auth/login (success) | `login` | user_id, actor_username | metadata read |
| POST /api/auth/login (failure) | `login` | user_id null, actor_username | metadata read |
| POST /api/auth/change-password | `password_change` | user_id | metadata read |
| POST /api/users (admin create) | `user_create` | admin user_id + target metadata | metadata read |
| DELETE /api/users/:id | `user_delete` | admin user_id + target metadata | metadata read |
| POST /api/users/:id/reset-password | `admin_password_reset` | admin user_id + target metadata | metadata read |
| POST /api/users/:id/reset-2fa | `admin_2fa_reset` | admin user_id + target metadata | metadata read |
| POST /api/users/:id/linking-key | `linking_key_generate` | user_id | fail closed (rolls back key) |
| Emergency CLI reset | `emergency_cli_password_reset` | target user_id | metadata read |
| POST/DELETE/PATCH /api/clients | `client_create` / `client_update` / `client_delete` | user_id + client_id metadata | metadata read |
| POST /api/clients/:id/reveal | `client_key_reveal` | user_id | fail closed |
| POST /api/clients/:id/regenerate | `client_key_regenerate` | user_id | fail closed |
| POST/DELETE /api/service-profiles | `service_profile_create` / `service_profile_delete` | user_id | metadata read |
| PATCH /api/settings | `system_setting_change` | admin user_id | metadata read |
| PATCH /api/settings/audit-retention | `audit_retention_change` | admin user_id | metadata read |
| POST /api/secrets (create) | `secret_create` | user_id, client_id | fail closed |
| POST /api/secrets/:name/rotate | `secret_rotate` | user_id, client_id | fail closed |
| DELETE /api/secrets/:name | `secret_delete` | user_id, client_id | fail closed |
| POST /api/secrets/:name/reveal | `ui_reveal` | user_id | fail closed (finalize must succeed) |
| MCP create/rotate/delete secret | `secret_create` / `secret_rotate` / `secret_delete` | user_id, client_id | fail closed |
| MCP list/search/get-reference | `secret_list` / `secret_search` / `secret_reference` | user_id, client_id | metadata read |
| GET /v1/client/secrets/:name | `client_secret_read` | user_id, client_id | fail closed |
| * /proxy/:service/* | `proxy` | user_id, client_id, source metadata | fail closed |
| Any route missing auth/scope | `authorization_denied` | user_id, client_id (if known) | metadata read + repeated-denial alert |
| WebAuthn register/auth, TOTP lifecycle | `webauthn_*`, `totp_*`, `stepup_failed` | user_id | metadata read |

Reads: `GET /api/user/logs` and `GET /api/clients/:id/logs` return cursor-paginated pages over `(created_at DESC, id DESC)` with filters `from`, `to`, `access_type`, `outcome`, `secret_name`, `page_size`, and `cursor`. `GET /api/user/logs/export` returns an immutable archival snapshot. Retention is bounded by `audit_retention_days` with a server-enforced `audit_retention_floor_days` minimum; pruning deletes by age only.

## Egress Policy

**Approved egress origin**:
An exact upstream scheme/host/port origin that an administrator or the configured `SECRETVAULT_EGRESS_ALLOWLIST` has authorized; path and method permissions remain profile-specific.
_Avoid_: Destination pattern, trusted URL substring

**Private-network mode**:
An explicit administrator-only opt-in that permits otherwise blocked internal HTTP/IP destinations for trusted appliance deployments.
_Avoid_: Safe internal URL, unrestricted local proxy

**Pinned DNS destination**:
The validated IP address selected immediately before dispatch and used for the actual upstream connection, while preserving the configured hostname for HTTP Host and TLS SNI.
_Avoid_: DNS pre-check, hostname revalidation
