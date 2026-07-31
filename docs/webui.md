# SecretVault Web UI & Admin Portal Guide (`/ui`)

SecretVault provides a responsive Web UI (`http://localhost:3004/ui` or `https://vault.example.com/ui`) for managing secrets, service profiles, users, and audit logs.

---

## 1. Web UI Features & Overview

The Web UI allows operators and administrators to:

- 🔑 **Manage Secrets**: Add, edit, rotate, and soft-delete encrypted secrets.
- 🌐 **Configure Service Profiles**: Define upstream reverse-proxy routes (`/proxy/:service/*`) with server-side credential injection.
- 👤 **User & Client Management**: Provision users and generate scoped client keys (`sv_...`).
- 📜 **Audit Trail Inspection**: Review access logs showing timestamp, caller user ID, target service, and path.

---

## 2. Service Profile Configuration (Reverse Proxy)

Service Profiles map proxy routes (`/proxy/<service_name>/*`) to upstream target URLs and inject stored secrets into HTTP headers:

1. Open **Service Profiles** in the Web UI dashboard.
2. Click **Create Profile**.
3. Fill in:
   - **Profile Name**: `openai` (used in proxy route `/proxy/openai/*`).
   - **Target Base URL**: `https://api.openai.com`.
   - **Auth Type**: `Bearer Token` (or `Header`, `Query Parameter`, `Basic Auth`).
   - **Secret Name**: `OPENAI_API_KEY`.
4. Click **Save Profile**.

Client applications can now issue requests to SecretVault's proxy using their linking key (`sv_...`), and SecretVault will inject the real `OPENAI_API_KEY` server-side before relaying to `api.openai.com`.

---

## 3. Human-Only Step-Up Authentication (Passkey / TOTP)

SecretVault strictly enforces that **raw plaintext secret values are never exposed to AI agents or unauthenticated API callers**.

In the Web UI, revealing a secret's raw plaintext value to a human operator requires **Step-Up Authentication**:

- 🔑 **Hardware Passkeys (WebAuthn / FIDO2)**: Security keys (YubiKey, Touch ID, Windows Hello).
- 📲 **TOTP 2FA**: Time-based one-time passwords from authenticator apps (Google Authenticator, 1Password).

When a human operator clicks **Reveal Secret**, SecretVault requires a Step-Up assertion before returning the decrypted value in memory.

---

## 4. Break-Glass Emergency Setup & Password Reset

If admin credentials are lost or locked out, SecretVault provides a break-glass CLI helper inside the server container:

```bash
# On the SecretVault server host:
docker exec -it secretvault-mcp secretvault-break-glass
```

Follow the prompts to reset the administrator password or generate a break-glass setup code.
