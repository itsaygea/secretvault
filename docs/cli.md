# SecretVault CLI & Terminal Manager Guide (`secretvault` / `securevault`)

The SecretVault CLI provides a zero-leak, interactive terminal manager and stdio command runner for managing secrets and executing tools without putting raw API keys on disk or in shell history.

---

## 1. Quick Commands & Binary Aliases

SecretVault CLI supports both `secretvault` and `securevault` command names:

```bash
# Launch interactive terminal manager
secretvault
# (or securevault)

# Auto-update CLI binaries to latest version
secretvault update
# (or securevault update)

# Re-run setup wizard for developer tools
secretvault setup

# Manage secrets via direct subcommands
secretvault secret list
secretvault secret create
secretvault secret rotate
secretvault secret delete
```

---

## 2. Interactive Terminal Manager (`secretvault` / `securevault`)

Running `secretvault` (or `securevault`, or `secretvault -i`) opens the interactive management menu:

```
════════════════════════════════════════════════════════════════════════
       ⚡ SecretVault Terminal Manager (Interactive Mode)
════════════════════════════════════════════════════════════════════════
Connected Server: https://vault.example.com
Client Key:       sv_YOUR_LINKING_KEY...

Select an action:
  [1] 📋 List Secrets
  [2] 🔑 Create New Secret
  [3] 🔄 Rotate Existing Secret
  [4] ❌ Delete Secret
  [5] 🚀 Run Stdio Command (Zero-Leak)
  [6] ⚙️ Re-run Setup Wizard
  [7] ⬆️ Update SecretVault CLI
  [8] 🚪 Exit
```

### Key Interactive Features
- 🔒 **Masked Input**: Passwords and secret values are masked as you type so credentials never echo on-screen or get saved in shell history.
- 📋 **Clean 2-Column Secret List**: Option `[1]` presents a streamlined table showing secret names and masked values (`sk-proj-****1234`).
- 🔤 **Automatic Case-Insensitivity**: All names are canonicalized (`canonicalName()`), preventing duplicate secrets (`OPENAI_API_KEY` vs `openai_api_key`).

---

## 3. Zero-Leak Stdio Runner (`secretvault run`)

Inject secrets directly into a child process's RAM environment (`process.env`) without writing plaintexts to disk or command-line arguments:

```bash
secretvault run --secret OPENAI_API_KEY -- npx -y @example/mcp-server
```

### Security Guarantees
- 🧠 **RAM-Only Lifetime**: Decrypted secrets exist solely inside the child process RAM while executing.
- 🛡️ **No Command-Line Leak**: Secrets are passed via environment variables, keeping them hidden from `/proc/<pid>/cmdline` and `ps`.
- 📁 **Zero-Config Credential Resolution**: Automatically uses your local credentials (`~/.secretvault/credential.json`).

---

## 4. Local Credential Persistence (`~/.secretvault/credential.json`)

`secretvault setup` (or `install-client.sh`) saves your local server URL and client key to `~/.secretvault/credential.json`:

```json
{
  "url": "https://vault.example.com",
  "clientKey": "sv_1234567890abcdef..."
}
```

- **POSIX Security**: Saved with strict `0600` (user-read/write only) file permissions.
- **Seamless Updates**: When re-running `install-client.sh` or `secretvault setup` to update, SecretVault automatically detects existing credentials and asks to preserve them:
  ```text
  ✓ Found existing SecretVault credentials:
    Server URL: https://vault.example.com
    Client Key: sv_1234567890abcdef...

  Keep existing credentials and re-configure tools? (Y/n) [y]:
  ```

---

## 5. CLI Auto-Updater (`secretvault update`)

Update your CLI binaries to the latest release at any time:

```bash
secretvault update
```

The auto-updater fetches the latest release from GitHub, re-builds system PATH binaries, and retains all your local credentials and developer tool configurations.
