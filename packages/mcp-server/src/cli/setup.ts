import * as readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { promptPassword } from "./secret.js";

interface ToolConfigSpec {
  name: string;
  configPath: string;
  format: "mcpServers" | "mcp_config" | "claude_code" | "codex";
}

function getHomeDir(): string {
  return os.homedir();
}

function getDetectedTools(): ToolConfigSpec[] {
  const home = getHomeDir();
  const isMac = process.platform === "darwin";
  const isWin = process.platform === "win32";
  const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  const appData = process.env.APPDATA || (isWin ? path.join(home, "AppData", "Roaming") : "");

  // 1. Antigravity IDE
  const antigravityDir = process.env.ANTIGRAVITY_CONFIG_DIR || process.env.GEMINI_CONFIG_DIR;
  const antigravityPath = antigravityDir
    ? path.join(antigravityDir, "mcp_config.json")
    : path.join(home, ".gemini", "config", "mcp_config.json");

  // 2. Claude Code CLI
  const customClaudeDir = process.env.CLAUDE_CONFIG_DIR;
  let claudeCodePath = customClaudeDir
    ? path.join(customClaudeDir, "claude.json")
    : path.join(home, ".claude.json");
  if (!customClaudeDir && !fs.existsSync(claudeCodePath) && fs.existsSync(path.join(home, ".claude", "settings.json"))) {
    claudeCodePath = path.join(home, ".claude", "settings.json");
  }

  // 3. Claude Desktop
  let claudeDesktopPath = "";
  if (isMac) {
    claudeDesktopPath = path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  } else if (isWin) {
    claudeDesktopPath = path.join(appData, "Claude", "claude_desktop_config.json");
  } else {
    claudeDesktopPath = path.join(xdgConfig, "Claude", "claude_desktop_config.json");
  }

  // 4. OpenCode
  let openCodePath = "";
  if (isMac) {
    const macAppSupport = path.join(home, "Library", "Application Support", "opencode", "opencode.json");
    const macXdg = path.join(xdgConfig, "opencode", "opencode.json");
    openCodePath = fs.existsSync(macAppSupport) ? macAppSupport : macXdg;
  } else if (isWin) {
    const winAppData = path.join(appData, "opencode", "opencode.json");
    const winXdg = path.join(xdgConfig, "opencode", "opencode.json");
    openCodePath = fs.existsSync(winAppData) ? winAppData : winXdg;
  } else {
    openCodePath = path.join(xdgConfig, "opencode", "opencode.json");
  }

  // 5. Codex
  const codexPath = process.env.CODEX_HOME
    ? path.join(process.env.CODEX_HOME, "config.toml")
    : path.join(home, ".codex", "config.toml");

  // 6. Cursor
  let cursorPath = "";
  if (isMac) {
    cursorPath = path.join(home, "Library", "Application Support", "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json");
  } else if (isWin) {
    cursorPath = path.join(appData, "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json");
  } else {
    cursorPath = path.join(xdgConfig, "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json");
  }

  const tools: ToolConfigSpec[] = [
    {
      name: "Antigravity IDE",
      configPath: antigravityPath,
      format: "mcpServers",
    },
    {
      name: "Claude Code CLI",
      configPath: claudeCodePath,
      format: "claude_code",
    },
    {
      name: "Claude Desktop",
      configPath: claudeDesktopPath,
      format: "mcpServers",
    },
    {
      name: "OpenCode",
      configPath: openCodePath,
      format: "mcpServers",
    },
    {
      name: "Codex",
      configPath: codexPath,
      format: "codex",
    },
    {
      name: "Cursor",
      configPath: cursorPath,
      format: "mcpServers",
    },
  ];

  return tools;
}

async function promptInput(rl: readline.Interface, question: string, defaultValue?: string): Promise<string> {
  const displayPrompt = defaultValue ? `${question} [${defaultValue}]: ` : `${question}: `;
  const answer = await rl.question(displayPrompt);
  return answer.trim() || (defaultValue ?? "");
}

function parseFlexibleJson(raw: string): Record<string, any> {
  try {
    return JSON.parse(raw);
  } catch {
    // Sanitize JSONC features (comments & trailing commas before closing braces/brackets)
    let clean = raw
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:\n])\/\/.*$/gm, "$1")
      .replace(/,(\s*[\}\]])/g, "$1");
    return JSON.parse(clean);
  }
}

export async function writeSafeJsonConfig(configPath: string, updateFn: (current: Record<string, any>) => Record<string, any>): Promise<void> {
  const dir = path.dirname(configPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  let currentConfig: Record<string, any> = {};
  if (fs.existsSync(configPath)) {
    const raw = fs.readFileSync(configPath, "utf8");
    try {
      currentConfig = parseFlexibleJson(raw);
    } catch {
      // SV-039: Preserve corrupted file before overwriting
      const corruptBackup = `${configPath}.corrupt.${Date.now()}`;
      fs.writeFileSync(corruptBackup, raw, { mode: 0o600 });
      console.log(`\x1b[1;33mWarning: Preserved invalid JSON config at '${corruptBackup}'\x1b[0m`);
      currentConfig = {};
    }
    // Create pre-modification backup
    const backupPath = `${configPath}.bak.${Date.now()}`;
    fs.writeFileSync(backupPath, raw, { mode: 0o600 });
  }

  const updatedConfig = updateFn(currentConfig);
  const jsonContent = JSON.stringify(updatedConfig, null, 2);

  // SV-039: Atomic file replacement with strict 0600 permissions
  const tmpPath = `${configPath}.tmp.${Date.now()}`;
  fs.writeFileSync(tmpPath, jsonContent, { mode: 0o600, encoding: "utf8" });
  fs.renameSync(tmpPath, configPath);
  fs.chmodSync(configPath, 0o600);
}

export async function writeSafeTomlConfig(
  configPath: string,
  serverName: string,
  configBlock: { command: string; args: string[] }
): Promise<void> {
  const dir = path.dirname(configPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  let raw = "";
  if (fs.existsSync(configPath)) {
    raw = fs.readFileSync(configPath, "utf8");
    // Create pre-modification backup
    const backupPath = `${configPath}.bak.${Date.now()}`;
    fs.writeFileSync(backupPath, raw, { mode: 0o600 });
  }

  const sectionHeader = `[mcp_servers.${serverName}]`;
  const sectionContent = `${sectionHeader}\ncommand = ${JSON.stringify(configBlock.command)}\nargs = ${JSON.stringify(configBlock.args)}\n`;

  let newContent = "";
  const sectionRegex = new RegExp(`\\[mcp_servers\\.${serverName}\\][\\s\\S]*?(?=\\n\\[|$)`, "g");

  if (raw.includes(sectionHeader)) {
    newContent = raw.replace(sectionRegex, sectionContent.trim());
  } else {
    newContent = raw ? `${raw.trimEnd()}\n\n${sectionContent}` : sectionContent;
  }

  // Atomic file replacement with strict 0600 permissions
  const tmpPath = `${configPath}.tmp.${Date.now()}`;
  fs.writeFileSync(tmpPath, newContent, { mode: 0o600, encoding: "utf8" });
  fs.renameSync(tmpPath, configPath);
  fs.chmodSync(configPath, 0o600);
}


export async function handleSetupCli(): Promise<void> {
  console.log("\x1b[1;36m");
  console.log("════════════════════════════════════════════════════════════════════════");
  console.log("       ⚡ SecretVault Client Setup & Tool Configuration Wizard           ");
  console.log("════════════════════════════════════════════════════════════════════════");
  console.log("\x1b[0m");

  const rl = readline.createInterface({ input, output });

  try {
    const serverUrl = await promptInput(rl, "SecretVault Server URL", "http://localhost:3004");

    // SV-020: warn when the operator points this tool at a non-loopback
    // plaintext URL — passwords and the new client key would traverse the
    // network unencrypted. Loopback and https are both safe.
    try {
      const parsed = new URL(serverUrl);
      const isLoopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1";
      if (parsed.protocol === "http:" && !isLoopback) {
        console.log("\n\x1b[1;33m⚠  WARNING: this URL uses plaintext HTTP on a non-loopback host.\x1b[0m");
        console.log("\x1b[1;33m   Passwords and the new client key will be sent unencrypted. Use an\x1b[0m");
        console.log("\x1b[1;33m   https:// URL (behind a reverse proxy) for anything beyond local testing.\x1b[0m\n");
      }
    } catch {
      // invalid URL — the fetch below will surface a clearer error
    }
    let clientKey = await promptInput(rl, "SecretVault Client Key (sv_...) [Leave blank to log in]", "");

    if (!clientKey) {
      console.log("\n\x1b[1;33mNo Client Key provided. Logging in to generate a new key...\x1b[0m");
      const username = await promptInput(rl, "Username", "admin");
      const password = await promptPassword(rl, "Password");
      const totpCode = await promptInput(rl, "2FA Code / TOTP (Leave blank if not enabled)", "");

      console.log("\x1b[36mAuthenticating with SecretVault server...\x1b[0m");
      let loginRes = await fetch(`${serverUrl}/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, totpCode: totpCode || undefined }),
      });
      if (!loginRes.ok) {
        loginRes = await fetch(`${serverUrl}/api/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password, totpCode: totpCode || undefined }),
        });
      }

      if (!loginRes.ok) {
        const errJson = await loginRes.json().catch(() => ({ error: "Authentication failed" })) as { error?: string };
        throw new Error(`Login failed: ${errJson.error || loginRes.statusText}`);
      }

      const loginData = await loginRes.json() as { token: string };
      const sessionToken = loginData.token;

      const hostname = os.hostname();
      const label = `CLI-Client-${hostname}-${Date.now().toString(36)}`;

      console.log(`\x1b[36mProvisioning new Client Key ('${label}')...\x1b[0m`);
      let keyRes = await fetch(`${serverUrl}/v1/clients`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({ app_name: label, scopes: ["mcp:read", "mcp:write"] }),
      });
      if (!keyRes.ok) {
        keyRes = await fetch(`${serverUrl}/api/clients`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${sessionToken}`,
          },
          body: JSON.stringify({ app_name: label, scopes: ["mcp:read", "mcp:write"] }),
        });
      }

      if (!keyRes.ok) {
        throw new Error(`Failed to provision client key: ${keyRes.statusText}`);
      }

      const keyData = await keyRes.json() as { client_key?: string; linking_key?: string; key?: string };
      clientKey = keyData.client_key || keyData.linking_key || keyData.key || "";
      if (!clientKey) {
        throw new Error("Server responded without client key string.");
      }

      console.log("\x1b[1;32m✓ Provisioned new Client Key successfully!\x1b[0m");
      console.log(`\x1b[1mClient Key:\x1b[0m ${clientKey.substring(0, 8)}...\n`);
    }

    // Diagnostic health check with client key
    console.log("\x1b[36mTesting server health check...\x1b[0m");
    const healthRes = await fetch(`${serverUrl}/health/ready`).catch(() => null);
    if (!healthRes || !healthRes.ok) {
      console.log("\x1b[1;33mWarning: Server /health/ready endpoint did not respond OK. Continuing setup...\x1b[0m");
    } else {
      console.log("\x1b[1;32m✓ SecretVault server connectivity verified.\x1b[0m\n");
    }

    const availableTools = getDetectedTools();
    console.log("\x1b[1mDetected Developer AI Tools:\x1b[0m");
    availableTools.forEach((tool, idx) => {
      const exists = fs.existsSync(tool.configPath);
      const statusStr = exists ? "\x1b[32m[Detected]\x1b[0m" : "\x1b[90m[Not Found - Will Create]\x1b[0m";
      console.log(`  [${idx + 1}] ${tool.name} ${statusStr}`);
      console.log(`      Path: ${tool.configPath}`);
    });

    const toolSelectionStr = await promptInput(rl, "\nSelect tools to configure (e.g., 'all' or '1,2')", "all");

    let selectedTools: ToolConfigSpec[] = [];
    if (toolSelectionStr.toLowerCase() === "all") {
      selectedTools = availableTools;
    } else {
      const indices = toolSelectionStr.split(",").map((s) => parseInt(s.trim(), 10) - 1);
      selectedTools = availableTools.filter((_, idx) => indices.includes(idx));
    }

    const secretVaultConfigBlock = {
      command: "npx",
      args: [
        "-y",
        "mcp-remote",
        `${serverUrl}/mcp`,
        "--header",
        `Authorization: Bearer ${clientKey}`,
        "--allow-http",
      ],
    };

    console.log("\n\x1b[1mUpdating tool configuration files with safe atomic writes...\x1b[0m");

    for (const tool of selectedTools) {
      try {
        if (tool.format === "codex") {
          await writeSafeTomlConfig(tool.configPath, "secretvault", secretVaultConfigBlock);
        } else {
          await writeSafeJsonConfig(tool.configPath, (currentConfig) => {
            if (!currentConfig.mcpServers || typeof currentConfig.mcpServers !== "object") {
              currentConfig.mcpServers = {};
            }
            currentConfig.mcpServers.secretvault = secretVaultConfigBlock;
            return currentConfig;
          });
        }

        console.log(`\x1b[1;32m✓ Configured ${tool.name}\x1b[0m (${tool.configPath})`);
      } catch (err: any) {
        console.error(`\x1b[1;31mFailed to configure ${tool.name}: ${err.message}\x1b[0m`);
      }
    }

    console.log("\n\x1b[1;32m========================================================================\x1b[0m");
    console.log("\x1b[1;32m       🎉 SECRETVAULT CLIENT SETUP COMPLETE                              \x1b[0m");
    console.log("\x1b[1;32m========================================================================\x1b[0m");
    console.log(`  Configured Server:  ${serverUrl}`);
    console.log(`  Configured Key:     ${clientKey.substring(0, 8)}...`);
    console.log(`  Configured Tools:   ${selectedTools.map((t) => t.name).join(", ")}`);
    console.log("\x1b[1;32m========================================================================\x1b[0m\n");
  } finally {
    rl.close();
    process.exit(0);
  }
}
