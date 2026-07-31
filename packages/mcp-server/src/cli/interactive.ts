import * as readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { loadClientCredentials } from "./credentialStore.js";
import { promptPassword } from "./secret.js";
import { handleSetupCli } from "./setup.js";
import { handleRunCli } from "../runner.js";
import { handleUpdateCli } from "./update.js";

async function promptInput(rl: readline.Interface, question: string, defaultValue?: string): Promise<string> {
  const displayPrompt = defaultValue ? `${question} [${defaultValue}]: ` : `${question}: `;
  const answer = await rl.question(displayPrompt);
  return answer.trim() || (defaultValue ?? "");
}

async function listSecretsInteractive(serverUrl: string, clientKey: string): Promise<void> {
  console.log(`\n\x1b[36mFetching secrets from ${serverUrl}...\x1b[0m\n`);
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${clientKey}`,
  };

  let res = await fetch(`${serverUrl}/v1/secrets`, { headers }).catch(() => null);
  if (!res || !res.ok) {
    res = await fetch(`${serverUrl}/api/secrets`, { headers }).catch(() => null);
  }

  if (!res || !res.ok) {
    console.error(`\x1b[31mFailed to list secrets from ${serverUrl}\x1b[0m`);
    return;
  }

  const rawData = (await res.json().catch(() => [])) as any;
  const secrets = Array.isArray(rawData) ? rawData : rawData?.data || rawData?.secrets || [];

  if (secrets.length === 0) {
    console.log("\x1b[33mNo secrets found for this client key.\x1b[0m\n");
    return;
  }

  console.log("\x1b[1mSECRET NAME                                        MASKED VALUE\x1b[0m");
  console.log("-------------------------------------------------------------------------------");
  secrets.forEach((s: any) => {
    const nameVal = (s.display_name || s.name || s.canonical_name || "UNKNOWN").padEnd(50);
    const maskedVal = s.masked_value || s.masked_preview || "••••••••";
    console.log(`${nameVal} ${maskedVal}`);
  });
  console.log("");
}

async function createSecretInteractive(rl: readline.Interface, serverUrl: string, clientKey: string): Promise<void> {
  console.log("\n\x1b[1;36mCreate New Secret\x1b[0m");
  const name = await promptInput(rl, "Secret Name (e.g. GITHUB_TOKEN)");
  if (!name) {
    console.log("\x1b[31mSecret name is required.\x1b[0m\n");
    return;
  }
  const value = await promptPassword(rl, "Secret Value (input masked)");
  if (!value) {
    console.log("\x1b[31mSecret value is required.\x1b[0m\n");
    return;
  }
  const environment = await promptInput(rl, "Environment", "global");
  const tagsStr = await promptInput(rl, "Tags (comma-separated, optional)", "");
  const tags = tagsStr ? tagsStr.split(",").map(t => t.trim()).filter(Boolean) : [];

  console.log("\x1b[36mSaving encrypted secret...\x1b[0m");
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${clientKey}`,
  };

  let res = await fetch(`${serverUrl}/v1/secrets`, {
    method: "POST",
    headers,
    body: JSON.stringify({ name, value, environment, tags }),
  }).catch(() => null);

  if (!res || !res.ok) {
    res = await fetch(`${serverUrl}/api/secrets`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name, value, environment, tags }),
    }).catch(() => null);
  }

  if (!res || !res.ok) {
    const errText = res ? await res.text().catch(() => "") : "Network error";
    console.error(`\x1b[31mFailed to create secret: ${errText}\x1b[0m\n`);
    return;
  }

  console.log(`\x1b[1;32m✓ Secret '${name}' created and encrypted successfully!\x1b[0m\n`);
}

async function rotateSecretInteractive(rl: readline.Interface, serverUrl: string, clientKey: string): Promise<void> {
  console.log("\n\x1b[1;36mRotate Existing Secret\x1b[0m");
  const name = await promptInput(rl, "Secret Name to Rotate");
  if (!name) {
    console.log("\x1b[31mSecret name is required.\x1b[0m\n");
    return;
  }
  const value = await promptPassword(rl, "New Secret Value (input masked)");
  if (!value) {
    console.log("\x1b[31mNew secret value is required.\x1b[0m\n");
    return;
  }

  console.log("\x1b[36mUpdating secret value...\x1b[0m");
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${clientKey}`,
  };

  let res = await fetch(`${serverUrl}/v1/secrets/${encodeURIComponent(name)}/rotate`, {
    method: "POST",
    headers,
    body: JSON.stringify({ value }),
  }).catch(() => null);

  if (!res || !res.ok) {
    res = await fetch(`${serverUrl}/api/secrets/${encodeURIComponent(name)}/rotate`, {
      method: "POST",
      headers,
      body: JSON.stringify({ value }),
    }).catch(() => null);
  }

  if (!res || !res.ok) {
    const errText = res ? await res.text().catch(() => "") : "Network error";
    console.error(`\x1b[31mFailed to rotate secret: ${errText}\x1b[0m\n`);
    return;
  }

  console.log(`\x1b[1;32m✓ Secret '${name}' rotated successfully!\x1b[0m\n`);
}

async function deleteSecretInteractive(rl: readline.Interface, serverUrl: string, clientKey: string): Promise<void> {
  console.log("\n\x1b[1;36mDelete Secret\x1b[0m");
  const name = await promptInput(rl, "Secret Name to Delete");
  if (!name) {
    console.log("\x1b[31mSecret name is required.\x1b[0m\n");
    return;
  }

  const confirm = await promptInput(rl, `Are you sure you want to delete '${name}'? (y/N)`, "n");
  if (confirm.toLowerCase() !== "y" && confirm.toLowerCase() !== "yes") {
    console.log("Deletion cancelled.\n");
    return;
  }

  console.log("\x1b[36mDeleting secret...\x1b[0m");
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${clientKey}`,
  };

  let res = await fetch(`${serverUrl}/v1/secrets/${encodeURIComponent(name)}`, {
    method: "DELETE",
    headers,
  }).catch(() => null);

  if (!res || !res.ok) {
    res = await fetch(`${serverUrl}/api/secrets/${encodeURIComponent(name)}`, {
      method: "DELETE",
      headers,
    }).catch(() => null);
  }

  if (!res || !res.ok) {
    const errText = res ? await res.text().catch(() => "") : "Network error";
    console.error(`\x1b[31mFailed to delete secret: ${errText}\x1b[0m\n`);
    return;
  }

  console.log(`\x1b[1;32m✓ Secret '${name}' deleted successfully!\x1b[0m\n`);
}

export async function handleInteractiveMenu(): Promise<void> {
  let stored = loadClientCredentials();

  if (!stored || !stored.clientKey) {
    console.log("\x1b[1;33mNo local client credentials found. Launching setup wizard...\x1b[0m\n");
    await handleSetupCli();
    stored = loadClientCredentials();
    if (!stored || !stored.clientKey) {
      console.error("\x1b[31mSetup incomplete. Exiting.\x1b[0m");
      process.exit(1);
    }
  }

  const serverUrl = process.env.SECRETVAULT_URL || stored.url || "http://localhost:3004";
  const clientKey = process.env.SECRETVAULT_CLIENT_KEY || stored.clientKey!;

  const rl = readline.createInterface({ input, output });

  try {
    while (true) {
      console.log("\x1b[1;36m════════════════════════════════════════════════════════════════════════\x1b[0m");
      console.log("       ⚡ SecretVault Terminal Manager (Interactive Mode)              ");
      console.log("\x1b[1;36m════════════════════════════════════════════════════════════════════════\x1b[0m");
      console.log(`Connected Server: \x1b[32m${serverUrl}\x1b[0m`);
      console.log(`Client Key:       \x1b[32m${clientKey.substring(0, 8)}...\x1b[0m\n`);

      console.log("Select an action:");
      console.log("  [1] 📋 List Secrets");
      console.log("  [2] 🔑 Create New Secret");
      console.log("  [3] 🔄 Rotate Existing Secret");
      console.log("  [4] ❌ Delete Secret");
      console.log("  [5] 🚀 Run Stdio Command (Zero-Leak)");
      console.log("  [6] ⚙️ Re-run Setup Wizard");
      console.log("  [7] ⬆️ Update SecretVault CLI");
      console.log("  [8] 🚪 Exit\n");

      const choice = await promptInput(rl, "Enter choice [1-8]", "1");

      switch (choice.trim()) {
        case "1":
          await listSecretsInteractive(serverUrl, clientKey);
          break;
        case "2":
          await createSecretInteractive(rl, serverUrl, clientKey);
          break;
        case "3":
          await rotateSecretInteractive(rl, serverUrl, clientKey);
          break;
        case "4":
          await deleteSecretInteractive(rl, serverUrl, clientKey);
          break;
        case "5": {
          const secretName = await promptInput(rl, "Secret Name to Inject (e.g. CONTEXT7_API_KEY)");
          const commandStr = await promptInput(rl, "Command to Run (e.g. npx -y @upstash/context7-mcp)");
          if (secretName && commandStr) {
            process.argv = [process.argv[0]!, process.argv[1]!, "run", "--secret", secretName, "--", ...commandStr.split(" ")];
            rl.close();
            await handleRunCli();
            return;
          }
          break;
        }
        case "6":
          rl.close();
          await handleSetupCli();
          return;
        case "7":
          rl.close();
          await handleUpdateCli();
          return;
        case "8":
        case "q":
        case "exit":
          console.log("\x1b[32mGoodbye!\x1b[0m");
          return;
        default:
          console.log("\x1b[33mInvalid selection. Please enter a number between 1 and 8.\x1b[0m\n");
      }
    }
  } finally {
    try { rl.close(); } catch { /* ignore */ }
  }
}
