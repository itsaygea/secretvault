import * as readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

interface SecretItem {
  name?: string;
  canonical_name?: string;
  display_name?: string;
  environment?: string;
  masked_preview?: string;
  masked_value?: string;
  preview?: string;
  tags?: string[];
  created_at?: string;
}

async function promptInput(rl: readline.Interface, question: string, defaultValue?: string): Promise<string> {
  const displayPrompt = defaultValue ? `${question} [${defaultValue}]: ` : `${question}: `;
  const answer = await rl.question(displayPrompt);
  return answer.trim() || (defaultValue ?? "");
}

export async function promptPassword(rl: readline.Interface, question: string): Promise<string> {
  if (process.stdin.isTTY) {
    return new Promise((resolve) => {
      process.stdout.write(`${question}: `);
      let password = "";
      const onData = (char: Buffer) => {
        const str = char.toString("utf8");
        for (const c of str) {
          if (c === "\n" || c === "\r" || c === "\u0004") {
            process.stdin.removeListener("data", onData);
            process.stdin.setRawMode(false);
            process.stdout.write("\n");
            resolve(password.trim());
            return;
          } else if (c === "\u007f" || c === "\b") {
            if (password.length > 0) {
              password = password.slice(0, -1);
            }
          } else if (c === "\u0003") {
            process.stdin.removeListener("data", onData);
            process.stdin.setRawMode(false);
            process.exit(1);
          } else {
            password += c;
          }
        }
      };
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.on("data", onData);
    });
  }
  const answer = await rl.question(`${question}: `);
  return answer.trim();
}

export async function handleSecretCli(): Promise<void> {
  const args = process.argv.slice(3);
  const subcommand = args[0] || "list";

  const urlIdx = args.indexOf("--url");
  let keyIdx = args.indexOf("--client-key");
  if (keyIdx === -1) keyIdx = args.indexOf("--client_key");
  if (keyIdx === -1) keyIdx = args.indexOf("--key");

  const nameIdx = args.indexOf("--name");
  const valIdx = args.indexOf("--value");

  const serverUrl = (urlIdx !== -1 && args[urlIdx + 1]) || process.env.SECRETVAULT_URL || "http://localhost:3004";
  const clientKey = (keyIdx !== -1 && args[keyIdx + 1]) || process.env.SECRETVAULT_CLIENT_KEY || process.env.SECRETVAULT_TOKEN || "";

  if (!clientKey && subcommand !== "help") {
    console.error("\x1b[1;31mError: Missing SecretVault Client Key or Token.\x1b[0m");
    console.error("Set SECRETVAULT_CLIENT_KEY environment variable or pass --client-key <sv_...>");
    process.exit(1);
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${clientKey}`,
  };

  switch (subcommand) {
    case "list":
    case "ls": {
      console.log(`\x1b[36mFetching secrets from ${serverUrl}...\x1b[0m\n`);
      let res = await fetch(`${serverUrl}/v1/secrets`, { headers });
      if (!res.ok) {
        res = await fetch(`${serverUrl}/api/secrets`, { headers });
      }
      if (!res.ok) {
        console.error(`\x1b[31mFailed to list secrets: ${res.statusText}\x1b[0m`);
        process.exit(1);
      }
      const rawData = await res.json() as any;
      const secrets: SecretItem[] = Array.isArray(rawData) ? rawData : (rawData?.secrets || []);

      if (secrets.length === 0) {
        console.log("No secrets found.");
        return;
      }

      console.log("\x1b[1mNAME                           DISPLAY NAME                   ENVIRONMENT     MASKED VALUE          TAGS\x1b[0m");
      console.log("------------------------------------------------------------------------------------------------------------------");
      secrets.forEach((s) => {
        const nameVal = s.name || s.canonical_name || "UNKNOWN";
        const namePad = nameVal.padEnd(30, " ");
        const dispPad = (s.display_name || nameVal).padEnd(30, " ");
        const envPad = (s.environment || "development").padEnd(15, " ");
        const maskPad = (s.masked_preview || s.masked_value || s.preview || "••••••••").padEnd(20, " ");
        const tagsStr = (s.tags || []).join(", ");
        console.log(`${namePad} ${dispPad} ${envPad} ${maskPad} ${tagsStr}`);
      });
      console.log(`\nTotal: ${secrets.length} secret(s)`);
      break;
    }

    case "create":
    case "add": {
      let name = (nameIdx !== -1 && args[nameIdx + 1]) || "";
      let value = (valIdx !== -1 && args[valIdx + 1]) || "";
      let displayName = name;
      let environment = "development";
      let tags: string[] = [];

      const rl = readline.createInterface({ input, output });
      try {
        if (!name || !value) {
          console.log("\x1b[1;36m--- Create New Secret ---\x1b[0m");
          if (!name) name = await promptInput(rl, "Secret Name (e.g. CONTEXT7_API_KEY)");
          if (!value) value = await promptPassword(rl, "Secret Value");
          displayName = await promptInput(rl, "Display Name (Optional)", name);
          environment = await promptInput(rl, "Environment [development|staging|production]", "development");
          const tagsStr = await promptInput(rl, "Tags (comma-separated, optional)", "");
          tags = tagsStr ? tagsStr.split(",").map((t) => t.trim()).filter(Boolean) : [];
        }

        let res = await fetch(`${serverUrl}/v1/secrets`, {
          method: "POST",
          headers,
          body: JSON.stringify({ name, value, display_name: displayName, environment, tags }),
        });
        if (!res.ok) {
          res = await fetch(`${serverUrl}/api/secrets`, {
            method: "POST",
            headers,
            body: JSON.stringify({ name, value, display_name: displayName, environment, tags }),
          });
        }

        if (!res.ok) {
          const err = await res.json().catch(() => ({})) as { error?: string };
          console.error(`\x1b[31mFailed to create secret: ${err.error || res.statusText}\x1b[0m`);
          process.exit(1);
        }

        console.log(`\x1b[1;32m✓ Secret '${name}' created successfully.\x1b[0m`);
      } finally {
        rl.close();
      }
      break;
    }

    case "rotate": {
      const rl = readline.createInterface({ input, output });
      try {
        console.log("\x1b[1;36m--- Rotate Secret ---\x1b[0m");
        const name = await promptInput(rl, "Target Secret Name");
        const value = await promptPassword(rl, "New Secret Value");

        let res = await fetch(`${serverUrl}/v1/secrets/${encodeURIComponent(name)}/rotate`, {
          method: "POST",
          headers,
          body: JSON.stringify({ new_value: value }),
        });
        if (!res.ok) {
          res = await fetch(`${serverUrl}/api/secrets/${encodeURIComponent(name)}/rotate`, {
            method: "POST",
            headers,
            body: JSON.stringify({ new_value: value }),
          });
        }

        if (!res.ok) {
          const err = await res.json().catch(() => ({})) as { error?: string };
          console.error(`\x1b[31mFailed to rotate secret: ${err.error || res.statusText}\x1b[0m`);
          process.exit(1);
        }

        console.log(`\x1b[1;32m✓ Secret '${name}' rotated successfully.\x1b[0m`);
      } finally {
        rl.close();
      }
      break;
    }

    case "delete":
    case "rm": {
      const rl = readline.createInterface({ input, output });
      try {
        console.log("\x1b[1;31m--- Delete Secret ---\x1b[0m");
        const name = await promptInput(rl, "Target Secret Name to DELETE");
        const confirm = await promptInput(rl, `Type 'YES' to permanently delete '${name}'`);

        if (confirm !== "YES") {
          console.log("Deletion cancelled.");
          return;
        }

        let res = await fetch(`${serverUrl}/v1/secrets/${encodeURIComponent(name)}`, {
          method: "DELETE",
          headers,
        });
        if (!res.ok) {
          res = await fetch(`${serverUrl}/api/secrets/${encodeURIComponent(name)}`, {
            method: "DELETE",
            headers,
          });
        }

        if (!res.ok) {
          const err = await res.json().catch(() => ({})) as { error?: string };
          console.error(`\x1b[31mFailed to delete secret: ${err.error || res.statusText}\x1b[0m`);
          process.exit(1);
        }

        console.log(`\x1b[1;32m✓ Secret '${name}' deleted successfully.\x1b[0m`);
      } finally {
        rl.close();
      }
      break;
    }

    default: {
      console.log("SecretVault Terminal Secret Manager");
      console.log("Usage: secretvault-mcp secret [list|create|rotate|delete] [--url <url>] [--key <key>]");
      break;
    }
  }
}
