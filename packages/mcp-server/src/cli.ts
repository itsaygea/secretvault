#!/usr/bin/env node
import { createClient } from "@supabase/supabase-js";
import { readFileSync } from "node:fs";
import { handleResetAdminPasswordCLI } from "./users.js";

/**
 * SV-AUD-007: the break-glass password must NEVER appear in process argv.
 * It is read, in priority order, from:
 *   1. --password-file <path>   (a 0600 file, preferred for automation)
 *   2. stdin (FD 0)             --password-stdin (first line)
 *   3. the SECRETVAULT_UI_PASSWORD environment variable
 * The legacy --password flag is refused unless --allow-secret-flags is set.
 */
async function readPassword(args: string[]): Promise<string> {
  const allowSecretFlags = args.includes("--allow-secret-flags");

  // --password-file <path>
  const fileIdx = args.indexOf("--password-file");
  if (fileIdx !== -1 && args[fileIdx + 1]) {
    return readFileSync(args[fileIdx + 1]!, "utf8").split(/\r?\n/)[0] ?? "";
  }

  // --password-stdin (read one line from FD 0)
  if (args.includes("--password-stdin")) {
    const raw = readFileSync(0, "utf8");
    return raw.split(/\r?\n/)[0] ?? "";
  }

  // Environment variable
  if (process.env.SECRETVAULT_UI_PASSWORD) {
    return process.env.SECRETVAULT_UI_PASSWORD;
  }

  // Legacy --password <value>: refused unless explicitly acknowledged.
  const pwIdx = args.indexOf("--password");
  if (pwIdx !== -1 && args[pwIdx + 1]) {
    if (!allowSecretFlags) {
      console.error("Security: --password is refused to avoid exposing it in process arguments.");
      console.error("Use --password-file <0600 path>, --password-stdin, or the SECRETVAULT_UI_PASSWORD env var.");
      console.error("Re-run with --allow-secret-flags to acknowledge the risk and keep the legacy behavior.");
      process.exit(1);
    }
    return args[pwIdx + 1]!;
  }

  return "";
}

async function main() {
  const args = process.argv.slice(2);
  let username = "admin";
  let reset2FA = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--username" && args[i + 1]) {
      username = args[i + 1];
      i++;
    } else if (args[i] === "--reset-2fa") {
      reset2FA = true;
    }
    // --password / --password-file / --password-stdin are consumed by readPassword().
  }

  const password = await readPassword(args);

  if (!password) {
    console.error("Usage: node dist/cli.js --username <user> (--password-file <path> | --password-stdin | SECRETVAULT_UI_PASSWORD) [--reset-2fa]");
    process.exit(1);
  }

  const supabaseUrl = process.env.SECRETVAULT_SUPABASE_URL;
  const serviceKey = process.env.SECRETVAULT_SUPABASE_SERVICE_KEY;

  if (!supabaseUrl || !serviceKey) {
    console.error("Error: SECRETVAULT_SUPABASE_URL and SECRETVAULT_SUPABASE_SERVICE_KEY environment variables are required.");
    process.exit(1);
  }

  const supabase = createClient(supabaseUrl, serviceKey, { db: { schema: "secretvault" } });
  const result = await handleResetAdminPasswordCLI(supabase as any, username, password, reset2FA);

  if (result.success) {
    console.log(`[break-glass] ${result.message}`);
    process.exit(0);
  } else {
    console.error(`[break-glass error] ${result.message}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("[break-glass error]", err);
  process.exit(1);
});
