#!/usr/bin/env node
import { createClient } from "@supabase/supabase-js";
import { handleResetAdminPasswordCLI } from "./users.js";

async function main() {
  const args = process.argv.slice(2);
  let username = "admin";
  let password = "";
  let reset2FA = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--username" && args[i + 1]) {
      username = args[i + 1];
      i++;
    } else if (args[i] === "--password" && args[i + 1]) {
      password = args[i + 1];
      i++;
    } else if (args[i] === "--reset-2fa") {
      reset2FA = true;
    }
  }

  if (!password) {
    console.error("Usage: node dist/cli.js --username <user> --password <newPassword> [--reset-2fa]");
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
