import { spawn } from "node:child_process";
import { loadClientCredentials } from "./credentialStore.js";

export async function handleUpdateCli(): Promise<void> {
  console.log("\x1b[1;36m");
  console.log("════════════════════════════════════════════════════════════════════════");
  console.log("       ⚡ SecretVault CLI Auto-Updater                                  ");
  console.log("════════════════════════════════════════════════════════════════════════");
  console.log("\x1b[0m");

  const stored = loadClientCredentials();
  if (stored?.url) {
    console.log(`Connected Vault: \x1b[32m${stored.url}\x1b[0m`);
  }
  if (stored?.clientKey) {
    console.log(`Preserving Key:  \x1b[32m${stored.clientKey.substring(0, 8)}...\x1b[0m`);
  }

  console.log("\n\x1b[36mFetching and installing latest SecretVault CLI executables...\x1b[0m\n");

  await new Promise<void>((resolve) => {
    const updateCmd = "curl -fsSL https://raw.githubusercontent.com/itsaygea/secretvault/main/install-client.sh | bash";
    const child = spawn("sh", ["-c", updateCmd], {
      stdio: "inherit",
      env: {
        ...process.env,
        // Non-interactive mode flag so installer uses existing credentials automatically
        SECRETVAULT_NON_INTERACTIVE: "1",
      },
    });

    child.on("exit", (code) => {
      if (code === 0) {
        console.log("\n\x1b[1;32m========================================================================\x1b[0m");
        console.log("\x1b[1;32m       🎉 SECRETVAULT CLI UPDATED SUCCESSFULLY                          \x1b[0m");
        console.log("\x1b[1;32m========================================================================\x1b[0m\n");
      } else {
        console.error(`\n\x1b[1;31mUpdate failed with exit code ${code ?? 1}\x1b[0m\n`);
        process.exitCode = code ?? 1;
      }
      resolve();
    });

    child.on("error", (err) => {
      console.error(`\x1b[1;31mFailed to start updater process: ${err.message}\x1b[0m\n`);
      process.exitCode = 1;
      resolve();
    });
  });
}
