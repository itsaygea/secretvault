import { spawn } from "node:child_process";
import http from "node:http";
import https from "node:https";

import { loadClientCredentials } from "./cli/credentialStore.js";

/**
 * SV-AUD-007: decide the child's environment and argv given a resolved secret.
 *
 * By default the secret is injected ONLY into the child environment and the
 * command arguments are passed through verbatim — never substituted. The legacy
 * `$SECRET` / `%SECRET%` substitution (which leaked the value into argv) is opt-
 * in via `allowArgSubstitution`. Pure and exported so the no-leak property can
 * be unit-tested deterministically.
 */
export function buildChildSpawn(
  secretName: string,
  secretValue: string,
  cmdArgs: string[],
  allowArgSubstitution: boolean,
): { env: NodeJS.ProcessEnv; argv: string[] } {
  const env: NodeJS.ProcessEnv = { ...process.env, [secretName]: secretValue };
  const argv = allowArgSubstitution
    ? cmdArgs.map(arg => arg.replace(`$${secretName}`, secretValue).replace(`%${secretName}%`, secretValue))
    : cmdArgs;
  return { env, argv };
}

/**
 * SV-AUD-007: secrets are NEVER injected into the child's command-line
 * arguments. Argument substitution (`$SECRET` / `%SECRET%`) leaked the raw
 * value into `/proc/<pid>/cmdline`, `ps`, crash reports, and shell history.
 *
 * Secrets now reach the child only through its environment (and inherited file
 * descriptors). The legacy substitution is gated behind an explicit, loudly-
 * warned `--allow-arg-substitution` opt-in so existing scripts that genuinely
 * require it can keep working, while the safe default never reconstructs a
 * secret-bearing argv.
 */
export async function handleRunCli(): Promise<void> {
  const args = process.argv.slice(3);

  let secretName = "";
  let allowArgSubstitution = false;

  const stored = loadClientCredentials();
  const vaultUrl = process.env.SECRETVAULT_URL || stored?.url || "http://localhost:3004";
  const clientKey = process.env.SECRETVAULT_CLIENT_KEY || stored?.clientKey || "";

  const separatorIdx = args.indexOf("--");
  const optionsArgs = separatorIdx !== -1 ? args.slice(0, separatorIdx) : args;
  const cmdArgs = separatorIdx !== -1 ? args.slice(separatorIdx + 1) : [];

  for (let i = 0; i < optionsArgs.length; i++) {
    if (optionsArgs[i] === "--secret" && optionsArgs[i + 1]) {
      secretName = optionsArgs[i + 1];
      i++;
    } else if (optionsArgs[i] === "--allow-arg-substitution") {
      allowArgSubstitution = true;
    }
  }

  if (!secretName) {
    console.error("[secretvault] Error: --secret <NAME> is required");
    process.exit(1);
  }

  if (!clientKey) {
    console.error("[secretvault] Error: SECRETVAULT_CLIENT_KEY environment variable or stored credential is required");
    process.exit(1);
  }

  if (cmdArgs.length === 0) {
    console.error("[secretvault] Error: No command provided after '--'");
    process.exit(1);
  }

  if (allowArgSubstitution) {
    console.error(
      "[secretvault] WARNING: --allow-arg-substitution places the resolved secret into the child's " +
      "command-line arguments, where it is visible via /proc/<pid>/cmdline and ps. Use environment-variable " +
      "or inherited-FD injection instead. This compatibility flag may be removed in a future release.",
    );
  }

  try {
    const targetUrl = new URL(`${vaultUrl.replace(/\/$/, "")}/v1/client/secrets/${encodeURIComponent(secretName)}`);
    const reqFn = targetUrl.protocol === "https:" ? https.request : http.request;

    const secretValue = await new Promise<string>((resolve, reject) => {
      const req = reqFn(targetUrl, {
        method: "GET",
        headers: { "Authorization": `Bearer ${clientKey}` },
      }, (res) => {
        let body = "";
        res.on("data", chunk => body += chunk);
        res.on("end", () => {
          try {
            const data = JSON.parse(body);
            if (data.value !== undefined) {
              resolve(data.value);
            } else {
              const errMsg = typeof data.error === "object" ? (data.error?.message || JSON.stringify(data.error)) : (data.error || data.message || "Secret resolution failed");
              reject(new Error(errMsg));
            }
          } catch (e) {
            reject(e);
          }
        });
      });
      req.on("error", reject);
      req.end();
    });

    // SV-AUD-007: inject the secret only into the child environment, never argv.
    // Legacy argument substitution is opt-in only.
    const { env, argv } = buildChildSpawn(secretName, secretValue, cmdArgs, allowArgSubstitution);

    const child = spawn(argv[0], argv.slice(1), {
      stdio: "inherit",
      env,
    });

    child.on("exit", (code) => process.exit(code ?? 0));
  } catch (err: any) {
    // Value-free error: never echo the secret.
    console.error(`[secretvault] Failed to resolve secret '${secretName}'.`);
    process.exit(1);
  }
}
