import { spawn } from "node:child_process";
import http from "node:http";
import https from "node:https";

export async function handleRunCli(): Promise<void> {
  const args = process.argv.slice(3);

  let secretName = "";
  const vaultUrl = process.env.SECRETVAULT_URL || "http://localhost:3004";
  const clientKey = process.env.SECRETVAULT_CLIENT_KEY || "";

  const separatorIdx = args.indexOf("--");
  const optionsArgs = separatorIdx !== -1 ? args.slice(0, separatorIdx) : args;
  const cmdArgs = separatorIdx !== -1 ? args.slice(separatorIdx + 1) : [];

  for (let i = 0; i < optionsArgs.length; i++) {
    if (optionsArgs[i] === "--secret" && optionsArgs[i + 1]) {
      secretName = optionsArgs[i + 1];
      i++;
    }
  }

  if (!secretName) {
    console.error("[secretvault] Error: --secret <NAME> is required");
    process.exit(1);
  }

  if (!clientKey) {
    console.error("[secretvault] Error: SECRETVAULT_CLIENT_KEY env var is required");
    process.exit(1);
  }

  if (cmdArgs.length === 0) {
    console.error("[secretvault] Error: No command provided after '--'");
    process.exit(1);
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

    const env = { ...process.env, [secretName]: secretValue };
    const finalCmdArgs = cmdArgs.map(arg => arg.replace(`$${secretName}`, secretValue).replace(`%${secretName}%`, secretValue));

    const child = spawn(finalCmdArgs[0], finalCmdArgs.slice(1), {
      stdio: "inherit",
      env,
    });

    child.on("exit", (code) => process.exit(code ?? 0));
  } catch (err: any) {
    console.error(`[secretvault] Failed to resolve secret '${secretName}': ${err.message || err}`);
    process.exit(1);
  }
}
