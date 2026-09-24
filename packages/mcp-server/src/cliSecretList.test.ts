import { describe, expect, it } from "@secretvault/testing";
import { handleSecretCli } from "./cli/secret.js";

describe("secret CLI list", () => {
  it("renders secrets from the current v1 data envelope", async () => {
    const originalArgv = process.argv;
    const originalUrl = process.env.SECRETVAULT_URL;
    const originalClientKey = process.env.SECRETVAULT_CLIENT_KEY;
    const originalFetch = globalThis.fetch;
    const originalLog = console.log;
    const originalError = console.error;
    const output: string[] = [];

    process.argv = ["node", "secretvault", "list"];
    process.env.SECRETVAULT_URL = "https://vault.example.com";
    process.env.SECRETVAULT_CLIENT_KEY = "example-client-key";
    globalThis.fetch = async () => new Response(JSON.stringify({
      data: [{
        name: "EXAMPLE_API_KEY",
        display_name: "Example API Key",
        environment: "production",
        masked_preview: "EXAMPLE-****1234",
        tags: ["demo"],
      }],
    }), { status: 200, headers: { "Content-Type": "application/json" } });
    console.log = (...args: unknown[]) => output.push(args.map(String).join(" "));
    console.error = (...args: unknown[]) => output.push(args.map(String).join(" "));

    try {
      await handleSecretCli();
    } finally {
      process.argv = originalArgv;
      if (originalUrl === undefined) delete process.env.SECRETVAULT_URL;
      else process.env.SECRETVAULT_URL = originalUrl;
      if (originalClientKey === undefined) delete process.env.SECRETVAULT_CLIENT_KEY;
      else process.env.SECRETVAULT_CLIENT_KEY = originalClientKey;
      globalThis.fetch = originalFetch;
      console.log = originalLog;
      console.error = originalError;
    }

    expect(output.join("\n")).toContain("EXAMPLE_API_KEY");
    expect(output.join("\n")).toContain("EXAMPLE-****1234");
    expect(output.join("\n")).toContain("Total: 1 secret(s)");
  });
});
