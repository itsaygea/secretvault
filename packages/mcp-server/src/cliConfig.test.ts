import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { writeSafeJsonConfig, writeSafeTomlConfig } from "./cli/setup.js";

describe("CLI Tool Config Atomic Safe Writes", () => {
  it("creates config file with mode 0600 and pre-modification backup", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sv-config-test-"));
    const configPath = path.join(tmpDir, "test_config.json");

    // Write initial config
    await writeSafeJsonConfig(configPath, (curr) => {
      curr.mcpServers = { initial: { command: "test" } };
      return curr;
    });

    expect(fs.existsSync(configPath)).toBe(true);
    const content1 = JSON.parse(fs.readFileSync(configPath, "utf8"));
    expect(content1.mcpServers.initial.command).toBe("test");

    const stats1 = fs.statSync(configPath);
    // mode 0600 on POSIX (mask with 0777)
    if (os.platform() !== "win32") {
      expect(stats1.mode & 0o777).toBe(0o600);
    }

    // Update config
    await writeSafeJsonConfig(configPath, (curr) => {
      curr.mcpServers.secretvault = { command: "npx" };
      return curr;
    });

    const content2 = JSON.parse(fs.readFileSync(configPath, "utf8"));
    expect(content2.mcpServers.initial.command).toBe("test");
    expect(content2.mcpServers.secretvault.command).toBe("npx");

    // Verify pre-modification backup was created
    const files = fs.readdirSync(tmpDir);
    const backups = files.filter(f => f.includes(".bak."));
    expect(backups.length).toBeGreaterThanOrEqual(1);

    // Clean up
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("preserves corrupt JSON files as .corrupt backup without crashing", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sv-config-corrupt-"));
    const configPath = path.join(tmpDir, "corrupt_config.json");

    // Write invalid JSON
    fs.writeFileSync(configPath, "{ invalid json content ... ");

    await writeSafeJsonConfig(configPath, (curr) => {
      curr.mcpServers = { secretvault: { command: "npx" } };
      return curr;
    });

    const content = JSON.parse(fs.readFileSync(configPath, "utf8"));
    expect(content.mcpServers.secretvault.command).toBe("npx");

    // Verify .corrupt backup exists
    const files = fs.readdirSync(tmpDir);
    const corruptBackups = files.filter(f => f.includes(".corrupt."));
    expect(corruptBackups.length).toBe(1);

    // Clean up
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("creates and updates TOML config for Codex with mode 0600", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sv-toml-test-"));
    const configPath = path.join(tmpDir, "config.toml");

    const spec = {
      command: "npx",
      args: ["-y", "mcp-remote", "http://localhost:3004/mcp", "--header", "Authorization: Bearer sv_test", "--allow-http"],
    };

    await writeSafeTomlConfig(configPath, "secretvault", spec);

    expect(fs.existsSync(configPath)).toBe(true);
    const tomlContent = fs.readFileSync(configPath, "utf8");
    expect(tomlContent).toContain("[mcp_servers.secretvault]");
    expect(tomlContent).toContain('command = "npx"');
    expect(tomlContent).toContain('"Authorization: Bearer sv_test"');

    const stats = fs.statSync(configPath);
    if (os.platform() !== "win32") {
      expect(stats.mode & 0o777).toBe(0o600);
    }

    // Test update existing TOML
    const updatedSpec = {
      command: "npx",
      args: ["-y", "mcp-remote", "http://localhost:3004/mcp", "--header", "Authorization: Bearer sv_updated", "--allow-http"],
    };
    await writeSafeTomlConfig(configPath, "secretvault", updatedSpec);

    const updatedToml = fs.readFileSync(configPath, "utf8");
    expect(updatedToml).toContain('"Authorization: Bearer sv_updated"');
    expect(updatedToml).not.toContain('"Authorization: Bearer sv_test"');

    // Clean up
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

