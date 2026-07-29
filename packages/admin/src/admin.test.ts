import { describe, expect, it, vi } from "vitest";
import { SecretVaultAdmin } from "./index.js";

const key = "sv_testkey12345678901234567890123456789012345678901234";

describe("SecretVaultAdmin", () => {
  it("uses the versioned management seam and does not expose proxy helpers", async () => {
    const fetcher = vi.fn(async (url: RequestInfo | URL) => {
      expect(String(url)).toBe("https://vault.example/v1/me");
      return new Response(JSON.stringify({ id: "u1", username: "admin", is_admin: true }), { status: 200 });
    });
    const admin = new SecretVaultAdmin({ baseUrl: "https://vault.example", clientKey: key, fetch: fetcher });

    await expect(admin.me()).resolves.toMatchObject({ username: "admin" });
    expect((admin as unknown as Record<string, unknown>).proxy).toBeUndefined();
    expect((admin as unknown as Record<string, unknown>).injectEnv).toBeUndefined();
  });

  it("supports authentication via sessionToken and static login method", async () => {
    const fetcher = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = String(url);
      if (urlStr.includes("/v1/auth/login")) {
        expect(init?.method).toBe("POST");
        return new Response(JSON.stringify({ token: "session_token_12345678901234567890" }), { status: 200 });
      }
      if (urlStr.includes("/v1/users")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("Authorization")).toBe("Bearer session_token_12345678901234567890");
        return new Response(JSON.stringify([{ id: "u1", username: "admin", is_admin: true }]), { status: 200 });
      }
      return new Response("{}", { status: 404 });
    });

    const admin = await SecretVaultAdmin.login(
      { baseUrl: "https://vault.example", fetch: fetcher },
      { username: "admin", password: "secretpassword" },
    );

    const users = await admin.listUsers();
    expect(users).toHaveLength(1);
    expect(users[0]?.username).toBe("admin");
  });

  it("passes caller abort and timeout options to the shared transport", async () => {
    const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      return new Response("[]", { status: 200 });
    });
    const admin = new SecretVaultAdmin({ baseUrl: "https://vault.example", clientKey: key, fetch: fetcher });
    const controller = new AbortController();

    await admin.listSecrets({ signal: controller.signal, timeoutMs: 1000 });
    expect(fetcher).toHaveBeenCalledOnce();
  });
});
