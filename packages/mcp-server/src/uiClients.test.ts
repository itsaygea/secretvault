import { describe, expect, it } from "@secretvault/testing";

type FakeElement = {
  innerHTML: string;
  innerText: string;
  textContent: string;
  value: string;
  disabled: boolean;
  setAttribute: (name: string, value: string) => void;
  querySelectorAll: () => FakeElement[];
};

function element(): FakeElement {
  return {
    innerHTML: "",
    innerText: "",
    textContent: "",
    value: "",
    disabled: false,
    setAttribute: () => undefined,
    querySelectorAll: () => [],
  };
}

const elements = new Map<string, FakeElement>([
  ["clients-table-body", element()],
  ["search-clients", element()],
  ["clients-page-status", element()],
  ["previous-clients-page", element()],
  ["next-clients-page", element()],
]);

// The UI modules are browser modules. These small globals are enough to drive
// the real client-list renderer without adding a DOM dependency to the server.
(globalThis as any).localStorage = { getItem: () => null };
(globalThis as any).window = { location: { protocol: "https:", host: "vault.example.com" } };
(globalThis as any).document = {
  getElementById: (id: string) => elements.get(id) ?? null,
  querySelector: (selector: string) => {
    if (selector.includes("previous-clients-page")) return elements.get("previous-clients-page");
    if (selector.includes("next-clients-page")) return elements.get("next-clients-page");
    return null;
  },
};

// @ts-expect-error The browser UI is intentionally plain JavaScript and has no
// generated TypeScript declaration surface.
const { loadClients } = await import("../ui/js/features/clients.js");

describe("Web UI client list", () => {
  it("renders existing client rows with a reveal action", async () => {
    const tbody = elements.get("clients-table-body")!;
    tbody.innerHTML = "";
    (globalThis as any).fetch = async () => new Response(JSON.stringify({
      data: [{
        id: "client-1",
        app_name: "Example Agent",
        key_prefix: "sv_1234567890abcdef",
        scopes: ["proxy:example-service"],
        last_used_at: null,
        created_at: "2026-01-01T00:00:00.000Z",
      }],
      next_cursor: null,
    }), { status: 200, headers: { "Content-Type": "application/json" } });

    await loadClients();

    expect(tbody.innerHTML).toContain("Example Agent");
    expect(tbody.innerHTML).toContain("sv_1234567890abcdef...");
    expect(tbody.innerHTML).toContain('data-action="reveal-client-key"');
  });
});
