import { describe, expect, it, afterEach } from "vitest";
import { PassThrough } from "node:stream";
import { destroyProxyAgents } from "./proxy.js";

describe("proxy keep-alive agents", () => {
  afterEach(() => {
    destroyProxyAgents();
  });

  it("exports destroyProxyAgents without error", () => {
    expect(typeof destroyProxyAgents).toBe("function");
    expect(() => destroyProxyAgents()).not.toThrow();
  });

  it("destroyProxyAgents is safe to call multiple times", () => {
    destroyProxyAgents();
    destroyProxyAgents();
  });
});

describe("proxy body streaming primitives", () => {
  it("PassThrough correctly sequences pipeline writes", async () => {
    const pt = new PassThrough({ highWaterMark: 65536 });
    const chunks: Buffer[] = [];
    pt.on("data", (c: Buffer) => chunks.push(c));

    pt.write(Buffer.from("chunk1"));
    pt.write(Buffer.from("chunk2"));
    pt.end();

    await new Promise<void>(resolve => pt.on("end", resolve));
    expect(Buffer.concat(chunks).toString()).toBe("chunk1chunk2");
  });

  it("PassThrough highWaterMark signals backpressure for large writes", () => {
    const pt = new PassThrough({ highWaterMark: 1024 });
    const large = Buffer.alloc(2048);
    expect(pt.write(large)).toBe(false);
    pt.destroy();
  });
});
