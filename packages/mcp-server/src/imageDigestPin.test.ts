import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "@secretvault/testing";

const root = resolve(import.meta.dirname, "..", "..", "..");

// SV-AUD-012: every external base image must be pinned to an immutable digest,
// not a mutable tag. A tag can be retagged; a digest pins exact bytes.
const BASE_IMAGES = [
  "node:22-alpine",
  "postgres:16-alpine",
  "postgrest/postgrest:v12.2.3",
  "nginx:1.27-alpine",
  "caddy:2-alpine",
];

const composeFiles = readdirSync(root)
  .filter((f) => /^docker-compose.*\.yml$/.test(f))
  .map((f) => ({ name: f, text: readFileSync(resolve(root, f), "utf8") }));

const dockerfile = readFileSync(resolve(root, "Dockerfile"), "utf8");

describe("container images are digest-pinned (SV-AUD-012)", () => {
  it("Dockerfile pins every base image it references to a sha256 digest", () => {
    for (const img of BASE_IMAGES) {
      const re = new RegExp(img.replace(/([:.])/g, "\\$1"));
      if (!re.test(dockerfile)) continue; // Dockerfile only uses node:22-alpine
      const pinned = new RegExp(img.replace(/([:.])/g, "\\$1") + "@sha256:[0-9a-f]{64}");
      expect(dockerfile, `${img} in Dockerfile must be @sha256-pinned`).toMatch(pinned);
    }
  });

  it.each(composeFiles.filter((c) => c.name !== "docker-compose.dist.yml"))(
    "$name pins every base image it references to a sha256 digest",
    ({ text }) => {
      for (const img of BASE_IMAGES) {
        const re = new RegExp(img.replace(/([:.])/g, "\\$1"));
        if (!re.test(text)) continue; // this compose file doesn't use this image
        const pinned = new RegExp(img.replace(/([:.])/g, "\\$1") + "@sha256:[0-9a-f]{64}");
        expect(text, `${img} in this compose file must be @sha256-pinned`).toMatch(pinned);
      }
    },
  );

  it("docker-compose.dist.yml requires a digest (refuses tag-only pulls)", () => {
    const dist = readFileSync(resolve(root, "docker-compose.dist.yml"), "utf8");
    // SECRETVAULT_DIGEST must be required, not optional (no :+ optional expansion).
    expect(dist).toMatch(/SECRETVAULT_DIGEST:\?SECRETVAULT_DIGEST must be set/);
    // No remaining optional `${SECRETVAULT_DIGEST:+...}` expansion.
    expect(dist).not.toMatch(/SECRETVAULT_DIGEST:\+\+/);
  });
});
