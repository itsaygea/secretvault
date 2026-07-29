import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import expectedManagementPaths from "../../../scripts/openapi-paths.json";

const openApi = JSON.parse(readFileSync(resolve(process.cwd(), "docs/openapi.json"), "utf8")) as {
  openapi: string;
  paths: Record<string, Record<string, { responses?: Record<string, { $ref?: string }> }>>;
  components: { schemas: Record<string, unknown> };
};

const managementPaths = expectedManagementPaths as string[];

describe("OpenAPI 3.1 contract", () => {
  it("is valid JSON with every management route represented", () => {
    expect(openApi.openapi).toBe("3.1.0");
    expect(openApi.components.schemas.ErrorEnvelope).toBeDefined();
    for (const path of managementPaths) {
      expect(openApi.paths[path], path).toBeDefined();
      for (const operation of Object.values(openApi.paths[path])) {
        if (!operation.responses) continue;
        expect(operation.responses.default?.$ref, path).toBe("#/components/responses/Error");
      }
    }
    expect(Object.keys(openApi.paths).some((path) => path.startsWith("/api/"))).toBe(false);
  });
});
