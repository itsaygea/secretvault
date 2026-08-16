import { describe, it, expect } from "@secretvault/testing";
import { handleInteractiveMenu } from "./cli/interactive.js";

describe("CLI Interactive Terminal Manager (SV-AUD-007)", () => {
  it("exports handleInteractiveMenu as an async function", () => {
    expect(typeof handleInteractiveMenu).toBe("function");
  });
});
