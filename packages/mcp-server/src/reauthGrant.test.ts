import { beforeEach, describe, expect, it } from "vitest";
import {
  consumeReauthGrant,
  generateReauthGrant,
  generateStepUpToken,
  initStepUpAuth,
  verifyReauthGrant,
  verifyStepUpToken,
  _resetReauthGrantStateForTests,
} from "./stepup.js";

const MASTER = Buffer.alloc(32, "f");
const USER = "user-victim";

beforeEach(() => {
  initStepUpAuth(MASTER);
  _resetReauthGrantStateForTests();
});

describe("SV-AUD-002 — purpose-bound reauth grants", () => {
  it("a grant verifies only for its exact operation", () => {
    const { grant } = generateReauthGrant(USER, "totp:add");
    expect(verifyReauthGrant(grant, USER, "totp:add")).toBe(true);
    // Wrong operation — must fail. This is the core PoC block: a grant for one
    // operation cannot authorise another.
    expect(verifyReauthGrant(grant, USER, "totp:replace")).toBe(false);
    expect(verifyReauthGrant(grant, USER, "totp:disable")).toBe(false);
    expect(verifyReauthGrant(grant, USER, "webauthn:add")).toBe(false);
  });

  it("a grant is bound to the issuing user", () => {
    const { grant } = generateReauthGrant(USER, "totp:add");
    expect(verifyReauthGrant(grant, "attacker", "totp:add")).toBe(false);
  });

  it("a webauthn:delete grant is bound to the exact credential id", () => {
    const { grant } = generateReauthGrant(USER, "webauthn:delete:cred-abc");
    expect(verifyReauthGrant(grant, USER, "webauthn:delete:cred-abc")).toBe(true);
    expect(verifyReauthGrant(grant, USER, "webauthn:delete:cred-xyz")).toBe(false);
    expect(verifyReauthGrant(grant, USER, "webauthn:delete")).toBe(false);
  });

  it("a grant is single-use: the second consume fails", () => {
    const { grant } = generateReauthGrant(USER, "totp:replace");
    expect(consumeReauthGrant(grant, USER, "totp:replace")).toBe(true);
    expect(consumeReauthGrant(grant, USER, "totp:replace")).toBe(false);
  });

  it("a tampered grant is rejected", () => {
    const { grant } = generateReauthGrant(USER, "totp:disable");
    const tampered = grant.slice(0, -4) + "0000";
    expect(verifyReauthGrant(tampered, USER, "totp:disable")).toBe(false);
  });

  it("a reveal step-up token is NOT accepted as a factor-management grant", () => {
    // SV-AUD-002 explicit requirement: a general reveal step-up must never serve
    // as a factor-management grant.
    const { stepUpToken } = generateStepUpToken(USER, "client-1");
    // The step-up token is valid for reveal...
    expect(verifyStepUpToken(stepUpToken, USER)).toBe(true);
    // ...but must not verify as any reauth grant.
    expect(consumeReauthGrant(stepUpToken, USER, "totp:add")).toBe(false);
    expect(consumeReauthGrant(stepUpToken, USER, "totp:replace")).toBe(false);
    expect(consumeReauthGrant(stepUpToken, USER, "totp:disable")).toBe(false);
    expect(consumeReauthGrant(stepUpToken, USER, "webauthn:add")).toBe(false);
  });

  it("an absent grant is rejected (session alone is insufficient)", () => {
    // This is the headline PoC block: a request with no x-secretvault-reauth
    // header carries no grant token at all.
    expect(consumeReauthGrant("", USER, "totp:add")).toBe(false);
    expect(consumeReauthGrant(undefined as unknown as string, USER, "totp:add")).toBe(false);
  });

  it("garbage that is not a reauth token is rejected", () => {
    expect(consumeReauthGrant("not-a-token", USER, "totp:add")).toBe(false);
    expect(consumeReauthGrant("stepup.user.x.y.z", USER, "totp:add")).toBe(false);
  });
});
