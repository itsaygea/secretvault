/**
 * @secretvault/testing — zero-dependency test harness over node:test.
 *
 * Implements exactly the vitest API surface this repo's suite uses
 * (inventoried 2026-08-16) so the tests run on Node's built-in runner with
 * no vitest/vite/esbuild toolchain in the dependency tree:
 *
 *   describe / it (+ .skip / .only / .each) / beforeAll / afterAll /
 *   beforeEach / afterEach
 *   expect(...): .not, .resolves, .rejects, toBe, toEqual, toStrictEqual,
 *     toMatch, toContain, toHaveLength, toBeNull, toBeUndefined, toBeDefined,
 *     toBeTruthy, toBeFalsy, toBeGreaterThan, toBeLessThan, toThrow,
 *     toMatchObject, toHaveBeenCalled, toHaveBeenCalledWith
 *   expect.any(Type) / expect.anything() / expect.objectContaining(partial)
 *   vi.fn(impl?) (+ .mock.calls / .mockReturnValue / .mockReturnValueOnce /
 *     .mockImplementation / .mockClear) / vi.stubEnv / vi.unstubAllEnvs
 *
 * Anything added here must stay dependency-free: this harness exists to keep
 * the dev toolchain at "only what we must trust" (typescript, tsx, @types).
 */

import {
  before,
  after,
  beforeEach as nodeBeforeEach,
  afterEach as nodeAfterEach,
  describe as nodeDescribe,
  it as nodeIt,
} from "node:test";
import { AssertionError } from "node:assert";

// ---------------------------------------------------------------------------
// Asymmetric matchers
// ---------------------------------------------------------------------------

const ANY = Symbol("sv.any");
const ANYTHING = Symbol("sv.anything");
const OBJECT_CONTAINING = Symbol("sv.objectContaining");
const ARRAY_CONTAINING = Symbol("sv.arrayContaining");
const STRING_MATCHING = Symbol("sv.stringMatching");

class AnyMatcher {
  readonly kind = ANY;
  constructor(readonly ctor: Function) {}
}
class AnythingMatcher {
  readonly kind = ANYTHING;
}
class ObjectContainingMatcher {
  readonly kind = OBJECT_CONTAINING;
  constructor(readonly partial: Record<string, unknown>) {}
}
class ArrayContainingMatcher {
  readonly kind = ARRAY_CONTAINING;
  constructor(readonly items: unknown[]) {}
}
class StringMatchingMatcher {
  readonly kind = STRING_MATCHING;
  constructor(readonly pattern: RegExp | string) {}
}

// ---------------------------------------------------------------------------
// Deep equality (asymmetric-aware)
// ---------------------------------------------------------------------------

type EqualMode = {
  /** subset=true: expected's keys must match; extra actual keys allowed. */
  subset: boolean;
  /** ignoreUndefined=true: own-undefined properties count as absent (vitest toEqual). */
  ignoreUndefined: boolean;
};

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object") return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function keysOf(obj: Record<string, unknown>, mode: EqualMode): string[] {
  const keys = Object.keys(obj);
  return mode.ignoreUndefined
    ? keys.filter((k) => obj[k] !== undefined)
    : keys;
}

function deepEqual(expected: unknown, actual: unknown, mode: EqualMode): boolean {
  // Asymmetric expected nodes.
  if (expected instanceof AnyMatcher) {
    if (expected.ctor === String) return typeof actual === "string";
    if (expected.ctor === Number) return typeof actual === "number" && !Number.isNaN(actual);
    if (expected.ctor === Boolean) return typeof actual === "boolean";
    if (expected.ctor === BigInt) return typeof actual === "bigint";
    if (expected.ctor === Symbol) return typeof actual === "symbol";
    if (expected.ctor === Function) return typeof actual === "function";
    if (expected.ctor === Array) return Array.isArray(actual);
    if (expected.ctor === Object) return isPlainObject(actual);
    return actual instanceof expected.ctor;
  }
  if (expected instanceof AnythingMatcher) return actual !== null && actual !== undefined;
  if (expected instanceof ObjectContainingMatcher) {
    if (!isPlainObject(actual)) return false;
    for (const k of Object.keys(expected.partial)) {
      if (!(k in actual)) return false;
      if (!deepEqual(expected.partial[k], actual[k], { ...mode, subset: true })) return false;
    }
    return true;
  }

  if (expected instanceof ArrayContainingMatcher) {
    if (!Array.isArray(actual)) return false;
    return expected.items.every((item) =>
      actual.some((el) => deepEqual(item, el, { ...mode, subset: false, ignoreUndefined: true })));
  }
  if (expected instanceof StringMatchingMatcher) {
    if (typeof actual !== "string") return false;
    return expected.pattern instanceof RegExp
      ? expected.pattern.test(actual)
      : actual.includes(expected.pattern);
  }

  if (Object.is(expected, actual)) return true;

  if (expected instanceof RegExp || actual instanceof RegExp) return false;
  if (expected instanceof Date || actual instanceof Date) {
    return expected instanceof Date && actual instanceof Date &&
      expected.getTime() === actual.getTime();
  }

  // Plain-object expected vs Error actual (e.g. toMatchObject on a caught
  // SecretVaultError): compare expected's keys against the error's own
  // enumerable properties. Must run before the Error-vs-Error branch below.
  if (isPlainObject(expected) && actual instanceof Error) {
    const a = actual as unknown as Record<string, unknown>;
    for (const k of keysOf(expected, mode)) {
      if (!(k in a)) return false;
      if (!deepEqual(expected[k], a[k], mode)) return false;
    }
    return true;
  }

  if (expected instanceof Error || actual instanceof Error) {
    if (!(expected instanceof Error) || !(actual instanceof Error)) return false;
    return expected.name === actual.name && expected.message === actual.message;
  }

  if (Array.isArray(expected) && Array.isArray(actual)) {
    if (!mode.subset && expected.length !== actual.length) return false;
    if (mode.subset && expected.length !== actual.length) return false;
    return expected.every((e, i) => deepEqual(e, actual[i], mode));
  }

  if (isPlainObject(expected) && isPlainObject(actual)) {
    const eKeys = keysOf(expected, mode);
    for (const k of eKeys) {
      if (!(k in actual)) return false;
      if (!deepEqual(expected[k], actual[k], mode)) return false;
    }
    // Non-subset mode requires no extra (non-undefined) actual keys.
    if (!mode.subset) {
      const aKeys = keysOf(actual, mode);
      if (aKeys.length !== eKeys.length) return false;
    }
    return true;
  }

  if (typeof expected === "number" && typeof actual === "number") {
    // vitest treats NaN equal to NaN in toEqual.
    if (Number.isNaN(expected) && Number.isNaN(actual)) return true;
  }

  return false;
}

function diffOf(expected: unknown, actual: unknown): string {
  try {
    return `\n  expected: ${JSON.stringify(expected)}\n  received: ${JSON.stringify(actual)}`;
  } catch {
    return `\n  expected: ${String(expected)}\n  received: ${String(actual)}`;
  }
}

function fail(message: string, expected: unknown, actual: unknown): never {
  throw new AssertionError({ message, expected, actual });
}

// ---------------------------------------------------------------------------
// expect()
// ---------------------------------------------------------------------------

type Matcher = (...args: unknown[]) => void;

class Expectation {
  constructor(
    private readonly actual: unknown,
    private readonly invert = false,
    private readonly isRejectedPromise = false,
    private readonly hint?: string,
  ) {}

  private run(ok: () => boolean, message: string, expected?: unknown, actual?: unknown): void {
    const passed = ok();
    if (this.invert ? passed : !passed) {
      const prefix = this.hint ? `${this.hint}: ` : "";
      fail(`${prefix}${this.invert ? "NOT expected: " : ""}${message}${diffOf(expected ?? "", actual ?? "")}`, expected, actual);
    }
  }

  private syncActual(): unknown {
    return this.actual;
  }

  get not(): Expectation {
    return new Expectation(this.actual, !this.invert, this.isRejectedPromise, this.hint);
  }

  get resolves(): MatcherSet {
    const actual = this.actual;
    return makeMatchers(Promise.resolve(actual), this.invert);
  }

  get rejects(): MatcherSet {
    const actual = this.actual;
    // Normalize: fulfill with the rejection reason; if the original promise
    // FULFILLS, reject with a clear AssertionError ("resolved instead of
    // rejecting") so the awaiting test fails with the right message.
    return makeMatchers(
      Promise.resolve(actual).then(
        (v) => { throw new AssertionError({ message: `expected rejection but promise resolved with ${String(v)}` }); },
        (e) => e,
      ),
      this.invert,
    );
  }

  // -- identity / primitives -------------------------------------------------
  toBe(expected: unknown): void {
    this.run(() => Object.is(this.syncActual(), expected), `toBe${diffOf(expected, this.syncActual())}`, expected, this.syncActual());
  }
  toEqual(expected: unknown): void {
    const a = this.syncActual();
    this.run(() => deepEqual(expected, a, { subset: false, ignoreUndefined: true }), `toEqual${diffOf(expected, a)}`, expected, a);
  }
  toStrictEqual(expected: unknown): void {
    const a = this.syncActual();
    this.run(() => deepEqual(expected, a, { subset: false, ignoreUndefined: false }), `toStrictEqual${diffOf(expected, a)}`, expected, a);
  }
  toMatchObject(expected: object): void {
    const e = expected as Record<string, unknown>;
    const a = this.syncActual();
    this.run(() => deepEqual(e, a, { subset: true, ignoreUndefined: true }), `toMatchObject${diffOf(e, a)}`, e, a);
  }
  toMatch(expected: RegExp | string): void {
    const a = this.syncActual();
    const ok = () => typeof a === "string" && (expected instanceof RegExp ? expected.test(a) : a.includes(expected));
    this.run(ok, `toMatch ${String(expected)} (received: ${String(a)})`, expected, a);
  }
  toContain(item: unknown): void {
    const a = this.syncActual();
    const ok = () => {
      if (typeof a === "string") return typeof item === "string" && a.includes(item);
      if (Array.isArray(a)) return a.some((el) => Object.is(el, item) || deepEqual(item, el, { subset: false, ignoreUndefined: true }));
      return false;
    };
    this.run(ok, `toContain ${String(item)} (received: ${String(a)})`, item, a);
  }
  toHaveLength(len: number): void {
    const a = this.syncActual() as { length?: number };
    this.run(() => a != null && a.length === len, `toHaveLength ${len} (received: ${a?.length})`, len, a?.length);
  }
  toBeNull(): void {
    this.run(() => this.syncActual() === null, `toBeNull (received: ${String(this.syncActual())})`, null, this.syncActual());
  }
  toBeUndefined(): void {
    this.run(() => this.syncActual() === undefined, `toBeUndefined (received: ${String(this.syncActual())})`, undefined, this.syncActual());
  }
  toBeDefined(): void {
    this.run(() => this.syncActual() !== undefined, `toBeDefined`, undefined, this.syncActual());
  }
  toBeTruthy(): void {
    this.run(() => Boolean(this.syncActual()), `toBeTruthy (received: ${String(this.syncActual())})`);
  }
  toBeFalsy(): void {
    this.run(() => !this.syncActual(), `toBeFalsy (received: ${String(this.syncActual())})`);
  }
  toBeGreaterThan(n: number): void {
    const a = this.syncActual() as number;
    this.run(() => typeof a === "number" && a > n, `toBeGreaterThan ${n} (received: ${a})`, n, a);
  }
  toBeLessThan(n: number): void {
    const a = this.syncActual() as number;
    this.run(() => typeof a === "number" && a < n, `toBeLessThan ${n} (received: ${a})`, n, a);
  }
  toBeGreaterThanOrEqual(n: number): void {
    const a = this.syncActual() as number;
    this.run(() => typeof a === "number" && a >= n, `toBeGreaterThanOrEqual ${n} (received: ${a})`, n, a);
  }
  toBeLessThanOrEqual(n: number): void {
    const a = this.syncActual() as number;
    this.run(() => typeof a === "number" && a <= n, `toBeLessThanOrEqual ${n} (received: ${a})`, n, a);
  }
  toBeInstanceOf(ctor: Function): void {
    const a = this.syncActual();
    this.run(() => a instanceof ctor, `toBeInstanceOf ${ctor.name} (received: ${a?.constructor?.name})`, ctor.name, a?.constructor?.name);
  }

  // -- mock assertions -------------------------------------------------------
  private mockCalls(): unknown[][] | null {
    const a = this.syncActual() as unknown as Record<string, unknown> | null | undefined;
    if (a && typeof a === "function" && "mock" in a) {
      const m = (a as { mock?: { calls?: unknown[] } }).mock;
      if (m && Array.isArray(m.calls)) return m.calls as unknown[][];
    }
    return null;
  }
  toHaveBeenCalled(): void {
    const calls = this.mockCalls();
    this.run(() => !!calls && calls.length > 0, `toHaveBeenCalled (received ${calls?.length ?? 0} calls)`);
  }
  toHaveBeenCalledOnce(): void {
    const calls = this.mockCalls();
    this.run(() => !!calls && calls.length === 1, `toHaveBeenCalledOnce (received ${calls?.length ?? 0} calls)`);
  }
  toHaveBeenCalledWith(...expected: unknown[]): void {
    const calls = this.mockCalls();
    const ok = () => {
      if (!calls) return false;
      return calls.some((call) => {
        if (call.length !== expected.length) return false;
        return expected.every((e, i) => deepEqual(e, call[i], { subset: false, ignoreUndefined: true }));
      });
    };
    this.run(ok, `toHaveBeenCalledWith(${expected.map((e) => String(e)).join(", ")}) (received ${calls?.length ?? 0} calls)`);
  }
  toThrow(expected?: RegExp | string | Function | Error): void {
    const a = this.syncActual();
    let threw: unknown;
    let didThrow = false;
    if (typeof a === "function") {
      try {
        (a as () => unknown)();
      } catch (e) {
        didThrow = true;
        threw = e;
      }
    } else {
      // A non-function "actual" here means we are matching a caught error
      // (e.g. via .rejects) — treat it as the thrown value.
      didThrow = true;
      threw = a;
    }
    const matches = () => {
      if (!didThrow) return false;
      if (expected === undefined) return true;
      const err = threw as Error;
      if (typeof expected === "string") return err?.message?.includes(expected) ?? false;
      if (expected instanceof RegExp) return expected.test(err?.message ?? "");
      if (expected instanceof Error) return err?.message === expected.message;
      return err instanceof (expected as Function);
    };
    this.run(matches, `toThrow ${String(expected)} (received: ${didThrow ? String((threw as Error)?.message ?? threw) : "no error"})`);
  }
}

// Async matcher sets for .resolves / .rejects. The `promise` passed in has
// already been normalized by the getters: it fulfills with the settled value
// (the resolved value for .resolves, the rejection reason for .rejects — the
// getter throws "resolved instead of rejecting" if the original fulfilled).
// Every matcher awaits it, then applies to that value.
type MatcherSet = Record<string, (...args: unknown[]) => Promise<void> | void>;

function makeMatchers(promise: Promise<unknown>, invert: boolean): MatcherSet {
  const apply = (method: string, args: unknown[]) =>
    promise.then((value) => {
      const exp = new Expectation(value, invert);
      (exp as unknown as Record<string, Function>)[method](...args);
    });
  const methods = [
    "toBe", "toEqual", "toStrictEqual", "toMatchObject", "toMatch", "toContain",
    "toHaveLength", "toBeNull", "toBeUndefined", "toBeDefined", "toBeTruthy",
    "toBeFalsy", "toBeGreaterThan", "toBeLessThan", "toBeGreaterThanOrEqual",
    "toBeLessThanOrEqual", "toBeInstanceOf", "toThrow", "toHaveBeenCalled",
    "toHaveBeenCalledOnce", "toHaveBeenCalledWith",
  ];
  const set: MatcherSet = {};
  for (const m of methods) set[m] = (...args: unknown[]) => apply(m, args);
  return set;
}

interface ExpectStatic {
  (actual: unknown, message?: string): Expectation;
  any(ctor: Function): AnyMatcher;
  anything(): AnythingMatcher;
  objectContaining(partial: Record<string, unknown>): ObjectContainingMatcher;
  arrayContaining(items: unknown[]): ArrayContainingMatcher;
  stringMatching(pattern: RegExp | string): StringMatchingMatcher;
}

export const expect = ((actual: unknown, message?: string) =>
  new Expectation(actual, false, false, message)) as ExpectStatic;
expect.any = (ctor: Function) => new AnyMatcher(ctor);
expect.anything = () => new AnythingMatcher();
expect.objectContaining = (partial: Record<string, unknown>) => new ObjectContainingMatcher(partial);
expect.arrayContaining = (items: unknown[]) => new ArrayContainingMatcher(items);
expect.stringMatching = (pattern: RegExp | string) => new StringMatchingMatcher(pattern);

// ---------------------------------------------------------------------------
// vi — the vitest API subset used by this suite
// ---------------------------------------------------------------------------

export type Mock<T extends (...args: any[]) => any> = T & {
  mock: { calls: unknown[][] };
  mockImplementation(fn: T): Mock<T>;
  mockReturnValue(value: ReturnType<T>): Mock<T>;
  mockReturnValueOnce(value: ReturnType<T>): Mock<T>;
  mockClear(): void;
};

export const vi = {
  fn<T extends (...args: any[]) => any>(impl?: T): Mock<T> {
    const calls: unknown[][] = [];
    let implementation: T | undefined = impl;
    const wrapper = ((...args: unknown[]) => {
      calls.push(args);
      return implementation ? (implementation as unknown as (...a: unknown[]) => unknown)(...args) : undefined;
    }) as unknown as Mock<T>;
    wrapper.mock = { calls };
    wrapper.mockImplementation = (fn: T) => {
      implementation = fn;
      return wrapper;
    };
    wrapper.mockReturnValue = (value: ReturnType<T>) => {
      implementation = (() => value) as unknown as T;
      return wrapper;
    };
    wrapper.mockReturnValueOnce = (value: ReturnType<T>) => {
      const prev = implementation;
      let used = false;
      implementation = ((...args: unknown[]) => {
        if (!used) {
          used = true;
          return value;
        }
        return prev ? (prev as unknown as (...a: unknown[]) => unknown)(...args) : undefined;
      }) as unknown as T;
      return wrapper;
    };
    wrapper.mockClear = () => {
      calls.length = 0;
    };
    return wrapper;
  },

  stubEnv(name: string, value: string): void {
    if (!(name in envBackup)) {
      envBackup[name] = { had: name in process.env, orig: process.env[name] };
    }
    process.env[name] = value;
  },

  unstubAllEnvs(): void {
    for (const [name, entry] of Object.entries(envBackup)) {
      if (entry.had) process.env[name] = entry.orig;
      else delete process.env[name];
    }
    for (const k of Object.keys(envBackup)) delete envBackup[k];
  },
};

const envBackup: Record<string, { had: boolean; orig: string | undefined }> = {};

// ---------------------------------------------------------------------------
// Runner — re-export node:test under vitest names (+ .each)
// ---------------------------------------------------------------------------

function formatEachName(template: string, args: unknown[]): string {
  let i = 0;
  return template.replace(/%[sdij]/g, (token) => {
    if (i >= args.length) return token;
    const a = args[i++];
    if (token === "%j") {
      try { return JSON.stringify(a); } catch { return String(a); }
    }
    return String(a);
  });
}

type EachFn = (cases: any[]) => (name: string, fn: (...args: any[]) => unknown) => void;

function makeEach(register: (name: string, fn: (...args: any[]) => unknown) => void): EachFn {
  return (cases: any[]) => (name: string, fn: (...args: any[]) => unknown) => {
    for (const c of cases) {
      const args = Array.isArray(c) ? c : [c];
      register(formatEachName(name, args), () => fn(...args));
    }
  };
}

type TestFn = {
  (name: string, fn?: () => unknown, timeout?: number): void;
  skip: (name: string, fn?: () => unknown, timeout?: number) => void;
  only: (name: string, fn?: () => unknown, timeout?: number) => void;
  each: EachFn;
  skipIf: (condition: boolean) => (name: string, fn?: () => unknown, timeout?: number) => void;
};

function decorate(fn: (name: string, fn?: () => unknown) => void, skip: TestFn["skip"], only: TestFn["only"]): TestFn {
  const t = fn as TestFn;
  t.skip = skip;
  t.only = only;
  t.each = makeEach((name, f) => fn(name, f));
  t.skipIf = (condition: boolean) => (condition ? skip : fn);
  return t;
}

/** Adapt a `() => unknown` callback to node:test's `() => void | Promise<void>`. */
const asNodeHook = (fn: () => unknown): (() => void | Promise<void>) =>
  () => fn() as void;

/** Register a vitest-style it: supports the optional (name, fn, timeoutMs) form. */
function registerTest(
  target: (name: string, fn: () => void | Promise<void>) => void,
  name: string,
  fn?: () => unknown,
  timeout?: number,
): void {
  if (fn && typeof timeout === "number") {
    // node:test per-test timeout — vitest's third argument.
    nodeIt(name, { timeout }, asNodeHook(fn));
  } else if (fn) {
    target(name, asNodeHook(fn));
  } else {
    target(name, () => {});
  }
}

export const it = decorate(
  (name: string, fn?: () => unknown, timeout?: number) => registerTest((n, f) => nodeIt(n, f), name, fn, timeout),
  (name: string, fn?: () => unknown, timeout?: number) => registerTest((n, f) => nodeIt.skip(n, f), name, fn, timeout),
  (name: string, fn?: () => unknown, timeout?: number) => registerTest((n, f) => nodeIt.only(n, f), name, fn, timeout),
);
export { it as test };

type DescribeFn = {
  (name: string, fn?: () => void): void;
  skip(name: string, fn?: () => void): void;
  only(name: string, fn?: () => void): void;
  skipIf(condition: boolean): (name: string, fn?: () => void) => void;
  each: EachFn;
};

export const describe = (() => {
  const d = ((name: string, fn?: () => void) => { nodeDescribe(name, asNodeHook(fn ?? (() => {}))); }) as DescribeFn;
  d.skip = (name: string, fn?: () => void) => { nodeDescribe.skip(name, asNodeHook(fn ?? (() => {}))); };
  d.only = (name: string, fn?: () => void) => { nodeDescribe.only(name, asNodeHook(fn ?? (() => {}))); };
  d.skipIf = (condition: boolean) => (condition ? d.skip : d) as (name: string, fn?: () => void) => void;
  d.each = makeEach((name, f) => { nodeDescribe(name, asNodeHook(f)); });
  return d;
})();

export const beforeAll = (fn: () => unknown) => { before(asNodeHook(fn)); };
export const afterAll = (fn: () => unknown) => { after(asNodeHook(fn)); };
export const beforeEach = (fn: () => unknown) => { nodeBeforeEach(asNodeHook(fn)); };
export const afterEach = (fn: () => unknown) => { nodeAfterEach(asNodeHook(fn)); };
