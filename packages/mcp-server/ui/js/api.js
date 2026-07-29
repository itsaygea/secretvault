import { getState, setState } from "./state.js";

let activeToken = () => getState().activeToken;

export function setActiveToken(token) {
  setState({ activeToken: token });
}

export function getActiveToken() {
  return getState().activeToken;
}

export function authHeaders(extra = {}) {
  return { ...extra, Authorization: `Bearer ${getActiveToken()}` };
}

function generateRequestId() {
  return `sv-req-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

const inflightRequests = new Map();

export async function apiFetch(path, options = {}) {
  const {
    method = "GET",
    body,
    timeoutMs = 15000,
    resourceKey,
    suppress401 = false,
    stepUp = false,
  } = options;

  const requestId = generateRequestId();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  if (resourceKey) {
    const existing = inflightRequests.get(resourceKey);
    if (existing) existing.abort();
    inflightRequests.set(resourceKey, controller);
  }

  const headers = authHeaders({ "X-Request-Id": requestId });
  if (body) headers["Content-Type"] = "application/json";

  try {
    const response = await fetch(path, {
      method,
      headers: stepUp
        ? { ...headers, "X-SecretVault-StepUp": getState().stepUpToken }
        : headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (response.status === 401 && !suppress401) {
      const { logout } = await import("./auth.js");
      logout();
      return { data: null, error: { message: "Session expired" }, status: 401, requestId };
    }

    let data;
    try {
      data = await response.json();
    } catch {
      return { data: null, error: { message: "Unexpected server response" }, status: response.status, requestId };
    }

    const serverRequestId = data?.requestId || data?.request_id || response.headers.get("X-Request-Id");

    if (!response.ok) {
      const msg = typeof data?.error === "string" ? data.error
        : typeof data?.error?.message === "string" ? data.error.message
        : data?.error?.code || `Server error (${response.status})`;
      return {
        data: null,
        error: { message: msg, code: data?.error?.code, status: response.status },
        status: response.status,
        requestId: serverRequestId || requestId,
      };
    }

    return { data, error: null, status: response.status, requestId: serverRequestId || requestId };
  } catch (err) {
    clearTimeout(timeoutId);
    const msg = err?.name === "AbortError" ? "Request timed out" : "Network error";
    return { data: null, error: { message: msg }, status: 0, requestId };
  } finally {
    if (resourceKey && inflightRequests.get(resourceKey) === controller) {
      inflightRequests.delete(resourceKey);
    }
  }
}

export function apiGet(path, opts = {}) {
  return apiFetch(path, { ...opts, method: "GET" });
}

export function apiPost(path, body, opts = {}) {
  return apiFetch(path, { ...opts, method: "POST", body });
}

export function apiPatch(path, body, opts = {}) {
  return apiFetch(path, { ...opts, method: "PATCH", body });
}

export function apiDelete(path, opts = {}) {
  return apiFetch(path, { ...opts, method: "DELETE" });
}

export function apiPostStepUp(path, body, opts = {}) {
  return apiFetch(path, { ...opts, method: "POST", body, stepUp: true });
}

const mutationLocks = new Map();

export async function withMutationGuard(opKey, fn) {
  if (mutationLocks.get(opKey)) {
    return { data: null, error: { message: "Already in progress" }, status: 0, requestId: "" };
  }
  mutationLocks.set(opKey, true);
  try {
    return await fn();
  } finally {
    mutationLocks.delete(opKey);
  }
}

export function isMutationLocked(opKey) {
  return mutationLocks.has(opKey);
}
