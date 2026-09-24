const SERVICE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/;

function emptyPreview(message = "") {
  return {
    valid: false,
    targetOrigin: "—",
    proxyUrl: "—",
    message,
  };
}

/**
 * Split a provider URL into the origin stored by a Service Profile and the
 * path a client must append to SecretVault's proxy route.
 *
 * The proxy resolves request paths against the configured upstream origin, so
 * a URL such as https://api.example.com/v1/chat/completions becomes:
 *   profile target: https://api.example.com
 *   proxy URL:      <vault>/proxy/example/v1/chat/completions
 */
export function buildProfileRoutePreview(upstreamValue, serviceName, vaultOrigin) {
  const rawTarget = String(upstreamValue ?? "").trim();
  const rawService = String(serviceName ?? "").trim();

  if (!rawTarget || !rawService) {
    return emptyPreview("Enter a service name and upstream URL to preview the proxy route.");
  }

  if (!SERVICE_NAME_PATTERN.test(rawService)) {
    return emptyPreview("Use a service name with letters, numbers, dots, underscores, hyphens, or tildes.");
  }

  let target;
  try {
    target = new URL(rawTarget);
  } catch {
    return emptyPreview("Enter a complete upstream URL, including https://.");
  }

  if (!["http:", "https:"].includes(target.protocol)) {
    return emptyPreview("The upstream URL must use http:// or https://.");
  }
  if (target.username || target.password || target.hash) {
    return emptyPreview("The upstream URL must not contain credentials or a fragment.");
  }

  let vault;
  try {
    vault = new URL(vaultOrigin || "").origin;
  } catch {
    vault = String(vaultOrigin || "").replace(/\/+$/, "");
  }
  if (!vault) return emptyPreview("SecretVault's public URL is not available.");

  const service = rawService.toLowerCase();
  const path = target.pathname === "/" ? "" : target.pathname.replace(/\/+$/, "");
  const clientPath = `${path}${target.search}`;

  return {
    valid: true,
    targetOrigin: target.origin,
    proxyUrl: `${vault}/proxy/${service}${clientPath}`,
    message: "The profile stores the upstream origin; clients keep the API path on the proxy URL.",
  };
}

export function getCurrentVaultOrigin() {
  if (typeof window !== "undefined" && window.location?.origin && window.location.origin !== "null") {
    return window.location.origin;
  }
  return "https://vault.example.com";
}
