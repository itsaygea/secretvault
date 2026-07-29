import type { SupabaseClient } from "@supabase/supabase-js";
import { canonicalName, encryptSecret, generatePrefixSuffix, maskSecret, validateSecretName } from "@secretvault/shared";
import type { Database } from "@secretvault/shared";
import { canonicalServiceName, isTargetOriginAllowed, isValidServiceName, normalizeProxyMethods, parseEgressAllowlist, validateProxyPathPrefixes, validateTargetUrl, validateInjectedName } from "./proxyPolicy.js";
import { recordAuditEvent } from "./audit.js";

const VALID_METHODS = ["basic", "bearer", "header", "cookie"];

export async function handleListProfiles(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  query?: { cursor?: string | null; pageSize?: number },
): Promise<{ status: number; body: unknown }> {
  const { clampPageSize, decodeCursor, encodeCursor, paginateQuery } = await import("./pagination.js");
  const pageSize = clampPageSize(query?.pageSize);
  let q = supabase
    .from("service_profiles")
    .select("id, name, target_url, auth_method, user_secret_name, pass_secret_name, header_name, cookie_name, allow_private_network, allowed_methods, allowed_path_prefixes, created_at")
    .eq("user_id", userId);

  if (query?.cursor) {
    const decoded = decodeCursor(query.cursor);
    if (decoded) {
      q = q.or(`name.gt.${decoded.after},and(name.eq.${decoded.after},id.gt.${decoded.tiebreaker})`);
    }
  }

  q = q.order("name").order("id");

  const { data, error } = await q.limit(pageSize + 1);

  if (error) return { status: 500, body: { error: error.message } };

  const page = await paginateQuery<any>(data ?? [], pageSize, (row) => encodeCursor(row.name, row.id));

  return { status: 200, body: { data: page.data, next_cursor: page.next_cursor } };
}

export async function handleCreateProfile(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  body: {
    name?: string;
    target_url?: string;
    auth_method?: string;
    user_secret_name?: string;
    pass_secret_name?: string;
    header_name?: string;
    cookie_name?: string;
    allow_private_network?: boolean;
    allowed_methods?: string[];
    allowed_path_prefixes?: string[];
    // SV-034: inline secret definitions so the profile and its supporting
    // secrets are created in one server-side flow with cleanup-on-failure,
    // instead of the browser creating secrets first and orphanning them on a
    // later profile-create failure.
    create_secrets?: { name?: string; value?: string; environment?: string; tags?: string[] }[];
  },
  isAdmin = false,
  masterKey?: Buffer,
): Promise<{ status: number; body: unknown }> {
  const { name, target_url, auth_method, user_secret_name, pass_secret_name, header_name, cookie_name, allow_private_network = false } = body;

  if (!name || !target_url || !auth_method) {
    return { status: 400, body: { error: "name, target_url, and auth_method are required" } };
  }

  if (!isValidServiceName(name)) {
    return { status: 400, body: { error: "name must be 1-64 characters and contain only letters, numbers, '.', '_', '-', or '~'" } };
  }

  // SV-053: store the canonical (lowercase) name so casing cannot create an
  // authorization mismatch or a duplicate-ambiguous profile against the
  // lowercased proxy scopes.
  const canonicalProfileName = canonicalServiceName(name);

  try {
    const target = validateTargetUrl(target_url, allow_private_network);
    if (allow_private_network && !isAdmin) {
      return { status: 403, body: { error: "Private-network destinations require an administrator session" } };
    }
    const allowlistedOrigins = parseEgressAllowlist(process.env.SECRETVAULT_EGRESS_ALLOWLIST);
    if (!isAdmin && !isTargetOriginAllowed(target, allowlistedOrigins)) {
      return { status: 403, body: { error: "Destination origin is not in the configured egress allowlist" } };
    }
  } catch (error) {
    return { status: 400, body: { error: error instanceof Error ? error.message : "Invalid target_url" } };
  }
  const allowedMethods = normalizeProxyMethods(body.allowed_methods);
  if (allowedMethods.length === 0) return { status: 400, body: { error: "allowed_methods must contain at least one supported HTTP method" } };
  const pathPolicy = validateProxyPathPrefixes(body.allowed_path_prefixes);
  if (!pathPolicy.valid) return { status: 400, body: { error: pathPolicy.error } };

  if (!VALID_METHODS.includes(auth_method)) {
    return { status: 400, body: { error: `auth_method must be one of: ${VALID_METHODS.join(", ")}` } };
  }

  if (!pass_secret_name) {
    return { status: 400, body: { error: "pass_secret_name is required (the secret holding the credential)" } };
  }

  // Validate the injected field name for the chosen auth method and require it.
  // SV-022: never store a header/cookie name that can change request framing,
  // inject CR/LF, or assert identity the proxy owns.
  if (auth_method === "header") {
    if (typeof header_name !== "string" || header_name.length === 0) {
      return { status: 400, body: { error: "header_name is required for auth_method 'header'" } };
    }
    if (validateInjectedName("header", header_name) === null) {
      return { status: 400, body: { error: "header_name must be a valid HTTP field-name token and must not be a reserved hop-by-hop, framing, routing, or credential header" } };
    }
  } else if (typeof header_name === "string" && header_name.length > 0) {
    return { status: 400, body: { error: "header_name is only valid for auth_method 'header'" } };
  }

  if (auth_method === "cookie") {
    if (typeof cookie_name !== "string" || cookie_name.length === 0) {
      return { status: 400, body: { error: "cookie_name is required for auth_method 'cookie'" } };
    }
    if (validateInjectedName("cookie", cookie_name) === null) {
      return { status: 400, body: { error: "cookie_name must be a valid cookie token (letters, digits, and !#$%&'*+-.^_`|~)" } };
    }
  } else if (typeof cookie_name === "string" && cookie_name.length > 0) {
    return { status: 400, body: { error: "cookie_name is only valid for auth_method 'cookie'" } };
  }

  // SV-034: create any inline secrets first, then the profile, with cleanup on
  // any failure so a failed profile-create leaves no orphan secrets. This is
  // the server-side equivalent of a transaction over the Supabase REST API.
  const createSecrets = Array.isArray(body.create_secrets) ? body.create_secrets : [];
  const createdSecretNames: string[] = [];

  // Validate every inline secret before writing any of them, so a single bad
  // name/value aborts the whole request with nothing created.
  let inlineDefs: { displayName: string; name: string; value: string; environment: string; tags: string[] }[];
  try {
    inlineDefs = createSecrets.map((entry) => {
      const displayName = entry?.name;
      const value = entry?.value;
      if (!displayName || !value) {
        throw new ClientError("each create_secrets entry requires a non-empty name and value");
      }
      try {
        validateSecretName(displayName);
      } catch (err) {
        throw new ClientError((err as Error).message);
      }
      return {
        displayName,
        name: canonicalName(displayName),
        value,
        environment: entry.environment ?? "production",
        tags: Array.isArray(entry.tags) ? entry.tags : [],
      };
    });
  } catch (err) {
    if (err instanceof ClientError) return { status: 400, body: { error: err.message } };
    return { status: 500, body: { error: (err as Error).message } };
  }

  // Resolve user_secret_name / pass_secret_name to inline secret names when the
  // caller asked to create them alongside the profile. The referenced name must
  // exist either as an existing secret or as one being created inline.
  const inlineNames = new Set(inlineDefs.map((d) => d.name));
  const resolveRef = (ref: string | undefined | null, field: string): string | null => {
    if (!ref) return null;
    if (ref === "__create_inline__") {
      throw new ClientError(`${field} asked to create an inline secret but no matching create_secrets entry was provided`);
    }
    // Accept either a plain name the caller will create inline, or an existing
    // name. Existence is enforced by the proxy at dispatch time.
    return canonicalName(ref);
  };

  let resolvedUserSecret: string | null = null;
  let resolvedPassSecret: string;
  try {
    if (masterKey) {
      for (const def of inlineDefs) {
        const { data: existing } = await supabase
          .from("secrets")
          .select("id")
          .eq("name", def.name)
          .eq("user_id", userId)
          .maybeSingle();
        if (existing) {
          throw new ClientError(`Secret '${def.name}' already exists; cannot create it inline`);
        }
        const { encrypted } = await encryptSecret(def.value, masterKey);
        const { error: secretError } = await supabase.from("secrets").insert({
          name: def.name,
          display_name: def.displayName,
          user_id: userId,
          environment: def.environment,
          encrypted_blob: encrypted,
          masked_preview: maskSecret(def.value),
          key_prefix: generatePrefixSuffix(def.value).prefix,
          key_suffix: generatePrefixSuffix(def.value).suffix,
          tags: def.tags,
        });
        if (secretError) {
          if (secretError.code === "23505") throw new ClientError(`Secret '${def.name}' already exists`);
          throw new Error(secretError.message);
        }
        createdSecretNames.push(def.name);
      }
    } else if (inlineDefs.length > 0) {
      throw new ClientError("Inline secret creation is not available (no master key in scope)");
    }

    resolvedUserSecret = user_secret_name ? resolveRef(user_secret_name, "user_secret_name") : null;
    resolvedPassSecret = resolveRef(pass_secret_name, "pass_secret_name")!;

    // If a referenced secret is not inline-created here, nothing more to check;
    // the proxy resolves it at dispatch. (We do not leak which exist.)
    void inlineNames;
  } catch (err) {
    if (err instanceof ClientError) return { status: 400, body: { error: err.message } };
    return { status: 500, body: { error: (err as Error).message } };
  }

  const { data, error } = await supabase
    .from("service_profiles")
    .insert({
      user_id: userId,
      name: canonicalProfileName,
      target_url,
      auth_method,
      user_secret_name: resolvedUserSecret,
      pass_secret_name: resolvedPassSecret,
      header_name: header_name ?? null,
      cookie_name: cookie_name ?? null,
      allow_private_network,
      allowed_methods: allowedMethods,
      allowed_path_prefixes: pathPolicy.prefixes,
    })
    .select("id, name, target_url, auth_method, user_secret_name, pass_secret_name, header_name, cookie_name, allow_private_network, allowed_methods, allowed_path_prefixes, created_at")
    .single();

  if (error) {
    // Profile creation failed: roll back every inline secret we just created so
    // no orphan credential material is left behind (SV-034).
    await rollbackSecrets(supabase, userId, createdSecretNames);
    if (error.code === "23505") return { status: 409, body: { error: `Profile '${canonicalProfileName}' already exists` } };
    return { status: 500, body: { error: error.message } };
  }

  void recordAuditEvent(supabase, {
    userId,
    secretName: "system",
    accessType: "service_profile_create",
    caller: "rest:/api/service-profiles",
    metadata: { profile_id: data.id, profile_name: data.name, target_url: data.target_url, created_secrets: createdSecretNames.join(",") },
  }).catch(() => undefined);

  return { status: 201, body: { ...data, created_secrets: createdSecretNames } };
}

// Best-effort cleanup of inline-created secrets when profile creation fails.
// Never throws — partial cleanup is preferable to leaving orphans, and the
// caller already has a failure to report.
async function rollbackSecrets(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  names: string[],
): Promise<void> {
  for (const name of names) {
    try {
      await supabase.from("secrets").delete().eq("name", name).eq("user_id", userId);
    } catch {
      // swallow — see comment above
    }
  }
}

// Lightweight client-error discriminator so validation failures map to 400
// while unexpected failures map to 500, without leaking internal details.
class ClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClientError";
  }
}

export async function handleDeleteProfile(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  profileId: string,
): Promise<{ status: number; body: unknown }> {
  const { data: profile } = await supabase
    .from("service_profiles")
    .select("id, name")
    .eq("id", profileId)
    .eq("user_id", userId)
    .single();

  if (!profile) return { status: 404, body: { error: "Profile not found" } };

  const { error } = await supabase.from("service_profiles").delete().eq("id", profileId);
  if (error) return { status: 500, body: { error: error.message } };

  void recordAuditEvent(supabase, {
    userId,
    secretName: "system",
    accessType: "service_profile_delete",
    caller: "rest:/api/service-profiles/:id",
    metadata: { profile_id: profileId, profile_name: profile.name },
  }).catch(() => undefined);

  return { status: 200, body: { deleted: true, name: profile.name } };
}

// Look up a profile by user and service name (used by proxy)
export async function getProfileForProxy(
  supabase: SupabaseClient<Database, "secretvault">,
  userId: string,
  serviceName: string,
) {
  const { data, error } = await supabase
    .from("service_profiles")
    .select("id, name, target_url, auth_method, user_secret_name, pass_secret_name, header_name, cookie_name, allow_private_network, allowed_methods, allowed_path_prefixes")
    .eq("user_id", userId)
    .eq("name", canonicalServiceName(serviceName))
    .single();

  if (error || !data) return null;
  return data;
}
