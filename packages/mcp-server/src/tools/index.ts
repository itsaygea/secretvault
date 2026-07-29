import type { SupabaseClient } from "@supabase/supabase-js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Database } from "@secretvault/shared";
import { registerListSecrets } from "./listSecrets.js";
import { registerGetSecretReference } from "./getSecretReference.js";
import { registerSearchSecrets } from "./searchSecrets.js";
import { registerCreateSecret } from "./createSecret.js";
import { registerRotateSecret } from "./rotateSecret.js";
import { registerDeleteSecret } from "./deleteSecret.js";
import type { Principal } from "../authz.js";

export function registerAllTools(
  server: McpServer,
  supabase: SupabaseClient<Database, "secretvault">,
  masterKey: Buffer,
  principal: Principal,
): void {
  registerListSecrets(server, supabase, principal);
  registerGetSecretReference(server, supabase, principal);
  registerSearchSecrets(server, supabase, principal);
  registerCreateSecret(server, supabase, masterKey, principal);
  registerRotateSecret(server, supabase, masterKey, principal);
  registerDeleteSecret(server, supabase, principal);
}
