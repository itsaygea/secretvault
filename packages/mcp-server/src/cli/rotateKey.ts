import { createClient } from "@supabase/supabase-js";
import { decryptSecret, encryptSecret, deriveDEK } from "@secretvault/shared";
import { resolveMasterKey } from "../keyLoader.js";

export async function rotateMasterKeyDatabase(
  supabase: any,
  oldMasterKey: Buffer,
  newMasterKey: Buffer,
  options?: { oldKeyId?: string; newKeyId?: string },
): Promise<{
  secretsCount: number;
  clientsCount: number;
  totpCount: number;
  pendingTotpCount: number;
}> {
  const oldKeyId = options?.oldKeyId ?? "old_key";
  const newKeyId = options?.newKeyId ?? "v1";

  // Create checkpoint row
  const { data: rotationRow, error: insertErr } = await supabase
    .from("master_key_rotations")
    .insert({
      status: "in_progress",
      old_key_id: oldKeyId,
      new_key_id: newKeyId,
    })
    .select()
    .single();

  const rotationId = rotationRow?.id;

  let secretsCount = 0;
  let clientsCount = 0;
  let totpCount = 0;
  let pendingTotpCount = 0;

  try {
    // 1. Re-encrypt secrets
    const { data: secrets } = await supabase.from("secrets").select("id, encrypted_blob, user_id, name");
    if (secrets && secrets.length > 0) {
      for (const secret of secrets) {
        if (!secret.encrypted_blob) continue;
        const plaintext = await decryptSecret(secret.encrypted_blob, oldMasterKey, { purpose: "secret" });
        const { encrypted: reencrypted } = await encryptSecret(plaintext, newMasterKey, {
          purpose: "secret",
          keyId: newKeyId,
        });
        await supabase.from("secrets").update({ encrypted_blob: reencrypted }).eq("id", secret.id);
        secretsCount++;
      }
    }

    // Update checkpoint
    if (rotationId) {
      await supabase.from("master_key_rotations").update({ processed_secrets: secretsCount }).eq("id", rotationId);
    }

    // 2. Re-encrypt client applications
    const { data: clients } = await supabase.from("client_applications").select("id, encrypted_key");
    if (clients && clients.length > 0) {
      for (const client of clients) {
        if (!client.encrypted_key) continue;
        const plaintext = await decryptSecret(client.encrypted_key, oldMasterKey, { purpose: "client_key" });
        const { encrypted: reencrypted } = await encryptSecret(plaintext, newMasterKey, {
          purpose: "client_key",
          keyId: newKeyId,
        });
        await supabase.from("client_applications").update({ encrypted_key: reencrypted }).eq("id", client.id);
        clientsCount++;
      }
    }

    // Update checkpoint
    if (rotationId) {
      await supabase.from("master_key_rotations").update({ processed_clients: clientsCount }).eq("id", rotationId);
    }

    // 3. Re-encrypt TOTP secrets
    const { data: totps } = await supabase.from("totp_secrets").select("id, secret_encrypted");
    if (totps && totps.length > 0) {
      for (const totp of totps) {
        if (!totp.secret_encrypted) continue;
        const plaintext = await decryptSecret(totp.secret_encrypted, oldMasterKey, { purpose: "totp_secret" });
        const { encrypted: reencrypted } = await encryptSecret(plaintext, newMasterKey, {
          purpose: "totp_secret",
          keyId: newKeyId,
        });
        await supabase.from("totp_secrets").update({ secret_encrypted: reencrypted }).eq("id", totp.id);
        totpCount++;
      }
    }

    // 4. Re-encrypt pending TOTP enrollments
    const { data: pendingTotps } = await supabase.from("totp_pending_enrollments").select("id, secret_encrypted");
    if (pendingTotps && pendingTotps.length > 0) {
      for (const pending of pendingTotps) {
        if (!pending.secret_encrypted) continue;
        const plaintext = await decryptSecret(pending.secret_encrypted, oldMasterKey, { purpose: "totp_secret" });
        const { encrypted: reencrypted } = await encryptSecret(plaintext, newMasterKey, {
          purpose: "totp_secret",
          keyId: newKeyId,
        });
        await supabase
          .from("totp_pending_enrollments")
          .update({ secret_encrypted: reencrypted })
          .eq("id", pending.id);
        pendingTotpCount++;
      }
    }

    // Mark completion
    if (rotationId) {
      await supabase
        .from("master_key_rotations")
        .update({
          status: "completed",
          processed_secrets: secretsCount,
          processed_clients: clientsCount,
          processed_totp: totpCount,
          processed_pending_totp: pendingTotpCount,
          completed_at: new Date().toISOString(),
        })
        .eq("id", rotationId);
    }

    // Log audit record
    await supabase.from("access_logs").insert({
      access_type: "master_key_rotated",
      details: `Master key rotated successfully. Processed ${secretsCount} secrets, ${clientsCount} clients, ${totpCount} TOTP factors.`,
    });

    return { secretsCount, clientsCount, totpCount, pendingTotpCount };
  } catch (err: any) {
    if (rotationId) {
      await supabase
        .from("master_key_rotations")
        .update({
          status: "failed",
          error_message: err?.message ?? String(err),
        })
        .eq("id", rotationId);
    }
    throw err;
  }
}

export async function handleRotateMasterKeyCli(): Promise<void> {
  const args = process.argv.slice(3);
  let oldKeyHex = process.env.OLD_MASTER_KEY;
  let newKeyHex = process.env.NEW_MASTER_KEY;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--old-key" && args[i + 1]) {
      oldKeyHex = args[i + 1];
      i++;
    } else if (args[i] === "--new-key" && args[i + 1]) {
      newKeyHex = args[i + 1];
      i++;
    }
  }

  if (!oldKeyHex || !newKeyHex) {
    console.error("ERROR: Master key rotation requires --old-key <64-hex> and --new-key <64-hex> (or OLD_MASTER_KEY and NEW_MASTER_KEY env vars).");
    process.exit(1);
  }

  const supabaseUrl = process.env.SECRETVAULT_SUPABASE_URL;
  const supabaseServiceKey = process.env.SECRETVAULT_SUPABASE_SERVICE_KEY;

  if (!supabaseUrl || !supabaseServiceKey) {
    console.error("ERROR: Missing SECRETVAULT_SUPABASE_URL or SECRETVAULT_SUPABASE_SERVICE_KEY environment variables.");
    process.exit(1);
  }

  const oldMasterKey = Buffer.from(oldKeyHex.trim(), "hex");
  const newMasterKey = Buffer.from(newKeyHex.trim(), "hex");

  if (oldMasterKey.length !== 32 || newMasterKey.length !== 32) {
    console.error("ERROR: Both old and new master keys must be exactly 32 bytes (64 hex characters).");
    process.exit(1);
  }

  console.log("Starting master key rotation...");
  const supabase = createClient(supabaseUrl, supabaseServiceKey);

  const result = await rotateMasterKeyDatabase(supabase, oldMasterKey, newMasterKey);
  console.log(`✓ Master key rotation complete! Re-encrypted ${result.secretsCount} secrets, ${result.clientsCount} clients, ${result.totpCount} TOTP keys.`);
}
