import { supabase } from "@/integrations/supabase/client";
import { createProtectedKeyPair, importPublicJwk, unlockPrivateKey } from "./crypto";

const PASSPHRASE_KEY = "sc_key_passphrase";

export type KeyRecord = {
  id: string;
  user_id: string;
  public_key_jwk: JsonWebKey;
  wrapped_private_key: string;
  kdf_salt: string;
  wrap_iv: string;
  algorithm: string;
  created_at: string;
};

export function cachePassphrase(passphrase: string) {
  sessionStorage.setItem(PASSPHRASE_KEY, passphrase);
}

export function cachedPassphrase(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem(PASSPHRASE_KEY);
}

export function clearPassphrase() {
  sessionStorage.removeItem(PASSPHRASE_KEY);
}

export async function getKeyRecord(userId: string): Promise<KeyRecord | null> {
  const { data } = await supabase.from("user_keys").select("*").eq("user_id", userId).maybeSingle();
  return (data as KeyRecord | null) ?? null;
}

/** Creates and stores an RSA-OAEP 2048 key pair; the private key is passphrase-wrapped. */
export async function provisionKeys(userId: string, passphrase: string): Promise<KeyRecord> {
  const bundle = await createProtectedKeyPair(passphrase);
  const { data, error } = await supabase
    .from("user_keys")
    .upsert(
      {
        user_id: userId,
        public_key_jwk: bundle.publicJwk as never,
        wrapped_private_key: bundle.wrappedPrivateKey,
        kdf_salt: bundle.kdfSalt,
        wrap_iv: bundle.wrapIv,
        algorithm: "RSA-OAEP-2048-SHA256",
      },
      { onConflict: "user_id" },
    )
    .select("*")
    .single();
  if (error) throw new Error(error.message);
  cachePassphrase(passphrase);
  return data as KeyRecord;
}

/**
 * Only the recipient's PUBLIC key is exposed, through a narrow security-definer
 * lookup. Wrapped private-key material is never readable across accounts.
 */
export async function getRecipientPublicKey(recipientId: string): Promise<CryptoKey> {
  const { data, error } = await supabase.rpc("get_public_key", { _user_id: recipientId });
  if (error) throw new Error(error.message);
  if (!data) throw new Error("The recipient has not published an RSA public key yet.");
  return importPublicJwk(data as JsonWebKey);
}

export async function getPrivateKey(userId: string, passphrase: string): Promise<CryptoKey> {
  const record = await getKeyRecord(userId);
  if (!record) throw new Error("No key pair found for this account.");
  try {
    const key = await unlockPrivateKey(passphrase, {
      wrappedPrivateKey: record.wrapped_private_key,
      kdfSalt: record.kdf_salt,
      wrapIv: record.wrap_iv,
    });
    cachePassphrase(passphrase);
    return key;
  } catch {
    throw new Error("Incorrect key passphrase — the private key could not be unwrapped.");
  }
}
