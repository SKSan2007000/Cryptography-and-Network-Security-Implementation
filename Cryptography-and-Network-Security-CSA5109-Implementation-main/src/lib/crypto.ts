/**
 * SentinelCrypt browser cryptography.
 *
 * All primitives are provided by the platform Web Crypto API:
 *  - AES-256-GCM  : file confidentiality + authenticity (per-transfer random key + 96-bit IV)
 *  - RSA-OAEP-2048/SHA-256 : wrapping of the per-transfer AES key for the receiver
 *  - SHA-256      : file fingerprint used for end-to-end integrity verification
 *  - PBKDF2-SHA256: derives a wrapping key from the user's key passphrase so the
 *                   RSA private key is never stored in plaintext.
 *
 * No custom / homemade algorithm is implemented anywhere in this project.
 */

export const CRYPTO_PARAMS = {
  aes: { name: "AES-GCM", length: 256, ivBytes: 12, tagBits: 128 },
  rsa: { name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256" },
  hash: "SHA-256",
  kdf: { name: "PBKDF2", iterations: 250_000, hash: "SHA-256", saltBytes: 16 },
} as const;

const subtle = () => globalThis.crypto.subtle;

export function toBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** SHA-256 fingerprint, hex encoded. */
export async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const view = data instanceof Uint8Array ? data : new Uint8Array(data);
  const buf = new ArrayBuffer(view.byteLength);
  new Uint8Array(buf).set(view);
  const digest = await subtle().digest(CRYPTO_PARAMS.hash, buf);
  return toHex(digest);
}

export function bufferOf(bytes: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

export function randomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/* ------------------------------------------------------------------ AES */

export async function generateAesKey(): Promise<CryptoKey> {
  return subtle().generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  const buf = new ArrayBuffer(raw.byteLength);
  new Uint8Array(buf).set(raw);
  return subtle().importKey("raw", buf, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}

export async function exportAesKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle().exportKey("raw", key));
}

export async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: ArrayBuffer,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  // A fresh random IV per encryption — never reused with the same key.
  const iv = randomBytes(CRYPTO_PARAMS.aes.ivBytes);
  const ciphertext = await subtle().encrypt(
    { name: "AES-GCM", iv: bufferOf(iv), tagLength: CRYPTO_PARAMS.aes.tagBits },
    key,
    plaintext,
  );
  return { ciphertext: new Uint8Array(ciphertext), iv };
}

export async function aesGcmDecrypt(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<ArrayBuffer> {
  const ct = new ArrayBuffer(ciphertext.byteLength);
  new Uint8Array(ct).set(ciphertext);
  return subtle().decrypt(
    { name: "AES-GCM", iv: bufferOf(iv), tagLength: CRYPTO_PARAMS.aes.tagBits },
    key,
    ct,
  );
}

/* ------------------------------------------------------------------ RSA */

export async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  return subtle().generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: CRYPTO_PARAMS.rsa.modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: CRYPTO_PARAMS.rsa.hash,
    },
    true,
    ["encrypt", "decrypt"],
  );
}

export async function exportPublicJwk(key: CryptoKey): Promise<JsonWebKey> {
  return subtle().exportKey("jwk", key);
}

export async function importPublicJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return subtle().importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

export async function importPrivatePkcs8(pkcs8: Uint8Array): Promise<CryptoKey> {
  const buf = new ArrayBuffer(pkcs8.byteLength);
  new Uint8Array(buf).set(pkcs8);
  return subtle().importKey("pkcs8", buf, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

/** Wrap (encrypt) the AES key with the receiver's RSA-OAEP public key. */
export async function wrapAesKey(publicKey: CryptoKey, aesKey: CryptoKey): Promise<string> {
  const raw = await exportAesKey(aesKey);
  const buf = new ArrayBuffer(raw.byteLength);
  new Uint8Array(buf).set(raw);
  const wrapped = await subtle().encrypt({ name: "RSA-OAEP" }, publicKey, buf);
  return toBase64(wrapped);
}

/** Unwrap the AES key using the receiver's RSA private key. */
export async function unwrapAesKey(privateKey: CryptoKey, wrapped: string): Promise<CryptoKey> {
  const bytes = fromBase64(wrapped);
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  const raw = await subtle().decrypt({ name: "RSA-OAEP" }, privateKey, buf);
  return importAesKey(new Uint8Array(raw));
}

/* --------------------------------------------------- private-key at rest */

async function deriveKekFromPassphrase(passphrase: string, salt: Uint8Array) {
  const material = await subtle().importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return subtle().deriveKey(
    {
      name: "PBKDF2",
      salt: bufferOf(salt),
      iterations: CRYPTO_PARAMS.kdf.iterations,
      hash: CRYPTO_PARAMS.kdf.hash,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export type ProtectedKeyBundle = {
  publicJwk: JsonWebKey;
  wrappedPrivateKey: string;
  kdfSalt: string;
  wrapIv: string;
};

/** Generate an RSA-OAEP key pair and protect the private key with a passphrase. */
export async function createProtectedKeyPair(passphrase: string): Promise<ProtectedKeyBundle> {
  const pair = await generateRsaKeyPair();
  const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey));
  const salt = randomBytes(CRYPTO_PARAMS.kdf.saltBytes);
  const kek = await deriveKekFromPassphrase(passphrase, salt);
  const pkcs8Buf = new ArrayBuffer(pkcs8.byteLength);
  new Uint8Array(pkcs8Buf).set(pkcs8);
  const { ciphertext, iv } = await aesGcmEncrypt(kek, pkcs8Buf);
  return {
    publicJwk: await exportPublicJwk(pair.publicKey),
    wrappedPrivateKey: toBase64(ciphertext),
    kdfSalt: toBase64(salt),
    wrapIv: toBase64(iv),
  };
}

/** Recover the RSA private key from its passphrase-protected form. */
export async function unlockPrivateKey(
  passphrase: string,
  bundle: { wrappedPrivateKey: string; kdfSalt: string; wrapIv: string },
): Promise<CryptoKey> {
  const kek = await deriveKekFromPassphrase(passphrase, fromBase64(bundle.kdfSalt));
  const pkcs8 = await aesGcmDecrypt(
    kek,
    fromBase64(bundle.wrapIv),
    fromBase64(bundle.wrappedPrivateKey),
  );
  return importPrivatePkcs8(new Uint8Array(pkcs8));
}

/* ------------------------------------------------------------- utilities */

export function generateTransferToken(): string {
  return toHex(randomBytes(32));
}

export function deviceFingerprint(): string {
  if (typeof window === "undefined") return "server";
  const parts = [
    navigator.userAgent,
    navigator.language,
    String(screen.width),
    String(screen.height),
    String(new Date().getTimezoneOffset()),
  ];
  let hash = 0;
  const source = parts.join("|");
  for (let i = 0; i < source.length; i += 1) {
    hash = (hash << 5) - hash + source.charCodeAt(i);
    hash |= 0;
  }
  return `dev_${(hash >>> 0).toString(16)}`;
}

/* ------------------------------------------------ RSA-OAEP text sealing */

/** Seal a short UTF-8 string (e.g. a one-time access token) with an RSA-OAEP public key. */
export async function rsaSealText(publicKey: CryptoKey, text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return toBase64(await subtle().encrypt({ name: "RSA-OAEP" }, publicKey, buf));
}

/** Open a string sealed with rsaSealText using the matching RSA private key. */
export async function rsaOpenText(privateKey: CryptoKey, sealed: string): Promise<string> {
  const bytes = fromBase64(sealed);
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  const plain = await subtle().decrypt({ name: "RSA-OAEP" }, privateKey, buf);
  return new TextDecoder().decode(plain);
}
