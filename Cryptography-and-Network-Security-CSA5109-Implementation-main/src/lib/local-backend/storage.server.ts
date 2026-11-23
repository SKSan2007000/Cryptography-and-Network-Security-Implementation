/**
 * Persistent Encrypted Storage Engine for Local Development Adapter
 *
 * Stores ONLY encrypted file payloads on disk in `./data/storage/encrypted-payloads/`.
 * Plaintext files are never written to disk.
 *
 * Implements HMAC-signed download URLs for secure receiver retrieval.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const STORAGE_SECRET =
  "sentinelcrypt_local_storage_secret_" + (process.env["SECRET_SALT"] || "local_dev_key");

export function getStorageDir(): string {
  const dir = path.resolve(process.cwd(), "data", "storage", "encrypted-payloads");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function resolveSecurePath(storagePath: string): string {
  // Normalize and prevent directory traversal
  const cleanPath = storagePath.replace(/^(\.\.(\/|\\|$))+/, "").replace(/^\/+/, "");
  const baseDir = getStorageDir();
  const fullPath = path.resolve(baseDir, cleanPath);

  if (!fullPath.startsWith(baseDir)) {
    throw new Error("Access denied: invalid storage path traversal.");
  }
  return fullPath;
}

export function saveEncryptedPayload(
  storagePath: string,
  data: Buffer | Uint8Array,
): { path: string; size: number } {
  const fullPath = resolveSecurePath(storagePath);
  const dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(fullPath, data);
  return { path: storagePath, size: data.byteLength };
}

export function readEncryptedPayload(storagePath: string): Buffer {
  const fullPath = resolveSecurePath(storagePath);
  if (!fs.existsSync(fullPath)) {
    throw new Error("Encrypted payload not found: " + storagePath);
  }
  return fs.readFileSync(fullPath);
}

export function createSignedDownloadUrl(
  storagePath: string,
  expiresInSeconds = 300,
): { signedUrl: string } {
  const expires = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const message = `${storagePath}:${expires}`;
  const sig = crypto.createHmac("sha256", STORAGE_SECRET).update(message).digest("hex");
  const signedUrl = `/api/local/storage/download?path=${encodeURIComponent(storagePath)}&expires=${expires}&sig=${sig}`;
  return { signedUrl };
}

export function verifySignedDownloadUrl(
  storagePath: string,
  expiresStr: string,
  sig: string,
): boolean {
  const expires = parseInt(expiresStr, 10);
  if (isNaN(expires) || expires < Math.floor(Date.now() / 1000)) {
    return false;
  }
  const message = `${storagePath}:${expires}`;
  const expectedSig = crypto.createHmac("sha256", STORAGE_SECRET).update(message).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expectedSig, "hex"));
  } catch {
    return false;
  }
}
