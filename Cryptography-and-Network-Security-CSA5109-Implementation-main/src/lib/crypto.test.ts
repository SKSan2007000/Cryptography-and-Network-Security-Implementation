import { describe, expect, it } from "vitest";

import {
  CRYPTO_PARAMS,
  aesGcmDecrypt,
  aesGcmEncrypt,
  bufferOf,
  createProtectedKeyPair,
  exportAesKey,
  fromBase64,
  generateAesKey,
  generateRsaKeyPair,
  generateTransferToken,
  importAesKey,
  importPublicJwk,
  randomBytes,
  sha256Hex,
  toBase64,
  toHex,
  unlockPrivateKey,
  unwrapAesKey,
  wrapAesKey,
} from "./crypto";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe("encoding helpers", () => {
  it("round-trips base64", () => {
    const bytes = randomBytes(48);
    expect(Array.from(fromBase64(toBase64(bytes)))).toEqual(Array.from(bytes));
  });

  it("produces lowercase hex of the right length", () => {
    expect(toHex(new Uint8Array([0, 15, 255]))).toBe("000fff");
  });
});

describe("SHA-256 integrity fingerprints", () => {
  it("matches the known digest of an empty input", async () => {
    expect(await sha256Hex(new Uint8Array())).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("changes when a single byte changes", async () => {
    const a = await sha256Hex(encoder.encode("report-v1"));
    const b = await sha256Hex(encoder.encode("report-v2"));
    expect(a).not.toBe(b);
    expect(a).toHaveLength(64);
  });
});

describe("AES-256-GCM", () => {
  it("uses 256-bit keys and 12-byte IVs", async () => {
    expect(CRYPTO_PARAMS.aes.length).toBe(256);
    expect(CRYPTO_PARAMS.aes.ivBytes).toBe(12);
    const raw = await exportAesKey(await generateAesKey());
    expect(raw.byteLength).toBe(32);
  });

  it("encrypts and decrypts a payload", async () => {
    const key = await generateAesKey();
    const plaintext = encoder.encode("confidential capstone submission");
    const { ciphertext, iv } = await aesGcmEncrypt(key, bufferOf(plaintext));
    expect(iv.byteLength).toBe(CRYPTO_PARAMS.aes.ivBytes);
    expect(toBase64(ciphertext)).not.toBe(toBase64(plaintext));
    const out = await aesGcmDecrypt(key, iv, ciphertext);
    expect(decoder.decode(out)).toBe("confidential capstone submission");
  });

  it("rejects tampered ciphertext (authentication tag failure)", async () => {
    const key = await generateAesKey();
    const { ciphertext, iv } = await aesGcmEncrypt(key, bufferOf(encoder.encode("payload")));
    const tampered = new Uint8Array(ciphertext);
    tampered[0] = tampered[0]! ^ 0xff;
    await expect(aesGcmDecrypt(key, iv, tampered)).rejects.toBeDefined();
  });

  it("fails to decrypt with the wrong key", async () => {
    const { ciphertext, iv } = await aesGcmEncrypt(
      await generateAesKey(),
      bufferOf(encoder.encode("payload")),
    );
    await expect(aesGcmDecrypt(await generateAesKey(), iv, ciphertext)).rejects.toBeDefined();
  });
});

describe("RSA-OAEP key wrapping", () => {
  it("wraps and unwraps the AES session key", async () => {
    const pair = await generateRsaKeyPair();
    const aesKey = await generateAesKey();
    const wrapped = await wrapAesKey(pair.publicKey, aesKey);
    const unwrapped = await unwrapAesKey(pair.privateKey, wrapped);
    expect(toBase64(await exportAesKey(unwrapped))).toBe(toBase64(await exportAesKey(aesKey)));
  });

  it("cannot unwrap with a different private key", async () => {
    const a = await generateRsaKeyPair();
    const b = await generateRsaKeyPair();
    const wrapped = await wrapAesKey(a.publicKey, await generateAesKey());
    await expect(unwrapAesKey(b.privateKey, wrapped)).rejects.toBeDefined();
  });
});

describe("passphrase-protected private keys", () => {
  it("unlocks with the correct passphrase and fails otherwise", async () => {
    const bundle = await createProtectedKeyPair("correct horse battery staple");
    const privateKey = await unlockPrivateKey("correct horse battery staple", bundle);
    const aesKey = await generateAesKey();
    const wrapped = await wrapAesKey(await importPublicJwk(bundle.publicJwk), aesKey);
    expect(toBase64(await exportAesKey(await unwrapAesKey(privateKey, wrapped)))).toBe(
      toBase64(await exportAesKey(aesKey)),
    );
    await expect(unlockPrivateKey("wrong passphrase", bundle)).rejects.toBeDefined();
  });
});

describe("transfer tokens", () => {
  it("generates unique high-entropy tokens", () => {
    const tokens = new Set(Array.from({ length: 200 }, () => generateTransferToken()));
    expect(tokens.size).toBe(200);
    expect([...tokens][0]!.length).toBeGreaterThanOrEqual(16);
  });
});

describe("AES key import", () => {
  it("re-imports an exported raw key", async () => {
    const raw = await exportAesKey(await generateAesKey());
    const key = await importAesKey(raw);
    const { ciphertext, iv } = await aesGcmEncrypt(key, bufferOf(encoder.encode("x")));
    expect(decoder.decode(await aesGcmDecrypt(key, iv, ciphertext))).toBe("x");
  });
});
