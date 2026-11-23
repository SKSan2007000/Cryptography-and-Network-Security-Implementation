import { describe, expect, it } from "vitest";

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  bufferOf,
  exportAesKey,
  fromBase64,
  generateAesKey,
  generateRsaKeyPair,
  generateTransferToken,
  sha256Hex,
  toBase64,
  unwrapAesKey,
  wrapAesKey,
} from "./crypto";
import { evaluateDownloadGate } from "./download-gate.server";
import { sha256HexServer } from "./security.server";

describe("Complete End-to-End File Transfer Lifecycle Verification", () => {
  // Test 1: Real PDF lifecycle
  it("executes complete lifecycle for PDF file with continuous SHA-256 integrity", async () => {
    // 1. Simulate real PDF byte header and content (%PDF-1.7...)
    const pdfHeader =
      "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nxref\n0 2\ntrailer\n<< /Root 1 0 R >>\n%%EOF";
    const pdfBytes = new TextEncoder().encode(pdfHeader);

    // 2. Sender calculates original SHA-256
    const originalHash = await sha256Hex(pdfBytes);
    expect(originalHash).toHaveLength(64);

    // 3. Sender generates random AES-256 key & 96-bit IV
    const aesKey = await generateAesKey();
    const { ciphertext, iv } = await aesGcmEncrypt(aesKey, bufferOf(pdfBytes));
    expect(iv.byteLength).toBe(12); // 96-bit IV

    // 4. Receiver generates RSA-OAEP 2048 keypair
    const receiverKeys = await generateRsaKeyPair();

    // 5. Sender protects AES key with receiver's RSA public key
    const wrappedKey = await wrapAesKey(receiverKeys.publicKey, aesKey);
    expect(wrappedKey).toBeDefined();

    // 6. Ciphertext hash calculated for transport verification
    const ciphertextHash = await sha256Hex(ciphertext);
    expect(ciphertextHash).not.toBe(originalHash);

    // 7. Receiver un緻ps the AES key using their RSA private key
    const recoveredAesKey = await unwrapAesKey(receiverKeys.privateKey, wrappedKey);
    const originalKeyRaw = await exportAesKey(aesKey);
    const recoveredKeyRaw = await exportAesKey(recoveredAesKey);
    expect(toBase64(recoveredKeyRaw)).toBe(toBase64(originalKeyRaw));

    // 8. Receiver decrypts ciphertext using AES-256-GCM
    const decryptedBuffer = await aesGcmDecrypt(recoveredAesKey, iv, ciphertext);

    // 9. Receiver calculates decrypted SHA-256
    const decryptedHash = await sha256Hex(decryptedBuffer);

    // 10. Verify SHA-256 matches exactly byte-for-byte
    expect(decryptedHash).toBe(originalHash);
    expect(new TextDecoder().decode(decryptedBuffer)).toBe(pdfHeader);
  });

  // Test 2: Real Text file lifecycle
  it("executes complete lifecycle for Text document", async () => {
    const textContent =
      "SentinelCrypt: Trust-Aware Secure File Transfer Platform. Highly Confidential.";
    const textBytes = new TextEncoder().encode(textContent);
    const originalHash = await sha256Hex(textBytes);

    const aesKey = await generateAesKey();
    const { ciphertext, iv } = await aesGcmEncrypt(aesKey, bufferOf(textBytes));

    const receiverKeys = await generateRsaKeyPair();
    const wrappedKey = await wrapAesKey(receiverKeys.publicKey, aesKey);

    const recoveredKey = await unwrapAesKey(receiverKeys.privateKey, wrappedKey);
    const decrypted = await aesGcmDecrypt(recoveredKey, iv, ciphertext);
    const decryptedHash = await sha256Hex(decrypted);

    expect(decryptedHash).toBe(originalHash);
    expect(new TextDecoder().decode(decrypted)).toBe(textContent);
  });

  // Test 3: Real Image file binary payload (simulated PNG header \x89PNG\r\n\x1a\n)
  it("executes complete lifecycle for Image file (PNG binary data)", async () => {
    const pngHeader = new Uint8Array([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
      0x52,
    ]);
    const imagePayload = new Uint8Array(2048);
    imagePayload.set(pngHeader, 0);
    for (let i = 16; i < 2048; i++) imagePayload[i] = (i * 37) % 256;

    const originalHash = await sha256Hex(imagePayload);
    const aesKey = await generateAesKey();
    const { ciphertext, iv } = await aesGcmEncrypt(aesKey, bufferOf(imagePayload));

    const receiverKeys = await generateRsaKeyPair();
    const wrappedKey = await wrapAesKey(receiverKeys.publicKey, aesKey);

    const recoveredKey = await unwrapAesKey(receiverKeys.privateKey, wrappedKey);
    const decrypted = await aesGcmDecrypt(recoveredKey, iv, ciphertext);
    const decryptedHash = await sha256Hex(decrypted);

    expect(decryptedHash).toBe(originalHash);
    expect(new Uint8Array(decrypted)).toEqual(imagePayload);
  });

  // Test 4: Larger file (1 Megabyte buffer)
  it("executes complete lifecycle for larger file within configured limit", async () => {
    const largePayload = new Uint8Array(1024 * 1024); // 1 MB
    for (let i = 0; i < largePayload.length; i += 1024) {
      largePayload[i] = i % 256;
    }

    const originalHash = await sha256Hex(largePayload);
    const aesKey = await generateAesKey();
    const { ciphertext, iv } = await aesGcmEncrypt(aesKey, bufferOf(largePayload));

    const receiverKeys = await generateRsaKeyPair();
    const wrappedKey = await wrapAesKey(receiverKeys.publicKey, aesKey);

    const recoveredKey = await unwrapAesKey(receiverKeys.privateKey, wrappedKey);
    const decrypted = await aesGcmDecrypt(recoveredKey, iv, ciphertext);
    const decryptedHash = await sha256Hex(decrypted);

    expect(decryptedHash).toBe(originalHash);
    expect(decrypted.byteLength).toBe(1024 * 1024);
  });

  // Test 5: Modified ciphertext payload (AES-GCM authentication tag verification failure)
  it("detects ciphertext tampering and rejects with authentication tag failure", async () => {
    const secretData = new TextEncoder().encode("Classified Defense Report");
    const aesKey = await generateAesKey();
    const { ciphertext, iv } = await aesGcmEncrypt(aesKey, bufferOf(secretData));

    // Attacker flips one byte in storage
    const tampered = new Uint8Array(ciphertext);
    tampered[10] = tampered[10]! ^ 0x01;

    // Decryption must fail (OperationError / tag mismatch)
    await expect(aesGcmDecrypt(aesKey, iv, tampered)).rejects.toBeDefined();
  });

  // Test 6: Wrong RSA key unwrap
  it("rejects AES key recovery when attempted by unauthorized recipient key", async () => {
    const legitimateRecipient = await generateRsaKeyPair();
    const unauthorizedAttacker = await generateRsaKeyPair();

    const aesKey = await generateAesKey();
    const wrappedKey = await wrapAesKey(legitimateRecipient.publicKey, aesKey);

    // Attacker attempts to unwrap key with attacker private key
    await expect(unwrapAesKey(unauthorizedAttacker.privateKey, wrappedKey)).rejects.toBeDefined();
  });

  // Test 7: Download Gate security checks
  it("enforces transfer token validity, expiration, download count, and unauthorized access", async () => {
    const SENDER = "11111111-1111-1111-1111-111111111111";
    const RECIPIENT = "22222222-2222-2222-2222-222222222222";
    const ATTACKER = "33333333-3333-3333-3333-333333333333";
    const VALID_TOKEN = generateTransferToken();
    const tokenHash = await sha256HexServer(VALID_TOKEN);

    const createTransferRecord = (id: string, overrides: Record<string, unknown> = {}) => ({
      id,
      sender_id: SENDER,
      recipient_id: RECIPIENT,
      status: "ENCRYPTED",
      token_hash: tokenHash,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      max_downloads: 1,
      download_count: 0,
      failed_attempts: 0,
      ...overrides,
    });

    // Mock DB
    const db: Record<string, Record<string, unknown>[]> = {
      transfers: [
        createTransferRecord("tr-unauth"),
        createTransferRecord("tr-invalid"),
        createTransferRecord("tr-valid"),
        createTransferRecord("tr-expired", {
          expires_at: new Date(Date.now() - 1000).toISOString(),
        }),
      ],
      profiles: [
        { id: RECIPIENT, trust_score: 95, trust_status: "TRUSTED" },
        { id: SENDER, trust_score: 95, trust_status: "TRUSTED" },
        { id: ATTACKER, trust_score: 95, trust_status: "TRUSTED" },
      ],
      app_sessions: [
        {
          id: "sess-1",
          user_id: RECIPIENT,
          revoked: false,
          ip_address: "127.0.0.1",
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        },
      ],
      transfer_keys: [
        { transfer_id: "tr-unauth", wrapped_key: "wrapped" },
        { transfer_id: "tr-invalid", wrapped_key: "wrapped" },
        { transfer_id: "tr-valid", wrapped_key: "wrapped" },
        { transfer_id: "tr-expired", wrapped_key: "wrapped" },
      ],
      notifications: [],
      audit_logs: [],
      threat_incidents: [],
      security_events: [],
      trust_events: [],
      devices: [],
    };

    const makeMockAdmin = () => {
      const table = (name: string) => (db[name] ??= []);
      const builder = (
        name: string,
        mode: "select" | "update" | "insert",
        payload?: Record<string, unknown>,
      ) => {
        const filters: { op: string; col: string; value: unknown }[] = [];
        const api: Record<string, unknown> = {};
        const run = () => {
          const rows = table(name).filter((r) =>
            filters.every((f) => {
              const v = r[f.col];
              if (f.op === "eq") return v === f.value;
              if (f.op === "gt") return String(v) > String(f.value);
              return true;
            }),
          );
          if (mode === "update" && payload) {
            rows.forEach((r) => Object.assign(r, payload));
            return { data: rows, error: null, count: rows.length };
          }
          return { data: rows, error: null, count: rows.length };
        };
        for (const op of ["eq", "gt", "gte", "lt", "neq"]) {
          api[op] = (col: string, value: unknown) => {
            filters.push({ op, col, value });
            return api;
          };
        }
        api["order"] = () => api;
        api["limit"] = () => api;
        api["select"] = () => api;
        api["maybeSingle"] = async () => {
          const { data } = run();
          return { data: data[0] ?? null, error: null };
        };
        api["single"] = async () => {
          const { data } = run();
          return { data: data[0] ?? null, error: null };
        };
        api["then"] = (resolve: (v: unknown) => unknown) => resolve(run());
        return api;
      };

      return {
        from: (name: string) => ({
          select: () => builder(name, "select"),
          update: (payload: Record<string, unknown>) => builder(name, "update", payload),
          insert: (payload: Record<string, unknown> | Record<string, unknown>[]) => {
            const rows = Array.isArray(payload) ? payload : [payload];
            const inserted: Record<string, unknown>[] = [];
            rows.forEach((r) => {
              const item = {
                id: `id-${Math.random().toString(36).slice(2)}`,
                created_at: new Date().toISOString(),
                ...r,
              };
              table(name).push(item);
              inserted.push(item);
            });
            const api: Record<string, unknown> = {
              data: inserted,
              error: null,
              select: () => api,
              maybeSingle: async () => ({ data: inserted[0] ?? null, error: null }),
              single: async () => ({ data: inserted[0] ?? null, error: null }),
              then: (resolve: (v: unknown) => unknown) => resolve({ data: inserted, error: null }),
            };
            return api;
          },
        }),
        storage: {
          from: () => ({
            createSignedUrl: async () => ({
              data: { signedUrl: "https://example.com/download" },
              error: null,
            }),
          }),
        },
      } as unknown as Parameters<typeof evaluateDownloadGate>[0];
    };

    const admin = makeMockAdmin();

    // 7a. Rejection: Unauthorized receiver
    const unauthResult = await evaluateDownloadGate(admin, {
      transferId: "tr-unauth",
      actorId: ATTACKER,
      token: VALID_TOKEN,
      ip: "127.0.0.1",
      deviceFingerprint: "dev-1",
      issueSignedUrl: false,
    });
    expect(unauthResult.ok).toBe(false);
    if (!unauthResult.ok) {
      expect(unauthResult.threat?.type).toBe("UNAUTHORIZED_RECEIVER");
    }

    // 7b. Rejection: Invalid token
    const invalidTokenResult = await evaluateDownloadGate(admin, {
      transferId: "tr-invalid",
      actorId: RECIPIENT,
      token: "incorrect-token-string",
      ip: "127.0.0.1",
      deviceFingerprint: "dev-1",
      issueSignedUrl: false,
    });
    expect(invalidTokenResult.ok).toBe(false);
    if (!invalidTokenResult.ok) {
      expect(invalidTokenResult.threat?.type).toBe("INVALID_TOKEN");
    }

    // 7c. Success: Valid authorization, token & session
    const validResult = await evaluateDownloadGate(admin, {
      transferId: "tr-valid",
      actorId: RECIPIENT,
      token: VALID_TOKEN,
      ip: "127.0.0.1",
      deviceFingerprint: "dev-1",
      issueSignedUrl: false,
    });
    expect(validResult.ok).toBe(true);

    // 7d. Rejection: Download limit exceeded on subsequent attempt
    const limitExceededResult = await evaluateDownloadGate(admin, {
      transferId: "tr-valid",
      actorId: RECIPIENT,
      token: VALID_TOKEN,
      ip: "127.0.0.1",
      deviceFingerprint: "dev-1",
      issueSignedUrl: false,
    });
    expect(limitExceededResult.ok).toBe(false);
    if (!limitExceededResult.ok) {
      expect(limitExceededResult.threat?.type).toBe("DOWNLOAD_LIMIT_EXCEEDED");
    }

    // 7e. Rejection: Expired transfer
    const expiredResult = await evaluateDownloadGate(admin, {
      transferId: "tr-expired",
      actorId: RECIPIENT,
      token: VALID_TOKEN,
      ip: "127.0.0.1",
      deviceFingerprint: "dev-1",
      issueSignedUrl: false,
    });
    expect(expiredResult.ok).toBe(false);
    if (!expiredResult.ok) {
      expect(expiredResult.threat?.type).toBe("TRANSFER_EXPIRED");
    }
  });
});
