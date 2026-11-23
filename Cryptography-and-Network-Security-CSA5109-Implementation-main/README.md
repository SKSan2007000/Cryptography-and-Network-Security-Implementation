# SentinelCrypt — Trust-Aware Secure File Transfer Platform

SentinelCrypt is an end-to-end encrypted file transfer platform with a transparent,
rule-based threat detection engine. Files are encrypted **in the browser** with
AES-256-GCM; the session key is wrapped for the recipient with RSA-OAEP-2048; and every
transfer is fingerprinted with SHA-256 so tampering is provably detectable. The server
never sees a plaintext file or an unwrapped key.

---

## 1. Security model

| Layer                | Mechanism                                                      | Where it runs          |
| -------------------- | -------------------------------------------------------------- | ---------------------- |
| File confidentiality | AES-256-GCM, fresh 96-bit IV per transfer                      | Browser (Web Crypto)   |
| Key exchange         | RSA-OAEP-2048 (SHA-256) wrapping of the AES key                | Browser                |
| Private key at rest  | PBKDF2-SHA-256 (250,000 iterations) → AES-256-GCM wrap         | Browser                |
| Integrity            | SHA-256 of plaintext and ciphertext, verified after decryption | Browser + server check |
| Access control       | Single-use hashed transfer token, expiry, download limit       | Server                 |
| Authorization        | Postgres Row Level Security on every table                     | Database               |
| Threat response      | Rule engine with trust deltas and automatic termination        | Server                 |

**Trust Score (0–100)** is an application-defined heuristic, not an industry standard.
It starts at 100 and decreases when the engine records an anomaly.

### Threat rules

| Threat                                                                      | Severity   | Trust delta | Response           |
| --------------------------------------------------------------------------- | ---------- | ----------- | ------------------ |
| `INTEGRITY_FAILURE`                                                         | critical   | −50         | terminate transfer |
| `INVALID_TOKEN`                                                             | high       | −30         | terminate transfer |
| `TOKEN_REPLAY`                                                              | high       | −30         | terminate transfer |
| `UNAUTHORIZED_RECEIVER`                                                     | high       | −20         | pause transfer     |
| `SUSPICIOUS_IP_CHANGE`                                                      | medium     | −15         | log + notify       |
| `CONCURRENT_SESSIONS` / `DEVICE_CHANGE`                                     | medium/low | −10 / −5    | log + notify       |
| `DOWNLOAD_LIMIT_EXCEEDED`, `TRANSFER_EXPIRED`, `EXCESSIVE_FAILED_DOWNLOADS` | varies     | −5 … −20    | block download     |

The authoritative table is `src/lib/security-rules.ts`.

---

## 2. Transfer pipeline

**Send**

1. Validate the file (25 MB limit, executable extensions blocked).
2. SHA-256 the plaintext → `original_sha256`.
3. Generate a random AES-256 key + 12-byte IV, encrypt with AES-GCM.
4. SHA-256 the ciphertext → `ciphertext_sha256`.
5. Fetch the recipient's RSA public key, wrap the AES key (RSA-OAEP).
6. Upload the ciphertext to private storage; persist metadata, wrapped key, and the
   SHA-256 hash of the single-use transfer token.

**Receive**

1. Present the transfer token → server verifies the token hash, expiry, download count,
   recipient identity, and session/device signals.
2. Server issues a short-lived signed URL for the ciphertext.
3. Unlock the RSA private key with the account passphrase (PBKDF2), unwrap the AES key.
4. Decrypt with AES-GCM (the GCM tag already rejects tampering).
5. SHA-256 the plaintext and report it to the server, which compares it to the sender's
   record. A mismatch raises `INTEGRITY_FAILURE` and terminates the transfer.

---

## 3. Application routes

Public: `/` landing, `/auth` sign in, `/register`, `/cryptography` (technical reference).

Authenticated: `/dashboard`, `/send`, `/inbox`, `/sent`, `/transfer/$id`, `/security`,
`/audit`, `/profile`, `/settings`, `/security-lab` (Controlled Security Testing Lab),
`/demo` (Threat Simulator).

Admin (requires the `admin` role): `/admin`, `/admin/users`, `/admin/transfers`,
`/admin/threats`, `/admin/audit`, `/admin/performance`.

---

## 4. Data model

`profiles`, `user_roles`, `user_keys`, `transfers`, `transfer_keys`, `file_metadata`,
`audit_logs`, `security_events`, `threat_incidents`, `notifications`, `devices`,
`app_sessions`. Every table has RLS enabled: users reach only their own rows (or rows of
transfers they are party to); administrators read globally through the `has_role`
security-definer function. `audit_logs`, `security_events`, and `threat_incidents` are
append-only from the server — clients cannot insert, update, or delete them.

---

## 5. Demonstration mode

**Controlled Security Testing Lab (`/security-lab`)** provisions dedicated lab accounts
(`lab-receiver@sentinelcrypt.test`, `lab-attacker@sentinelcrypt.test`) and real encrypted
lab transfers, then executes seven scenarios through the production download gate,
threat engine, and integrity verifier: Invalid Transfer Token, Token Replay,
Unauthorized Receiver, Expired Transfer, Integrity Tampering, Suspicious Session /
Network Anomaly, and Abnormal Download Attempts. Each run reports observed source
evidence, detection stage, threat type, response action, trust before/after, transfer
status change, notifications created, and audit entries recorded.

**Threat Simulator (`/demo`)** triggers rule evaluations flagged `simulated = true`, so
every simulated incident is labelled **DEMO SIMULATION** in the admin threat table and
never contaminates real audit conclusions.

Session monitoring enrols a user's first device without penalty and reuses the live
session for the same device fingerprint, so ordinary sign-in and navigation never deduct
trust; only genuinely new devices, other-device concurrency, and differing network
sources raise threats.

---

## 6. Running and testing

```bash
npm install
npm run dev      # http://localhost:8080
npx vitest run   # automated test suite
```

The test suite covers SHA-256 fingerprints against known vectors, AES-256-GCM
round-trips, tamper and wrong-key rejection, RSA-OAEP wrap/unwrap, passphrase-protected
private keys, transfer-token uniqueness, trust-score arithmetic and banding, threat rule
invariants, and file validation.

---

## 7. Honest limitations

- Trust Score is a project-defined heuristic, not a certified risk metric.
- Threat detection is rule-based, not machine learning; there is no anomaly model.
- Files are limited to 25 MB and encrypted in memory, so very large files are out of scope.
- Losing the key passphrase makes previously received files permanently undecryptable —
  by design, since the server never holds the private key.
- IP and device signals come from request metadata and can be spoofed by a determined
  attacker; they are corroborating signals, not proof.
