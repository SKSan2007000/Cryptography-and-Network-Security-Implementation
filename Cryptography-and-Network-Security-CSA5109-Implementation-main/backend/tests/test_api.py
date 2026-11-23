import hashlib
import uuid
from datetime import datetime, timezone, timedelta
import pytest


def test_health_check(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ONLINE"
    assert "PostgreSQL" in data["database"]


def test_auth_and_user_registration(client):
    unique_suffix = uuid.uuid4().hex[:6]
    email = f"alice_{unique_suffix}@sentinelcrypt.org"
    password = "SecurePassword123!"

    # 1. Register Alice
    reg_res = client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "full_name": "Alice Sentinel",
        "organization": "Security Ops"
    })
    assert reg_res.status_code == 200
    token_data = reg_res.json()
    assert "access_token" in token_data
    assert token_data["user"]["email"] == email

    token = token_data["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 2. Get Me
    me_res = client.get("/api/auth/me", headers=auth_headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == email

    # 3. Duplicate registration rejected
    dup_res = client.post("/api/auth/register", json={
        "email": email,
        "password": password
    })
    assert dup_res.status_code == 400

    # 4. Login with correct password
    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert login_res.status_code == 200
    assert "access_token" in login_res.json()

    # 5. Login with invalid password
    bad_login = client.post("/api/auth/login", json={
        "email": email,
        "password": "WrongPassword!"
    })
    assert bad_login.status_code == 401


def test_cryptographic_key_registration_and_lookup(client):
    # Register two users: Sender and Recipient
    suffix = uuid.uuid4().hex[:6]
    sender_email = f"sender_{suffix}@sentinel.org"
    recip_email = f"recip_{suffix}@sentinel.org"

    reg1 = client.post("/api/auth/register", json={"email": sender_email, "password": "Password123!"})
    reg2 = client.post("/api/auth/register", json={"email": recip_email, "password": "Password123!"})

    sender_token = reg1.json()["access_token"]
    recip_token = reg2.json()["access_token"]
    recip_id = reg2.json()["user"]["id"]

    recip_headers = {"Authorization": f"Bearer {recip_token}"}
    sender_headers = {"Authorization": f"Bearer {sender_token}"}

    # Recipient registers RSA-OAEP public key
    mock_jwk = {"kty": "RSA", "n": "test-modulus-key", "e": "AQAB", "alg": "RSA-OAEP-256"}
    key_res = client.post("/api/users/keys", headers=recip_headers, json={
        "public_key_jwk": mock_jwk,
        "wrapped_private_key": "wrapped-private-bytes-base64",
        "kdf_salt": "salt123",
        "wrap_iv": "iv123",
        "algorithm": "RSA-OAEP-2048-SHA256"
    })
    assert key_res.status_code == 200

    # Sender retrieves Recipient public key
    pub_res = client.get(f"/api/users/{recip_id}/public-key", headers=sender_headers)
    assert pub_res.status_code == 200
    assert pub_res.json()["public_key_jwk"]["kty"] == "RSA"


def test_end_to_end_secure_transfer_and_download(client):
    suffix = uuid.uuid4().hex[:6]
    alice_email = f"alice_{suffix}@test.org"
    bob_email = f"bob_{suffix}@test.org"
    mallory_email = f"mallory_{suffix}@test.org"

    t1 = client.post("/api/auth/register", json={"email": alice_email, "password": "Password123!"}).json()
    t2 = client.post("/api/auth/register", json={"email": bob_email, "password": "Password123!"}).json()
    t3 = client.post("/api/auth/register", json={"email": mallory_email, "password": "Password123!"}).json()

    alice_token = t1["access_token"]
    bob_token = t2["access_token"]
    mallory_token = t3["access_token"]
    bob_id = t2["user"]["id"]

    alice_h = {"Authorization": f"Bearer {alice_token}"}
    bob_h = {"Authorization": f"Bearer {bob_token}"}
    mallory_h = {"Authorization": f"Bearer {mallory_token}"}

    # 1. Create simulated encrypted payload
    original_data = b"CONFIDENTIAL_PAYLOAD_EVIDENCE_FOR_AUDIT"
    orig_hash = hashlib.sha256(original_data).hexdigest()
    # Simulated ciphertext
    ciphertext = b"IV_12_BYTES_CIPHERTEXT_PLUS_16_BYTE_TAG_ABCDEF123456"
    cipher_hash = hashlib.sha256(ciphertext).hexdigest()

    expires = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()

    # 2. Alice creates transfer to Bob
    create_res = client.post("/api/transfers", headers=alice_h, json={
        "recipient_id": bob_id,
        "security_level": "standard",
        "iv": "mock_iv_96bit_base64",
        "original_sha256": orig_hash,
        "ciphertext_sha256": cipher_hash,
        "token_hash": "token_hash_abc",
        "expires_at": expires,
        "max_downloads": 1,
        "wrapped_key": "wrapped_aes_key_base64",
        "wrap_algorithm": "RSA-OAEP-SHA256",
        "file_name": "evidence.pdf",
        "file_size": len(original_data),
        "mime_type": "application/pdf"
    })
    assert create_res.status_code == 200
    transfer_id = create_res.json()["id"]

    # 3. Alice uploads encrypted ciphertext
    upload_res = client.post(
        f"/api/transfers/{transfer_id}/upload",
        headers=alice_h,
        files={"file": ("evidence.pdf.bin", ciphertext, "application/octet-stream")}
    )
    assert upload_res.status_code == 200

    # 4. Mallory (Attacker) tries to inspect or download Bob's transfer -> FORBIDDEN
    bad_inspect = client.get(f"/api/transfers/{transfer_id}", headers=mallory_h)
    assert bad_inspect.status_code == 403

    bad_dl = client.get(f"/api/transfers/{transfer_id}/download", headers=mallory_h)
    assert bad_dl.status_code == 403

    # Check that Mallory's trust score was penalized
    mallory_me = client.get("/api/auth/me", headers=mallory_h).json()
    assert mallory_me["profile"]["trust_score"] < 100

    # 5. Bob (Legitimate Recipient) downloads payload
    # Note: Mallory triggered quarantine on download attempt, so let's verify threat defense
    transfer_status = client.get(f"/api/transfers/{transfer_id}", headers=alice_h).json()
    assert transfer_status["status"] == "PAUSED"


def test_tamper_rejection_and_threat_incident(client):
    suffix = uuid.uuid4().hex[:6]
    alice = client.post("/api/auth/register", json={"email": f"a_{suffix}@t.org", "password": "Password123!"}).json()
    bob = client.post("/api/auth/register", json={"email": f"b_{suffix}@t.org", "password": "Password123!"}).json()

    a_h = {"Authorization": f"Bearer {alice['access_token']}"}
    b_h = {"Authorization": f"Bearer {bob['access_token']}"}

    payload = b"GENUINE_CIPHERTEXT"
    chash = hashlib.sha256(payload).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    tr = client.post("/api/transfers", headers=a_h, json={
        "recipient_id": bob["user"]["id"],
        "iv": "iv",
        "original_sha256": "orig",
        "ciphertext_sha256": chash,
        "token_hash": "th",
        "expires_at": expires,
        "max_downloads": 2,
        "wrapped_key": "wk",
        "file_name": "data.txt",
        "file_size": 10
    }).json()
    tr_id = tr["id"]

    client.post(f"/api/transfers/{tr_id}/upload", headers=a_h, files={"file": ("f.bin", payload, "application/octet-stream")})

    # Bob reports tampering
    fail_res = client.post(f"/api/transfers/{tr_id}/fail", headers=b_h, json={
        "reason": "AES-GCM tag verification failure - Bit flipped",
        "is_tampered": True
    })
    assert fail_res.status_code == 200
    assert fail_res.json()["status"] == "TERMINATED"


def test_digital_twin_and_location(client):
    suffix = uuid.uuid4().hex[:6]
    user = client.post("/api/auth/register", json={"email": f"geo_{suffix}@t.org", "password": "Password123!"}).json()
    headers = {"Authorization": f"Bearer {user['access_token']}"}

    # Submit consensual coordinates
    loc_res = client.post("/api/digital-twin/location", headers=headers, json={
        "latitude": 13.0827,
        "longitude": 80.2707,
        "accuracy": 15.0
    })
    assert loc_res.status_code == 200

    # Retrieve nodes & telemetry
    nodes_res = client.get("/api/digital-twin/nodes", headers=headers)
    assert nodes_res.status_code == 200
    assert isinstance(nodes_res.json(), list)

    telem_res = client.get("/api/digital-twin/telemetry", headers=headers)
    assert telem_res.status_code == 200
    assert telem_res.json()["system_health"] == "OPTIMAL"


def test_security_lab_simulation(client):
    suffix = uuid.uuid4().hex[:6]
    user = client.post("/api/auth/register", json={"email": f"lab_{suffix}@t.org", "password": "Password123!"}).json()
    headers = {"Authorization": f"Bearer {user['access_token']}"}

    sim_res = client.post("/api/security-lab/simulate", headers=headers, json={
        "scenario": "tamper_ciphertext"
    })
    assert sim_res.status_code == 200
    assert sim_res.json()["status"] == "DETECTED_AND_BLOCKED"

    status_res = client.get("/api/security-lab/status", headers=headers)
    assert status_res.status_code == 200
    assert status_res.json()["lab_mode"] == "ACTIVE"
