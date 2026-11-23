import os
import re
from pathlib import Path
from typing import Optional
from fastapi import HTTPException
from backend.app.config import settings


def get_storage_base() -> Path:
    base = Path(settings.STORAGE_PATH).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base


def sanitize_filename(filename: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", filename)
    return cleaned.strip("._") or "payload"


def resolve_safe_path(rel_path: str) -> Path:
    base = get_storage_base()
    # Normalize separators
    normalized = rel_path.replace("\\", "/").strip("/")
    target = (base / normalized).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(status_code=400, detail="Invalid storage path traversal")
    return target


def save_encrypted_payload(rel_path: str, data: bytes) -> str:
    """Save an encrypted payload to safe disk storage."""
    target = resolve_safe_path(rel_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as f:
        f.write(data)
    return str(target.relative_to(get_storage_base())).replace("\\", "/")


def read_encrypted_payload(rel_path: str) -> bytes:
    """Read an encrypted payload from disk storage."""
    target = resolve_safe_path(rel_path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Encrypted payload not found on disk")
    with open(target, "rb") as f:
        return f.read()


def delete_encrypted_payload(rel_path: str) -> bool:
    """Delete an encrypted payload file if it exists."""
    try:
        target = resolve_safe_path(rel_path)
        if target.exists() and target.is_file():
            target.unlink()
            return True
        return False
    except Exception:
        return False
