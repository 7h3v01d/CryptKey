"""
cryptkey_license.py – Shared license engine for CryptKey v2.1+
================================================================
Uses Ed25519 asymmetric signing:
  • The PRIVATE key lives only in the license generator (never shipped).
  • The PUBLIC key is embedded in the app – it can verify but never forge.

Key format (before base64):
    <tier>:<expiry_YYYYMMDD>:<machine_or_ANY>:<ed25519_sig_hex>

Consumers (the app) only need:
    validate_license_key(key_str, public_key_b64) -> dict

Vendors (the generator) also use:
    generate_license_key(tier, expiry_days, machine_id, private_key_b64) -> str
    generate_keypair() -> (private_key_b64, public_key_b64)
    load_or_create_keypair(store_path, password) -> (priv_b64, pub_b64)
"""

import base64
import hashlib
import json
import os
import uuid
import platform
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    BestAvailableEncryption,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# ── Tier definitions ──────────────────────────────────────────────────────────
LICENSE_TIERS: dict = {
    "free": {
        "label": "Free", "max_files": 10,
        "shred": False, "batch": False, "price": "Free",
    },
    "personal": {
        "label": "Personal", "max_files": 500,
        "shred": True, "batch": False, "price": "$29",
    },
    "commercial": {
        "label": "Commercial", "max_files": -1,
        "shred": True, "batch": True, "price": "$99",
    },
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def machine_id() -> str:
    """Stable 16-char per-machine fingerprint."""
    parts = [platform.node(), platform.machine(), platform.processor()]
    try:
        parts.append(str(uuid.getnode()))
    except Exception:
        pass
    raw = "|".join(p for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Keypair management ────────────────────────────────────────────────────────

def generate_keypair() -> tuple[str, str]:
    """
    Generate a fresh Ed25519 keypair.
    Returns (private_key_b64, public_key_b64) – both PEM-encoded then base64'd
    for easy JSON storage.
    """
    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return (
        base64.b64encode(priv_pem).decode(),
        base64.b64encode(pub_pem).decode(),
    )


def _encrypt_private_key(priv_pem: bytes, password: str) -> bytes:
    """
    Re-serialize the private key with password-based encryption (PKCS8 + AES-256-CBC).
    This is what gets written to disk — even if someone steals the file,
    they cannot use the key without the master password.
    """
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    return private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        BestAvailableEncryption(password.encode()),
    )


def _decrypt_private_key(encrypted_pem: bytes, password: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(
        encrypted_pem, password=password.encode())


def load_or_create_keypair(store_path: Path, password: str) -> tuple[str, str]:
    """
    Load existing keypair from *store_path* (decrypting with *password*),
    or generate a new one, encrypt it, and save it.

    Returns (private_key_b64_unencrypted_in_memory, public_key_b64).
    The value stored on disk is always password-encrypted.
    """
    meta_path = store_path.with_suffix(".pub.json")

    if store_path.exists() and meta_path.exists():
        # Load existing
        encrypted_pem = store_path.read_bytes()
        try:
            private_key = _decrypt_private_key(encrypted_pem, password)
        except Exception as e:
            raise ValueError(f"Wrong master password or corrupted keyfile: {e}")
        pub_pem = private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        priv_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        return (
            base64.b64encode(priv_pem).decode(),
            base64.b64encode(pub_pem).decode(),
        )
    else:
        # Generate fresh
        private_key = Ed25519PrivateKey.generate()
        priv_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem = private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        encrypted_pem = _encrypt_private_key(priv_pem, password)
        store_path.parent.mkdir(parents=True, exist_ok=True)
        store_path.write_bytes(encrypted_pem)

        # Save public key + metadata separately (not secret)
        meta = {
            "created": _utcnow().isoformat(),
            "public_key_b64": base64.b64encode(pub_pem).decode(),
            "note": "Embed public_key_b64 in the CryptKey app source (LICENSE_PUBLIC_KEY).",
        }
        meta_path.write_text(json.dumps(meta, indent=2))

        return (
            base64.b64encode(priv_pem).decode(),
            base64.b64encode(pub_pem).decode(),
        )


# ── Sign / verify ─────────────────────────────────────────────────────────────

def _payload(tier: str, expiry: str, mid: str) -> bytes:
    return f"{tier}:{expiry}:{mid}".encode()


def generate_license_key(tier: str, expiry_days: int,
                          private_key_b64: str,
                          mid: str = "ANY") -> str:
    """
    Sign a license payload with the Ed25519 private key.
    Returns a base64-encoded token safe to copy-paste or email.
    """
    tier = tier.lower()
    if tier not in LICENSE_TIERS:
        raise ValueError(f"Unknown tier: {tier!r}")
    expiry = (_utcnow() + timedelta(days=expiry_days)).strftime("%Y%m%d")
    payload = _payload(tier, expiry, mid)

    priv_pem = base64.b64decode(private_key_b64)
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    sig_hex = private_key.sign(payload).hex()

    raw = f"{tier}:{expiry}:{mid}:{sig_hex}"
    return base64.b64encode(raw.encode()).decode()


def validate_license_key(key_str: str, public_key_b64: str) -> dict:
    """
    Verify a license key against the Ed25519 public key.
    Returns a result dict with keys: valid, tier, expiry, machine, message.
    """
    if not key_str or not key_str.strip():
        return {"valid": False, "tier": "free", "expiry": None,
                "machine": "ANY", "message": "No license key – running as Free."}
    try:
        raw = base64.b64decode(key_str.strip()).decode()
        # Format: tier:expiry:machine:sig_hex
        # sig_hex is 128 hex chars (64 bytes Ed25519), but split on ':' carefully
        # since machine could theoretically contain none – split on first 3 ':'
        parts = raw.split(":", 3)
        if len(parts) != 4:
            raise ValueError("Malformed key (expected 4 colon-separated fields)")
        tier, expiry_str, mid, sig_hex = parts

        if tier not in LICENSE_TIERS:
            raise ValueError(f"Unknown tier '{tier}'")

        payload = _payload(tier, expiry_str, mid)
        sig_bytes = bytes.fromhex(sig_hex)

        pub_pem = base64.b64decode(public_key_b64)
        public_key: Ed25519PublicKey = serialization.load_pem_public_key(pub_pem)
        try:
            public_key.verify(sig_bytes, payload)
        except InvalidSignature:
            raise ValueError("Signature verification failed – key may be forged or tampered")

        expiry_dt = datetime.strptime(expiry_str, "%Y%m%d")
        expired = _utcnow() > expiry_dt

        if expired:
            return {"valid": False, "tier": tier, "expiry": expiry_dt,
                    "machine": mid,
                    "message": f"License expired on {expiry_dt.strftime('%Y-%m-%d')}."}

        if mid != "ANY" and mid != machine_id():
            return {"valid": False, "tier": tier, "expiry": expiry_dt,
                    "machine": mid,
                    "message": "License is locked to a different machine."}

        label = LICENSE_TIERS[tier]["label"]
        return {
            "valid": True, "tier": tier, "expiry": expiry_dt, "machine": mid,
            "message": (f"✓ {label} license – valid until "
                        f"{expiry_dt.strftime('%Y-%m-%d')}"),
        }

    except Exception as e:
        return {"valid": False, "tier": "free", "expiry": None,
                "machine": "ANY", "message": f"Invalid key: {e}"}
