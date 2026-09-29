"""
Envelope encryption helpers, built on Fernet (AES-128 in CBC mode with a
SHA-256 HMAC, from the `cryptography` library — authenticated encryption,
so a tampered file fails to decrypt rather than decrypting to garbage).

The pattern used across this app for every file:

    1. Generate a brand-new random key just for this one file.
    2. Encrypt the file's bytes with that key       -> stored on disk.
    3. Encrypt ("wrap") that key with the app's master key
                                                     -> stored in the database.

To read the file back: unwrap the per-file key using the master key, then
use that to decrypt the file bytes. The master key is the only secret that
must be kept safe (it lives in .env, never in the database or the repo).
"""

from cryptography.fernet import Fernet
from flask import current_app


def get_master_fernet() -> Fernet:
    return Fernet(current_app.config["MASTER_KEY"])


def generate_file_key() -> bytes:
    """A fresh, random key — one per uploaded file."""
    return Fernet.generate_key()


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)


def wrap_key(file_key: bytes) -> bytes:
    """Encrypt a per-file key using the master key, for safe DB storage."""
    return get_master_fernet().encrypt(file_key)


def unwrap_key(wrapped_key: bytes) -> bytes:
    """Recover a per-file key using the master key."""
    if isinstance(wrapped_key, memoryview):
        wrapped_key = bytes(wrapped_key)
    return get_master_fernet().decrypt(wrapped_key)
