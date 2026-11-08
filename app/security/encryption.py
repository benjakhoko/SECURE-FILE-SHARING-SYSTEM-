"""Authenticated AES-256-GCM encryption for files at rest.

Stored file layout:
    MAGIC (5 bytes) | NONCE (12 bytes) | CIPHERTEXT + GCM TAG

The key is read from ``FILE_ENCRYPTION_KEY`` (environment / .env), which must be
a URL-safe base64 encoding of exactly 32 random bytes. It is never written to
the database or to source code.
"""

import base64
import binascii
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

MAGIC = b"SFSE\x01"
NONCE_SIZE = 12
KEY_SIZE = 32


class EncryptionError(Exception):
    """Raised when encryption/decryption fails or configuration is invalid."""


def generate_key() -> str:
    """Create a new URL-safe base64 AES-256 key suitable for .env."""
    return base64.urlsafe_b64encode(os.urandom(KEY_SIZE)).decode("ascii")


def _key_bytes() -> bytes:
    raw = current_app.config.get("FILE_ENCRYPTION_KEY") or ""
    if not raw:
        raise EncryptionError(
            "FILE_ENCRYPTION_KEY is not configured. Generate one with "
            "'flask generate-key' and add it to your .env file."
        )
    try:
        key = base64.urlsafe_b64decode(raw.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise EncryptionError("FILE_ENCRYPTION_KEY is not valid base64.") from exc
    if len(key) != KEY_SIZE:
        raise EncryptionError("FILE_ENCRYPTION_KEY must decode to exactly 32 bytes.")
    return key


def validate_key() -> None:
    """Validate the configured key (raises EncryptionError when invalid)."""
    _key_bytes()


def encrypt_bytes(plaintext: bytes) -> bytes:
    """Encrypt bytes with a fresh random nonce and return the on-disk blob."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise EncryptionError("Plaintext must be bytes.")
    aesgcm = AESGCM(_key_bytes())
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), MAGIC)
    return MAGIC + nonce + ciphertext


def decrypt_bytes(blob: bytes) -> bytes:
    """Verify and decrypt an on-disk blob.

    Raises ``EncryptionError`` if the blob is malformed or has been tampered
    with (GCM authentication failure). Never leaks cryptographic details.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise EncryptionError("Encrypted payload is invalid.")
    blob = bytes(blob)
    minimum = len(MAGIC) + NONCE_SIZE + 16  # tag length
    if len(blob) < minimum or not blob.startswith(MAGIC):
        raise EncryptionError("Encrypted file has an invalid format.")
    nonce = blob[len(MAGIC) : len(MAGIC) + NONCE_SIZE]
    ciphertext = blob[len(MAGIC) + NONCE_SIZE :]
    try:
        return AESGCM(_key_bytes()).decrypt(nonce, ciphertext, MAGIC)
    except Exception as exc:  # InvalidTag and any malformed input
        raise EncryptionError(
            "Encrypted file failed integrity verification. It may have been modified."
        ) from exc
