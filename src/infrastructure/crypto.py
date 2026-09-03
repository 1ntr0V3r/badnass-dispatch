"""Infrastructure crypto adapters.

Implements:
- HmacIntegrityService: HMAC-SHA256 with constant-time comparison
- DriverDataEncryptor: AES-256-GCM authenticated encryption for CNDP/GDPR PII
"""

from __future__ import annotations

import hashlib
import hmac
import os
from base64 import b64decode, b64encode
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# HMAC Integrity Service
# ---------------------------------------------------------------------------


class HmacIntegrityService:
    """Verifies HMAC-SHA256 signatures using constant-time comparison.

    Protects against timing-based side-channel attacks that could allow
    an attacker to infer the valid signature byte-by-byte.
    """

    def verify_hmac(
        self,
        payload: bytes,
        received_signature: str,
        client_secret: str,
    ) -> bool:
        """Verify HMAC-SHA256 via constant-time hmac.compare_digest.

        Args:
            payload: Raw request body bytes to verify.
            received_signature: Hex-encoded signature from X-Signature-HMAC header.
            client_secret: Pre-shared secret for this client.

        Returns:
            True if signature is cryptographically valid.
        """
        try:
            secret_bytes = client_secret.encode("utf-8")
            expected_mac = hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_mac, received_signature.lower())
        except Exception:  # noqa: BLE001
            return False


# ---------------------------------------------------------------------------
# AES-256-GCM Driver PII Encryptor
# ---------------------------------------------------------------------------


@dataclass
class EncryptedBlob:
    """Container for AES-256-GCM ciphertext with authentication tag and nonce."""

    nonce_b64: str          # 12-byte GCM nonce, base64-encoded
    ciphertext_b64: str     # Ciphertext + GCM auth tag, base64-encoded


class DriverDataEncryptor:
    """AES-256-GCM authenticated encryption for sensitive driver PII.

    Complies with:
    - CNDP Loi 09-08 (Moroccan data protection law)
    - GDPR Article 32 (appropriate technical security measures)

    Each encryption call uses a fresh cryptographically random 12-byte nonce
    to guarantee semantic security (IND-CPA) even when encrypting identical
    plaintexts multiple times.

    Key is loaded from AES_256_KEY_HEX environment variable (32 raw bytes = 64 hex chars).
    """

    def __init__(self, key_hex: str) -> None:
        """Initialize with 256-bit key from hex string.

        Args:
            key_hex: 64-character hex string representing 32 raw bytes.

        Raises:
            ValueError: If key is not exactly 32 bytes.
        """
        raw_key = bytes.fromhex(key_hex)
        if len(raw_key) != 32:
            raise ValueError(
                f"AES-256 key must be 32 bytes (64 hex chars), got {len(raw_key)} bytes"
            )
        self._aesgcm = AESGCM(raw_key)

    def encrypt(self, plaintext: str) -> EncryptedBlob:
        """Encrypt plaintext with AES-256-GCM using a fresh random nonce.

        Args:
            plaintext: UTF-8 string to encrypt (e.g., national ID, phone).

        Returns:
            EncryptedBlob with nonce and ciphertext (both base64-encoded).
        """
        nonce = os.urandom(12)  # 96-bit nonce per GCM recommendation
        plaintext_bytes = plaintext.encode("utf-8")
        ciphertext = self._aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
        return EncryptedBlob(
            nonce_b64=b64encode(nonce).decode("ascii"),
            ciphertext_b64=b64encode(ciphertext).decode("ascii"),
        )

    def decrypt(self, blob: EncryptedBlob) -> str:
        """Decrypt an EncryptedBlob back to plaintext.

        Args:
            blob: Previously encrypted blob.

        Returns:
            Decrypted UTF-8 string.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails (tampered data).
        """
        nonce = b64decode(blob.nonce_b64)
        ciphertext = b64decode(blob.ciphertext_b64)
        plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext_bytes.decode("utf-8")

    def encrypt_field(self, value: str) -> str:
        """Encrypt and serialize to a single storable string (nonce::ciphertext).

        Args:
            value: Plaintext string.

        Returns:
            Serialized encrypted string for DB storage.
        """
        blob = self.encrypt(value)
        return f"{blob.nonce_b64}::{blob.ciphertext_b64}"

    def decrypt_field(self, stored: str) -> str:
        """Deserialize and decrypt a stored encrypted field.

        Args:
            stored: Previously serialized string from encrypt_field().

        Returns:
            Original plaintext string.
        """
        nonce_b64, ciphertext_b64 = stored.split("::", 1)
        return self.decrypt(EncryptedBlob(nonce_b64=nonce_b64, ciphertext_b64=ciphertext_b64))
