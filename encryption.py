
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Encryption configuration
KEY_LENGTH = 32       # 32 bytes = 256 bits
SALT_LENGTH = 16      # 16 bytes
NONCE_LENGTH = 12     # 12 bytes
ITERATIONS = 600000


def generate_salt():
    """Generate a cryptographically random salt."""
    return os.urandom(SALT_LENGTH)


def derive_key(passphrase, salt):
    """Derive a 256-bit encryption key using PBKDF2."""

    if not passphrase:
        raise ValueError("Passphrase cannot be empty")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS
    )

    return kdf.derive(passphrase.encode("utf-8"))


def build_aad(entry_id, entry_version, format_version):
    """Build associated authenticated data."""

    return (
        f"vault:{format_version}:entry:{entry_id}:"
        f"version:{entry_version}"
    ).encode("utf-8")


def encrypt_data(key, plaintext, aad):
    """Encrypt plaintext using AES-256-GCM."""

    nonce = os.urandom(NONCE_LENGTH)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        aad
    )

    return nonce, ciphertext


def decrypt_data(key, nonce, ciphertext, aad):
    """Decrypt and authenticate AES-256-GCM ciphertext."""

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        aad
    )

    return plaintext
