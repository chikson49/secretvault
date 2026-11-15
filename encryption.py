
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305
)


KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
ITERATIONS = 600000

AES_CIPHER = "AES-256-GCM"
CHACHA_CIPHER = "ChaCha20-Poly1305"

SUPPORTED_CIPHERS = (
    AES_CIPHER,
    CHACHA_CIPHER
)


def generate_salt():
    return os.urandom(SALT_LENGTH)


def derive_key(passphrase, salt, iterations=ITERATIONS):

    if not passphrase:
        raise ValueError("Passphrase cannot be empty")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations
    )

    return kdf.derive(passphrase.encode("utf-8"))


def build_aad(entry_id, entry_version, format_version):

    return (
        f"vault:{format_version}:entry:{entry_id}:"
        f"version:{entry_version}"
    ).encode("utf-8")


def encrypt_data(
    key,
    plaintext,
    aad,
    cipher_name=AES_CIPHER
):

    nonce = os.urandom(NONCE_LENGTH)

    if cipher_name == AES_CIPHER:
        cipher = AESGCM(key)

    elif cipher_name == CHACHA_CIPHER:
        cipher = ChaCha20Poly1305(key)

    else:
        raise ValueError("Unsupported cipher")

    ciphertext = cipher.encrypt(
        nonce,
        plaintext,
        aad
    )

    return nonce, ciphertext


def decrypt_data(
    key,
    nonce,
    ciphertext,
    aad,
    cipher_name=AES_CIPHER
):

    if cipher_name == AES_CIPHER:
        cipher = AESGCM(key)

    elif cipher_name == CHACHA_CIPHER:
        cipher = ChaCha20Poly1305(key)

    else:
        raise ValueError("Unsupported cipher")

    return cipher.decrypt(
        nonce,
        ciphertext,
        aad
    )
