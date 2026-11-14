
import json
import uuid

import database
import encryption

from cryptography.exceptions import InvalidTag


CIPHER_NAME = "AES-256-GCM"
VERIFICATION_MARKER = b"SECRET_VAULT_PASSWORD_CHECK"


def create_vault(passphrase):

    database.create_tables()

    # Prevent accidentally overwriting an existing vault
    if database.get_metadata() is not None:
        raise ValueError("A vault already exists!")

    # Generate a random salt
    salt = encryption.generate_salt()

    # Derive the encryption key
    key = encryption.derive_key(
        passphrase,
        salt,
        encryption.ITERATIONS
    )

    # Encrypt the verification marker
    verification_aad = b"vault-verification:v1"

    verification_nonce, verification_ciphertext = (
        encryption.encrypt_data(
            key,
            VERIFICATION_MARKER,
            verification_aad
        )
    )

    # Store metadata in SQLite
    database.save_metadata(
        salt,
        encryption.ITERATIONS,
        CIPHER_NAME,
        verification_nonce,
        verification_ciphertext
    )

    return key


def unlock_vault(passphrase):

    metadata = database.get_metadata()

    if metadata is None:
        raise ValueError("No vault exists!")

    (
        salt,
        kdf_algorithm,
        iterations,
        cipher_name,
        format_version,
        verification_nonce,
        verification_ciphertext
    ) = metadata

    # Validate the stored configuration
    if kdf_algorithm != "PBKDF2-HMAC-SHA256":
        raise ValueError("Unsupported KDF algorithm")

    if cipher_name != CIPHER_NAME:
        raise ValueError("Unsupported cipher")

    if format_version != 1:
        raise ValueError("Unsupported vault format")

    # Derive the key using the original vault settings
    key = encryption.derive_key(
        passphrase,
        salt,
        iterations
    )

    # Verify the passphrase
    verification_aad = b"vault-verification:v1"

    decrypted_marker = encryption.decrypt_data(
        key,
        verification_nonce,
        verification_ciphertext,
        verification_aad
    )

    if decrypted_marker != VERIFICATION_MARKER:
        raise InvalidTag("Passphrase verification failed")

    return key


def add_secret(key, name, username, password):

    entry_id = str(uuid.uuid4())
    entry_version = 1
    format_version = 1

    # Store all sensitive fields inside the encrypted payload
    secret_data = {
        "name": name,
        "username": username,
        "password": password
    }

    plaintext = json.dumps(secret_data).encode("utf-8")

    # Bind the entry ID and version using AAD
    aad = encryption.build_aad(
        entry_id,
        entry_version,
        format_version
    )

    nonce, ciphertext = encryption.encrypt_data(
        key,
        plaintext,
        aad
    )

    # Store only encrypted data
    database.save_entry(
        entry_id,
        entry_version,
        nonce,
        ciphertext
    )

    return entry_id


def retrieve_secret(key, entry_id):

    entry = database.get_entry(entry_id)

    if entry is None:
        raise ValueError("Secret not found")

    (
        stored_id,
        entry_version,
        nonce,
        ciphertext
    ) = entry

    aad = encryption.build_aad(
        stored_id,
        entry_version,
        1
    )

    plaintext = encryption.decrypt_data(
        key,
        nonce,
        ciphertext,
        aad
    )

    return json.loads(plaintext.decode("utf-8"))
