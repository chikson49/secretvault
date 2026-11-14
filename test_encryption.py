
import encryption
from cryptography.exceptions import InvalidTag


# Test passphrase
passphrase = "MyTestPassphrase123!"

# Generate salt
salt = encryption.generate_salt()

# Derive key
key = encryption.derive_key(passphrase, salt)

# Test data
plaintext = b"This is my first encrypted vault secret."

# Create associated data
aad = encryption.build_aad(
    entry_id="entry-001",
    entry_version=1,
    format_version=1
)

# Encrypt
nonce, ciphertext = encryption.encrypt_data(
    key,
    plaintext,
    aad
)

print("Original plaintext:", plaintext)
print("Generated nonce:", nonce.hex())
print("Encrypted data:", ciphertext.hex())

# Decrypt
decrypted = encryption.decrypt_data(
    key,
    nonce,
    ciphertext,
    aad
)

print("\nDecrypted plaintext:", decrypted)
print("Encryption/decryption successful:", decrypted == plaintext)


# Test tampering
tampered_ciphertext = bytearray(ciphertext)
tampered_ciphertext[0] ^= 1

try:
    encryption.decrypt_data(
        key,
        nonce,
        bytes(tampered_ciphertext),
        aad
    )

    print("Tampering test FAILED")

except InvalidTag:
    print("Tampering detected successfully!")
