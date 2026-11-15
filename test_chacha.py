
import encryption

from cryptography.exceptions import InvalidTag

# 1. Generate a random encryption key
salt = encryption.generate_salt()

key = encryption.derive_key(
    "TestPassphrase123!",
    salt
)

# 2. Define test plaintext and AAD
plaintext = b"This is my first ChaCha20 encrypted secret."
aad = b"chacha-test-v1"

print("Original plaintext:", plaintext)

# 3. Encrypt using ChaCha20-Poly1305
nonce, ciphertext = encryption.encrypt_data(
    key,
    plaintext,
    aad,
    encryption.CHACHA_CIPHER
)

print("\nGenerated nonce:", nonce.hex())
print("Encrypted data:", ciphertext.hex())

# 4. Decrypt using ChaCha20-Poly1305
decrypted = encryption.decrypt_data(
    key,
    nonce,
    ciphertext,
    aad,
    encryption.CHACHA_CIPHER
)

print("\nDecrypted plaintext:", decrypted)

print(
    "Encryption/decryption successful:",
    decrypted == plaintext
)

# 5. Test ciphertext tampering
modified_ciphertext = bytearray(ciphertext)
modified_ciphertext[0] ^= 1

try:
    encryption.decrypt_data(
        key,
        nonce,
        bytes(modified_ciphertext),
        aad,
        encryption.CHACHA_CIPHER
    )

    print("WARNING: Tampering was not detected!")

except InvalidTag:
    print("\nTampering detected successfully!")
