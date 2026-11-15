
import sqlite3
import shutil
import getpass

import database
import vault

from cryptography.exceptions import InvalidTag

ORIGINAL_DB = "secure_vault.db"
TEST_DB = "tampered_test.db"

# 1. Create a copy of the original database
shutil.copy2(ORIGINAL_DB, TEST_DB)

print("Database copy created.")

# 2. Ask for the entry ID to test
entry_id = input("Enter an existing entry ID: ")

# 3. Modify the ciphertext in the copied database
conn = sqlite3.connect(TEST_DB)

entry = conn.execute(
    "SELECT ciphertext FROM entries WHERE id = ?",
    (entry_id,)
).fetchone()

if entry is None:
    print("Entry not found.")
    conn.close()
    raise SystemExit

ciphertext = bytearray(entry[0])

# Flip one bit in the ciphertext
ciphertext[0] ^= 1

conn.execute(
    "UPDATE entries SET ciphertext = ? WHERE id = ?",
    (bytes(ciphertext), entry_id)
)

conn.commit()
conn.close()

print("Ciphertext modified in test database.")

# 4. Point the application at the copied database
database.DB_NAME = TEST_DB

# 5. Unlock the copied vault
passphrase = getpass.getpass("Enter your original master passphrase: ")

try:
    key = vault.unlock_vault(passphrase)
    print("Vault unlocked successfully.")

    # 6. Attempt to retrieve the modified entry
    secret = vault.retrieve_secret(key, entry_id)

    print("WARNING: Modified entry was decrypted:", secret)

except InvalidTag:
    print("SUCCESS: AES-GCM detected tampering!")
    print("The modified entry was rejected.")

except Exception as error:
    print("Unexpected error:", error)

print("\nOriginal database remains unchanged.")
print("Test database:", TEST_DB)
