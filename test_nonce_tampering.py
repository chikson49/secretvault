
import sqlite3
import shutil
import database
import vault
import getpass

from cryptography.exceptions import InvalidTag

ORIGINAL_DB = "secure_vault.db"
TEST_DB = "nonce_tampered_test.db"

# 1. Create a copy of the original database
shutil.copy2(ORIGINAL_DB, TEST_DB)

print("Database copy created.")

# 2. Select an existing entry
entry_id = input("Enter an existing entry ID: ")

# 3. Modify the nonce in the copied database
conn = sqlite3.connect(TEST_DB)

entry = conn.execute(
    "SELECT nonce FROM entries WHERE id = ?",
    (entry_id,)
).fetchone()

if entry is None:
    print("Entry not found.")
    conn.close()
    raise SystemExit

nonce = bytearray(entry[0])

# Flip one bit in the nonce
nonce[0] ^= 1

conn.execute(
    "UPDATE entries SET nonce = ? WHERE id = ?",
    (bytes(nonce), entry_id)
)

conn.commit()
conn.close()

print("Nonce modified in test database.")

# 4. Point the application to the copied database
database.DB_NAME = TEST_DB

# 5. Unlock the vault
passphrase = getpass.getpass(
    "Enter your original master passphrase: "
)


try:
    print("\nStep 1: Attempting to unlock vault...")

    key = vault.unlock_vault(passphrase)

    print("SUCCESS: Vault unlocked successfully.")

    print("\nStep 2: Attempting to retrieve modified entry...")

    secret = vault.retrieve_secret(key, entry_id)

    print("WARNING: Modified nonce was accepted:", secret)

except InvalidTag:
    print("\nSUCCESS: AES-GCM detected tampering!")

    print("The InvalidTag exception occurred.")

except Exception as error:
    print("\nUnexpected error:", repr(error))

print("\nOriginal database remains unchanged.")
print("Test database:", TEST_DB)

