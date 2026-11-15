
import sqlite3
import shutil
import database
import vault
import getpass

from cryptography.exceptions import InvalidTag

ORIGINAL_DB = "secure_vault.db"
TEST_DB = "aad_tampered_test.db"

# 1. Copy the original database
shutil.copy2(ORIGINAL_DB, TEST_DB)

print("Database copy created.")

# 2. Select an existing entry
entry_id = input("Enter an existing entry ID: ")

# 3. Change the entry version in the copied database
conn = sqlite3.connect(TEST_DB)

entry = conn.execute(
    "SELECT entry_version FROM entries WHERE id = ?",
    (entry_id,)
).fetchone()

if entry is None:
    print("Entry not found.")
    conn.close()
    raise SystemExit

original_version = entry[0]
modified_version = original_version + 1

conn.execute(
    "UPDATE entries SET entry_version = ? WHERE id = ?",
    (modified_version, entry_id)
)

conn.commit()
conn.close()

print("Entry version modified in test database.")
print("Original version:", original_version)
print("Modified version:", modified_version)

# 4. Point the application to the copied database
database.DB_NAME = TEST_DB

# 5. Attempt to unlock and retrieve the entry
passphrase = getpass.getpass(
    "Enter your original master passphrase: "
)

try:
    key = vault.unlock_vault(passphrase)

    print("Vault unlocked successfully.")

    secret = vault.retrieve_secret(key, entry_id)

    print("WARNING: Modified entry version was accepted:", secret)

except InvalidTag:
    print("SUCCESS: AES-GCM detected AAD tampering!")
    print("The modified entry was rejected.")

except Exception as error:
    print("Unexpected error:", error)

print("\nOriginal database remains unchanged.")
print("Test database:", TEST_DB)
