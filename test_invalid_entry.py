
import database
import vault
import getpass

# Use the original database
database.DB_NAME = "secure_vault.db"

print("Testing invalid entry retrieval.")

# 1. Ask for the master passphrase
passphrase = getpass.getpass("Enter your master passphrase: ")

try:
    # 2. Unlock the vault
    key = vault.unlock_vault(passphrase)

    print("Vault unlocked successfully.")

    # 3. Use an entry ID that should not exist
    invalid_entry_id = "00000000-0000-0000-0000-000000000000"

    print("\nAttempting to retrieve a non-existent entry...")

    secret = vault.retrieve_secret(key, invalid_entry_id)

    if secret is None:
        print("SUCCESS: No record was returned.")
    else:
        print("WARNING: Unexpected record returned:", secret)

except ValueError as error:
    if str(error) == "Secret not found":
        print("SUCCESS: Application handled missing entry.")
    else:
        print("Unexpected ValueError:", error)

except Exception as error:
    print("Unexpected error:", type(error).__name__, str(error))
