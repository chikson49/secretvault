
import sqlite3

conn = sqlite3.connect("secure_vault.db")

conn.execute("""
    ALTER TABLE vault_metadata
    ADD COLUMN verification_nonce BLOB
""")

conn.execute("""
    ALTER TABLE vault_metadata
    ADD COLUMN verification_ciphertext BLOB
""")

conn.commit()
conn.close()

print("Database schema updated successfully!")
