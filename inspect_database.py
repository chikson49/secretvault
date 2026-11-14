
import sqlite3

# Open the database in read-only mode
conn = sqlite3.connect(
    "file:secure_vault.db?mode=ro",
    uri=True
)

print("=== DATABASE INSPECTION ===")

# Inspect the entries table structure
columns = conn.execute(
    "PRAGMA table_info(entries)"
).fetchall()

print("\nEntries table columns:")
for column in columns:
    print(column[1], "-", column[2])

# Retrieve encrypted records without decrypting them
entries = conn.execute("""
    SELECT id, entry_version, nonce, ciphertext
    FROM entries
""").fetchall()

print("\n=== STORED ENTRIES ===")
print("Number of entries:", len(entries))

for entry in entries:
    entry_id, version, nonce, ciphertext = entry

    print("\nEntry ID:", entry_id)
    print("Entry version:", version)
    print("Nonce length:", len(nonce), "bytes")
    print("Ciphertext length:", len(ciphertext), "bytes")
    print("Ciphertext (hex):", ciphertext.hex())

conn.close()

print("\nDatabase inspection completed.")
