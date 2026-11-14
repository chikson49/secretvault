import sqlite3

conn = sqlite3.connect("secure_vault.db")

print("Vault metadata columns:")
for column in conn.execute("PRAGMA table_info(vault_metadata)"):
    print(column)

print("\nEntries columns:")
for column in conn.execute("PRAGMA table_info(entries)"):
    print(column)

conn.close()
