
import sqlite3

DB_NAME = "secure_vault.db"


def create_connection():
    """Create a connection to the SQLite database."""
    return sqlite3.connect(DB_NAME)


def create_tables():
    """Create the vault metadata and encrypted entries tables."""

    with create_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                kdf_algorithm TEXT NOT NULL,
                kdf_iterations INTEGER NOT NULL,
                cipher_name TEXT NOT NULL,
                format_version INTEGER NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                entry_version INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL
            )
        """)


def save_metadata(salt, iterations, cipher_name):
    """Save the initial vault configuration."""

    with create_connection() as conn:
        conn.execute("""
            INSERT INTO vault_metadata
            (id, salt, kdf_algorithm, kdf_iterations,
             cipher_name, format_version)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            1,
            salt,
            "PBKDF2-HMAC-SHA256",
            iterations,
            cipher_name,
            1
        ))


def get_metadata():
    """Retrieve vault configuration."""

    with create_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT salt, kdf_algorithm, kdf_iterations,
                   cipher_name, format_version
            FROM vault_metadata
            WHERE id = 1
        """)

        return cursor.fetchone()


def save_entry(entry_id, entry_version, nonce, ciphertext):
    """Save an encrypted entry."""

    with create_connection() as conn:
        conn.execute("""
            INSERT INTO entries
            (id, entry_version, nonce, ciphertext)
            VALUES (?, ?, ?, ?)
        """, (entry_id, entry_version, nonce, ciphertext))


def get_entry(entry_id):
    """Retrieve an encrypted entry."""

    with create_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, entry_version, nonce, ciphertext
            FROM entries
            WHERE id = ?
        """, (entry_id,))

        return cursor.fetchone()


def list_entries():
    """List available entry IDs."""

    with create_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM entries")

        return cursor.fetchall()
