
import sqlite3

DB_NAME = "secure_vault.db"


def create_connection():
    return sqlite3.connect(DB_NAME)


def create_tables():
    """Create the vault database tables."""

    with create_connection() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                kdf_algorithm TEXT NOT NULL,
                kdf_iterations INTEGER NOT NULL,
                cipher_name TEXT NOT NULL,
                format_version INTEGER NOT NULL,
                verification_nonce BLOB NOT NULL,
                verification_ciphertext BLOB NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                entry_version INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL
            )
        """)


def save_metadata(salt, iterations, cipher_name,
                  verification_nonce, verification_ciphertext):

    with create_connection() as conn:
        conn.execute("""
            INSERT INTO vault_metadata (
                id, salt, kdf_algorithm, kdf_iterations,
                cipher_name, format_version,
                verification_nonce, verification_ciphertext
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            1,
            salt,
            "PBKDF2-HMAC-SHA256",
            iterations,
            cipher_name,
            1,
            verification_nonce,
            verification_ciphertext
        ))


def update_entry(entry_id, expected_version, new_version, nonce, ciphertext):

    with create_connection() as conn:
        cursor = conn.execute("""
            UPDATE entries
            SET entry_version = ?,
                nonce = ?,
                ciphertext = ?
            WHERE id = ? AND entry_version = ?
        """, (
            new_version,
            nonce,
            ciphertext,
            entry_id,
            expected_version
        ))

        return cursor.rowcount


def get_metadata():

    with create_connection() as conn:
        return conn.execute("""
            SELECT salt, kdf_algorithm, kdf_iterations,
                   cipher_name, format_version,
                   verification_nonce, verification_ciphertext
            FROM vault_metadata
            WHERE id = 1
        """).fetchone()


def save_entry(entry_id, entry_version, nonce, ciphertext):

    with create_connection() as conn:
        conn.execute("""
            INSERT INTO entries (
                id, entry_version, nonce, ciphertext
            )
            VALUES (?, ?, ?, ?)
        """, (entry_id, entry_version, nonce, ciphertext))


def get_entry(entry_id):

    with create_connection() as conn:
        return conn.execute("""
            SELECT id, entry_version, nonce, ciphertext
            FROM entries
            WHERE id = ?
        """, (entry_id,)).fetchone()


def list_entries():

    with create_connection() as conn:
        return conn.execute("""
            SELECT id FROM entries
        """).fetchall()
