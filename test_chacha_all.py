
import sqlite3
import shutil
import os
import tempfile

import database
import vault

from cryptography.exceptions import InvalidTag


ORIGINAL_DB = "chacha_vault.db"

ENTRY_ID = "5302e970-3ba3-4b87-9c71-5f05b484ee65"


def print_result(test_name, passed, detail=""):

    status = "PASS" if passed else "FAIL"

    print(f"[{status}] {test_name}")

    if detail:
        print("       " + detail)


def modify_database(source, destination, field):

    shutil.copy2(source, destination)

    conn = sqlite3.connect(destination)

    try:
        row = conn.execute(
            f"SELECT {field} FROM entries WHERE id = ?",
            (ENTRY_ID,)
        ).fetchone()

        if row is None:
            raise ValueError("Test entry not found")

        original = row[0]

        if field == "entry_version":
            modified = original + 1
        else:
            modified = bytearray(original)
            modified[0] ^= 1
            modified = bytes(modified)

        conn.execute(
            f"UPDATE entries SET {field} = ? WHERE id = ?",
            (modified, ENTRY_ID)
        )

        conn.commit()

    finally:
        conn.close()


def test_correct_passphrase(passphrase):

    database.DB_NAME = ORIGINAL_DB

    try:
        key = vault.unlock_vault(passphrase)
        print_result("Correct passphrase", True)
        return key

    except Exception as error:
        print_result("Correct passphrase", False, str(error))
        return None


def test_wrong_passphrase():

    try:
        vault.unlock_vault("DefinitelyWrongPassphrase123!")
        print_result("Wrong passphrase rejection", False)

    except InvalidTag:
        print_result("Wrong passphrase rejection", True)

    except Exception as error:
        print_result(
            "Wrong passphrase rejection",
            False,
            str(error)
        )



def test_tampering(field, description, passphrase):

    database.DB_NAME = ORIGINAL_DB

    test_db = f"chacha_test_{field}.db"

    try:
        modify_database(
            ORIGINAL_DB,
            test_db,
            field
        )

        database.DB_NAME = test_db

        key = vault.unlock_vault(passphrase)

        try:
            vault.retrieve_secret(key, ENTRY_ID)

            print_result(
                description,
                False,
                "Modified data accepted"
            )

        except InvalidTag:
            print_result(
                description,
                True,
                "Authentication failed as expected"
            )

    except Exception as error:
        print_result(description, False, str(error))

    finally:
        # Switch away from the test database
        database.DB_NAME = ORIGINAL_DB

        # Allow SQLite to release file handles
        try:
            conn = sqlite3.connect(test_db)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
        except sqlite3.Error:
            pass

        # Remove the temporary database
        try:
            if os.path.exists(test_db):
                os.remove(test_db)
        except PermissionError:
            print(
                "WARNING: Could not remove temporary database:",
                test_db
            )


def test_invalid_entry(key):

    database.DB_NAME = ORIGINAL_DB

    try:
        vault.retrieve_secret(
            key,
            "00000000-0000-0000-0000-000000000000"
        )

        print_result("Invalid entry ID", False)

    except ValueError:
        print_result("Invalid entry ID", True, "Missing entry rejected")

    except Exception as error:
        print_result("Invalid entry ID", False, str(error))


def main():

    print("\n======================================")
    print(" CHACHA20-POLY1305 SECURITY TEST SUITE")
    print("======================================")

    if not os.path.exists(ORIGINAL_DB):
        print("ChaCha database not found!")
        return

    database.DB_NAME = ORIGINAL_DB

    metadata = database.get_metadata()

    if metadata is None or metadata[3] != "ChaCha20-Poly1305":
        print("Selected database is not a ChaCha20 vault!")
        return

    passphrase = input("Enter ChaCha vault passphrase: ")

    key = test_correct_passphrase(passphrase)

    if key is None:
        print("\nCannot continue: vault unlock failed.")
        return

    test_wrong_passphrase()

    test_tampering(
        "ciphertext",
        "Ciphertext tampering",
        passphrase
    )

    test_tampering(
        "nonce",
        "Nonce tampering",
        passphrase
    )

    test_tampering(
        "entry_version",
        "Entry version / AAD tampering",
        passphrase
    )

    test_invalid_entry(key)

    database.DB_NAME = ORIGINAL_DB

    print("\n======================================")
    print(" TEST SUITE COMPLETED")
    print(" Original database remains unchanged.")
    print("======================================")


if __name__ == "__main__":
    main()
