
from getpass import getpass

import database
import vault
import encryption

from cryptography.exceptions import InvalidTag


def main():

    print("\n===== SECURE VAULT =====")
    print("Select encryption algorithm:")
    print("1. AES-256-GCM")
    print("2. ChaCha20-Poly1305")

    cipher_choice = input("\nSelect an option: ")

    # Select cipher and its dedicated database
    if cipher_choice == "1":

        cipher_name = encryption.AES_CIPHER
        #database.DB_NAME = "swapped_test.db"
        database.DB_NAME = "secure_vault.db"

    elif cipher_choice == "2":

        cipher_name = encryption.CHACHA_CIPHER
        database.DB_NAME = "chacha_vault.db"

    else:
        print("Invalid option.")
        return

    print("\nSelected:", cipher_name)
    print("Database:", database.DB_NAME)

    # Initialize the selected database
    database.create_tables()

    metadata = database.get_metadata()

    # First-time setup
    if metadata is None:

        print("\n=== Create Secure Vault ===")

        passphrase = getpass("Create master passphrase: ")
        confirmation = getpass("Confirm master passphrase: ")

        if passphrase != confirmation:
            print("Passphrases do not match.")
            return

        if not passphrase:
            print("Passphrase cannot be empty.")
            return

        try:
            key = vault.create_vault(
                passphrase,
                cipher_name
            )

            print("\nVault created successfully!")

        except ValueError as error:
            print("\nUnable to create vault:", error)
            return

    # Existing vault
    else:

        # Make sure the selected algorithm matches the database
        stored_cipher = metadata[3]

        if stored_cipher != cipher_name:

            print("\nCipher mismatch!")
            print("This database uses:", stored_cipher)
            print("You selected:", cipher_name)
            print("Please restart and select the correct algorithm.")
            return

        print("\n=== Unlock Secure Vault ===")

        passphrase = getpass("Enter master passphrase: ")

        try:
            key = vault.unlock_vault(passphrase)
            print("\nVault unlocked successfully!")

        except InvalidTag:
            print("\nIncorrect passphrase or invalid vault data.")
            return

        except ValueError as error:
            print(f"\nUnable to unlock vault: {error}")
            return

    # Main menu
    while True:

        print("1. Add secret")
        print("2. Retrieve secret")
        print("3. Modify secret")
        print("4. List entry IDs")
        print("5. Lock and exit")

        choice = input("\nSelect an option: ")

        if choice == "1":

            name = input("Secret name: ")
            username = input("Username: ")
            password = getpass("Secret password: ")

            try:
                entry_id = vault.add_secret(
                    key,
                    name,
                    username,
                    password
                )

                print("\nSecret encrypted and saved!")
                print("Entry ID:", entry_id)

            except Exception as error:
                print("Unable to save secret:", error)

        elif choice == "2":

            entry_id = input("Enter entry ID: ")

            try:
                secret = vault.retrieve_secret(
                    key,
                    entry_id
                )

                print("\n=== Retrieved Secret ===")
                print("Name:", secret["name"])
                print("Username:", secret["username"])
                print("Password:", secret["password"])

            except InvalidTag:
                print("Authentication failed. Data may have been modified.")

            except ValueError as error:
                print(error)

        elif choice == "3":

            entry_id = input("Enter entry ID to modify: ")

            name = input("New secret name: ")
            username = input("New username: ")
            password = getpass("New secret password: ")

            try:
                new_version = vault.update_secret(
                    key,
                    entry_id,
                    name,
                    username,
                    password
                )

                print("\nSecret updated successfully!")
                print("New entry version:", new_version)

            except InvalidTag:
                print("Authentication failed. Existing data may have been modified.")

            except ValueError as error:
                print("Unable to update secret:", error)               

        elif choice == "4":

            entries = database.list_entries()

            if not entries:
                print("\nNo secrets stored.")

            else:
                print("\nStored entry IDs:")

                for entry in entries:
                    print(entry[0])

        elif choice == "5":

            print("\nVault locked. Goodbye!")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
