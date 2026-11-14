
from getpass import getpass

import database
import vault

from cryptography.exceptions import InvalidTag


def main():

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

        key = vault.create_vault(passphrase)

        print("\nVault created successfully!")

    # Existing vault
    else:

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

        print("\n===== SECURE VAULT =====")
        print("1. Add secret")
        print("2. Retrieve secret")
        print("3. List entry IDs")
        print("4. Lock and exit")

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

            entries = database.list_entries()

            if not entries:
                print("\nNo secrets stored.")

            else:
                print("\nStored entry IDs:")

                for entry in entries:
                    print(entry[0])

        elif choice == "4":

            print("\nVault locked. Goodbye!")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
