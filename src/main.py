from getpass import getpass

from cryptography.exceptions import InvalidTag

from .crypto import Generate_Salt, Derive_Key

from .database import (
	Initialize_Database, Get_Salt, Create_Vault, Get_Vault, Update_Vault,
)
from .password_generator import Generate_Password

from .vault import Encrypt_Vault, Decrypt_Vault

from pathlib import Path

#Creates the master password when program is first started up
def Create_Master_Password():
	SCRIPT_DIR = Path(__file__).parent
	file_path = SCRIPT_DIR / "common-passwords.txt"

	while True:
		bad_password = False
		Password = getpass("Create a master password: ")
		if len(Password) < 8:
			print("Master password must be at least 8 characters.")
			continue
		
		with open(file_path, "r", encoding="utf-8") as file: 
			for line in file:
				value = line.strip()	
				if value == Password:
					print("Common password detected, consider a stronger password.")
					bad_password = True
					break

		if bad_password:
			continue
			
		Confirmation = getpass("Confirm master password: ")
		if Password != Confirmation:
			print("Passwords do not match.")
			continue

		return Password

#Creates a password vault
def Initialize_Vault():
	print("\nNo password vault was found.")
	print("Let's create one.\n")
	Master_Password = Create_Master_Password()
	Salt = Generate_Salt()
	Key = Derive_Key(Master_Password, Salt)
	Credentials = []
	Nonce, Ciphertext = Encrypt_Vault(Credentials, Key)
	Create_Vault(Salt, Nonce, Ciphertext)
	print("\nPassword vault created successfully.")

	return Key

#Uses the correct master password to unlock the vault
def Unlock_Vault():
	Salt = Get_Salt()
	if Salt is None:
		return Initialize_Vault()

	print("\nPassword vault found.")

	for Attempt in range(3):
		Master_Password = getpass("Enter master password: ")
		Key = Derive_Key(Master_Password, Salt)
		Vault_Data = Get_Vault()
		if Vault_Data is None:
			print("Vault data could not be found.")
			return None

		Nonce, Ciphertext = Vault_Data
		try:
			Decrypt_Vault(Nonce, Ciphertext, Key)
			print("\nVault unlocked successfully.")
			return Key
		except InvalidTag:
			print("Incorrect master password.")
	print("\nToo many failed attempts.")
	return None

#Encrypts and saves credentials
def Save_Credentials(Credentials, Key):
	Nonce, Ciphertext = Encrypt_Vault(Credentials, Key)
	Update_Vault(Nonce, Ciphertext)

#Adds a new credential to the vault
def Add_Credential(Credentials, Key):
	print("\n--- Add Credential ---")
	Website = input("Website: ").strip()
	Username = input("Username: ").strip()
	while True:
		Choice = input(
			"Would you like to generate a password? (y/n): "
		).strip().lower()

		if Choice in ("y", "n"):
			break
		print("Please enter y or n.")
	if Choice == "y":
		while True:
			try:
				Length = int(
					input("Password length (8-128): ")
				)
				Password = Generate_Password(Length)
				break
			except ValueError as Error:
				print(Error)
		print(f"Generated password: {Password}")
	else:
		Password = getpass("Password: ")
	Credential = {
		"website": Website,
		"username": Username,
		"password": Password,
	}

	Credentials.append(Credential)
	Save_Credentials(Credentials, Key)
	print("Credential added successfully.")

#Displays saved credentials
def View_Credentials(Credentials):
	print("\n--- Saved Credentials ---")
	if not Credentials:
		print("No credentials have been saved.")
		return
	for Index, Credential in enumerate(Credentials, start=1):
		print(
			f"{Index}. "
			f"{Credential['website']} "
			f"({Credential['username']})"
		)
	while True:
		Choice = input(
			"\nEnter credential number to view, or 0 to return: "
		).strip()

		try:
			Number = int(Choice)
		except ValueError:
			print("Please enter a number.")
			continue
		if Number == 0:
			return

		if 1 <= Number <= len(Credentials):
			Credential = Credentials[Number - 1]

			print("\nWebsite:", Credential["website"])
			print("Username:", Credential["username"])
			print("Password: ********")
			Reveal = input(
				"Reveal password? (y/n): "
			).strip().lower()
			if Reveal == "y":
				print("Password:", Credential["password"])
			return

		print("Invalid credential number.")

#Deletes a saved credential from the vault
def Delete_Credential(Credentials, Key):
	print("\n--- Delete Credential ---")
	if not Credentials:
		print("No credentials have been saved.")
		return
	for Index, Credential in enumerate(Credentials, start=1):
		print(
			f"{Index}. "
			f"{Credential['website']} "
			f"({Credential['username']})"
		)
	while True:
		Choice = input(
			"\nEnter credential number to delete, or 0 to return: "
		).strip()
		try:
			Number = int(Choice)
		except ValueError:
			print("Please enter a number.")
			continue
		if Number == 0:
			return

		if 1 <= Number <= len(Credentials):
			Credential = Credentials[Number - 1]
			Confirmation = input(
				f"Delete {Credential['website']}? (y/n): "
			).strip().lower()

			if Confirmation == "y":
				Credentials.pop(Number - 1)
				Save_Credentials(Credentials, Key)
				print("Credential deleted.")
			return
		print("Invalid credential number.")


#Generates and displays a password for user
def Generate_Password_Menu():
	print("\n--- Password Generator ---")
	while True:
		try:
			Length = int(
				input("Password length (8-128): ")
			)
			Password = Generate_Password(Length)
			print("\nGenerated password:")
			print(Password)
			return
		except ValueError as Error:
			print(Error)

#Runs the password manager interface
def Password_Manager_Menu(Key):
	Vault_Data = Get_Vault()
	if Vault_Data is None:
		print("Unable to load vault.")
		return
	Nonce, Ciphertext = Vault_Data
	try:
		Credentials = Decrypt_Vault(
			Nonce, Ciphertext, Key,
		)
	except InvalidTag:
		print("The vault could not be decrypted.")
		print("The data may have been modified.")
		return

	while True:
		print("\n================================")
		print("        PASSWORD MANAGER")
		print("================================")
		print("1. Add credential")
		print("2. View credentials")
		print("3. Delete credential")
		print("4. Generate password")
		print("5. Exit")
		Choice = input("\nChoose an option: ").strip()

		if Choice == "1":
			Add_Credential(Credentials, Key)

		elif Choice == "2":
			View_Credentials(Credentials)

		elif Choice == "3":
			Delete_Credential(Credentials, Key)

		elif Choice == "4":
			Generate_Password_Menu()

		elif Choice == "5":
			print("\nGoodbye.")
			return

		else:
			print("Invalid option.")

#Starts the password manager
def Main():
	Initialize_Database()
	Key = Unlock_Vault()
	if Key is None:
		return
	Password_Manager_Menu(Key)

if __name__ == "__main__":
	Main()