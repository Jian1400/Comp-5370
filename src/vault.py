import json

from .crypto import Encrypt_Data, Decrypt_Data

#Convert credentials into JSON and encrypts them
def Encrypt_Vault(Credentials, Key):
	Plaintext = json.dumps(
		Credentials, ensure_ascii = False,
	).encode("utf-8")
	return Encrypt_Data(Plaintext, Key)

#Decrypts the vault and converts it back into credentials
def Decrypt_Vault(Nonce, Ciphertext, Key):
	Plaintext = Decrypt_Data(Nonce, Ciphertext, Key)
	return json.loads(Plaintext.decode("utf-8"))