import os

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

Salt_Size = 16
Nonce_Size = 12
Key_Size = 32
PBKDF2_Iterations = 600_000

#Generates a random salt
def Generate_Salt():
	return os.urandom(Salt_Size)

#Derives a 256-bit encryption key from the master password
def Derive_Key(Master_Password, Salt):
	Password_Bytes = Master_Password.encode("utf-8")
	kdf = PBKDF2HMAC(
		algorithm = hashes.SHA256(), length = Key_Size, salt = Salt, iterations = PBKDF2_Iterations,
		)
	return kdf.derive(Password_Bytes)

#Encrypts data using AES-GCM
def Encrypt_Data(Data, Key):
	Nonce = os.urandom(Nonce_Size)
	aesgcm = AESGCM(Key)
	Ciphertext = aesgcm.encrypt(Nonce, Data, None)
	return Nonce, Ciphertext 

#Decrypts data using AES-GCM
def Decrypt_Data(Nonce, Ciphertext, Key):
	aesgcm = AESGCM(Key)
	return aesgcm.decrypt(Nonce, Ciphertext, None)