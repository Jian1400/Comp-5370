from src.vault import Encrypt_Vault, Decrypt_Vault
from cryptography.exceptions import InvalidTag
import pytest


def test_vault_encrypts_and_decrypts_credentials():
	Key = b"0123456789abcdef0123456789abcdef"
	Credentials = {"website": "example.com", "username": "testuser", "password": "TestPassword123!"}
	Nonce, Ciphertext = Encrypt_Vault(Credentials, Key)
	Result = Decrypt_Vault(Nonce, Ciphertext, Key)
	assert Result == Credentials
	assert Ciphertext != str(Credentials).encode()



def test_vault_reject_wrong_key():
	Key = b"0123456789abcdef0123456789abcdef"
	Wrong_Key = b"abcdef0123456789abcdef0123456789"
	Credentials = {"website": "example.com", "password": "test"}
	Nonce, Ciphertext = Encrypt_Vault(Credentials, Key)
	with pytest.raises(InvalidTag):
		Decrypt_Vault(Nonce, Ciphertext, Wrong_Key)



def test_vault_reject_modified_ciphertext():
	Key = b"0123456789abcdef0123456789abcdef"
	Credentials = {"website": "example.com", "password": "test"}
	Nonce, Ciphertext = Encrypt_Vault(Credentials, Key)
	Modified_Ciphertext = bytearray(Ciphertext)
	Modified_Ciphertext[-1] ^= 1
	with pytest.raises(InvalidTag):
		Decrypt_Vault(Nonce, bytes(Modified_Ciphertext), Key)
