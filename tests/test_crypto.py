import pytest

from cryptography.exceptions import InvalidTag

from src.crypto import (
	Generate_Salt,
	Derive_Key,
	Encrypt_Data,
	Decrypt_Data,
)

def test_key_derivation_is_consistent():
	Password = "TestPassword123!"
	Salt = Generate_Salt()
	Key1 = Derive_Key(Password, Salt)
	Key2 = Derive_Key(Password, Salt)
	assert Key1 == Key2

def test_different_salts_create_different_keys():
	Password = "TestPassword123!"
	Salt1 = Generate_Salt()
	Salt2 = Generate_Salt()
	Key1 = Derive_Key(Password, Salt1)
	Key2 = Derive_Key(Password, Salt2)
	assert Key1 != Key2

def test_encryption_and_decryption():
	Password = "TestPassword123!"
	Salt = Generate_Salt()
	Key = Derive_Key(Password, Salt)
	Original = b"Test credential data"
	Nonce, Ciphertext = Encrypt_Data(Original, Key)
	Decrypted = Decrypt_Data(Nonce, Ciphertext, Key)
	assert Decrypted == Original
	
def test_wrong_key_fails():
	Password1 = "TestPassword123!"
	Password2 = "DifferentPassword456!"
	Salt = Generate_Salt()
	Key1 = Derive_Key(Password1, Salt)
	Key2 = Derive_Key(Password2, Salt)
	Original = b"Secret information"
	Nonce, Ciphertext = Encrypt_Data(Original, Key1)
	with pytest.raises(InvalidTag):
		Decrypt_Data(Nonce, Ciphertext, Key2)

def test_modified_ciphertext_fails():
	Password = "TestPassword123!"
	Salt = Generate_Salt()
	Key = Derive_Key(Password, Salt)
	Original = b"Secret information"
	Nonce, Ciphertext = Encrypt_Data(Original, Key)
	Modified = bytearray(Ciphertext)
	Modified[0] ^= 1
	with pytest.raises(InvalidTag):
		Decrypt_Data(Nonce, bytes(Modified), Key)