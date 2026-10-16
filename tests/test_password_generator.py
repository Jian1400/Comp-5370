from src.password_generator import Generate_Password

def test_password_has_requested_length():
	Password = Generate_Password(20)
	assert len(Password) == 20

def test_password_contains_different_character_types():
	Password = Generate_Password(20)
	assert any(Character.islower() for Character in Password)
	assert any(Character.isupper() for Character in Password)
	assert any(Character.isdigit() for Character in Password)

def test_passwords_are_not_always_identical():
	Password1 = Generate_Password(20)
	Password2 = Generate_Password(20)
	assert Password1 != Password2