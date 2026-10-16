import secrets
import string

#Generates a cryptographically strong random password
def Generate_Password(length = 20):
	if length < 8:
		raise ValueError("Password length must be at least 8.")
	if length > 128:
		raise ValueError("Password length cannot exceed 128.")

	Lowercase = string.ascii_lowercase
	Uppercase = string.ascii_uppercase
	Numbers = string.digits
	Symbols = "!@#$%^&*()-_=+"
	Characters = Lowercase + Uppercase + Numbers + Symbols

	Password = [
		secrets.choice(Lowercase), secrets.choice(Uppercase), secrets.choice(Numbers), secrets.choice(Symbols),
	]
	for _ in range(length - 4):
		Password.append(secrets.choice(Characters))
	secrets.SystemRandom().shuffle(Password)
	return "".join(Password)