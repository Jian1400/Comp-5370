import sqlite3
from pathlib import Path

Database_Path = Path(__file__).resolve().parent.parent / "vault.db"

#Creates a connection to the SQLite database
def Get_Connection():
	return sqlite3.connect(Database_Path)

#Creates the database tables if they do not exist
def Initialize_Database():
	Connection = Get_Connection()
	Cursor = Connection.cursor()
	Cursor.execute(
		"""CREATE TABLE IF NOT EXISTS metadata (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			salt BLOB NOT NULL
		)
		"""
	)
	Cursor.execute(
		"""
		CREATE TABLE IF NOT EXISTS vault (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			nonce BLOB NOT NULL,
			ciphertext BLOB NOT NULL
		)
		"""
	)
	Connection.commit()
	Connection.close()

#Returns the stored salt
def Get_Salt():
	Connection = Get_Connection()
	Cursor = Connection.cursor()
	Cursor.execute("SELECT salt FROM metadata WHERE id = 1")
	Result = Cursor.fetchone()
	Connection.close()

	if Result is None:
		return None
	return Result[0]

#Creates the initial encrypted vault
def Create_Vault(Salt, Nonce, Ciphertext):
	Connection = Get_Connection()
	Cursor = Connection.cursor()
	Cursor.execute(
		"INSERT INTO metadata (id, salt) VALUES (1, ?)", (Salt,),
	)
	Cursor.execute(
		"""
		INSERT INTO vault (id, nonce, ciphertext)
		VALUES (1, ?, ?)
		""",
		(Nonce, Ciphertext),
	)
	Connection.commit()
	Connection.close()

#Returns the encrypted vault
def Get_Vault():
	Connection = Get_Connection()
	Cursor = Connection.cursor()
	Cursor.execute(
		"SELECT nonce, ciphertext FROM vault WHERE id = 1"
	)
	Result = Cursor.fetchone()
	Connection.close()
	return Result

#Updates data inside the encrypted vault
def Update_Vault(Nonce, Ciphertext):
	Connection = Get_Connection()
	Cursor = Connection.cursor()
	Cursor.execute(
		"""
		UPDATE vault
		SET nonce = ?, ciphertext = ?
		WHERE id = 1
		""",
		(Nonce, Ciphertext),
	)
	Connection.commit()
	Connection.close() 