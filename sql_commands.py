import sqlite3


def get_key(user):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("SELECT key FROM Users WHERE user=?;", (user,))
	rows = c.fetchall()
	conn.close()
	if len(rows) == 1:
		return rows[0][0]
	return len(rows) != 0


def remove_account(user):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("DELETE FROM Users WHERE user=?", (user,))
	c.execute("DELETE FROM Sessions WHERE user=?", (user,))
	c.execute("INSERT INTO InactiveUsers VALUES (?)", (user,))
	conn.commit()
	conn.close()


def get_user(session_id):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("SELECT user FROM Sessions WHERE id=?;", (session_id,))
	rows = c.fetchall()
	conn.close()
	if len(rows) == 1:
		return rows[0][0]
	return len(rows) != 0


def add_user(user, hashed, salt, key):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("SELECT * FROM Users WHERE user=?", (user,))
	rows = c.fetchall()
	c.execute("SELECT * FROM InactiveUsers WHERE user=?", (user,))
	inactive_rows = c.fetchall()
	if not len(rows) + len(inactive_rows):
		c.execute("INSERT INTO Users VALUES(?, ?, ?, ?)", (user, hashed, salt, key))
		conn.commit()
		conn.close()
		return True
	return False


def get_user_data(user):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("SELECT hash, salt FROM Users WHERE user=?", (user,))
	rows = c.fetchall()
	conn.close()
	if len(rows) == 1:
		return rows[0]
	return len(rows) != 0


def add_session_id(user, session_id):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("SELECT * FROM Sessions WHERE user=?", (user,))
	rows = c.fetchall()
	if not len(rows):
		c.execute("INSERT INTO Sessions VALUES(?, ?)", (user, session_id))
		conn.commit()
		conn.close()
		return True
	return False


def get_session_id(user):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("SELECT id FROM Sessions WHERE user=?", (user,))
	rows = c.fetchall()
	if len(rows) == 1:
		return rows[0][0]
	return len(rows) != 0


def add_message(session_id, data):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("INSERT INTO Messages (id, data) VALUES(?, ?)", (session_id, data))
	conn.commit()
	conn.close()


def get_message(session_id):
	conn = sqlite3.connect('database.db')
	c = conn.cursor()
	c.execute("SELECT data, message_id FROM Messages WHERE id=?", (session_id,))
	rows = c.fetchall()
	message = False
	if len(rows) > 0:
		c.execute("DELETE FROM Messages WHERE message_id=?", (rows[0][1],))
		message = rows[0][0]
	conn.commit()
	conn.close()
	return message
