import sqlite3

conn = sqlite3.connect("users.db")
cur = conn.cursor()
cur.execute("SELECT id, username, key, salt FROM users")
for row in cur.fetchall():
    print(row)
conn.close()