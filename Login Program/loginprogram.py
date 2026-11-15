#============================================================================================# Importsed lb's and Global variables
from getpass import getpass
import unicodedata
import hashlib
import secrets
import sqlite3
import pathlib

DB_PATH = ("users.db")
#============================================================================================# DB_Process
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

def init_db():
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT TEXT NOT NULL UNIQUE,
        key      TEXT,
        salt     TEXT
    )
    """)
    conn.commit()

def update_db(username: str, key: str, salt: str):
    try:
        cur.execute(
            "INSERT INTO users (username, key, salt) VALUES (?, ?, ?)",
            (username, key, salt),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None

def get_user(username: str):
    cur.execute("SELECT key, salt FROM users WHERE username = ?", (username,))
    return cur.fetchone()

init_db()
#============================================================================================# Hash functions
def hash_pass(password: str, salt: bytes | None = None):
    if salt == None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return key.hex(), salt.hex()

def is_login_valid(username: int, password: str) -> bool:
    row = get_user(username)
    if row is None:
        return False
    stored_key, stored_salt = row
    new_key, _ = hash_pass(password, bytes.fromhex(stored_salt))
    return secrets.compare_digest(new_key, stored_key)
#============================================================================================# Signup
def is_pass_valid(password:str):
    if len(password) < 8:
        print ("\nPassword must be at least 8 characters.")
        return True
    if len(password) > 128:
        print ("\nPassword must be at most 128 characters.")
        return True
    if " " in password:
        print ("\nPassword cannot contain spaces.")
        return True
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        print ("\nPassword cannot contain invalid characters.")
        return True    
    return False 

def signup():
    print("\nPlease enter your new credentials")
    while True:
        username = input("Username: ").strip()
        if username:
            break
        print("Username cannot be empty.")
    while True:
        pass1 = getpass("Password: ")
        if is_pass_valid(pass1):
            continue
        pass2 = getpass("Confirm password: ")
        if (pass1 == pass2):
            break
        print("\nPasswords do not match, try again.")

    key, salt = hash_pass(pass2)
    user_id = update_db(username, key, salt)
    if user_id is None:
        print("That username is taken.")
        return False
    print("\nAccount created! You can now log in.\n")
    return True
#============================================================================================# Login
def login():
    tries = 0
    while tries < 10:
        print("\nEnter your credentials")
        username = input("Username: ").strip()
        password = getpass("Password: ")
        if is_login_valid(username, password):
            print("\nWelcome!\n") #Yay
            return True
        print("Invalid username or password, try again.")
        tries += 1
    print("\nSuspicious activity detected, you will be timed out.\n")
#============================================================================================# Mode Selection
def is_mode_valid(user_input: int)->bool:
    return user_input in ['1','2','3']

def mode_interface()->int:
    print("Greetings what would you like to do?")
    while True:
        option = input("[Login 1|Signup 2|Exit 3]: ").strip()
        if is_mode_valid(option):
            return int(option)
        print("\nTry again.")
#============================================================================================# Mode Id
while True: 
    mode = mode_interface()
    if mode == 1:
        login()
    elif mode == 2:
        signup()
    else:
        print("Goodbye.")
        break
conn.commit()