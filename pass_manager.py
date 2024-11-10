
import os
import sys
import getpass
import pyperclip
import bcrypt
import time
import sqlite3
import pickle
import random
import string
import pyotp
from cryptography.fernet import Fernet
from colorama import Fore, init
import pyfiglet

init(autoreset=True)

HOME_DIR = os.path.expanduser("~")
LOCAL_DIR = os.path.join(HOME_DIR, ".local", "pass_manager")
KEY_FILE = os.path.join(LOCAL_DIR, "secret.key")
MASTER_FILE = os.path.join(LOCAL_DIR, "master.key")
AUTH_TIME_FILE = os.path.join(LOCAL_DIR, "auth_time.pkl")
AUTH_VALIDITY_PERIOD = 300  # 5 minutes in seconds
DB_FILE = os.path.join(LOCAL_DIR, "passwords.db")  # SQLite database file

last_auth_time = None

def print_banner():
    """Displays a text banner for the program."""
    banner = pyfiglet.figlet_format("PassMan")
    print(Fore.CYAN + banner)

def print_success(message):
    """Displays a success message."""
    print(Fore.GREEN + "[✓] " + message)

def print_error(message):
    """Displays an error message."""
    print(Fore.RED + "[✘] " + message)

def print_info(message):
    """Displays an informational message."""
    print(Fore.YELLOW + "[i] " + message)

def set_master_password():
    """Sets the master password and stores it as a hashed version."""
    if os.path.exists(MASTER_FILE):
        print_error("The master password is already set.")
        sys.exit(1)

    master_password = getpass.getpass("Set the master password: ")

    if not master_password:
        print_error("The master password cannot be empty.")
        sys.exit(1)

    hashed = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())

    try:
        os.makedirs(LOCAL_DIR, exist_ok=True)
        with open(MASTER_FILE, "wb") as master_file:
            master_file.write(hashed)
        print_success(f"Master password set and stored in {MASTER_FILE}.")
    except Exception as e:
        print_error(f"Error while setting the master password: {e}")
        sys.exit(1)

def load_auth_time():
    """Loads the last authentication time from the file."""
    global last_auth_time
    if os.path.exists(AUTH_TIME_FILE):
        with open(AUTH_TIME_FILE, "rb") as auth_time_file:
            last_auth_time = pickle.load(auth_time_file)
    else:
        last_auth_time = None

def save_auth_time():
    """Saves the current authentication time to a file."""
    global last_auth_time
    with open(AUTH_TIME_FILE, "wb") as auth_time_file:
        pickle.dump(last_auth_time, auth_time_file)

def check_master_password():
    """Verifies if the entered master password is correct and valid for 5 minutes."""
    global last_auth_time

    if last_auth_time and (time.time() - last_auth_time < AUTH_VALIDITY_PERIOD):
        return

    if not os.path.exists(MASTER_FILE):
        print_error("The master password is not set. Please set it with 'set_master'.")
        sys.exit(1)

    master_password = getpass.getpass("Enter the master password: ")
    with open(MASTER_FILE, "rb") as master_file:
        stored_hashed = master_file.read()

    if bcrypt.checkpw(master_password.encode(), stored_hashed):
        last_auth_time = time.time()
        save_auth_time()
        print_success("Authentication successful.")
    else:
        print_error("Incorrect master password.")
        sys.exit(1)

def generate_key():
    """Generates an encryption key and stores it in a file."""
    if os.path.exists(KEY_FILE):
        print_error("The encryption key already exists.")
        return

    os.makedirs(LOCAL_DIR, exist_ok=True)
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print_success(f"Encryption key generated and stored in {KEY_FILE}")

def load_key():
    """Loads the encryption key from the file."""
    if not os.path.exists(KEY_FILE):
        print_error("The encryption key does not exist. Please generate it.")
        sys.exit(1)
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def encrypt_password(password):
    """Encrypts a password."""
    fernet = Fernet(load_key())
    return fernet.encrypt(password.encode())

def decrypt_password(encrypted_password):
    """Decrypts a password."""
    fernet = Fernet(load_key())
    return fernet.decrypt(encrypted_password).decode()

def init_db():
    """Initializes the SQLite database with an additional field for TOTP secret."""
    os.makedirs(LOCAL_DIR, exist_ok=True)
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE passwords (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                password BLOB,
                email TEXT,
                comment TEXT,
                totp_secret TEXT
            )
        ''')
        conn.commit()
        conn.close()
        print_success(f"Database '{DB_FILE}' initialized.")
    else:
        print_info("The database already exists.")

def generate_random_password(length=16):
    """Génère un mot de passe aléatoire avec une longueur spécifiée."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def add(name, password=None, email=None, comment=None, totp_secret=None):
    """Adds an encrypted password, TOTP secret, and additional details to the database."""
    if password is None:
        password = generate_random_password()

    encrypted_password = encrypt_password(password)
    
    if totp_secret is None:
        totp_secret = input("Enter TOTP secret for the service: ")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO passwords (name, password, email, comment, totp_secret)
            VALUES (?, ?, ?, ?, ?)
        """, (name, encrypted_password, email, comment, totp_secret))
        conn.commit()
        print_success(f"Password for '{name}' added. Generated password: {password}")
        if email:
            print_success(f"Email: {email}")
        if comment:
            print_success(f"Comment: {comment}")
        if totp_secret:
            print_success(f"TOTP Secret: {totp_secret}")
    except sqlite3.IntegrityError:
        print_error(f"A password for '{name}' already exists.")
    finally:
        conn.close()

def fix_base32_padding(secret):
    """Adds the necessary padding to a base32 secret."""
    return secret + '=' * (8 - len(secret) % 8) if len(secret) % 8 != 0 else secret

def get_password(name):
    """Retrieve and copy the password for a service to the clipboard."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password,email,totp_secret FROM passwords WHERE name=?", (name,))
    row = cursor.fetchone()
    conn.close()

    if row:
        encrypted_password = row[0]
        email = row[1]
        totp_secret = row[2]
        decrypted_password = decrypt_password(encrypted_password)
        pyperclip.copy(decrypted_password)
        if email:
            print_info(f"Email: {email}")
        if totp_secret:
            totp_code = pyotp.TOTP(totp_secret).now()
            print_info(f"OTP code: {totp_code}")
        if decrypt_password:
            print_success(f"Password for '{name}' copied to clipboard !")
    else:
        print_error(f"No password found for '{name}'.")

def delete_service(name):
    """Deletes a service from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE name=?", (name,))
    conn.commit()

    if cursor.rowcount > 0:
        print_success(f"Service '{name}' deleted.")
    else:
        print_error(f"No service found with the name '{name}'.")
    conn.close()

def list_services():
    """Lists all stored passwords in the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT name,totp_secret FROM passwords ORDER BY name")
    rows = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM passwords")
    result = cursor.fetchone()
    if result is not None:
        count = result[0]
        print_info(f"Total number of stored passwords: {count}")
    else:
        print_info("No passwords found in the database.")
    conn.close()

    if rows:
        print_success("List of stored passwords:")
        for row in rows:
             print(f" - {row[0]}")
    else:
        print_info("No passwords stored.")

def get_totp_code(name):
    """Retrieves and generates the TOTP code for a service."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT totp_secret FROM passwords WHERE name=?", (name,))
    row = cursor.fetchone()
    conn.close()

    if row and row[0]:
        totp_secret = row[0]
        totp_code = pyotp.TOTP(totp_secret).now()
        print_success(f"OTP code for '{name}': {totp_code}")
    else:
        print_error(f"No TOTP secret found for '{name}'.")

def main():
    print_banner()
    load_auth_time()

    if len(sys.argv) < 2:
        print(Fore.YELLOW + "Usage: python pass_manager.py <command> <args>")
        print(Fore.YELLOW + "Commands:")
        print(Fore.YELLOW + "  init                 # Initialize the database")
        print(Fore.YELLOW + "  set_master           # Set the master password")
        print(Fore.YELLOW + "  generate_key         # Set the encryption key")
        print(Fore.YELLOW + "  add <name> <password> # Add a password entry")
        print(Fore.YELLOW + "  get <name>           # Get the password and copy to clipboard")
        print(Fore.YELLOW + "  delete <name>        # Delete a password entry")
        print(Fore.YELLOW + "  list                 # List all services")
        print(Fore.YELLOW + "  get_otp <name>      # Get OTP code for a service")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        init_db()
    elif command == "set_master":
        set_master_password()
        check_master_password()
    elif command == "generate_key":
        generate_key()
    elif command == "add":
        check_master_password()
        if len(sys.argv) < 3:
            print_error("Service name is required.")
            sys.exit(1)
        name = sys.argv[2]
        password = input("Enter password (leave empty for auto-generate): ") or None
        email = input("Enter email (optional): ")
        comment = input("Enter comment (optional): ")
        totp_secret = input("Enter TOTP secret (optional): ")
        add(name, password, email, comment, totp_secret)
        save_auth_time()
    elif command == "get":
        check_master_password()
        if len(sys.argv) < 3:
            print_error("Service name is required.")
            sys.exit(1)
        get_password(sys.argv[2])
        save_auth_time()
    elif command == "delete":
        check_master_password()
        if len(sys.argv) < 3:
            print_error("Service name is required.")
            sys.exit(1)
        delete_service(sys.argv[2])
    elif command == "list":
        check_master_password()
        list_services()
        save_auth_time()
    elif command == "get_otp":
        check_master_password()
        if len(sys.argv) < 3:
            print_error("Service name is required.")
            sys.exit(1)
        get_totp_code(sys.argv[2])
        save_auth_time()
    else:
        print_error("Invalid command.")
        sys.exit(1)
if __name__ == "__main__":
    main()

