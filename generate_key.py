import os
import sys
import getpass
import bcrypt
from colorama import Fore, init

# Initialize colorama for cross-platform rendering
init(autoreset=True)

# Directories and files for storage
HOME_DIR = os.path.expanduser("~")
LOCAL_DIR = os.path.join(HOME_DIR, ".local", "pass_manager")
MASTER_FILE = os.path.join(LOCAL_DIR, "master.key")

def print_success(message):
    print(Fore.GREEN + "[✓] " + message)

def print_error(message):
    print(Fore.RED + "[✘] " + message)

def print_info(message):
    print(Fore.YELLOW + "[i] " + message)

def set_master_password():
    """Sets the master password and stores it in a hashed format."""
    if os.path.exists(MASTER_FILE):
        print_error("The master password is already set.")
        sys.exit(1)

    master_password = getpass.getpass("Set the master password: ")

    if not master_password:
        print_error("The master password cannot be empty.")
        sys.exit(1)

    hashed = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())

    try:
        # Create the folder if necessary
        os.makedirs(LOCAL_DIR, exist_ok=True)

        # Create the master.key file
        with open(MASTER_FILE, "wb") as master_file:
            master_file.write(hashed)

        # Check if the file was created
        if os.path.exists(MASTER_FILE):
            print_success(f"Master password set and stored in {MASTER_FILE}.")
        else:
            print_error(f"Failed to create the file {MASTER_FILE}.")

    except Exception as e:
        print_error(f"Error while setting the master password: {e}")
        sys.exit(1)

def main():
    print(Fore.CYAN + "Welcome to Pass Manager")

    if len(sys.argv) < 2:
        print(Fore.YELLOW + "Usage:")
        print(Fore.YELLOW + "  python generate_key.py set_master       # Set the master password")
        sys.exit(1)

    command = sys.argv[1]

    if command == "set_master":
        set_master_password()
    else:
        print_error("Unknown command.")
        sys.exit(1)

if __name__ == "__main__":
    main()

