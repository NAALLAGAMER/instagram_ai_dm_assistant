from getpass import getpass
from werkzeug.security import generate_password_hash

password = getpass("Choose a dashboard password: ")
if len(password) < 14:
    raise SystemExit("Use at least 14 characters.")
print("\nAdd this line to .env:\nDASHBOARD_PASSWORD_HASH=" + generate_password_hash(password))
