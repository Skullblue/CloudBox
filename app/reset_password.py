"""Set a new CloudBox password from the host. Reads the new password from stdin (never from argv).

Used by:  sudo cloudbox reset-password
Signs out every device, because the session secret is rotated along with the password.
"""
import sys

import main

pw = sys.stdin.read().rstrip("\n")
if len(pw) < main.MIN_PASSWORD_LEN:
    sys.exit(f"Password must be at least {main.MIN_PASSWORD_LEN} characters.")
main.set_password(pw)
print("Password updated. All devices have been signed out.")
