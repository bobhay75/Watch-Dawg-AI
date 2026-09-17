"""Create a private operator record without password command arguments."""
import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--username', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9_-]{3,40}', args.username):
        parser.error('Username must be 3–40 lowercase letters, digits, _ or -')
    password = getpass.getpass('Unique passphrase (15+ characters): ')
    if len(password) < 15 or len(password.encode()) > 1024:
        parser.error('Use 15+ characters, at most 1024 bytes')
    if password != getpass.getpass('Confirm passphrase: '):
        parser.error('Passphrases do not match')
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=131072, r=8, p=1,
                            maxmem=256 * 1024 * 1024, dklen=64)
    record = {'username': args.username, 'salt': salt.hex(),
              'hash': digest.hex(),
              'scopes': ['ai:audit']}
    # Exclusive creation prevents accidental replacement of existing accounts.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump([record], output)
        output.write('\n')
    print('Operator file created. Restart the frontend to load it.')


if __name__ == '__main__':
    main()
