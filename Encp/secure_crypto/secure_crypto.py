import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants for key derivation
KDF_ITERATIONS = 100_000
KEY_LENGTH = 32   # 256-bit AES key
SALT_SIZE = 16    # 128-bit salt
IV_SIZE = 12      # 96-bit IV for GCM mode
TAG_SIZE = 16     # 128-bit authentication tag


def _derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a cryptographic key from the given password and salt using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file(input_path: str, password: str) -> str:
    """
    Encrypts the file at input_path using AES-GCM.
    Returns the path to the encrypted file (same directory, '.enc' suffix).
    """
    # Prepare paths and random values
    input_path = Path(input_path)
    output_path = input_path.with_suffix(input_path.suffix + '.enc')
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = _derive_key(password.encode(), salt)

    # Read plaintext
    plaintext = input_path.read_bytes()

    # Encrypt using AES-GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # Write out: salt || iv || tag || ciphertext
    with open(output_path, 'wb') as f:
        f.write(salt + iv + tag + ciphertext)

    return str(output_path)


def decrypt_file(input_path: str, password: str) -> str:
    """
    Decrypts the file at input_path (which must have been encrypted by encrypt_file).
    Returns the path to the decrypted file (removes '.enc' suffix).
    """
    input_path = Path(input_path)
    data = input_path.read_bytes()

    # Extract salt, iv, tag, and ciphertext
    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    tag = data[SALT_SIZE+IV_SIZE:SALT_SIZE+IV_SIZE+TAG_SIZE]
    ciphertext = data[SALT_SIZE+IV_SIZE+TAG_SIZE:]

    key = _derive_key(password.encode(), salt)

    # Decrypt using AES-GCM
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write out decrypted file (strip '.enc')
    if input_path.suffix == '.enc':
        output_path = input_path.with_suffix('')
    else:
        output_path = input_path.with_suffix(input_path.suffix.replace('.enc', ''))

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return str(output_path)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file using a password (AES-GCM).')
    parser.add_argument('mode', choices=['enc', 'dec'], help='enc = encrypt, dec = decrypt')
    parser.add_argument('file', help='Path to the input file')
    parser.add_argument('-p', '--password', required=True, help='Password for encryption/decryption')
    args = parser.parse_args()

    if args.mode == 'enc':
        out = encrypt_file(args.file, args.password)
        print(f'Encrypted file: {out}')
    else:
        out = decrypt_file(args.file, args.password)
        print(f'Decrypted file: {out}')
