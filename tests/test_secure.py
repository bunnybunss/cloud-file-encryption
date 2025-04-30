import os
import sys
import pytest
from pathlib import Path

# Ensure the Encp package is on sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Encp")))

from secure_crypto.secure_crypto import encrypt_file, decrypt_file

def test_encrypt_decrypt_roundtrip(tmp_path):
    # Create a sample text file
    original_file = tmp_path / "foo.txt"
    original_file.write_text("hello world")

    # Encrypt the file using a test password
    encrypted_name = encrypt_file(str(original_file), "pwd123")
    encrypted_path = tmp_path / encrypted_name
    assert encrypted_path.exists(), "Encrypted file was not created"

    # Decrypt the file using the same password
    decrypted_name = decrypt_file(str(encrypted_path), "pwd123")
    decrypted_path = tmp_path / decrypted_name
    assert decrypted_path.exists(), "Decrypted file was not created"

    # Verify the contents match the original
    content = decrypted_path.read_text()
    assert content == "hello world", f"Expected 'hello world', got '{content}'"