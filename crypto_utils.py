# crypto_utils.py
from cryptography.fernet import Fernet

# Generate a key once and save it to use for encryption/decryption
# You can generate it separately and hardcode here for simplicity
KEY = Fernet.generate_key()
f = Fernet(KEY)

def encrypt_data(data: bytes) -> bytes:
    """
    Encrypt bytes data using Fernet symmetric encryption.
    """
    return f.encrypt(data)

def decrypt_data(data: bytes) -> bytes:
    """
    Decrypt bytes data using Fernet symmetric encryption.
    """
    return f.decrypt(data)

def get_key() -> bytes:
    """
    Return the key (optional, in case you want to share with peers securely)
    """
    return KEY
