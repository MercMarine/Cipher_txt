"""

Author - MercMarine
GitHub - https://github.com/MercMarine

crypto_engine.py - Классы для шифрования/дешифрования данных.

"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_LENGTH = 16
NONCE_LENGTH = 12
PBKDF2_ITERATIONS = 600000

# Получение 256-битного ключа из пароля и соли (Деривация)

def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )

# Шифрование данных

def encrypt_bytes(data: bytes, password: str) -> bytes:
    if not data or not password:
        raise ValueError("Data and password cannot be empty.")

    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext_and_tag

# Дешифрование данных

def decrypt_bytes(encrypted_data: bytes, password: str) -> bytes:
    try:
        if len(encrypted_data) < SALT_LENGTH + NONCE_LENGTH:
            raise ValueError("File is too small or damaged.")
        salt = encrypted_data[:SALT_LENGTH]
        nonce = encrypted_data[SALT_LENGTH: SALT_LENGTH + NONCE_LENGTH]
        ciphertext_and_tag = encrypted_data[SALT_LENGTH + NONCE_LENGTH:]
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_and_tag, None)

    except Exception:
        raise ValueError("Decipher Error: invalid password or file is damaged.")