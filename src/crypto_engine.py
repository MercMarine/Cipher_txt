"""

Author - MercMarine
GitHub - https://github.com/MercMarine
crypto_engine.py - Классы для шифрования/дешифрования данных.

"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import argon2

SALT_LENGTH = 16
NONCE_LENGTH = 12
PBKDF2_ITERATIONS = 600000
KDF_PBKDF2 = b'\x01'
KDF_ARGON2 = b'\x02'
CIPHER_AES = b'\x01'
CIPHER_CHACHA20 = b'\x02'

def _derive_key(password: str, salt: bytes, kdf_algo: str) -> bytes:
    if kdf_algo.strip() == "argon2id":
        return argon2.low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=argon2.low_level.Type.ID
        )
    else:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PBKDF2_ITERATIONS
        )

def encrypt_bytes(data: bytes, password: str, kdf_algo: str = "pbkdf2", cipher_algo: str = "aes-gcm") -> bytes:
    if not data or not password:
        raise ValueError("Data and password cannot be empty.")
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)

    kdf_algo_clean = kdf_algo.strip().lower()
    cipher_algo_clean = cipher_algo.strip().lower()

    key = _derive_key(password, salt, kdf_algo_clean)

    if cipher_algo_clean == "chacha20":
        cipher = ChaCha20Poly1305(key)
        kdf_id = KDF_ARGON2 if kdf_algo_clean == "argon2id" else KDF_PBKDF2
        cipher_id = CIPHER_CHACHA20
    else:
        cipher = AESGCM(key)
        kdf_id = KDF_ARGON2 if kdf_algo_clean == "argon2id" else KDF_PBKDF2
        cipher_id = CIPHER_AES

    ciphertext_and_tag = cipher.encrypt(nonce, data, None)

    header = b'\x01' + kdf_id + cipher_id

    return header + salt + nonce + ciphertext_and_tag

def decrypt_bytes(encrypted_data: bytes, password: str) -> bytes:
    try:
        if len(encrypted_data) < 3 + SALT_LENGTH + NONCE_LENGTH:
            raise ValueError("File is too small or damaged.")

        version = encrypted_data[0]
        kdf_id = encrypted_data[1:2]
        cipher_id = encrypted_data[2:3]

        if version != 0x01:
            raise ValueError("Unsupported version of file format.")

        kdf_algo = "argon2id" if kdf_id == KDF_ARGON2 else "pbkdf2"
        cipher_algo = "chacha20" if cipher_id == CIPHER_CHACHA20 else "aes-gcm"

        salt = encrypted_data[3 : 3 + SALT_LENGTH]
        nonce = encrypted_data[3 + SALT_LENGTH : 3 + SALT_LENGTH + NONCE_LENGTH]
        ciphertext_and_tag = encrypted_data[3 + SALT_LENGTH + NONCE_LENGTH :]

        key = _derive_key(password, salt, kdf_algo)

        if cipher_algo == "chacha20":
            cipher = ChaCha20Poly1305(key)
        else:
            cipher = AESGCM(key)

        return cipher.decrypt(nonce, ciphertext_and_tag, None)

    except Exception as e:
        raise ValueError("Decipher Error: invalid password or file is damaged.")