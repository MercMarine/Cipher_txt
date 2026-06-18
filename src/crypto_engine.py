"""

Author - MercMarine
GitHub - https://github.com/MercMarine
crypto_engine.py - Классы для шифрования/дешифрования данных.

"""

import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import argon2

SALT_LENGTH = 16
PBKDF2_ITERATIONS = 600000

# Идентификаторы дериваций
KDF_PBKDF2 = b'\x01'
KDF_ARGON2 = b'\x02'
KDF_SCRYPT = b'\x03'

# Идентификаторы шифров
CIPHER_AES = b'\x01'
CIPHER_CHACHA20 = b'\x02'
CIPHER_AES_CBC_HMAC = b'\x03'

# Размеры nonce для каждого шифра
NONCE_SIZES = {
    CIPHER_AES: 12,
    CIPHER_CHACHA20: 12,
    CIPHER_AES_CBC_HMAC: 16
}

# Размер ключа для каждого шифра
KEY_SIZES = {
    CIPHER_AES: 32,
    CIPHER_CHACHA20: 32,
    CIPHER_AES_CBC_HMAC: 64
}


def _derive_key(password: str, salt: bytes, kdf_algo: str, key_length: int = 32) -> bytes:
    pwd_bytes = password.encode('utf-8')
    kdf_algo_lower = kdf_algo.strip().lower()

    if kdf_algo_lower == "argon2id":
        return argon2.low_level.hash_secret_raw(
            secret=pwd_bytes,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=key_length,
            type=argon2.low_level.Type.ID
        )
    elif kdf_algo_lower == "scrypt":
        return hashlib.scrypt(
            pwd_bytes,
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=key_length
        )
    else:
        return hashlib.pbkdf2_hmac(
            'sha256',
            pwd_bytes,
            salt,
            PBKDF2_ITERATIONS,
            dklen=key_length
        )


def _encrypt_aes_cbc_hmac(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes_key = key[:32]
    hmac_key = key[32:]

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    return mac + ciphertext


def _decrypt_aes_cbc_hmac(key: bytes, iv: bytes, mac_and_ciphertext: bytes) -> bytes:
    if len(mac_and_ciphertext) < 32:
        raise ValueError("Data too short")

    aes_key = key[:32]
    hmac_key = key[32:]
    stored_mac = mac_and_ciphertext[:32]
    ciphertext = mac_and_ciphertext[32:]

    expected_mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("HMAC verification failed")

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def encrypt_bytes(data: bytes, password: str, kdf_algo: str = "pbkdf2", cipher_algo: str = "aes-gcm") -> bytes:
    if not data or not password:
        raise ValueError("Data and password cannot be empty.")

    kdf_algo_lower = kdf_algo.strip().lower()
    cipher_algo_lower = cipher_algo.strip().lower()

    if cipher_algo_lower == "aes-cbc":
        cipher_id = CIPHER_AES_CBC_HMAC
    elif cipher_algo_lower == "chacha20":
        cipher_id = CIPHER_CHACHA20
    else:
        cipher_id = CIPHER_AES

    if kdf_algo_lower == "argon2id":
        kdf_id = KDF_ARGON2
    elif kdf_algo_lower == "scrypt":
        kdf_id = KDF_SCRYPT
    else:
        kdf_id = KDF_PBKDF2

    salt = os.urandom(SALT_LENGTH)
    nonce_size = NONCE_SIZES[cipher_id]
    key_size = KEY_SIZES[cipher_id]
    nonce = os.urandom(nonce_size)
    key = _derive_key(password, salt, kdf_algo_lower, key_size)

    if cipher_id == CIPHER_CHACHA20:
        cipher = ChaCha20Poly1305(key)
        ciphertext_and_tag = cipher.encrypt(nonce, data, None)
    elif cipher_id == CIPHER_AES_CBC_HMAC:
        ciphertext_and_tag = _encrypt_aes_cbc_hmac(key, nonce, data)
    else:
        cipher = AESGCM(key)
        ciphertext_and_tag = cipher.encrypt(nonce, data, None)

    header = b'\x01' + kdf_id + cipher_id

    return header + salt + nonce + ciphertext_and_tag


def decrypt_bytes(encrypted_data: bytes, password: str) -> bytes:
    try:
        if len(encrypted_data) < 3 + SALT_LENGTH:
            raise ValueError("File is too small or damaged.")

        version = encrypted_data[0]
        kdf_id = encrypted_data[1:2]
        cipher_id = encrypted_data[2:3]

        if version != 0x01:
            raise ValueError("Unsupported version of file format.")

        if cipher_id not in NONCE_SIZES:
            raise ValueError(f"Unknown cipher algorithm: {cipher_id.hex()}")

        kdf_map = {KDF_PBKDF2: "pbkdf2", KDF_ARGON2: "argon2id", KDF_SCRYPT: "scrypt"}
        kdf_algo = kdf_map.get(kdf_id)
        if kdf_algo is None:
            raise ValueError(f"Unknown KDF algorithm: {kdf_id.hex()}")

        nonce_size = NONCE_SIZES[cipher_id]
        key_size = KEY_SIZES[cipher_id]

        offset = 3
        salt = encrypted_data[offset:offset + SALT_LENGTH]
        offset += SALT_LENGTH
        nonce = encrypted_data[offset:offset + nonce_size]
        offset += nonce_size
        ciphertext_and_tag = encrypted_data[offset:]
        key = _derive_key(password, salt, kdf_algo, key_size)

        if cipher_id == CIPHER_CHACHA20:
            cipher = ChaCha20Poly1305(key)
            return cipher.decrypt(nonce, ciphertext_and_tag, None)
        elif cipher_id == CIPHER_AES_CBC_HMAC:
            return _decrypt_aes_cbc_hmac(key, nonce, ciphertext_and_tag)
        else:
            cipher = AESGCM(key)
            return cipher.decrypt(nonce, ciphertext_and_tag, None)

    except ValueError:
        raise
    except Exception as e:
        raise ValueError("Decipher Error: invalid password or file is damaged.")