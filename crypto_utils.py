"""
crypto_utils.py - the cryptographic core of the password manager.

  Argon2id    : master password + salt  ->  32-byte key   (slow on purpose)
  AES-256-GCM : key + data  ->  encrypted data with a tamper-proof seal (tag)

Nothing in this file ever stores or prints the master password or the key.
"""
import os

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16    # bytes of random salt (namak)
NONCE_SIZE = 12   # bytes of random nonce - the standard size for AES-GCM
KEY_SIZE = 32     # 32 bytes = 256-bit key -> AES-256

# Argon2id cost settings. They are saved inside vault.json, so they can be
# raised in the future without breaking old vaults.
DEFAULT_KDF = {
    "time_cost": 3,        # passes over memory (more = slower)
    "memory_cost": 65536,  # in KiB -> 64 MB of RAM per guess (hurts GPUs)
    "parallelism": 4,      # threads
}


def generate_salt():
    """Fresh random salt from the OS's secure random generator."""
    return os.urandom(SALT_SIZE)


def derive_key(master_password, salt, kdf=None):
    """Master password + salt -> 32-byte AES key (Argon2id)."""
    kdf = kdf or DEFAULT_KDF
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_cost"],
        parallelism=kdf["parallelism"],
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def encrypt_data(key, plaintext):
    """Lock text with AES-256-GCM. Returns nonce + ciphertext + tag."""
    nonce = os.urandom(NONCE_SIZE)               # never reuse a nonce with the same key
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext                    # nonce is not secret, it rides along


def decrypt_data(key, blob):
    """Unlock data. Raises cryptography.exceptions.InvalidTag if the key is
    wrong OR if even one byte of the data was changed (integrity check)."""
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()
