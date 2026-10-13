"""
vault.py - loads, saves and edits the encrypted vault file.

vault.json only ever contains:
  - the salt          (not secret)
  - the Argon2 settings (not secret)
  - the encrypted data (useless without the master password)
The master password and the key are NEVER written to disk -> zero knowledge.
"""
import json
import os
import shutil
from datetime import datetime

from crypto_utils import (DEFAULT_KDF, decrypt_data, derive_key,
                          encrypt_data, generate_salt)

VAULT_FILE = "vault.json"
BACKUP_DIR = "backups"
FORMAT_VERSION = 1


def vault_exists(path=VAULT_FILE):
    return os.path.exists(path)


class Vault:
    def __init__(self, key, salt, kdf, entries, path=VAULT_FILE):
        self.key = key            # lives only in RAM while unlocked
        self.salt = salt
        self.kdf = kdf
        self.entries = entries    # {"gmail": {"username": ..., "password": ..., ...}}
        self.path = path

    # ---------- open / create ----------
    @classmethod
    def create(cls, master_password, path=VAULT_FILE):
        salt = generate_salt()
        kdf = dict(DEFAULT_KDF)
        key = derive_key(master_password, salt, kdf)
        vault = cls(key, salt, kdf, {}, path)
        vault.save()
        return vault

    @classmethod
    def unlock(cls, master_password, path=VAULT_FILE):
        """Wrong password -> InvalidTag. Broken file -> ValueError / KeyError."""
        with open(path) as f:
            stored = json.load(f)
        salt = bytes.fromhex(stored["salt"])
        kdf = stored.get("kdf", dict(DEFAULT_KDF))   # older vaults have no "kdf" field
        key = derive_key(master_password, salt, kdf)
        text = decrypt_data(key, bytes.fromhex(stored["data"]))
        return cls(key, salt, kdf, json.loads(text), path)

    # ---------- saving (built for Availability) ----------
    def save(self):
        blob = encrypt_data(self.key, json.dumps(self.entries))
        payload = {
            "version": FORMAT_VERSION,
            "kdf": self.kdf,
            "salt": self.salt.hex(),
            "data": blob.hex(),
        }
        # 1. keep the previous version as vault.json.bak (still encrypted)
        if os.path.exists(self.path):
            shutil.copy2(self.path, self.path + ".bak")
        # 2. write to a temp file first, then swap it in one step.
        #    If the laptop dies mid-save, the old vault.json is still intact.
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)          # only your user account can read the file
        os.replace(tmp, self.path)

    # ---------- entries ----------
    def add(self, site, username, password):
        now = datetime.now().isoformat(timespec="seconds")
        old = self.entries.get(site, {})
        self.entries[site] = {
            "username": username,
            "password": password,
            "created": old.get("created", now),
            "updated": now,
        }
        self.save()

    def get(self, site):
        return self.entries.get(site)

    def delete(self, site):
        if site not in self.entries:
            return False
        del self.entries[site]
        self.save()
        return True

    def sites(self):
        return sorted(self.entries)

    # ---------- account ----------
    def check_master_password(self, password):
        import hmac
        return hmac.compare_digest(derive_key(password, self.salt, self.kdf), self.key)

    def change_master_password(self, new_password):
        """New salt + new key, then re-encrypt everything."""
        self.salt = generate_salt()
        self.key = derive_key(new_password, self.salt, self.kdf)
        self.save()
        # The .bak copy is encrypted with the OLD password - remove it, so an
        # old (maybe leaked) password can't open anything any more.
        bak = self.path + ".bak"
        if os.path.exists(bak):
            os.remove(bak)

    def backup(self, folder=BACKUP_DIR):
        """Timestamped copy of the encrypted file (safe to keep on a USB/cloud)."""
        os.makedirs(folder, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(folder, f"vault-{stamp}.json")
        shutil.copy2(self.path, dest)
        return dest

    def lock(self):
        """Drop the key and decrypted entries from this object."""
        self.key = None
        self.entries = {}
