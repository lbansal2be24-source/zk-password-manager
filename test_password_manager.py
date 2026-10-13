"""
Automated tests. Run:  python -m unittest -v
"""
import json
import os
import string
import tempfile
import unittest
from unittest import mock

from cryptography.exceptions import InvalidTag

import breach
from crypto_utils import decrypt_data, derive_key, encrypt_data, generate_salt
from generator import SYMBOLS, generate_password
from strength import check_strength
from vault import Vault


class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.salt = generate_salt()
        self.key = derive_key("correct horse", self.salt)

    def test_same_password_same_salt_same_key(self):
        self.assertEqual(self.key, derive_key("correct horse", self.salt))

    def test_new_salt_gives_new_key(self):
        self.assertNotEqual(self.key, derive_key("correct horse", generate_salt()))

    def test_key_is_256_bits(self):
        self.assertEqual(len(self.key), 32)

    def test_encrypt_decrypt_roundtrip(self):
        blob = encrypt_data(self.key, "secret 123")
        self.assertEqual(decrypt_data(self.key, blob), "secret 123")

    def test_same_plaintext_encrypts_differently(self):
        self.assertNotEqual(encrypt_data(self.key, "x"), encrypt_data(self.key, "x"))

    def test_wrong_key_fails(self):
        blob = encrypt_data(self.key, "secret")
        with self.assertRaises(InvalidTag):
            decrypt_data(derive_key("wrong horse", self.salt), blob)

    def test_tampering_detected(self):
        blob = bytearray(encrypt_data(self.key, "secret"))
        blob[15] ^= 1
        with self.assertRaises(InvalidTag):
            decrypt_data(self.key, bytes(blob))


class TestVault(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "vault.json")

    def tearDown(self):
        self.dir.cleanup()

    def test_create_add_unlock(self):
        v = Vault.create("master-pass-1", self.path)
        v.add("gmail", "me@test.com", "pw123")
        again = Vault.unlock("master-pass-1", self.path)
        self.assertEqual(again.get("gmail")["password"], "pw123")

    def test_file_has_no_plaintext(self):
        v = Vault.create("master-pass-1", self.path)
        v.add("gmail", "me@test.com", "VerySecretValue")
        with open(self.path) as f:
            raw = f.read()
        for leak in ("VerySecretValue", "gmail", "me@test.com", "master-pass-1"):
            self.assertNotIn(leak, raw)

    def test_wrong_master_password(self):
        Vault.create("master-pass-1", self.path)
        with self.assertRaises(InvalidTag):
            Vault.unlock("master-pass-2", self.path)

    def test_old_format_without_kdf_still_opens(self):
        v = Vault.create("master-pass-1", self.path)
        v.add("gmail", "u", "p")
        with open(self.path) as f:
            data = json.load(f)
        old = {"salt": data["salt"], "data": data["data"]}   # step-3 format
        with open(self.path, "w") as f:
            json.dump(old, f)
        self.assertEqual(Vault.unlock("master-pass-1", self.path).get("gmail")["password"], "p")

    def test_delete(self):
        v = Vault.create("master-pass-1", self.path)
        v.add("a", "u", "p")
        self.assertTrue(v.delete("a"))
        self.assertFalse(v.delete("a"))
        self.assertIsNone(Vault.unlock("master-pass-1", self.path).get("a"))

    def test_change_master_password(self):
        v = Vault.create("master-pass-1", self.path)
        v.add("a", "u", "p")
        v.change_master_password("master-pass-2")
        with self.assertRaises(InvalidTag):
            Vault.unlock("master-pass-1", self.path)
        self.assertEqual(Vault.unlock("master-pass-2", self.path).get("a")["password"], "p")
        self.assertFalse(os.path.exists(self.path + ".bak"))

    def test_bak_file_kept(self):
        v = Vault.create("master-pass-1", self.path)
        v.add("a", "u", "p")
        self.assertTrue(os.path.exists(self.path + ".bak"))

    def test_backup(self):
        v = Vault.create("master-pass-1", self.path)
        dest = v.backup(os.path.join(self.dir.name, "backups"))
        self.assertTrue(Vault.unlock("master-pass-1", dest))


class TestGenerator(unittest.TestCase):
    def test_length_and_character_groups(self):
        for _ in range(50):
            pw = generate_password(16)
            self.assertEqual(len(pw), 16)
            self.assertTrue(any(c in string.ascii_lowercase for c in pw))
            self.assertTrue(any(c in string.ascii_uppercase for c in pw))
            self.assertTrue(any(c in string.digits for c in pw))
            self.assertTrue(any(c in SYMBOLS for c in pw))

    def test_too_short_rejected(self):
        with self.assertRaises(ValueError):
            generate_password(4)


class TestStrength(unittest.TestCase):
    def test_common_password_is_weak(self):
        self.assertLess(check_strength("password123")[0], 28)

    def test_generated_password_is_strong(self):
        self.assertGreaterEqual(check_strength(generate_password(20))[0], 80)


class TestBreach(unittest.TestCase):
    # "password" -> SHA-1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    def fake_response(self, text):
        resp = mock.Mock()
        resp.text = text
        resp.raise_for_status = mock.Mock()
        return resp

    def test_found(self):
        body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\nAAAA:1"
        with mock.patch("breach.requests.get", return_value=self.fake_response(body)) as get:
            self.assertEqual(breach.check_pwned("password"), 9545824)
            self.assertTrue(get.call_args[0][0].endswith("/5BAA6"))   # only 5 chars sent

    def test_not_found(self):
        with mock.patch("breach.requests.get", return_value=self.fake_response("AAAA:1")):
            self.assertEqual(breach.check_pwned("password"), 0)


if __name__ == "__main__":
    unittest.main()
