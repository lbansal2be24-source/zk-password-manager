"""
breach.py - has this password appeared in a known data breach?

Uses the free Have I Been Pwned "Pwned Passwords" API with k-anonymity:
  1. SHA-1 hash the password locally           e.g. 5BAA61E4C9B93F3F0682...
  2. Send ONLY the first 5 characters           -> "5BAA6"
  3. The API returns every leaked hash starting with "5BAA6" (hundreds)
  4. We look for our full hash in that list ON OUR OWN MACHINE
The API never sees the password or even its full hash.
"""
import hashlib

import requests

API_URL = "https://api.pwnedpasswords.com/range/{}"


class BreachCheckError(Exception):
    """No internet, or the API didn't answer."""


def check_pwned(password):
    """Returns how many times the password was seen in breaches (0 = not found)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(
            API_URL.format(prefix),
            headers={
                "Add-Padding": "true",                 # hides even the response size
                "User-Agent": "zk-password-manager",
            },
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise BreachCheckError(str(e)) from e

    for line in response.text.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix == suffix:
            return int(count)
    return 0
