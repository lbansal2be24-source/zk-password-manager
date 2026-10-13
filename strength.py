"""
strength.py - rough password strength estimate (entropy in bits).

entropy = length x log2(size of character pool)
It's an estimate: it can't spot things like your name + birth year,
so a long random password is always the safest choice.
"""
import math
import string

COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "111111", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
}
WEAK_PARTS = ("password", "qwerty", "12345", "abcdef", "admin")


def check_strength(password):
    """Returns (bits, label)."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 33

    bits = len(password) * math.log2(pool) if pool else 0.0

    lowered = password.lower()
    if lowered in COMMON or any(part in lowered for part in WEAK_PARTS):
        bits = min(bits, 20)            # famous passwords are guessed instantly
    if len(set(password)) <= 3:
        bits = min(bits, 20)            # "aaaaaaaa", "abababab"

    if bits < 28:
        label = "Very weak 🔴"
    elif bits < 40:
        label = "Weak 🟠"
    elif bits < 60:
        label = "Medium 🟡"
    elif bits < 80:
        label = "Strong 🟢"
    else:
        label = "Very strong 💪"
    return round(bits), label
