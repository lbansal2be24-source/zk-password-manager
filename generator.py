"""
generator.py - strong random passwords.

Uses the `secrets` module (cryptographically secure), NOT `random`
(which is predictable and must never be used for passwords or keys).
"""
import secrets
import string

SYMBOLS = "!@#$%^&*-_=+?"


def generate_password(length=16):
    if length < 8:
        raise ValueError("Length kam se kam 8 honi chahiye")

    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS]
    all_chars = "".join(groups)

    # at least one character from every group...
    password = [secrets.choice(group) for group in groups]
    # ...the rest completely random
    password += [secrets.choice(all_chars) for _ in range(length - len(groups))]
    # shuffle so the guaranteed characters aren't always at the start
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


if __name__ == "__main__":
    for _ in range(3):
        print(generate_password())
