"""
main.py - command-line app for the zero-knowledge password manager.

Run:  python main.py
"""
import sys
import time
from getpass import getpass

from cryptography.exceptions import InvalidTag

import clipboard
from breach import BreachCheckError, check_pwned
from generator import generate_password
from strength import check_strength
from vault import Vault, vault_exists

AUTO_LOCK_SECONDS = 120   # 2 minutes of no activity -> vault locks itself
MAX_ATTEMPTS = 3
MIN_MASTER_LENGTH = 8


# ======================= login / setup =======================

def ask_new_master_password(prompt):
    while True:
        pw = getpass(prompt)
        if len(pw) < MIN_MASTER_LENGTH:
            print(f"Kam se kam {MIN_MASTER_LENGTH} characters chahiye!")
            continue
        print("Strength:", check_strength(pw)[1])
        if pw != getpass("Dobara likho: "):
            print("Match nahi hua, phir try karo.")
            continue
        return pw


def setup():
    print("🔐 Naya vault bana rahe hain")
    print("⚠️  Master password bhool gaye to vault KABHI nahi khulega - koi recovery nahi hai.")
    return Vault.create(ask_new_master_password("Master password banao: "))


def login():
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return Vault.unlock(getpass("Master password: "))
        except InvalidTag:
            print("❌ Galat password (ya vault file ke saath chhedchhad hui hai)")
            time.sleep(attempt)          # har galat try ke baad thoda zyada wait
        except (ValueError, KeyError):
            print("⚠️  vault.json kharab lag rahi hai. Restore karne ke liye README dekho.")
            sys.exit(1)
    print(f"{MAX_ATTEMPTS} galat attempts. Bye!")
    sys.exit(1)


# ======================= menu actions =======================

def ask_site():
    return input("Website: ").strip().lower()


def confirm(question):
    return input(f"{question} (y/N): ").strip().lower() == "y"


def do_add(vault):
    site = ask_site()
    if not site:
        print("Website khaali nahi ho sakti")
        return
    if vault.get(site) and not confirm(f"'{site}' pehle se hai. Update karein?"):
        return
    username = input("Username: ").strip()
    password = getpass("Password (khaali chhodo = auto-generate): ")
    generated = not password
    if generated:
        password = generate_password()
        print("🎲 Strong password generate kiya")
    else:
        print("Strength:", check_strength(password)[1])
    vault.add(site, username, password)
    print("✅ Saved")
    if generated and clipboard.copy(password):
        print(f"📋 Password clipboard pe copy ho gaya ({clipboard.CLEAR_AFTER} sec mein clear hoga)")


def do_view(vault):
    site = ask_site()
    entry = vault.get(site)
    if not entry:
        print("Nahi mila")
        return
    print("Username:", entry["username"])
    if clipboard.copy(entry["password"]):
        print(f"📋 Password clipboard pe copy ho gaya ({clipboard.CLEAR_AFTER} sec mein clear hoga)")
        if confirm("Screen pe bhi dikhana hai?"):
            print("Password:", entry["password"])
    else:
        print("Password:", entry["password"])


def do_list(vault):
    if not vault.entries:
        print("Vault khaali hai")
        return
    for site in vault.sites():
        entry = vault.entries[site]
        updated = entry.get("updated", "-")
        print(f"- {site:<20} {entry['username']:<30} updated: {updated}")


def do_delete(vault):
    site = ask_site()
    if not vault.get(site):
        print("Nahi mila")
        return
    if confirm(f"'{site}' pakka delete karein?"):
        vault.delete(site)
        print("🗑️  Deleted")


def do_generate(vault):
    raw = input("Length (Enter = 16): ").strip()
    try:
        length = int(raw) if raw else 16
        password = generate_password(length)
    except ValueError:
        print("Length 8 ya usse zyada ka number hona chahiye")
        return
    print("🎲", password)
    if clipboard.copy(password):
        print("📋 Clipboard pe copy ho gaya")


def do_audit(vault):
    """Security check of every saved password: weak, reused, breached."""
    if not vault.entries:
        print("Vault khaali hai")
        return
    print("🕵️  Audit chal raha hai (breach check ke liye internet chahiye)...\n")

    # which sites share the same password?
    by_password = {}
    for site, entry in vault.entries.items():
        by_password.setdefault(entry["password"], []).append(site)

    breach_cache = {}
    problems = 0
    for site in vault.sites():
        pw = vault.entries[site]["password"]
        issues = []

        bits, label = check_strength(pw)
        if bits < 60:
            issues.append(f"weak ({label})")

        others = [s for s in by_password[pw] if s != site]
        if others:
            issues.append("reused on " + ", ".join(others))

        if pw not in breach_cache:
            try:
                breach_cache[pw] = check_pwned(pw)
            except BreachCheckError:
                breach_cache[pw] = None
        count = breach_cache[pw]
        if count is None:
            issues.append("breach check failed (internet?)")
        elif count:
            issues.append(f"found in {count:,} breaches!")

        if issues:
            problems += 1
            print(f"⚠️  {site}: " + "; ".join(issues))
        else:
            print(f"✅ {site}: OK")

    print(f"\n{problems} site(s) need attention." if problems else "\nSab passwords safe hain 💪")


def do_change_master(vault):
    if not vault.check_master_password(getpass("Current master password: ")):
        print("❌ Galat password")
        return
    new_pw = ask_new_master_password("Naya master password: ")
    vault.change_master_password(new_pw)
    print("✅ Master password badal gaya. Vault naye salt + key se re-encrypt hua.")
    print("ℹ️  Purane 'backups/' folder ki files abhi bhi PURANE password se khulengi.")


def do_backup(vault):
    path = vault.backup()
    print(f"💾 Encrypted backup bana: {path}")
    print("   Isko USB / cloud pe rakh sakte ho - bina master password ke yeh bekaar hai.")


# number, word, description, function  (function None = exit)
MENU = [
    ("1", "add", "Add / update password", do_add),
    ("2", "view", "View password", do_view),
    ("3", "list", "List websites", do_list),
    ("4", "delete", "Delete", do_delete),
    ("5", "generate", "Generate password", do_generate),
    ("6", "audit", "Security audit (weak / reused / breached)", do_audit),
    ("7", "change", "Change master password", do_change_master),
    ("8", "backup", "Backup vault", do_backup),
    ("9", "exit", "Lock & exit", None),
]
CHOICES = {}
for number, word, _, func in MENU:
    CHOICES[number] = CHOICES[word] = func


def print_menu():
    items = [f"{number}. {word.capitalize()}" for number, word, _, _ in MENU]
    print("\n" + "   ".join(items[:5]))
    print("   ".join(items[5:]))


def lock(vault):
    vault.lock()
    clipboard.clear()


def menu(vault):
    last_activity = time.monotonic()
    while True:
        print_menu()
        choice = input("Choose: ").strip().lower()

        # Auto-lock: if the user was away too long, ask for the password again
        if time.monotonic() - last_activity > AUTO_LOCK_SECONDS:
            lock(vault)
            print(f"\n🔒 {AUTO_LOCK_SECONDS // 60} min koi activity nahi - vault auto-lock ho gaya.")
            vault = login()
            last_activity = time.monotonic()
            continue

        if choice in ("quit", "lock"):
            choice = "exit"
        if choice not in CHOICES:
            print("❓ Galat choice - number (1-9) ya [word] likho")
        elif CHOICES[choice] is None:
            lock(vault)
            print("🔒 Vault locked. Bye! 👋")
            return
        else:
            CHOICES[choice](vault)
        last_activity = time.monotonic()


def main():
    vault = None
    try:
        vault = login() if vault_exists() else setup()
        menu(vault)
    except (KeyboardInterrupt, EOFError):       # Ctrl+C / Ctrl+D
        if vault:
            lock(vault)
        print("\n🔒 Vault locked. Bye! 👋")


if __name__ == "__main__":
    main()
