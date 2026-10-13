"""
clipboard.py - copy a password to the Mac clipboard and wipe it after 20 s.

Why: printing a password on screen lets anyone behind you (shoulder surfing)
or a screen recording see it. The clipboard is safer, and auto-clearing it
means the password doesn't sit there forever.
Works on macOS (pbcopy/pbpaste). On other systems copy() returns False and
the app simply shows the password instead.
"""
import platform
import shutil
import subprocess
import threading

CLEAR_AFTER = 20  # seconds
_last_copied = None


def _available():
    return platform.system() == "Darwin" and shutil.which("pbcopy") is not None


def _paste():
    return subprocess.run(["pbpaste"], capture_output=True, text=True).stdout


def _set(text):
    subprocess.run(["pbcopy"], input=text, text=True, check=True)


def _clear_if_still(text):
    # only wipe if the user hasn't copied something else meanwhile
    if _available() and _paste() == text:
        _set("")


def copy(text):
    global _last_copied
    if not _available():
        return False
    _set(text)
    _last_copied = text
    timer = threading.Timer(CLEAR_AFTER, _clear_if_still, args=(text,))
    timer.daemon = True
    timer.start()
    return True


def clear():
    """Called on lock / exit."""
    global _last_copied
    if _last_copied is not None:
        _clear_if_still(_last_copied)
        _last_copied = None
