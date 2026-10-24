"""Encrypt small secrets (the SNMP community string) before they are stored.

The report (§3.12) requires SNMP credentials to be "stored securely". The key is
derived from the application SECRET_KEY, which lives in the environment / instance
folder and never in the database, so a copy of the database alone does not reveal
the community strings.

* Stored values look like ``enc:v1:<token>``.
* Older plaintext values (no prefix) are still readable and are re-encrypted the
  next time the device is saved.
* If SECRET_KEY changes, old tokens cannot be decrypted; ``decrypt`` returns None
  and the administrator re-enters the community string.
"""
import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

log = logging.getLogger(__name__)

PREFIX = "enc:v1:"


def _fernet():
    digest = hashlib.sha256(current_app.config["SECRET_KEY"].encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def is_encrypted(value):
    return bool(value) and value.startswith(PREFIX)


def encrypt(plain):
    """Return the storable form of a secret ('' / None stay empty)."""
    if not plain:
        return None
    if is_encrypted(plain):
        return plain
    return PREFIX + _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt(stored):
    """Return the plaintext secret, or None if it cannot be recovered."""
    if not stored:
        return None
    if not is_encrypted(stored):
        return stored  # legacy plaintext row
    try:
        return _fernet().decrypt(stored[len(PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        log.warning("A stored SNMP community string could not be decrypted (SECRET_KEY changed?)")
        return None
