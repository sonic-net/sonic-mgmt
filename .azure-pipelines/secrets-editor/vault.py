"""Pure-Python implementation of the ansible-vault 1.1 / AES256 format.

The standard `ansible-vault` PyPI packages depend on ansible-core, which
imports `fcntl` and therefore does not work on Windows. This module avoids
that dependency by using `cryptography` directly (already pulled in by
azure-identity).

Format reference (after the header line):

    $ANSIBLE_VAULT;1.1;AES256
    <hex-encoded payload, optionally line-wrapped>

The hex-decoded payload has three ASCII lines separated by `\\n`, each itself
hex-encoded:

    <hex(salt)>\\n<hex(hmac)>\\n<hex(ciphertext)>

- salt: 32 random bytes
- key derivation: PBKDF2-HMAC-SHA256, 10000 iterations, 80 bytes output,
  split into cipher_key (32) || hmac_key (32) || iv (16).
- encryption: AES-256 in CTR mode with PKCS7 padding (block size 128 bits).
- hmac: HMAC-SHA256 of the ciphertext using hmac_key.

Compatible with `ansible-vault encrypt/decrypt --vault-password-file ...`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets as _secrets

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VAULT_HEADER = "$ANSIBLE_VAULT;1.1;AES256"
PBKDF2_ITERATIONS = 10000
SALT_LEN = 32
KEY_LEN = 32
HMAC_KEY_LEN = 32
IV_LEN = 16
LINE_WIDTH = 80


def _derive(password: bytes, salt: bytes) -> tuple[bytes, bytes, bytes]:
    keymat = hashlib.pbkdf2_hmac(
        "sha256", password, salt, PBKDF2_ITERATIONS,
        dklen=KEY_LEN + HMAC_KEY_LEN + IV_LEN,
    )
    return (
        keymat[:KEY_LEN],
        keymat[KEY_LEN:KEY_LEN + HMAC_KEY_LEN],
        keymat[KEY_LEN + HMAC_KEY_LEN:],
    )


class VaultError(Exception):
    """Raised when a payload is malformed or HMAC verification fails."""


def decrypt(text: str, password: str) -> bytes:
    """Decrypt an ansible-vault 1.1 payload. Returns plaintext bytes."""
    lines = text.strip().splitlines()
    if not lines or not lines[0].startswith("$ANSIBLE_VAULT"):
        raise VaultError("Input is not an ansible-vault payload")
    header_parts = lines[0].split(";")
    if len(header_parts) < 3 or header_parts[1].strip() != "1.1" \
            or header_parts[2].strip() != "AES256":
        raise VaultError(f"Unsupported vault header: {lines[0]!r}")

    body_hex = "".join(lines[1:]).strip()
    try:
        inner = bytes.fromhex(body_hex).decode("ascii")
    except (ValueError, UnicodeDecodeError) as e:
        raise VaultError("Malformed outer hex payload") from e

    parts = inner.strip().split("\n")
    if len(parts) != 3:
        raise VaultError("Inner payload does not have salt/hmac/ciphertext")
    try:
        salt = bytes.fromhex(parts[0])
        expected_hmac = bytes.fromhex(parts[1])
        ciphertext = bytes.fromhex(parts[2])
    except ValueError as e:
        raise VaultError("Malformed inner hex payload") from e

    cipher_key, hmac_key, iv = _derive(password.encode("utf-8"), salt)
    actual_hmac = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_hmac, actual_hmac):
        raise VaultError("HMAC verification failed (wrong password?)")

    cipher = Cipher(algorithms.AES(cipher_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt(plaintext: bytes, password: str) -> str:
    """Encrypt plaintext with the ansible-vault 1.1 format. Returns the
    ASCII-armored payload (header + hex body + trailing newline)."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    salt = _secrets.token_bytes(SALT_LEN)
    cipher_key, hmac_key, iv = _derive(password.encode("utf-8"), salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(cipher_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    digest = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
    inner = (salt.hex() + "\n" + digest.hex() + "\n" + ciphertext.hex()).encode("ascii")
    body = inner.hex()
    wrapped = "\n".join(body[i:i + LINE_WIDTH] for i in range(0, len(body), LINE_WIDTH))
    return VAULT_HEADER + "\n" + wrapped + "\n"


# Sanity self-test entry point: `python -m vault selftest`.
if __name__ == "__main__":  # pragma: no cover
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        pwd = "test-password-1234"
        msg = b'{"hello": "world", "n": 42}\n'
        ct = encrypt(msg, pwd)
        assert ct.startswith(VAULT_HEADER + "\n")
        pt = decrypt(ct, pwd)
        assert pt == msg, (pt, msg)
        try:
            decrypt(ct, "wrong-password")
            raise AssertionError("expected VaultError on wrong password")
        except VaultError:
            pass
        print("selftest OK")
        sys.exit(0)
    print("usage: python -m vault selftest", file=sys.stderr)
    sys.exit(2)
