from __future__ import annotations

from base64 import b64decode
from hashlib import md5


def ssh_public_key_md5_fingerprint(value: str) -> str:
    """
    Compute the md5 fingerprint of a SSH public key.
    """
    parts = value.strip().split()
    if len(parts) < 2:
        raise ValueError("invalid ssh public key")

    raw = b64decode(parts[1].encode("ascii"))
    digest = md5(raw).hexdigest()

    return ":".join(a + b for a, b in zip(digest[::2], digest[1::2]))
