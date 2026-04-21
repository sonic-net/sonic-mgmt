"""
Generate MySQL sha256 compatible plugins hash for a given password and salt

based on
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 * https://crypto.stackexchange.com/questions/77427/whats-the-algorithm-behind-mysqls-sha256-password-hashing-scheme/111174#111174
 * https://github.com/hashcat/hashcat/blob/master/tools/test_modules/m07400.pm
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib


def _to64(v, n):
    """Convert a 32-bit integer to a base-64 string"""
    i64 = (
        [".", "/"]
        + [chr(x) for x in range(48, 58)]
        + [chr(x) for x in range(65, 91)]
        + [chr(x) for x in range(97, 123)]
    )
    result = ""
    while n > 0:
        n -= 1
        result += i64[v & 0x3F]
        v >>= 6
    return result


def _hashlib_sha256(data):
    """Return SHA-256 digest from hashlib ."""
    return hashlib.sha256(data).digest()


def _sha256_digest(key, salt, loops):
    """Return a SHA-256 digest of the concatenation of the key, the salt, and the key, repeated as necessary."""
    # https://www.akkadia.org/drepper/SHA-crypt.txt
    num_bytes = 32
    bytes_key = key.encode()
    bytes_salt = salt.encode()
    digest_b = _hashlib_sha256(bytes_key + bytes_salt + bytes_key)

    tmp = bytes_key + bytes_salt
    for i in range(len(bytes_key), 0, -num_bytes):
        tmp += digest_b if i > num_bytes else digest_b[:i]

    i = len(bytes_key)
    while i > 0:
        tmp += digest_b if (i & 1) != 0 else bytes_key
        i >>= 1

    digest_a = _hashlib_sha256(tmp)

    tmp = b""
    for i in range(len(bytes_key)):
        tmp += bytes_key

    digest_dp = _hashlib_sha256(tmp)

    byte_sequence_p = b""
    for i in range(len(bytes_key), 0, -num_bytes):
        byte_sequence_p += digest_dp if i > num_bytes else digest_dp[:i]

    tmp = b""
    til = 16 + digest_a[0]

    for i in range(til):
        tmp += bytes_salt

    digest_ds = _hashlib_sha256(tmp)

    byte_sequence_s = b""
    for i in range(len(bytes_salt), 0, -num_bytes):
        byte_sequence_s += digest_ds if i > num_bytes else digest_ds[:i]

    digest_c = digest_a

    for i in range(loops):
        tmp = byte_sequence_p if (i & 1) else digest_c
        if i % 3:
            tmp += byte_sequence_s
        if i % 7:
            tmp += byte_sequence_p
        tmp += digest_c if (i & 1) else byte_sequence_p
        digest_c = _hashlib_sha256(tmp)

    inc1, inc2, mod, end = (10, 21, 30, 0)

    i = 0
    tmp = ""

    while True:
        tmp += _to64(
            (digest_c[i] << 16)
            | (digest_c[(i + inc1) % mod] << 8)
            | digest_c[(i + inc1 * 2) % mod],
            4,
        )
        i = (i + inc2) % mod
        if i == end:
            break

    tmp += _to64((digest_c[31] << 8) | digest_c[30], 3)

    return tmp


def mysql_sha256_password_hash(password, salt):
    """Return a MySQL compatible caching_sha2_password hash in raw format."""
    if len(salt) != 20:
        raise ValueError("Salt must be 20 characters long.")

    count = 5
    iteration = 1000 * count

    digest = _sha256_digest(password, salt, iteration)
    return "$A${0:>03}${1}{2}".format(count, salt, digest)


def mysql_sha256_password_hash_hex(password, salt):
    """Return a MySQL compatible caching_sha2_password hash in hex format."""
    return mysql_sha256_password_hash(password, salt).encode().hex().upper()
