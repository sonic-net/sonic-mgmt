# Copyright (c) 2019, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations


def binary_exp_mod(f: int, e: int, *, m: int) -> int:
    """Computes f^e mod m in O(log e) multiplications modulo m."""
    # Compute len_e = floor(log_2(e))
    len_e = -1
    x = e
    while x > 0:
        x >>= 1
        len_e += 1
    # Compute f**e mod m
    result = 1
    for k in range(len_e, -1, -1):
        result = (result * result) % m
        if ((e >> k) & 1) != 0:
            result = (result * f) % m
    return result


def simple_gcd(a: int, b: int) -> int:
    """Compute GCD of its two inputs."""
    while b != 0:
        a, b = b, a % b
    return a


def quick_is_not_prime(n: int) -> bool:
    """Does some quick checks to see if we can poke a hole into the primality of n.

    A result of `False` does **not** mean that the number is prime; it just means
    that we could not detect quickly whether it is not prime.
    """
    if n <= 2:
        return n < 2
    # The constant in the next line is the product of all primes < 200
    prime_product = 7799922041683461553249199106329813876687996789903550945093032474868511536164700810
    gcd = simple_gcd(n, prime_product)
    if gcd > 1:
        if n < 200 and gcd == n:
            # Explicitly check for all primes < 200
            return n not in (
                2,
                3,
                5,
                7,
                11,
                13,
                17,
                19,
                23,
                29,
                31,
                37,
                41,
                43,
                47,
                53,
                59,
                61,
                67,
                71,
                73,
                79,
                83,
                89,
                97,
                101,
                103,
                107,
                109,
                113,
                127,
                131,
                137,
                139,
                149,
                151,
                157,
                163,
                167,
                173,
                179,
                181,
                191,
                193,
                197,
                199,
            )
        return True
    # TODO: maybe do some iterations of Miller-Rabin to increase confidence
    # (https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
    return False


def count_bytes(no: int) -> int:
    """
    Given an integer, compute the number of bytes necessary to store its absolute value.
    """
    no = abs(no)
    if no == 0:
        return 0
    return (no.bit_length() + 7) // 8


def count_bits(no: int) -> int:
    """
    Given an integer, compute the number of bits necessary to store its absolute value.
    """
    no = abs(no)
    if no == 0:
        return 0
    return no.bit_length()


def convert_int_to_bytes(no: int, *, count: int | None = None) -> bytes:
    """
    Convert the absolute value of an integer to a byte string in network byte order.

    If ``count`` is provided, it must be sufficiently large so that the integer's
    absolute value can be represented with these number of bytes. The resulting byte
    string will have length exactly ``count``.

    The value zero will be converted to an empty byte string if ``count`` is provided.
    """
    no = abs(no)
    if count is None:
        count = count_bytes(no)
    return no.to_bytes(count, byteorder="big")


def convert_int_to_hex(no: int, *, digits: int | None = None) -> str:
    """
    Convert the absolute value of an integer to a string of hexadecimal digits.

    If ``digits`` is provided, the string will be padded on the left with ``0``s so
    that the returned value has length ``digits``. If ``digits`` is not sufficient,
    the string will be longer.
    """
    no = abs(no)
    value = f"{no:x}"
    if digits is not None and len(value) < digits:
        value = "0" * (digits - len(value)) + value
    return value


def convert_bytes_to_int(data: bytes) -> int:
    """
    Convert a byte string to an unsigned integer in network byte order.
    """
    return int.from_bytes(data, byteorder="big", signed=False)


__all__ = (
    "binary_exp_mod",
    "simple_gcd",
    "quick_is_not_prime",
    "count_bytes",
    "count_bits",
    "convert_int_to_bytes",
    "convert_int_to_hex",
    "convert_bytes_to_int",
)
