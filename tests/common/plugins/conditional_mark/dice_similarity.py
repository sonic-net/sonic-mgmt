"""Sorensen-Dice coefficient for string similarity.

Computes similarity between two strings using character bigram multisets.
This is a self-contained copy of the algorithm from the qw2026 repository,
inlined here to avoid adding an external dependency to sonic-mgmt.

The Dice coefficient ranges from 0.0 (no shared bigrams) to 1.0 (identical
strings).  It is used by the failure-validated xfail mechanism to score how
similar a current test failure is to a stored reference failure signature.
"""

from __future__ import annotations

from collections import Counter


def _bigrams(value: str) -> Counter[str]:
    """Return the multiset of adjacent character bigrams."""
    return Counter(value[index: index + 2] for index in range(len(value) - 1))


def dice_coefficient(first: str, second: str) -> float:
    """Calculate the Sorensen-Dice similarity of two strings, in [0, 1].

    Args:
        first: First string.
        second: Second string.

    Returns:
        float: Similarity score between 0.0 and 1.0.
    """
    if not isinstance(first, str) or not isinstance(second, str):
        raise TypeError("dice_coefficient inputs must be strings")
    if first == second:
        return 1.0
    if len(first) < 2 or len(second) < 2:
        return 0.0

    first_bigrams = _bigrams(first)
    second_bigrams = _bigrams(second)
    intersection = sum((first_bigrams & second_bigrams).values())
    return 2.0 * intersection / (sum(first_bigrams.values()) + sum(second_bigrams.values()))
