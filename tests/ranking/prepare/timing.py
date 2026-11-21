"""Elapsed time reporting for Prepare actions."""

from contextlib import contextmanager
from time import monotonic


@contextmanager
def measure(action):
    start = monotonic()
    result = 'FAILED'
    try:
        yield
        result = 'OK'
    finally:
        print('Prepare | {} | {:.2f}s | {}'.format(
            action, monotonic() - start, result), flush=True)
