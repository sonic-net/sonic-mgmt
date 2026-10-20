"""Custom URL patterns for Failure-Validated xfail.

This file contains internal issue tracker URL patterns that should not be
upstreamed to the SONiC community.  Patterns defined here are appended to
the built-in patterns in failure_signature.py at import time.

Each entry is a tuple of (compiled_regex, source_name).  The regex must
have exactly one capture group for the issue number.
"""

import re   # noqa: F401

CUSTOM_URL_PATTERNS = [
]
