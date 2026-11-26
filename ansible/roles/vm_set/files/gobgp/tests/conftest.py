"""pytest bootstrap: make the ``gobgp`` package importable with no install.

Put the package parent (``ansible/roles/vm_set/files``) on ``sys.path`` so the
tests can ``import gobgp`` whether run from the repo root, this directory, or CI.
The gRPC fakes live in :mod:`gobgp.tests.fakes`.
"""
import os
import sys

_FILES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
if _FILES_DIR not in sys.path:
    sys.path.insert(0, _FILES_DIR)
