"""Centralized relative path constants for transceiver attribute infrastructure.

This module consolidates commonly used relative paths so that they can be
maintained in one place and imported where needed.

Add new constants here rather than redefining them across files.
"""
import os
from pathlib import Path


# Repository root - robust approach using pathlib from this file's location
# Structure: repo_root/tests/transceiver/attribute_parser/paths.py
# So parents[3] gives us the repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]


# Root directory (relative to repository root)
REL_TRANSCEIVER_INV_DIR = os.path.join('ansible', 'files', 'transceiver', 'inventory')

# Subdirectories
REL_ATTR_DIR = os.path.join(REL_TRANSCEIVER_INV_DIR, 'attributes')
REL_TEMPLATES_DIR = os.path.join(REL_TRANSCEIVER_INV_DIR, 'templates')
REL_DUT_INFO_DIR = os.path.join(REL_TRANSCEIVER_INV_DIR, 'dut_info')

# Files
REL_NORMALIZATION_MAPPINGS_FILE = os.path.join(REL_TRANSCEIVER_INV_DIR, 'normalization_mappings.json')
REL_DEPLOYMENT_TEMPLATES_FILE = os.path.join(REL_TEMPLATES_DIR, 'deployment_templates.json')

# Shard-directory layout
SHARD_VENDORS_DIR = os.path.join('transceivers', 'vendors')
SHARD_PART_NUMBERS_SEGMENT = 'part_numbers'


def get_repo_root():
    """Get the repository root directory as a Path object.

    Returns:
        Path: Repository root directory
    """
    return _REPO_ROOT


def iter_vendor_pn_dirs(category_dir):
    """Yield ``(vendor, pn, pn_dir)`` for each per-PN directory under a category.

    Walks the shared shard layout
    ``<category_dir>/transceivers/vendors/<V>/part_numbers/<PN>/`` and yields a
    tuple for every part-number directory found. Directory names are returned
    sorted for deterministic ordering. Missing intermediate directories are
    skipped silently so callers can treat an absent layout as "no per-PN data".

    Args:
        category_dir: Absolute path to a category directory (the directory that
            directly contains the ``transceivers`` sub-directory).

    Yields:
        tuple: ``(vendor, pn, pn_dir)`` where ``pn_dir`` is the absolute path to
            the ``.../part_numbers/<PN>`` directory.
    """
    vendors_path = os.path.join(category_dir, SHARD_VENDORS_DIR)
    if not os.path.isdir(vendors_path):
        return
    for vendor in sorted(os.listdir(vendors_path)):
        pn_parent = os.path.join(vendors_path, vendor, SHARD_PART_NUMBERS_SEGMENT)
        if not os.path.isdir(pn_parent):
            continue
        for pn in sorted(os.listdir(pn_parent)):
            pn_dir = os.path.join(pn_parent, pn)
            if not os.path.isdir(pn_dir):
                continue
            yield vendor, pn, pn_dir
