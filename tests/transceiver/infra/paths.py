"""Centralized relative path constants for transceiver attribute infrastructure.

This module consolidates commonly used relative paths so that they can be
maintained in one place and imported where needed.

Add new constants here rather than redefining them across files.
"""
import os
from pathlib import Path


# Repository root - robust approach using pathlib from this file's location
# Structure: repo_root/tests/transceiver/infra/paths.py
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


def get_repo_root():
    """Get the repository root directory as a Path object.

    Returns:
        Path: Repository root directory
    """
    return _REPO_ROOT
