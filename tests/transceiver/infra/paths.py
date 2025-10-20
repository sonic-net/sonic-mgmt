"""Centralized relative path constants for transceiver attribute infrastructure.

This module consolidates commonly used relative paths so that they can be
maintained in one place and imported where needed.

Add new constants here rather than redefining them across files.
"""
import os


# Root directory (relative to repository root)
REL_TRANSCEIVER_INV_DIR = os.path.join('ansible', 'files', 'transceiver', 'inventory')

# Subdirectories
REL_ATTR_DIR = os.path.join(REL_TRANSCEIVER_INV_DIR, 'attributes')
REL_TEMPLATES_DIR = os.path.join(REL_TRANSCEIVER_INV_DIR, 'templates')

# Files
REL_DUT_INFO_FILE = os.path.join(REL_TRANSCEIVER_INV_DIR, 'dut_info.json')
REL_DEPLOYMENT_TEMPLATES_FILE = os.path.join(REL_TEMPLATES_DIR, 'deployment_templates.json')


