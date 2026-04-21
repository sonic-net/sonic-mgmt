# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import errno
import os


def write_key_safe(path, key):
    """
    Write the key to 'path'.
    """
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    prev_umask = os.umask(0o177)
    try:
        with open(path, "w") as f:
            f.write(key + "\n")
    finally:
        os.umask(prev_umask)


def read_key(path):
    """
    Read entire file and strip trailing whitespace/newlines.
    """
    with open(path, "r") as f:
        return f.read().strip()


def read_secret(value_or_path):
    if value_or_path is None:
        return None

    if isinstance(value_or_path, str) and os.path.isfile(value_or_path):
        return read_key(value_or_path)

    return str(value_or_path).strip()
