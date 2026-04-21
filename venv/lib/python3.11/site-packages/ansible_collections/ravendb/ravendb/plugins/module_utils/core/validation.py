# -*- coding: utf-8 -*-
#
# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import re
try:

    from urllib.parse import urlparse
except Exception:

    from urlparse import urlparse

try:
    from ipaddress import ip_address as _ip_address
except Exception:
    _ip_address = None

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_TAG_RE = re.compile(r"^[A-Z0-9]{1,4}$")


def is_valid_url(url):
    """Return True if the given URL is a string with a valid HTTP or HTTPS scheme."""
    if not isinstance(url, str):
        return False
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def validate_url(url):
    """Validate a URL string and return (ok, error)."""
    if not is_valid_url(url):
        return False, "Invalid URL: {}".format(url)
    return True, None


def is_valid_name(name):
    """Generic name rule: must contain only letters, numbers, dashes, or underscores."""
    return isinstance(name, str) and bool(_NAME_RE.match(name))


def is_valid_database_name(name):
    """Return True if the database name matches RavenDB rules."""
    return is_valid_name(name)


def validate_database_name(name):
    """Validate database name and return (ok, error)."""
    if not is_valid_database_name(name):
        return (
            False,
            "Invalid database name: {}. Only letters, numbers, dashes, and underscores are allowed.".format(name),
        )
    return True, None


def is_valid_replication_factor(factor):
    """Return True if replication factor is a positive integer."""
    return isinstance(factor, int) and factor > 0


def validate_replication_factor(factor):
    """Validate replication factor and return (ok, error)."""
    if not is_valid_replication_factor(factor):
        return False, "Invalid replication factor: {}. Must be a positive integer.".format(factor)
    return True, None


def validate_replication_factor_optional(factor):
    """Accepts None or a positive integer."""
    if factor is None:
        return True, None
    return validate_replication_factor(factor)


def validate_topology_members(members, replication_factor):
    """Validate that topology_members is a list of tags with length == replication_factor."""
    if not members:
        return True, None
    if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
        return False, "topology_members must be a list of strings."
    if replication_factor is not None and len(members) != replication_factor:
        return False, "topology_members length ({}) must equal replication_factor ({}).".format(len(members), replication_factor)
    return True, None


def validate_paths_exist(*paths):
    """Ensure all given file paths exist on the filesystem."""
    for p in paths:
        if p and not os.path.isfile(p):
            return False, "Path does not exist: {}".format(p)
    return True, None


def is_valid_state(state):
    """Return True if the state is either 'present' or 'absent'."""
    return state in ("present", "absent")


def validate_state(state):
    """Validate state and return (ok, error)."""
    if not is_valid_state(state):
        return False, "Invalid state: {}. Must be 'present' or 'absent'.".format(state)
    return True, None


def is_valid_index_name(name):
    return is_valid_name(name)


def validate_index_name(name):
    if not is_valid_index_name(name):
        return False, "Invalid index name: {}. Only letters, numbers, dashes, and underscores are allowed.".format(name)
    return True, None


def validate_state_optional(state):
    """Accepts None, 'present', or 'absent' (for mode-only operations)."""
    if state is None:
        return True, None
    return validate_state(state)


def is_valid_mode(mode):
    return mode in (None, 'resumed', 'paused', 'enabled', 'disabled', 'reset')


def validate_mode(mode):
    if not is_valid_mode(mode):
        return False, "Invalid mode: {}. Must be one of 'resumed', 'paused', 'enabled', 'disabled', 'reset'.".format(mode)
    return True, None


def is_valid_bool(value):
    return isinstance(value, bool)


def validate_bool(name, value):
    if not is_valid_bool(value):
        return False, "Invalid {} flag: {}. Must be a boolean.".format(name, value)
    return True, None


def is_valid_dict(value):
    return isinstance(value, dict) or value is None


def validate_dict(name, value):
    if not is_valid_dict(value):
        return False, "Invalid {}: Must be a dictionary.".format(name)
    return True, None


def is_valid_tag(tag):
    """Return True if the tag is uppercase alphanumeric with length 1..4."""
    return isinstance(tag, str) and bool(_TAG_RE.match(tag))


def validate_tag(tag):
    if not is_valid_tag(tag):
        return False, "Invalid node tag: {}. Must be uppercase alphanumeric (1–4 chars).".format(tag)
    return True, None


def ip_host_warning(url, validate_certificate):
    if not validate_certificate:
        return None
    if not is_valid_url(url):
        return None
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return None
    if not host or _ip_address is None:
        return None
    try:
        _ip_address(host)
        return "Host is an IP; certificate name validation may fail. Consider validate_certificate=false."
    except Exception:
        return None


def collect_errors(*results):
    """
    Accept many (ok, err) tuples and return (ok, combined_err_string_or_None).
    Aggregates all error messages.
    """
    errors = [err for ok, err in results if not ok and err]
    return (len(errors) == 0, "; ".join(errors) if errors else None)
