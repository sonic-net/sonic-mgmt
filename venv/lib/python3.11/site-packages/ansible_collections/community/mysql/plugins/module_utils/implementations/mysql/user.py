# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.mysql.plugins.module_utils.version import LooseVersion
from ansible_collections.community.mysql.plugins.module_utils.mysql import get_server_version

import re
import shlex


def use_old_user_mgmt(cursor):
    version = get_server_version(cursor)

    return LooseVersion(version) < LooseVersion("5.7")


def supports_identified_by_password(cursor):
    version = get_server_version(cursor)
    return LooseVersion(version) < LooseVersion("8")


def server_supports_alter_user(cursor):
    version = get_server_version(cursor)

    return LooseVersion(version) >= LooseVersion("5.6")


def server_supports_password_expire(cursor):
    version = get_server_version(cursor)

    return LooseVersion(version) >= LooseVersion("5.7")


def get_tls_requires(cursor, user, host):
    """Get user TLS requirements.
    We must use SHOW GRANTS because some tls fileds are encoded.

    Args:
        cursor (cursor): DB driver cursor object.
        user (str): User name.
        host (str): User host name.

    Returns: Dictionary containing current TLS required
    """
    if not use_old_user_mgmt(cursor):
        query = "SHOW CREATE USER '%s'@'%s'" % (user, host)
    else:
        query = "SHOW GRANTS for '%s'@'%s'" % (user, host)

    cursor.execute(query)
    grants = cursor.fetchone()

    # Mysql_info use a DictCursor so we must convert back to a list
    # otherwise we get KeyError 0
    if isinstance(grants, dict):
        grants = list(grants.values())
    grants_str = ''.join(grants)

    pattern = r"(?<=\bREQUIRE\b)(.*?)(?=(?:\bPASSWORD\b|$))"
    requires_match = re.search(pattern, grants_str)
    requires = requires_match.group().strip() if requires_match else ""

    if requires.startswith('NONE'):
        return None

    if requires.startswith('SSL'):
        return {'SSL': None}

    if requires.startswith('X509'):
        return {'X509': None}

    items = iter(shlex.split(requires))
    requires = dict(zip(items, items))
    return requires or None
