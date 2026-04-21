# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.mysql.plugins.module_utils.version import LooseVersion
from ansible_collections.community.mysql.plugins.module_utils.mysql import get_server_version


def use_old_user_mgmt(cursor):
    version = get_server_version(cursor)

    return LooseVersion(version) < LooseVersion("10.2")


def supports_identified_by_password(cursor):
    return True


def server_supports_alter_user(cursor):
    version = get_server_version(cursor)

    return LooseVersion(version) >= LooseVersion("10.2")


def server_supports_password_expire(cursor):
    version = get_server_version(cursor)

    return LooseVersion(version) >= LooseVersion("10.4.3")


def get_tls_requires(cursor, user, host):
    """Get user TLS requirements.
    Reads directly from mysql.user table allowing for a more
    readable code.

    Args:
        cursor (cursor): DB driver cursor object.
        user (str): User name.
        host (str): User host name.

    Returns: Dictionary containing current TLS required
    """
    tls_requires = dict()

    query = ('SELECT ssl_type, ssl_cipher, x509_issuer, x509_subject '
             'FROM mysql.user WHERE User = %s AND Host = %s')
    cursor.execute(query, (user, host))
    res = cursor.fetchone()

    # Mysql_info use a DictCursor so we must convert back to a list
    # otherwise we get KeyError 0
    if isinstance(res, dict):
        res = list(res.values())

    # When user don't require SSL, res value is: ('', '', '', '')
    if not any(res):
        return None

    if res[0] == 'ANY':
        tls_requires['SSL'] = None

    if res[0] == 'X509':
        tls_requires['X509'] = None

    if res[1]:
        tls_requires['CIPHER'] = res[1]

    if res[2]:
        tls_requires['ISSUER'] = res[2]

    if res[3]:
        tls_requires['SUBJECT'] = res[3]
    return tls_requires
