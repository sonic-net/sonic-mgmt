# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.mysql.plugins.module_utils.mysql import get_server_version
from ansible_collections.community.mysql.plugins.module_utils.version import LooseVersion


def uses_replica_terminology(cursor):
    """Checks if REPLICA must be used instead of SLAVE"""
    return LooseVersion(get_server_version(cursor)) >= LooseVersion('8.0.22')
