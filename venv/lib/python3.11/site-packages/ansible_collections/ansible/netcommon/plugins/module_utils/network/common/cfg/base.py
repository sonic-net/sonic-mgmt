#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type
"""
The base class for all resource modules
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.network import (
    get_resource_connection,
)


class ConfigBase(object):
    """The base class for all resource modules"""

    ACTION_STATES = ["merged", "replaced", "overridden", "deleted", "purged"]

    def __init__(self, module):
        self._module = module
        self.state = module.params["state"]
        self._connection = None

        if self.state not in ["rendered", "parsed"]:
            self._connection = get_resource_connection(module)
