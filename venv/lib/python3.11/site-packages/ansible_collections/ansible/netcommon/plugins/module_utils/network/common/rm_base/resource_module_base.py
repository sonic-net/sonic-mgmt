# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2021 Red Hat Inc.
#
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.network import (
    get_resource_connection,
)


class RmEngineBase(object):  # pylint: disable=R0902
    """Base class for Network Resource Modules"""

    ACTION_STATES = ["merged", "replaced", "overridden", "deleted", "purged"]

    def __init__(self, *_args, **kwargs):
        self._connection = None
        self._module = kwargs.get("module", None)
        self.state = None
        # backward compatibility for modules, in which, module is not passed
        # to the NetworkTemplate
        if self._module:
            if "state" in self._module.params.keys():
                self.state = self._module.params["state"]

            self._get_connection()

    def _get_connection(self):
        if self.state not in ["rendered", "parsed"]:
            if self._connection:
                return self._connection
            self._connection = get_resource_connection(self._module)
            return self._connection
        return None
