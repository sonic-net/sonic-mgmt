# (c) 2023 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
author: Ansible Networking Team (@ansible-network)
name: default
short_description: General purpose cliconf plugin for new platforms
description:
- This plugin attemts to provide low level abstraction apis for sending and receiving CLI
  commands from arbitrary network devices.
version_added: 5.2.0
"""

import json

from ansible.errors import AnsibleConnectionFailure

from ansible_collections.ansible.netcommon.plugins.plugin_utils.cliconf_base import CliconfBase


class Cliconf(CliconfBase):
    def __init__(self, *args, **kwargs):
        super(Cliconf, self).__init__(*args, **kwargs)
        self._device_info = {}

    def get_device_info(self):
        if not self._device_info:
            device_info = {}

            device_info["network_os"] = "default"
            self._device_info = device_info

        return self._device_info

    def get_config(self, flags=None, format=None):
        network_os = self.get_device_info()["network_os"]
        raise AnsibleConnectionFailure("get_config is not supported by network_os %s" % network_os)

    def edit_config(self, candidate=None, commit=True, replace=None, comment=None):
        network_os = self.get_device_info()["network_os"]
        raise AnsibleConnectionFailure("edit_config is not supported by network_os %s" % network_os)

    def get_capabilities(self):
        result = super(Cliconf, self).get_capabilities()
        result["device_operations"] = self.get_device_operations()
        return json.dumps(result)

    def get_device_operations(self):
        return {
            "supports_diff_replace": False,
            "supports_commit": False,
            "supports_rollback": False,
            "supports_defaults": False,
            "supports_onbox_diff": False,
            "supports_commit_comment": False,
            "supports_multiline_delimiter": False,
            "supports_diff_match": False,
            "supports_diff_ignore_lines": False,
            "supports_generate_diff": False,
            "supports_replace": False,
        }
