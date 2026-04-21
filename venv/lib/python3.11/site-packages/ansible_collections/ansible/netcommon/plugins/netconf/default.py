#
# (c) 2017 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
author:
 - Ansible Networking Team (@ansible-network)
name: default
short_description: Use default netconf plugin to run standard netconf commands as
  per RFC
description:
- This default plugin provides low level abstraction apis for sending and receiving
  netconf commands as per Netconf RFC specification.
version_added: 1.0.0
options:
  ncclient_device_handler:
    type: str
    default: default
    description:
    - Specifies the ncclient device handler name for network os that support default
      netconf implementation as per Netconf RFC specification. To identify the ncclient
      device handler name refer ncclient library documentation.
"""
import json

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.ansible.netcommon.plugins.plugin_utils.netconf_base import NetconfBase


class Netconf(NetconfBase):
    def get_text(self, ele, tag):
        try:
            return to_text(ele.find(tag).text, errors="surrogate_then_replace").strip()
        except AttributeError:
            pass

    def get_device_info(self):
        device_info = dict()
        device_info["network_os"] = "default"
        return device_info

    def get_capabilities(self):
        result = dict()
        result["rpc"] = self.get_base_rpc()
        result["network_api"] = "netconf"
        result["device_info"] = self.get_device_info()
        result["server_capabilities"] = list(self.m.server_capabilities)
        result["client_capabilities"] = list(self.m.client_capabilities)
        result["session_id"] = self.m.session_id
        result["device_operations"] = self.get_device_operations(result["server_capabilities"])
        return json.dumps(result)
