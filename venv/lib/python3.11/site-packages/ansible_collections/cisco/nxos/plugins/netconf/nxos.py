#
# (c) 2021 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
author: Ansible Networking Team (@ansible-network)
name: nxos
short_description: Use nxos netconf plugin to run netconf commands on Cisco NX-OS platform.
description:
- This nxos plugin provides low level abstraction apis for sending and receiving
  netconf commands from Cisco NX-OS network devices.
version_added: 2.3.0
options:
  ncclient_device_handler:
    type: str
    default: nexus
    description:
    - Specifies the ncclient device handler name for Cisco NX-OS network os. To
      identify the ncclient device handler name refer ncclient library documentation.
"""

from ansible_collections.ansible.netcommon.plugins.plugin_utils.netconf_base import NetconfBase


class Netconf(NetconfBase):
    pass
