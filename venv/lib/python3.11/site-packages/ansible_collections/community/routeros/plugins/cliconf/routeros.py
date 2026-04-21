# Copyright (c) 2017 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
author: "Egor Zaitsev (@heuels)"
name: routeros
short_description: Use routeros cliconf to run command on MikroTik RouterOS platform
description:
  - This routeros plugin provides low level abstraction APIs for sending and receiving CLI commands from MikroTik RouterOS
    network devices.
"""

import re
import json

from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.cliconf import CliconfBase


class Cliconf(CliconfBase):

    def get_device_info(self):
        device_info = {}
        device_info['network_os'] = 'RouterOS'

        resource = self.get('/system resource print')
        data = to_text(resource, errors='surrogate_or_strict').strip()
        match = re.search(r'version: (\S+)', data)
        if match:
            device_info['network_os_version'] = match.group(1)

        routerboard = self.get('/system routerboard print')
        data = to_text(routerboard, errors='surrogate_or_strict').strip()
        match = re.search(r'model: (.+)$', data, re.M)
        if match:
            device_info['network_os_model'] = match.group(1)

        identity = self.get('/system identity print')
        data = to_text(identity, errors='surrogate_or_strict').strip()
        match = re.search(r'name: (.+)$', data, re.M)
        if match:
            device_info['network_os_hostname'] = match.group(1)

        return device_info

    def get_config(self, source='running', flags=None, format=None):
        return

    def edit_config(self, command):
        return

    def get(self, command, prompt=None, answer=None, sendonly=False, newline=True, check_all=False):
        return self.send_command(command=command, prompt=prompt, answer=answer, sendonly=sendonly, newline=newline, check_all=check_all)

    def get_capabilities(self):
        result = super(Cliconf, self).get_capabilities()
        return json.dumps(result)
