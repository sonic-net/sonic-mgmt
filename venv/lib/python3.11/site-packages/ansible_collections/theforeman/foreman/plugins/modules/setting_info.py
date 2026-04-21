#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2021 Eric D Helms
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: setting_info
version_added: 2.1.0
short_description: Fetch information about Settings
description:
  - Fetch information about Settings
author:
  - "Eric Helms (@ehelms)"
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.infomodule
'''

EXAMPLES = '''
- name: "Show a setting"
  theforeman.foreman.setting_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "http_proxy"

- name: "Show all settings with proxy"
  theforeman.foreman.setting_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    search: "name = proxy"
'''

RETURN = '''
setting:
  description: Details about the found setting
  returned: success and I(name) was passed
  type: dict
settings:
  description: List of all found settings and their details
  returned: success and I(search) was passed
  type: list
  elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    ForemanInfoAnsibleModule,
)


class ForemanSettingInfo(ForemanInfoAnsibleModule):
    pass


def main():
    module = ForemanSettingInfo()

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
