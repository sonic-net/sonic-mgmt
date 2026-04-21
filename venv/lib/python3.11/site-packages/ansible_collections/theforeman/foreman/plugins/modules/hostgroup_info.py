#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2023 Louis Tiches HallasTech
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
module: hostgroup_info
version_added: 3.9.0
short_description: Get information about hostgroup(s)
description:
  - Get information about hostgroup(s)
author:
  - "Louis Tiches (@TheRedGreek)"
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.infomodule
'''

EXAMPLES = '''
- name: "Show a hostgroup"
  theforeman.foreman.hostgroup_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "Default Hostgroup"

- name: "Show all hostgroups with 'name ~ Default'"
  theforeman.foreman.hostgroup_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    search: "name ~ Default"
'''

RETURN = '''
hostgroup:
  description: Details about the found hostgroup
  returned: success and I(name) was passed
  type: dict
hostgroups:
  description: List of all found hostgroups and their details
  returned: success and I(search) was passed
  type: list
  elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    ForemanInfoAnsibleModule,
)


class ForemanHostgroupInfo(ForemanInfoAnsibleModule):
    pass


def main():
    module = ForemanHostgroupInfo()

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
