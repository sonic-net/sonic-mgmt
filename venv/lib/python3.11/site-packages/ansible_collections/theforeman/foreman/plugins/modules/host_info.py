#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2020 Evgeni Golov
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
module: host_info
version_added: 2.0.0
short_description: Fetch information about Hosts
description:
  - Fetch information about Hosts
author:
  - "Evgeni Golov (@evgeni)"
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.infomodule
'''

EXAMPLES = '''
- name: "Show a host"
  theforeman.foreman.host_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "host.example.com"

- name: "Show all hosts with domain example.com"
  theforeman.foreman.host_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    search: "domain = example.com"
'''

RETURN = '''
host:
  description: Details about the found host
  returned: success and I(name) was passed
  type: dict
hosts:
  description: List of all found hosts and their details
  returned: success and I(search) was passed
  type: list
  elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    ForemanInfoAnsibleModule,
)


class ForemanHostInfo(ForemanInfoAnsibleModule):
    pass


def main():
    module = ForemanHostInfo()

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
