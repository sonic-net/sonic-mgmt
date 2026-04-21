#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2021 Evgeni Golov
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
module: host_errata_info
version_added: 2.1.0
short_description: Fetch information about Host Errata
description:
  - Fetch information about Host Errata
author:
  - "Evgeni Golov (@evgeni)"
options:
  host:
    description:
      - Name of the host to fetch errata for.
    required: true
    type: str
  content_view:
    description:
      - Calculate Applicable Errata based on a particular Content View.
      - Required together with I(lifecycle_environment).
      - If this is set, I(organization) also needs to be set.
    required: false
    type: str
  lifecycle_environment:
    description:
      - Calculate Applicable Errata based on a particular Lifecycle Environment.
      - Required together with I(content_view).
      - If this is set, I(organization) also needs to be set.
    required: false
    type: str
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.infomodulewithoutname
'''

EXAMPLES = '''
- name: "List installable errata for host"
  theforeman.foreman.host_errata_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    host: "host.example.com"

- name: "List applicable errata for host"
  theforeman.foreman.host_errata_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    host: "host.example.com"
    lifecycle_environment: "Library"
    content_view: "Default Organization View"
'''

RETURN = '''
host_errata:
  description: List of all found errata for the host and their details
  returned: success
  type: list
  elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    ForemanInfoAnsibleModule
)


class ForemanHostErrataInfo(ForemanInfoAnsibleModule):
    pass


def main():
    module = ForemanHostErrataInfo(
        foreman_spec=dict(
            name=dict(invisible=True),
            host=dict(type='entity', required=True),
            content_view=dict(type='entity', scope=['organization']),
            lifecycle_environment=dict(type='entity', flat_name='environment_id', scope=['organization']),
        ),
        entity_opts=dict(
            resource_type='host_errata',
        ),
        required_together=[
            ('content_view', 'lifecycle_environment'),
        ],
        required_by={
            'content_view': 'organization',
            'lifecycle_environment': 'organization',
        },
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
