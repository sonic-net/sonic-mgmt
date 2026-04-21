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
module: puppetclasses_import
version_added: 2.0.0
short_description: Import Puppet Classes from a Proxy
description:
  - Import Puppet Classes from a Proxy
author:
  - "Evgeni Golov (@evgeni)"
options:
  smart_proxy:
    description:
      - Smart Proxy to import Puppet Classes from
    required: true
    type: str
  environment:
    description:
      - Puppet Environment to import Puppet Classes from
    required: false
    type: str
  except:
    description:
      - Which types of Puppet Classes to exclude from the import.
    choices:
      - new
      - updated
      - obsolete
    required: false
    type: list
    elements: str
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
extends_documentation_fragment:
  - theforeman.foreman.foreman
'''

EXAMPLES = '''
- name: Import Puppet Classes
  theforeman.foreman.puppetclasses_import:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    smart_proxy: "foreman.example.com"
'''

RETURN = '''
result:
  description: Details about the Puppet Class import
  returned: success
  type: dict
  contains:
    environments_with_new_puppetclasses:
      description:
        - Number of Puppet Environments with new Puppet Classes
      type: int
      returned: when I(environment) not specificed
    environments_updated_puppetclasses:
      description:
        - Number of Puppet Environments with updated Puppet Classes
      type: int
      returned: when I(environment) not specificed
    environments_obsolete:
      description:
        - Number of Puppet Environments with removed Puppet Classes
      type: int
      returned: when I(environment) not specificed
    environments_ignored:
      description:
        - Number of ignored Puppet Environments
      type: int
      returned: when I(environment) not specificed
    results:
      description:
        - List of Puppet Environments and the changes made to them
      type: list
      returned: success
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanAnsibleModule, _flatten_entity


def main():
    module = ForemanAnsibleModule(
        foreman_spec={
            'smart_proxy': dict(type='entity', required=True, flat_name='id'),
            'environment': dict(type='entity'),
            'except': dict(type='list', elements='str', choices=['new', 'updated', 'obsolete']),
        },
        supports_check_mode=False,
    )

    with module.api_connection():
        module.auto_lookup_entities()

        if 'except' in module.foreman_params:
            module.foreman_params['except'] = ','.join(module.foreman_params.get('except'))

        result = module.resource_action('smart_proxies', 'import_puppetclasses', record_change=False,
                                        params=_flatten_entity(module.foreman_params, module.foreman_spec))
        if (result.get('environments_updated_puppetclasses', 0) + result.get('environments_with_new_puppetclasses', 0)
                + result.get('environments_obsolete', 0) + result.get('environments_ignored', 0)):
            module.set_changed()

        module.exit_json(result=result)


if __name__ == '__main__':
    main()
