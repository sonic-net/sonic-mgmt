#!/usr/bin/python
# -*- coding: utf-8 -*-
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
module: smart_proxy
version_added: 1.4.0
short_description: Manage Smart Proxies
description:
  - Create, update and delete Smart Proxies
author:
  - "James Stuart (@jstuart)"
  - "Matthias M Dellweg (@mdellweg)"
  - "Jeffrey van Pelt (@Thulium-Drake)"
options:
  name:
    description:
      - Name of the Smart Proxy
    required: true
    type: str
  lifecycle_environments:
    description:
      - Lifecycle Environments synced to the Smart Proxy.
      - Only available for Katello installations.
    required: false
    elements: str
    type: list
  url:
    description:
      - URL of the Smart Proxy
    required: true
    type: str
  download_policy:
    description:
      - The download policy for the Smart Proxy
      - Only available for Katello installations.
      - The download policy C(background) is deprecated and not available since Katello 4.3.
      - The download policy C(streamed) is available since Katello 4.5.
    choices:
      - background
      - immediate
      - on_demand
      - streamed
      - inherit
    required: false
    type: str
notes:
  - Even with I(state=present) this module does not install a new Smart Proxy.
  - It can only associate an existing Smart Proxy listening at the specified I(url).
  - Consider using I(foreman-installer) to create Smart Proxies.
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.entity_state
  - theforeman.foreman.foreman.taxonomy
'''

EXAMPLES = '''
# Create a local Smart Proxy
- name: "Create Smart Proxy"
  theforeman.foreman.smart_proxy:
    username: "admin"
    password: "changeme"
    server_url: "https://{{ ansible_fqdn }}"
    name: "{{ ansible_fqdn }}"
    url: "https://{{ ansible_fqdn }}:9090"
    download_policy: "immediate"
    lifecycle_environments:
      - "Development"
    organizations:
      - "Default Organization"
    locations:
      - "Default Location"
    state: present
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    smart_proxies:
      description: List of smart_proxies.
      type: list
      elements: dict
'''


from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanTaxonomicEntityAnsibleModule


class ForemanSmartProxyModule(ForemanTaxonomicEntityAnsibleModule):
    pass


def main():
    module = ForemanSmartProxyModule(
        foreman_spec=dict(
            name=dict(required=True),
            url=dict(required=True),
            lifecycle_environments=dict(required=False, type='entity_list'),
            download_policy=dict(required=False, choices=['background', 'immediate', 'on_demand', 'streamed', 'inherit']),
        ),
        required_plugins=[('katello', ['lifecycle_environments', 'download_policy'])],
    )

    with module.api_connection():
        handle_lifecycle_environments = not module.desired_absent and 'lifecycle_environments' in module.foreman_params
        if handle_lifecycle_environments:
            module.lookup_entity('lifecycle_environments')
            lifecycle_environments = module.foreman_params.pop('lifecycle_environments', [])

        smart_proxy = module.lookup_entity('entity')
        new_smart_proxy = module.run()

        if handle_lifecycle_environments:

            if smart_proxy:
                payload = {
                    'id': new_smart_proxy['id'],
                }
                current_lces = module.resource_action('capsule_content', 'lifecycle_environments', payload, ignore_check_mode=True, record_change=False)
            else:
                current_lces = {'results': []}

            desired_environment_ids = set(lifecycle_environment['id'] for lifecycle_environment in lifecycle_environments)
            current_environment_ids = set(lifecycle_environment['id'] for lifecycle_environment in current_lces['results']) if current_lces else set()

            module.record_before('smart_proxy_content/lifecycle_environment_ids', current_environment_ids)
            module.record_after('smart_proxy_content/lifecycle_environment_ids', desired_environment_ids)
            module.record_after_full('smart_proxy_content/lifecycle_environment_ids', desired_environment_ids)

            if desired_environment_ids != current_environment_ids:
                environment_ids_to_add = desired_environment_ids - current_environment_ids
                if environment_ids_to_add:
                    for environment_id_to_add in environment_ids_to_add:
                        payload = {
                            'id': new_smart_proxy['id'],
                            'environment_id': environment_id_to_add,
                        }
                        module.resource_action('capsule_content', 'add_lifecycle_environment', payload)
                environment_ids_to_remove = current_environment_ids - desired_environment_ids
                if environment_ids_to_remove:
                    for environment_id_to_remove in environment_ids_to_remove:
                        payload = {
                            'id': smart_proxy['id'],
                            'environment_id': environment_id_to_remove,
                        }
                        module.resource_action('capsule_content', 'remove_lifecycle_environment', payload)


if __name__ == '__main__':
    main()
