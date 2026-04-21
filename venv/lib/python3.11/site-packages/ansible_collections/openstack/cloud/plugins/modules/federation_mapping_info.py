#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: federation_mapping_info
short_description: Fetch Keystone federation mappings
author: OpenStack Ansible SIG
description:
  - Fetch Keystone federation mappings.
options:
  name:
    description:
      - ID or name of the federation mapping.
    type: str
    aliases: ['id']
notes:
    - Name equals the ID of a federation mapping.
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Fetch all federation mappings
  openstack.cloud.federation_mapping_info:
    cloud: example_cloud

- name: Fetch federation mapping by name
  openstack.cloud.federation_mapping_info:
    cloud: example_cloud
    name: example_mapping
'''

RETURN = r'''
mappings:
  description: List of federation mapping dictionaries.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The id of the mapping
      type: str
      sample: "ansible-test-mapping"
    name:
      description: Name of the mapping. Equal to C(id).
      type: str
      sample: "ansible-test-mapping"
    rules:
      description: List of rules for the mapping
      type: list
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityFederationMappingInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(aliases=['id']),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        # name is id for federation mappings
        id = self.params['name']

        if id:
            # handle id parameter separately because self.conn.identity.\
            # mappings() does not allow to filter by id
            # Ref.: https://review.opendev.org/c/openstack/
            #       openstacksdk/+/858522
            mapping = self.conn.identity.find_mapping(name_or_id=id,
                                                      ignore_missing=True)
            mappings = [mapping] if mapping else []
        else:
            mappings = self.conn.identity.mappings()

        self.exit_json(changed=False,
                       mappings=[mapping.to_dict(computed=False)
                                 for mapping in mappings])


def main():
    module = IdentityFederationMappingInfoModule()
    module()


if __name__ == '__main__':
    main()
