#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: federation_mapping
short_description: Manage a federation mapping
author: OpenStack Ansible SIG
description:
  - Manage a federation mapping.
options:
  name:
    description:
      - The name of the mapping to manage.
    required: true
    type: str
    aliases: ['id']
  rules:
    description:
      - The rules that comprise the mapping. These are pairs of I(local) and
        I(remote) definitions. For more details on how these work please see
        the OpenStack documentation
        U(https://docs.openstack.org/keystone/latest/admin/federation/mapping_combinations.html).
      - Required if I(state) is C(present).
    type: list
    elements: dict
    suboptions:
      local:
        description:
        - Information on what local attributes will be mapped.
        required: true
        type: list
        elements: dict
      remote:
        description:
        - Information on what remote attributes will be mapped.
        required: true
        type: list
        elements: dict
  state:
    description:
      - Whether the mapping should be C(present) or C(absent).
    choices: ['present', 'absent']
    default: present
    type: str
notes:
    - Name equals the ID of a mapping.
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create a new mapping
  openstack.cloud.federation_mapping:
    cloud: example_cloud
    name: example_mapping
    rules:
    - local:
      - user:
          name: '{0}'
      - group:
          id: '0cd5e9'
      remote:
      - type: UserName
      - type: orgPersonType
        any_one_of:
        - Contractor
        - SubContractor

- name: Delete a mapping
  openstack.cloud.federation_mapping:
    name: example_mapping
    state: absent
'''

RETURN = r'''
mapping:
  description: Dictionary describing the federation mapping.
  returned: always
  type: dict
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


class IdentityFederationMappingModule(OpenStackModule):
    argument_spec = dict(
        name=dict(required=True, aliases=['id']),
        rules=dict(
            type='list',
            elements='dict',
            options=dict(
                local=dict(required=True, type='list', elements='dict'),
                remote=dict(required=True, type='list', elements='dict')
            )),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        required_if=[('state', 'present', ['rules'])],
        supports_check_mode=True
    )

    def run(self):
        state = self.params['state']

        id = self.params['name']
        mapping = self.conn.identity.find_mapping(id)

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, mapping))

        if state == 'present' and not mapping:
            # Create mapping
            mapping = self._create()
            self.exit_json(changed=True,
                           mapping=mapping.to_dict(computed=False))

        elif state == 'present' and mapping:
            # Update mapping
            update = self._build_update(mapping)
            if update:
                mapping = self._update(mapping, update)

            self.exit_json(changed=bool(update),
                           mapping=mapping.to_dict(computed=False))

        elif state == 'absent' and mapping:
            # Delete mapping
            self._delete(mapping)
            self.exit_json(changed=True)

        elif state == 'absent' and not mapping:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, mapping):
        update = {}

        if len(self.params['rules']) < 1:
            self.fail_json(msg='At least one rule must be passed')

        attributes = dict((k, self.params[k]) for k in ['rules']
                          if k in self.params and self.params[k] is not None
                          and self.params[k] != mapping[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        return self.conn.identity.create_mapping(id=self.params['name'],
                                                 rules=self.params['rules'])

    def _delete(self, mapping):
        self.conn.identity.delete_mapping(mapping.id)

    def _update(self, mapping, update):
        attributes = update.get('attributes')
        if attributes:
            mapping = self.conn.identity.update_mapping(mapping.id,
                                                        **attributes)

        return mapping

    def _will_change(self, state, mapping):
        if state == 'present' and not mapping:
            return True
        elif state == 'present' and mapping:
            return bool(self._build_update(mapping))
        elif state == 'absent' and mapping:
            return True
        else:
            # state == 'absent' and not mapping:
            return False


def main():
    module = IdentityFederationMappingModule()
    module()


if __name__ == '__main__':
    main()
