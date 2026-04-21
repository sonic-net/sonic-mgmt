#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025, ScaleUp Technologies GmbH & Co. KG
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: trait
short_description: Add/Delete a trait from OpenStack
author: OpenStack Ansible SIG
description:
  - Add or Delete a trait from OpenStack
options:
  id:
    description:
      - ID/Name of this trait
    required: true
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Creates a trait with the ID CUSTOM_WINDOWS_SPLA
- openstack.cloud.trait:
      cloud: openstack
      state: present
      id: CUSTOM_WINDOWS_SPLA
'''

RETURN = '''
trait:
    description: Dictionary describing the trait.
    returned: On success when I(state) is 'present'
    type: dict
    contains:
        id:
            description: ID of the trait.
            returned: success
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule)


class TraitModule(OpenStackModule):

    argument_spec = dict(
        id=dict(required=True),
        state=dict(default='present',
                   choices=['absent', 'present']),
    )

    module_kwargs = dict(
        supports_check_mode=True,
    )

    def _system_state_change(self, trait):
        state = self.params['state']
        if state == 'present' and not trait:
            return True
        if state == 'absent' and trait:
            return True
        return False

    def run(self):

        state = self.params['state']
        id = self.params['id']

        try:
            trait = self.conn.placement.get_trait(id)
        except self.sdk.exceptions.NotFoundException:
            trait = None

        if self.ansible.check_mode:
            self.exit_json(changed=self._system_state_change(trait), trait=trait)

        changed = False
        if state == 'present':
            if not trait:
                trait = self.conn.placement.create_trait(id)
                changed = True

            self.exit_json(
                changed=changed, trait=trait.to_dict(computed=False))

        elif state == 'absent':
            if trait:
                self.conn.placement.delete_trait(id, ignore_missing=False)
                self.exit_json(changed=True)

            self.exit_json(changed=False)


def main():
    module = TraitModule()
    module()


if __name__ == '__main__':
    main()
