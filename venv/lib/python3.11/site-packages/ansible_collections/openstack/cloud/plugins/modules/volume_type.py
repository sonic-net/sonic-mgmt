#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Cleura AB
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_type
short_description: Manage OpenStack volume type
author: OpenStack Ansible SIG
description:
  - Add, remove or update volume types in OpenStack.
options:
  name:
    description:
      - Volume type name or id.
    required: true
    type: str
  description:
    description:
      - Description of the volume type.
    type: str
  extra_specs:
    description:
      - List of volume type properties
    type: dict
  is_public:
    description:
      - Make volume type accessible to the public.
      - Can be set only during creation
    type: bool
  state:
    description:
      - Indicate desired state of the resource.
      - When I(state) is C(present), then I(is_public) is required.
    choices: ['present', 'absent']
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
    - name: Delete volume type by name
      openstack.cloud.volume_type:
        name: test_type
        state: absent

    - name: Delete volume type by id
      openstack.cloud.volume_type:
        name: fbadfa6b-5f17-4c26-948e-73b94de57b42
        state: absent

    - name: Create volume type
      openstack.cloud.volume_type:
        name: unencrypted_volume_type
        state: present
        extra_specs:
          volume_backend_name: LVM_iSCSI
        description: Unencrypted volume type
        is_public: True
'''

RETURN = '''
volume_type:
  description: Dictionary describing volume type
  returned: On success when I(state) is 'present'
  type: dict
  contains:
    name:
      description: volume type name
      returned: success
      type: str
      sample: test_type
    extra_specs:
      description: volume type extra parameters
      returned: success
      type: dict
      sample: null
    is_public:
      description: whether the volume type is public
      returned: success
      type: bool
      sample: True
    description:
      description: volume type description
      returned: success
      type: str
      sample: Unencrypted volume type
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeTypeModule(OpenStackModule):
    argument_spec = dict(
        name=dict(type='str', required=True),
        description=dict(type='str', required=False),
        extra_specs=dict(type='dict', required=False),
        is_public=dict(type='bool'),
        state=dict(
            type='str', default='present', choices=['absent', 'present']),
    )
    module_kwargs = dict(
        required_if=[('state', 'present', ['is_public'])],
        supports_check_mode=True,
    )

    @staticmethod
    def _extract_result(details):
        if details is not None:
            return details.to_dict(computed=False)
        return {}

    def run(self):
        state = self.params['state']
        name_or_id = self.params['name']
        volume_type = self.conn.block_storage.find_type(name_or_id)

        if self.ansible.check_mode:
            self.exit_json(
                changed=self._will_change(state, volume_type))

        if state == 'present' and not volume_type:
            # Create type
            create_result = self._create()
            volume_type = self._extract_result(create_result)
            self.exit_json(changed=True, volume_type=volume_type)

        elif state == 'present' and volume_type:
            # Update type
            update = self._build_update(volume_type)
            update_result = self._update(volume_type, update)
            volume_type = self._extract_result(update_result)
            self.exit_json(changed=bool(update), volume_type=volume_type)

        elif state == 'absent' and volume_type:
            # Delete type
            self._delete(volume_type)
            self.exit_json(changed=True)

    def _build_update(self, volume_type):
        return {
            **self._build_update_extra_specs(volume_type),
            **self._build_update_volume_type(volume_type)}

    def _build_update_extra_specs(self, volume_type):
        update = {}

        old_extra_specs = volume_type['extra_specs']
        new_extra_specs = self.params['extra_specs'] or {}

        delete_extra_specs_keys = \
            set(old_extra_specs.keys()) - set(new_extra_specs.keys())

        if delete_extra_specs_keys:
            update['delete_extra_specs_keys'] = delete_extra_specs_keys

        stringified = {k: str(v) for k, v in new_extra_specs.items()}

        if old_extra_specs != stringified:
            update['create_extra_specs'] = new_extra_specs

        return update

    def _build_update_volume_type(self, volume_type):
        update = {}
        allowed_attributes = [
            'is_public', 'description', 'name']
        type_attributes = {
            k: self.params[k]
            for k in allowed_attributes
            if k in self.params and self.params.get(k) is not None
            and self.params.get(k) != volume_type.get(k)}

        if type_attributes:
            update['type_attributes'] = type_attributes

        return update

    def _create(self):
        kwargs = {k: self.params[k]
                  for k in ['name', 'is_public', 'description', 'extra_specs']
                  if self.params.get(k) is not None}
        volume_type = self.conn.block_storage.create_type(**kwargs)
        return volume_type

    def _delete(self, volume_type):
        self.conn.block_storage.delete_type(volume_type.id)

    def _update(self, volume_type, update):
        if not update:
            return volume_type
        volume_type = self._update_volume_type(volume_type, update)
        volume_type = self._update_extra_specs(volume_type, update)
        return volume_type

    def _update_extra_specs(self, volume_type, update):
        delete_extra_specs_keys = update.get('delete_extra_specs_keys')
        if delete_extra_specs_keys:
            self.conn.block_storage.delete_type_extra_specs(
                volume_type, delete_extra_specs_keys)
            # refresh volume_type information
            volume_type = self.conn.block_storage.find_type(volume_type.id)

        create_extra_specs = update.get('create_extra_specs')
        if create_extra_specs:
            self.conn.block_storage.update_type_extra_specs(
                volume_type, **create_extra_specs)
            # refresh volume_type information
            volume_type = self.conn.block_storage.find_type(volume_type.id)

        return volume_type

    def _update_volume_type(self, volume_type, update):
        type_attributes = update.get('type_attributes')
        if type_attributes:
            updated_type = self.conn.block_storage.update_type(
                volume_type, **type_attributes)
            return updated_type
        return volume_type

    def _will_change(self, state, volume_type):
        if state == 'present' and not volume_type:
            return True
        if state == 'present' and volume_type:
            return bool(self._build_update(volume_type))
        if state == 'absent' and volume_type:
            return True
        return False


def main():
    module = VolumeTypeModule()
    module()


if __name__ == '__main__':
    main()
