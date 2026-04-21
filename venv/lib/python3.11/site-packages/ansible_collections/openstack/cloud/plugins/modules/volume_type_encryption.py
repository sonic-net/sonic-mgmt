#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Cleura AB
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_type_encryption
short_description: Manage OpenStack volume type encryption
author: OpenStack Ansible SIG
description:
  - Add, remove or update volume type encryption in OpenStack.
options:
  volume_type:
    description:
      - Volume type name or id.
    required: true
    type: str
  state:
    description:
      - Indicate desired state of the resource.
      - When I(state) is C(present), then I(encryption options) are required.
    choices: ['present', 'absent']
    default: present
    type: str
  encryption_provider:
    description:
      - class that provides encryption support for the volume type
      - admin only
    type: str
  encryption_cipher:
    description:
      - encryption algorithm or mode
      - admin only
    type: str
  encryption_control_location:
    description:
      - Set the notional service where the encryption is performed
      - admin only
    choices: ['front-end', 'back-end']
    type: str
  encryption_key_size:
    description:
      - Set the size of the encryption key of this volume type
      - admin only
    choices: [128, 256, 512]
    type: int
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
    - name: Create volume type encryption
      openstack.cloud.volume_type_encryption:
        volume_type: test_type
        state: present
        encryption_provider: nova.volume.encryptors.luks.LuksEncryptor
        encryption_cipher: aes-xts-plain64
        encryption_control_location: front-end
        encryption_key_size: 256

    - name: Delete volume type encryption
      openstack.cloud.volume_type_encryption:
        volume_type: test_type
        state: absent
      register: the_result
'''

RETURN = '''
encryption:
  description: Dictionary describing volume type encryption
  returned: On success when I(state) is 'present'
  type: dict
  contains:
    cipher:
      description: encryption cipher
      returned: success
      type: str
      sample: aes-xts-plain64
    control_location:
      description: encryption location
      returned: success
      type: str
      sample: front-end
    created_at:
      description: Resource creation date and time
      returned: success
      type: str
      sample: "2023-08-04T10:23:03.000000"
    deleted:
      description: Boolean if the resource was deleted
      returned: success
      type: str
      sample: false,
    deleted_at:
      description: Resource delete date and time
      returned: success
      type: str
      sample: null,
    encryption_id:
      description: UUID of the volume type encryption
      returned: success
      type: str
      sample: b75d8c5c-a6d8-4a5d-8c86-ef4f1298525d
    id:
      description: Alias to encryption_id
      returned: success
      type: str
      sample: b75d8c5c-a6d8-4a5d-8c86-ef4f1298525d
    key_size:
      description: Size of the key
      returned: success
      type: str
      sample: 256,
    provider:
      description: Encryption provider
      returned: success
      type: str
      sample: "nova.volume.encryptors.luks.LuksEncryptor"
    updated_at:
      description: Resource last update date and time
      returned: success
      type: str
      sample: null
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeTypeModule(OpenStackModule):
    argument_spec = dict(
        volume_type=dict(type='str', required=True),
        state=dict(
            type='str', default='present', choices=['absent', 'present']),
        encryption_provider=dict(type='str', required=False),
        encryption_cipher=dict(type='str', required=False),
        encryption_control_location=dict(
            type='str', choices=['front-end', 'back-end'], required=False),
        encryption_key_size=dict(
            type='int', choices=[128, 256, 512], required=False),
    )
    module_kwargs = dict(
        required_if=[('state', 'present', [
            'encryption_provider', 'encryption_cipher',
            'encryption_control_location', 'encryption_key_size'])],
        supports_check_mode=True,
    )

    @staticmethod
    def _extract_result(details):
        if details is not None:
            return details.to_dict(computed=False)
        return {}

    def run(self):
        state = self.params['state']
        name = self.params['volume_type']
        volume_type = self.conn.block_storage.find_type(name)

        # TODO: Add get type_encryption by id
        type_encryption = self.conn.block_storage.get_type_encryption(
            volume_type.id)
        encryption_id = type_encryption.get('encryption_id')

        if self.ansible.check_mode:
            self.exit_json(
                changed=self._will_change(state, encryption_id))

        if state == 'present':
            update = self._build_update_type_encryption(type_encryption)
            if not bool(update):
                # No change is required
                self.exit_json(changed=False)

            if not encryption_id:  # Create new type encryption
                result = self.conn.block_storage.create_type_encryption(
                    volume_type, **update)
            else:  # Update existing type encryption
                result = self.conn.block_storage.update_type_encryption(
                    encryption=type_encryption, **update)
            encryption = self._extract_result(result)
            self.exit_json(changed=bool(update), encryption=encryption)
        elif encryption_id is not None:
            # absent state requires type encryption delete
            self.conn.block_storage.delete_type_encryption(type_encryption)
            self.exit_json(changed=True)

    def _build_update_type_encryption(self, type_encryption):
        attributes_map = {
            'encryption_provider': 'provider',
            'encryption_cipher': 'cipher',
            'encryption_key_size': 'key_size',
            'encryption_control_location': 'control_location'}

        encryption_attributes = {
            attributes_map[k]: self.params[k]
            for k in self.params
            if k in attributes_map.keys() and self.params.get(k) is not None
            and self.params.get(k) != type_encryption.get(attributes_map[k])}

        if 'encryption_provider' in encryption_attributes.keys():
            encryption_attributes['provider'] = \
                encryption_attributes['encryption_provider']

        return encryption_attributes

    def _update_type_encryption(self, type_encryption, update):
        if update:
            updated_type = self.conn.block_storage.update_type_encryption(
                encryption=type_encryption,
                **update)
            return updated_type
        return {}

    def _will_change(self, state, type_encryption):
        encryption_id = type_encryption.get('encryption_id')
        if state == 'present' and not encryption_id:
            return True
        if state == 'present' and encryption_id is not None:
            return bool(self._build_update_type_encryption(type_encryption))
        if state == 'absent' and encryption_id is not None:
            return True
        return False


def main():
    module = VolumeTypeModule()
    module()


if __name__ == '__main__':
    main()
