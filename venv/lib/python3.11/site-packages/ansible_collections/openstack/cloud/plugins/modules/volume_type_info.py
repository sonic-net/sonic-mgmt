#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Cleura AB
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_type_info
short_description: Get OpenStack volume type details
author: OpenStack Ansible SIG
description:
  - Get volume type details in OpenStack.
  - Get volume type encryption details in OpenStack
options:
  name:
    description:
      - Volume type name or id.
    required: true
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
    - name: Get volume type details
      openstack.cloud.volume_type_info:
        name: test_type

    - name: Get volume type details by id
      openstack.cloud.volume_type_info:
        name: fbadfa6b-5f17-4c26-948e-73b94de57b42
'''

RETURN = '''
access_project_ids:
  description:
    - List of project IDs allowed to access volume type
    - Public volume types returns 'null' value as it is not applicable
  returned: On success when I(state) is 'present'
  type: list
  elements: str
volume_type:
  description: Dictionary describing volume type
  returned: On success when I(state) is 'present'
  type: dict
  contains:
    id:
      description: volume_type uuid
      returned: success
      type: str
      sample: b75d8c5c-a6d8-4a5d-8c86-ef4f1298525d
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
      sample: false
    deleted_at:
      description: Resource delete date and time
      returned: success
      type: str
      sample: null
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
      sample: 256
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
        name=dict(type='str', required=True)
    )
    module_kwargs = dict(
        supports_check_mode=True,
    )

    @staticmethod
    def _extract_result(details):
        if details is not None:
            return details.to_dict(computed=False)
        return {}

    def run(self):
        name_or_id = self.params['name']
        volume_type = self.conn.block_storage.find_type(name_or_id)

        type_encryption = self.conn.block_storage.get_type_encryption(
            volume_type.id)

        if volume_type.is_public:
            type_access = None
        else:
            type_access = [
                proj['project_id']
                for proj in self.conn.block_storage.get_type_access(
                    volume_type.id)]

        self.exit_json(
            changed=False,
            volume_type=self._extract_result(volume_type),
            encryption=self._extract_result(type_encryption),
            access_project_ids=type_access)


def main():
    module = VolumeTypeModule()
    module()


if __name__ == '__main__':
    main()
