#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Ciril Troxler <ciril.troxler@cloudscale.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: volume_snapshot
short_description: Manage volume snapshots on the cloudscale.ch IaaS service
description:
  - Get, create, update, delete volume snapshots on the cloudscale.ch IaaS service.
notes:
  - If I(uuid) option is provided, it takes precedence over I(name) for volume snapshot selection.
    This allows to update the volume snapshot's name.
  - If no I(uuid) option is provided, I(name) is used for volume snapshot selection.
    If more than one volume snapshot with this name exists, execution is aborted.
  - To revert a snapshot use the volume module.
author:
  - Ciril Troxler (@ctx)
version_added: "2.5.0"
options:
  state:
    description:
      - State of the volume snapshot.
    choices: [ present, absent ]
    default: present
    type: str
  name:
    description:
      - Name of the volume snapshot. Either I(name) or I(uuid) are required.
    type: str
  uuid:
    description:
      - UUID of the volume snapshot.
    type: str
  source_volume:
    description:
      - UUID of the volume this snapshot belongs to.
        If I(name) and I(source_volume) are present, a new volume snapshot is created.
        This parameter has no effect on existing volume snapshots (I(uuid) option is present).
    type: str
  tags:
    description:
      - Tags assigned to the volume snapshot. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
# Create a volume snapshot for a volume
- name: Create a volume snapshot
  cloudscale_ch.cloud.volume_snapshot:
    name: 'pre-dist-upgrade'
    source_volume: '2db69ba3-1864-4608-853a-0771b6885a3a'
    tags: {}
    api_token: xxxxx

# Get a volume snapshot by name
- name: Get facts of a volume snapshot
  cloudscale_ch.cloud.volume_snapshot:
    name: 'pre-dist-upgrade'
    api_token: xxxxx

# Delete a volume snapshot
- name: Delete a volume snapshot
  cloudscale_ch.cloud.volume_snapshot:
    uuid: '351d461c-2333-455f-b788-db11bf0b4aa2'
    state: absent
'''

RETURN = '''
href:
  description: The API URL to get details about this volume snapshot.
  returned: state == present
  type: str
  sample: https://api.cloudscale.ch/v1/volume-snapshots/e504dc99-ff01-4e89-ad89-7df080f97b4b
uuid:
  description: The unique identifier for this volume snapshot.
  returned: state == present
  type: str
  sample: e504dc99-ff01-4e89-ad89-7df080f97b4b
name:
  description: The display name of the volume snapshot.
  returned: state == present
  type: str
  sample: my_ssd_volume_snapshot
created_at:
  description: The creation date and time of the resource.
  returned: state == present
  type: str
  sample: "2025-04-10T11:05:45.777073Z"
size_gb:
  description: The size of the volume in GB.
  returned: state == present
  type: str
  sample: 50
source_volume:
  description: The source volume this volume snapshot belongs to.
  returned: state == present
  type: dict
  sample:
    "source_volume": {
        "href": "https://api.cloudscale.ch/v1/volumes/0952b1ca-3657-4901-b4c8-669796ec55e6",
        "name": "my_ssd_volume",
        "uuid": "0952b1ca-3657-4901-b4c8-669796ec55e6"
    }
state:
  description: The current status of the volume.
  returned: success
  type: str
  sample: present
status:
  description: The current status of the volume snapshot.
  returned: success
  type: str
  sample: available
tags:
  description: Tags associated with the volume.
  returned: state == present
  type: dict
  sample: { 'project': 'my project' }
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import (
    AnsibleCloudscaleBase,
    cloudscale_argument_spec,
)


class AnsibleCloudscaleVolumeSnapshot(AnsibleCloudscaleBase):

    def __init__(self, module):
        super(AnsibleCloudscaleVolumeSnapshot, self).__init__(
            module,
            resource_name='volume-snapshots',
            resource_create_param_keys=[
                'name',
                'source_volume',
                'tags',
            ],
            resource_update_param_keys=[
                'uuid',
                'tags',
            ],
        )

    def absent(self):
        resource = super().absent()
        if not self._module.check_mode:
            self.wait_for_state('state', 'absent')
        return resource


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str'),
        uuid=dict(type='str'),
        source_volume=dict(type='str'),
        tags=dict(type='dict'),
        state=dict(type='str', default='present', choices=('present', 'absent')),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(),
        required_one_of=(('name', 'uuid'),),
        required_if=(('state', 'absent', ('uuid',),),),
        supports_check_mode=True,
    )

    cloudscale_volume_snapshot = AnsibleCloudscaleVolumeSnapshot(module)

    if module.params['state'] == 'absent':
        result = cloudscale_volume_snapshot.absent()
    else:
        result = cloudscale_volume_snapshot.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
