#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018, Gaudenz Steinlin <gaudenz.steinlin@cloudscale.ch>
# Copyright (c) 2019, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: volume
short_description: Manages volumes on the cloudscale.ch IaaS service.
description:
  - Create, attach/detach, update, delete and revert volumes on the cloudscale.ch IaaS service.
notes:
  - To create a new volume at least the I(name) and I(size_gb) options
    are required.
  - A volume can be created and attached to a server in the same task.
author:
  - Gaudenz Steinlin (@gaudenz)
  - René Moser (@resmo)
  - Denis Krienbühl (@href)
version_added: "1.0.0"
options:
  state:
    description:
      - State of the volume.
    default: present
    choices: [ present, absent ]
    type: str
  name:
    description:
      - Name of the volume. Either name or UUID must be present to change an
        existing volume.
    type: str
  uuid:
    description:
      - UUID of the volume. Either name or UUID must be present to change an
        existing volume.
    type: str
  size_gb:
    description:
      - Size of the volume in GB.
    type: int
  type:
    description:
      - Type of the volume. Cannot be changed after creating the volume.
        Defaults to C(ssd) on volume creation.
    choices: [ ssd, bulk ]
    type: str
  zone:
    description:
      - Zone in which the volume resides (e.g. C(lpg1) or C(rma1)). Cannot be
        changed after creating the volume. Defaults to the project default zone.
    type: str
  servers:
    description:
      - UUIDs of the servers this volume is attached to. Set this to C([]) to
        detach the volume. Currently a volume can only be attached to a
        single server.
      - The aliases C(server_uuids) and C(server_uuid) are deprecated and will
        be removed in version 3.0.0 of this collection.
    aliases: [ server_uuids, server_uuid ]
    type: list
    elements: str
  revert:
    description:
      - 'UUID of the snapshot to revert the volume to. This must be the most recent
        snapshot of the volume.
        For root volumes: the respective server must be shut down.
        For non-root volumes: the volume to be reverted must be detached'
    type: str
  tags:
    description:
      - Tags associated with the volume. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
# Create a new SSD volume
- name: Create an SSD volume
  cloudscale_ch.cloud.volume:
    name: my_ssd_volume
    zone: 'lpg1'
    size_gb: 50
    api_token: xxxxxx
  register: my_ssd_volume

# Attach an existing volume to a server
- name: Attach volume to server
  cloudscale_ch.cloud.volume:
    uuid: "{{ my_ssd_volume.uuid }}"
    servers:
      - ea3b39a3-77a8-4d0b-881d-0bb00a1e7f48
    api_token: xxxxxx

# Create and attach a volume to a server
- name: Create and attach volume to server
  cloudscale_ch.cloud.volume:
    name: my_ssd_volume
    zone: 'lpg1'
    size_gb: 50
    servers:
      - ea3b39a3-77a8-4d0b-881d-0bb00a1e7f48
    api_token: xxxxxx

# Detach volume from server
- name: Detach volume from server
  cloudscale_ch.cloud.volume:
    uuid: "{{ my_ssd_volume.uuid }}"
    servers: []
    api_token: xxxxxx

# Revert a volume to the most recent snapshot
- name: Revert volume to snapshot
  cloudscale_ch.cloud.volume:
    uuid: "{{ my_ssd_volume.uuid }}"
    revert: "e504dc99-ff01-4e89-ad89-7df080f97b4b"
    api_token: xxxxxx

# Delete a volume
- name: Delete volume
  cloudscale_ch.cloud.volume:
    name: my_ssd_volume
    state: absent
    api_token: xxxxxx
'''

RETURN = '''
href:
  description: The API URL to get details about this volume.
  returned: state == present
  type: str
  sample: https://api.cloudscale.ch/v1/volumes/2db69ba3-1864-4608-853a-0771b6885a3a
uuid:
  description: The unique identifier for this volume.
  returned: state == present
  type: str
  sample: 2db69ba3-1864-4608-853a-0771b6885a3a
name:
  description: The display name of the volume.
  returned: state == present
  type: str
  sample: my_ssd_volume
size_gb:
  description: The size of the volume in GB.
  returned: state == present
  type: str
  sample: 50
type:
  description: The type of the volume.
  returned: state == present
  type: str
  sample: bulk
zone:
  description: The zone of the volume.
  returned: state == present
  type: dict
  sample: {'slug': 'lpg1'}
server_uuids:
  description: The UUIDs of the servers this volume is attached to. This return
    value is deprecated and will disappear in the future when the field is
    removed from the API.
  returned: state == present
  type: list
  sample: ['47cec963-fcd2-482f-bdb6-24461b2d47b1']
servers:
  description: The list of servers this volume is attached to.
  returned: state == present
  type: list
  sample: [
            {
                "href": "https://api.cloudscale.ch/v1/servers/47cec963-fcd2-482f-bdb6-24461b2d47b1",
                "name": "my_server",
                "uuid": "47cec963-fcd2-482f-bdb6-24461b2d47b1"
            }
          ]
state:
  description: The current status of the volume.
  returned: success
  type: str
  sample: present
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
from copy import deepcopy


class AnsibleCloudscaleVolume(AnsibleCloudscaleBase):

    def create(self, resource):
        # Fail when missing params for creation
        self._module.fail_on_missing_params(['name', 'size_gb'])
        return super(AnsibleCloudscaleVolume, self).create(resource)

    def find_difference(self, key, resource, param):
        is_different = False

        if key != 'servers':
            return super(AnsibleCloudscaleVolume, self).find_difference(key, resource, param)

        server_has = resource[key]
        server_wanted = param
        if len(server_wanted) != len(server_has):
            is_different = True
        else:
            for has in server_has:
                if has["uuid"] not in server_wanted:
                    is_different = True

        return is_different

    def revert(self):
        resource = self.query()
        revert_url = resource['href'] + '/revert'
        revert_param = {'snapshot': self._module.params['revert']}
        revert = self._post(revert_url, revert_param)
        result = self.wait_for_state('current_operation', False)
        result['changed'] = True
        result['revert'] = self._module.params['revert']
        result['diff'] = dict()
        result['diff']['before'] = deepcopy(resource)
        result['diff']['after'] = deepcopy(resource)
        result['diff']['after'].update({
            'revert': self._module.params['revert'],
        })
        return result


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        state=dict(type='str', default='present', choices=('present', 'absent')),
        name=dict(type='str'),
        uuid=dict(type='str'),
        zone=dict(type='str'),
        size_gb=dict(type='int'),
        type=dict(type='str', choices=('ssd', 'bulk')),
        servers=dict(type='list', elements='str', aliases=['server_uuids', 'server_uuid']),
        revert=dict(type='str'),
        tags=dict(type='dict'),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(('name', 'uuid'),),
        supports_check_mode=True,
    )

    # TODO remove in version 3.0.0
    if module.params.get('server_uuid') or module.params.get('server_uuids'):
        module.deprecate('The aliases "server_uuid" and "server_uuids" have '
                         'been deprecated and will be removed, use "servers" '
                         'instead.',
                         version='3.0.0', collection_name='cloudscale_ch.cloud')

    cloudscale_volume = AnsibleCloudscaleVolume(
        module,
        resource_name='volumes',
        resource_create_param_keys=[
            'name',
            'type',
            'zone',
            'size_gb',
            'servers',
            'tags',
        ],
        resource_update_param_keys=[
            'name',
            'size_gb',
            'servers',
            'tags',
        ],
    )

    if module.params['state'] == 'absent':
        result = cloudscale_volume.absent()
    elif module.params['revert']:
        result = cloudscale_volume.revert()
    else:
        result = cloudscale_volume.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
