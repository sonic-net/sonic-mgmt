#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: objects_user
short_description: Manages objects users on the cloudscale.ch IaaS service
description:
  - Create, update and remove objects users cloudscale.ch IaaS service.
author:
  - Rene Moser (@resmo)
version_added: 1.1.0
options:
  display_name:
    description:
      - Display name of the objects user.
      - Either I(display_name) or I(id) is required.
    type: str
    aliases:
      - name
  id:
    description:
      - Name of the objects user.
      - Either I(display_name) or I(id) is required.
    type: str
  tags:
    description:
      - Tags associated with the objects user. Set this to C({}) to clear any tags.
    type: dict
  state:
    description:
      - State of the objects user.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = r'''
- name: Create an objects user
  cloudscale_ch.cloud.objects_user:
    display_name: alan
    tags:
      project: luna
    api_token: xxxxxx
  register: object_user

- name: print keys
  debug:
    var: object_user.keys

- name: Update an objects user
  cloudscale_ch.cloud.objects_user:
    display_name: alan
    tags:
      project: gemini
    api_token: xxxxxx

- name: Remove an objects user
  cloudscale_ch.cloud.objects_user:
    display_name: alan
    state: absent
    api_token: xxxxxx
'''

RETURN = r'''
href:
  description: The API URL to get details about this resource.
  returned: success when state == present
  type: str
  sample: https://api.cloudscale.ch/v1/objects-users/6fe39134bf4178747eebc429f82cfafdd08891d4279d0d899bc4012db1db6a15
display_name:
  description: The display name of the objects user.
  returned: success
  type: str
  sample: alan
id:
  description: The ID of the objects user.
  returned: success
  type: str
  sample: 6fe39134bf4178747eebc429f82cfafdd08891d4279d0d899bc4012db1db6a15
keys:
  description: List of key objects.
  returned: success
  type: complex
  contains:
    access_key:
      description: The access key.
      returned: success
      type: str
      sample: 0ZTAIBKSGYBRHQ09G11W
    secret_key:
      description: The secret key.
      returned: success
      type: str
      sample: bn2ufcwbIa0ARLc5CLRSlVaCfFxPHOpHmjKiH34T
tags:
  description: Tags assosiated with the objects user.
  returned: success
  type: dict
  sample: { 'project': 'my project' }
state:
  description: The current status of the objects user.
  returned: success
  type: str
  sample: present
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.api import AnsibleCloudscaleBase, cloudscale_argument_spec


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        display_name=dict(type='str', aliases=['name']),
        id=dict(type='str'),
        tags=dict(type='dict'),
        state=dict(type='str', default='present', choices=('present', 'absent')),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(('display_name', 'id'),),
        required_if=(('state', 'present', ('display_name',),),),
        supports_check_mode=True,
    )

    cloudscale_objects_user = AnsibleCloudscaleBase(
        module,
        resource_name='objects-users',
        resource_key_uuid='id',
        resource_key_name='display_name',
        resource_create_param_keys=[
            'display_name',
            'tags',
        ],
        resource_update_param_keys=[
            'display_name',
            'tags',
        ],
    )

    if module.params['state'] == "absent":
        result = cloudscale_objects_user.absent()
    else:
        result = cloudscale_objects_user.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
