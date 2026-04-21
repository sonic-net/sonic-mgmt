#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: intersight_target_claim
short_description: Target claim configuraiton for Cisco Intersight
description:
- Target claim configuraiton for Cisco Intersight
- Used to claim or unclaim a Target from Cisco Intersight
- For more information see L(Cisco Intersight,https://intersight.com/apidocs).
extends_documentation_fragment: intersight
options:
  claim_code:
    description:
    - Claim code required for registering a new Target
    - Required if I(state=present)
    type: str
    required: false
  device_id:
    description:
    - Device id (serial number) of target
    - Targets containing multiple Target ids (e.g. IMM) can be formatted as <target1_id>&<target2_id>
    type: str
    required: true
  state:
    description:
    - If C(present), will verify the resource is present and will create if needed.
    - If C(absent), will verify the resource is absent and will delete if needed.
    type: str
    choices: [present, absent]
    default: present
author:
- Brandon Beck (@techBeck03)
- CiscoUcs (@CiscoUcs)
'''

EXAMPLES = r'''
- name: Claim new Target
  cisco.intersight.intersight_target_claim:
    device_id: "{{ device_id }}"
    claim_code: "{{ claim_code }}"
    state: present

- name: Delete a Target (unclaim)
  cisco.intersight.intersight_target_claim:
    device_id: "{{ device_id }}"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
      "Account": {
        "ClassId": "mo.MoRef",
        "Moid": "8675309",
        "ObjectType": "iam.Account",
        "link": "https://www.intersight.com/api/v1/iam/Accounts/8675309"
      },
      "AccountMoid": "8675309",
      "Ancestors": null,
      "ClassId": "asset.DeviceClaim",
      "CreateTime": "2021-05-10T17:32:13.522665238Z",
      "Device": {
        "ClassId": "mo.MoRef",
        "Moid": "9035768",
        "ObjectType": "asset.DeviceRegistration",
        "link": "https://www.intersight.com/api/v1/asset/DeviceRegistrations/9035768"
      },
      "DisplayNames": {
        "short": [
          "FDO241604EM&FDO24161700"
        ]
      },
      "DomainGroupMoid": "5b4e48a96a636d6d346cd1c5",
      "ModTime": "2021-05-10T17:32:13.522665238Z",
      "Moid": "8675309",
      "ObjectType": "asset.DeviceClaim",
      "Owners": [
          "90357688675309"
      ],
      "PermissionResources": null,
      "SecurityToken": "A95486674376E",
      "SerialNumber": "FDO86753091&FDO86753092",
      "SharedScope": "",
      "Tags": [],
      "trace_id": "NB3e883980a98adace8f7b9c2409cced1a"
    }
'''

from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        claim_code=dict(type='str'),
        device_id=dict(type='str', required=True),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=[
            ('state', 'present', (['claim_code']), False),
        ]
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Check if device already exists in target list
    target_ids = module.params['device_id'].split('&')
    target_filter = ''
    for idx, target_id in enumerate(target_ids):
        if idx == 0:
            target_filter += f"contains(TargetId,'{target_id}')"
        else:
            target_filter += f" or contains(TargetId,'{target_id}')"
    intersight.get_resource(
        resource_path='/asset/Targets',
        query_params={
            "$select": "TargetId,RegisteredDevice",
            "$filter": target_filter,
            "$expand": "RegisteredDevice($select=DeviceClaim)"
        },
        return_list=False,
    )

    if module.params['state'] == 'present':
        # Send claim request if device id not already claimed
        if not intersight.result['api_response']:
            intersight.configure_resource(
                moid=None,
                resource_path='/asset/DeviceClaims',
                body=dict(
                    SecurityToken=module.params['claim_code'],
                    SerialNumber=module.params['device_id']
                ),
                query_params=None,
                update_method='post'
            )

    elif module.params['state'] == 'absent':
        # Check if target exists
        if intersight.result['api_response'].get('Moid'):
            intersight.delete_resource(
                moid=intersight.result['api_response'].get('RegisteredDevice').get('DeviceClaim').get('Moid'),
                resource_path='/asset/DeviceClaims',
            )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
