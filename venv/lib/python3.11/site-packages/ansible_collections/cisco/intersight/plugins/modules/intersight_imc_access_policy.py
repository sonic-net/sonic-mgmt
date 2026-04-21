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
module: intersight_imc_access_policy
short_description: IMC Access Policy configuration for Cisco Intersight
description:
  - IMC Access Policy configuration for Cisco Intersight.
  - Used to configure IP addresses and VLAN used for external connectivity to Cisco IMC.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
    type: str
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Profiles and Policies that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the IMC Access Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  description:
    description:
      - The user-defined description of the IMC access policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  out_of_band:
    description:
      - If C(true), will enable Out-Of-Band configuration.
      - If C(false), will enable In-Band configuration.
    type: bool
    default: false
  vlan_id:
    description:
      - VLAN to be used for server access over Inband network.
      - Required if C(out_of_band) is C(false).
    type: int
  ip_pool:
    description:
      - IP Pool used to assign IP address and other required network settings.
    type: str
    required: true
author:
  - David Soper (@dsoper2)
'''

EXAMPLES = r'''
- name: Configure IMC Access policy
  intersight_imc_access_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: sjc02-d23-access
    description: IMC access for SJC02 rack D23
    tags:
      - Site: D23
    vlan_id: 131
    ip_pool: sjc02-d23-ext-mgmt

- name: Delete IMC Access policy
  intersight_imc_access_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: sjc02-d23-access
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "sjc02-d23-access",
        "ObjectType": "access.Policy",
        "Profiles": [
            {
                "Moid": "5e4ec7ae77696e2d30840cfc",
                "ObjectType": "server.Profile",
            },
            {
                "Moid": "5e84d78777696e2d302ec195",
                "ObjectType": "server.Profile",
            }
        ],
        "Tags": [
            {
                "Key": "Site",
                "Value": "SJC02"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec, compare_values


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        out_of_band=dict(type='bool', default=False),
        vlan_id=dict(type='int'),
        ip_pool=dict(type='str', required=True),
    )

    module = AnsibleModule(
        argument_spec,
        required_if=[
            ('out_of_band', False, ['vlan_id']),
        ],
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)

    organization_moid = None
    # GET Organization Moid
    intersight.get_resource(
        resource_path='/organization/Organizations',
        query_params={
            '$filter': "Name eq '" + intersight.module.params['organization'] + "'",
            '$select': 'Moid',
        },
    )
    if intersight.result['api_response'].get('Moid'):
        # resource exists and moid was returned
        organization_moid = intersight.result['api_response']['Moid']

    ip_pool_moid = None
    # GET IP Pool Moid
    filter_str = "Name eq '" + intersight.module.params['ip_pool'] + "'"
    filter_str += "and Organization.Moid eq '" + organization_moid + "'"
    intersight.get_resource(
        resource_path='/ippool/Pools',
        query_params={
            '$filter': filter_str,
            '$select': 'Moid',
        },
    )
    if intersight.result['api_response'].get('Moid'):
        # resource exists and moid was returned
        ip_pool_moid = intersight.result['api_response']['Moid']

    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''
    intersight.api_body = {
        'Name': intersight.module.params['name'],

        'Organization': {
            'Name': intersight.module.params['organization'],
        },
    }
    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

    if intersight.module.params['out_of_band']:
        intersight.api_body['ConfigurationType'] = {
            'ObjectType': 'access.ConfigurationType',
            'ConfigureInband': False,
            'ConfigureOutOfBand': True,
        }
        intersight.api_body['OutOfBandIpPool'] = {
            'ObjectType': 'ippool.Pool',
            'Moid': ip_pool_moid,
        }
    else:
        intersight.api_body['InbandVlan'] = intersight.module.params['vlan_id']
        intersight.api_body['ConfigurationType'] = {
            'ObjectType': 'access.ConfigurationType',
            'ConfigureInband': True,
            'ConfigureOutOfBand': False,
        }
        intersight.api_body['InbandIpPool'] = {
            'ObjectType': 'ippool.Pool',
            'Moid': ip_pool_moid,
        }

    # get the current state of the resource
    filter_str = "Name eq '" + intersight.module.params['name'] + "'"
    filter_str += "and Organization.Moid eq '" + organization_moid + "'"
    intersight.get_resource(
        resource_path='/access/Policies',
        query_params={
            '$filter': filter_str,
        },
    )

    moid = None
    resource_values_match = False
    if intersight.result['api_response'].get('Moid'):
        # resource exists and moid was returned
        moid = intersight.result['api_response']['Moid']
        if module.params['state'] == 'present':
            resource_values_match = compare_values(intersight.api_body, intersight.result['api_response'])
        else:  # state == 'absent'
            intersight.delete_resource(
                moid=moid,
                resource_path='/access/Policies',
            )
            moid = None

    if module.params['state'] == 'present' and not resource_values_match:
        # remove read-only Organization key
        intersight.api_body.pop('Organization')
        if not moid:
            # Organization must be set, but can't be changed after initial POST
            intersight.api_body['Organization'] = {
                'Moid': organization_moid,
            }
        intersight.configure_resource(
            moid=moid,
            resource_path='/access/Policies',
            body=intersight.api_body,
            query_params={
                '$filter': filter_str,
            },
        )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
