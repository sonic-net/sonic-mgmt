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
module: intersight_rest_api
short_description: REST API configuration for Cisco Intersight
description:
- Direct REST API configuration for Cisco Intersight.
- All REST API resources and properties must be specified.
- For more information see L(Cisco Intersight,https://intersight.com/apidocs).
extends_documentation_fragment: intersight
options:
  resource_path:
    description:
    - Resource URI being configured related to api_uri.
    type: str
    required: yes
  query_params:
    description:
    - Query parameters for the Intersight API query languange.
    type: dict
  update_method:
    description:
    - The HTTP method used for update operations.
    - Some Intersight resources require POST operations for modifications.
    - json-patch is used for partial updates.
    - json-patch is only supported for patch operations on existing resources and requires the list_body to be a list of dictionaries.
    - See L(The Intersight API Docs, https://intersight.com/apidocs/introduction/methods/) for details on JSON Patch.
    type: str
    choices: [ patch, post, json-patch ]
    default: patch
  api_body:
    description:
    - The paylod for API requests used to modify resources.
    type: dict
  list_body:
    description:
    - The paylod for API requests used to modify resources.
    - Should be used instead of api_body if a list is required in the API payload.
    type: list
    elements: dict
  return_list:
    description:
    - If C(yes), will return a list of API results in the api_response.
    - By default only the 1st element of the API Results list is returned.
    - Can only be used with GET operations.
    type: bool
    default: no
  state:
    description:
    - If C(present), will verify the resource is present and will create if needed.
    - If C(absent), will verify the resource is absent and will delete if needed.
    type: str
    choices: [present, absent]
    default: present
author:
- David Soper (@dsoper2)
- CiscoUcs (@CiscoUcs)
'''

EXAMPLES = r'''
- name: Configure Boot Policy
  intersight_rest_api:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    api_key_uri: "{{ api_key_uri }}"
    validate_certs: "{{ validate_certs }}"
    resource_path: /boot/PrecisionPolicies
    query_params:
      $filter: "Name eq 'vmedia-localdisk'"
    api_body: {
      "Name": "vmedia-localdisk",
      "ConfiguredBootMode": "Legacy",
      "BootDevices": [
        {
          "ObjectType": "boot.VirtualMedia",
          "Enabled": true,
          "Name": "remote-vmedia",
          "Subtype": "cimc-mapped-dvd"
        },
        {
          "ObjectType": "boot.LocalDisk",
          "Enabled": true,
          "Name": "localdisk",
          "Slot": "MRAID",
          "Bootloader": null
        }
      ],
    }
    state: present

- name: Delete Boot Policy
  intersight_rest_api:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    api_key_uri: "{{ api_key_uri }}"
    validate_certs: "{{ validate_certs }}"
    resource_path: /boot/PrecisionPolicies
    query_params:
      $filter: "Name eq 'vmedia-localdisk'"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
      "BootDevices": [
        {
          "Enabled": true,
          "Name": "remote-vmedia",
          "ObjectType": "boot.VirtualMedia",
          "Subtype": "cimc-mapped-dvd"
        },
        {
          "Bootloader": null,
          "Enabled": true,
          "Name": "boot-lun",
          "ObjectType": "boot.LocalDisk",
          "Slot": "MRAID"
        }
      ],
      "ConfiguredBootMode": "Legacy",
      "Name": "vmedia-localdisk",
      "ObjectType": "boot.PrecisionPolicy",
    }
'''

from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec, compare_values
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        resource_path=dict(type='str', required=True),
        query_params=dict(type='dict'),
        update_method=dict(type='str', choices=['patch', 'post', 'json-patch'], default='patch'),
        api_body=dict(type='dict'),
        list_body=dict(type='list', elements='dict'),
        return_list=dict(type='bool', default=False),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ['return_list', 'api_body'],
            ['return_list', 'state'],
            ['api_body', 'list_body'],
        ],
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    if module.params['list_body']:
        module.params['api_body'] = module.params['list_body']

    # determine requested operation (config, delete, or neither (get resource only))
    if module.params['state'] == 'present':
        request_delete = False
        # api_body implies resource configuration through post/patch
        # no api_body implies a get operation
        request_config = bool(module.params['api_body'])
        if request_config and not module.params['query_params']:
            # no query_params will try to create the resource without getting the current state
            get_resource = False
        else:
            get_resource = True
    else:  # state == 'absent'
        # state == 'absent' with no query_params is not permitted to avoid accidental deletion
        if not module.params['query_params']:
            raise ValueError('Please specify query_params when state is absent')
        request_delete = True
        request_config = False
        get_resource = True

    if get_resource:
        # get the current state of the resource
        intersight.get_resource(
            resource_path=module.params['resource_path'],
            query_params=module.params['query_params'],
            return_list=module.params['return_list'],
        )

    moid = None
    resource_values_match = False
    if (request_config or request_delete) and intersight.result['api_response'].get('Moid'):
        # resource exists and moid was returned
        moid = intersight.result['api_response']['Moid']
        if request_config:
            resource_values_match = compare_values(module.params['api_body'], intersight.result['api_response'])
        else:  # request_delete
            intersight.delete_resource(
                moid=moid,
                resource_path=module.params['resource_path'],
            )

    if request_config and not resource_values_match:
        intersight.configure_resource(
            moid=moid,
            resource_path=module.params['resource_path'],
            body=module.params['api_body'],
            query_params=module.params['query_params'],
            update_method=module.params['update_method'],
        )
    if module.params['return_list'] and not isinstance(intersight.result['api_response'], list):
        intersight.result['api_response'] = []

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
