#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_bleprofile
short_description: Configure Bluetooth Low Energy profile.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    bleprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            advertising:
                type: list
                elements: str
                description: Advertising type.
                choices:
                    - 'ibeacon'
                    - 'eddystone-uid'
                    - 'eddystone-url'
            beacon_interval:
                aliases: ['beacon-interval']
                type: int
                description: Beacon interval
            ble_scanning:
                aliases: ['ble-scanning']
                type: str
                description: Enable/disable Bluetooth Low Energy
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            eddystone_instance:
                aliases: ['eddystone-instance']
                type: str
                description: Eddystone instance ID.
            eddystone_namespace:
                aliases: ['eddystone-namespace']
                type: str
                description: Eddystone namespace ID.
            eddystone_url:
                aliases: ['eddystone-url']
                type: str
                description: Eddystone URL.
            eddystone_url_encode_hex:
                aliases: ['eddystone-url-encode-hex']
                type: str
                description: Eddystone encoded URL hexadecimal string
            ibeacon_uuid:
                aliases: ['ibeacon-uuid']
                type: str
                description: Universally Unique Identifier
            major_id:
                aliases: ['major-id']
                type: int
                description: Major ID.
            minor_id:
                aliases: ['minor-id']
                type: int
                description: Minor ID.
            name:
                type: str
                description: Bluetooth Low Energy profile name.
                required: true
            txpower:
                type: str
                description: Transmit power level
                choices:
                    - '0'
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '6'
                    - '7'
                    - '8'
                    - '9'
                    - '10'
                    - '11'
                    - '12'
            scan_interval:
                aliases: ['scan-interval']
                type: int
                description: Scan Interval
            scan_period:
                aliases: ['scan-period']
                type: int
                description: Scan Period
            scan_threshold:
                aliases: ['scan-threshold']
                type: str
                description: Minimum signal level/threshold in dBm required for the AP to report detected BLE device
            scan_time:
                aliases: ['scan-time']
                type: int
                description: Scan Time
            scan_type:
                aliases: ['scan-type']
                type: str
                description: Scan Type
                choices:
                    - 'active'
                    - 'passive'
            scan_window:
                aliases: ['scan-window']
                type: int
                description: Scan Windows
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure Bluetooth Low Energy profile.
      fortinet.fortimanager.fmgr_bleprofile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        bleprofile:
          name: "your value" # Required variable, string
          # advertising:
          #   - "ibeacon"
          #   - "eddystone-uid"
          #   - "eddystone-url"
          # beacon_interval: <integer>
          # ble_scanning: <value in [disable, enable]>
          # comment: <string>
          # eddystone_instance: <string>
          # eddystone_namespace: <string>
          # eddystone_url: <string>
          # eddystone_url_encode_hex: <string>
          # ibeacon_uuid: <string>
          # major_id: <integer>
          # minor_id: <integer>
          # txpower: <value in [0, 1, 2, ...]>
          # scan_interval: <integer>
          # scan_period: <integer>
          # scan_threshold: <string>
          # scan_time: <integer>
          # scan_type: <value in [active, passive]>
          # scan_window: <integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/wireless-controller/ble-profile',
        '/pm/config/global/obj/wireless-controller/ble-profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'bleprofile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'advertising': {'type': 'list', 'choices': ['ibeacon', 'eddystone-uid', 'eddystone-url'], 'elements': 'str'},
                'beacon-interval': {'type': 'int'},
                'ble-scanning': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'type': 'str'},
                'eddystone-instance': {'type': 'str'},
                'eddystone-namespace': {'type': 'str'},
                'eddystone-url': {'type': 'str'},
                'eddystone-url-encode-hex': {'type': 'str'},
                'ibeacon-uuid': {'type': 'str'},
                'major-id': {'type': 'int'},
                'minor-id': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'txpower': {'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12'], 'type': 'str'},
                'scan-interval': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'scan-period': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'scan-threshold': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'scan-time': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'scan-type': {'v_range': [['7.4.1', '']], 'choices': ['active', 'passive'], 'type': 'str'},
                'scan-window': {'v_range': [['7.4.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'bleprofile'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
