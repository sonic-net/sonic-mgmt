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
module: fmgr_wtpprofile_lan
short_description: WTP LAN port mapping.
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
    wtp-profile:
        description: Deprecated, please use "wtp_profile"
        type: str
    wtp_profile:
        description: The parameter (wtp-profile) in requested url.
        type: str
    wtpprofile_lan:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            port_mode:
                aliases: ['port-mode']
                type: str
                description: LAN port mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port_ssid:
                aliases: ['port-ssid']
                type: str
                description: Bridge LAN port to SSID.
            port1_mode:
                aliases: ['port1-mode']
                type: str
                description: LAN port 1 mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port1_ssid:
                aliases: ['port1-ssid']
                type: str
                description: Bridge LAN port 1 to SSID.
            port2_mode:
                aliases: ['port2-mode']
                type: str
                description: LAN port 2 mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port2_ssid:
                aliases: ['port2-ssid']
                type: str
                description: Bridge LAN port 2 to SSID.
            port3_mode:
                aliases: ['port3-mode']
                type: str
                description: LAN port 3 mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port3_ssid:
                aliases: ['port3-ssid']
                type: str
                description: Bridge LAN port 3 to SSID.
            port4_mode:
                aliases: ['port4-mode']
                type: str
                description: LAN port 4 mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port4_ssid:
                aliases: ['port4-ssid']
                type: str
                description: Bridge LAN port 4 to SSID.
            port5_mode:
                aliases: ['port5-mode']
                type: str
                description: LAN port 5 mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port5_ssid:
                aliases: ['port5-ssid']
                type: str
                description: Bridge LAN port 5 to SSID.
            port6_mode:
                aliases: ['port6-mode']
                type: str
                description: LAN port 6 mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port6_ssid:
                aliases: ['port6-ssid']
                type: str
                description: Bridge LAN port 6 to SSID.
            port7_mode:
                aliases: ['port7-mode']
                type: str
                description: LAN port 7 mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port7_ssid:
                aliases: ['port7-ssid']
                type: str
                description: Bridge LAN port 7 to SSID.
            port8_mode:
                aliases: ['port8-mode']
                type: str
                description: LAN port 8 mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port8_ssid:
                aliases: ['port8-ssid']
                type: str
                description: Bridge LAN port 8 to SSID.
            port_esl_mode:
                aliases: ['port-esl-mode']
                type: str
                description: ESL port mode.
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port_esl_ssid:
                aliases: ['port-esl-ssid']
                type: str
                description: Bridge ESL port to SSID.
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
    - name: WTP LAN port mapping.
      fortinet.fortimanager.fmgr_wtpprofile_lan:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        wtp_profile: <your own value>
        wtpprofile_lan:
          # port_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port_ssid: <string>
          # port1_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port1_ssid: <string>
          # port2_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port2_ssid: <string>
          # port3_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port3_ssid: <string>
          # port4_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port4_ssid: <string>
          # port5_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port5_ssid: <string>
          # port6_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port6_ssid: <string>
          # port7_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port7_ssid: <string>
          # port8_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port8_ssid: <string>
          # port_esl_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          # port_esl_ssid: <string>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/lan',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/lan'
    ]
    url_params = ['adom', 'wtp-profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wtp-profile': {'type': 'str', 'api_name': 'wtp_profile'},
        'wtp_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'wtpprofile_lan': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'port-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port-ssid': {'type': 'str'},
                'port1-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port1-ssid': {'type': 'str'},
                'port2-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port2-ssid': {'type': 'str'},
                'port3-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port3-ssid': {'type': 'str'},
                'port4-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port4-ssid': {'type': 'str'},
                'port5-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port5-ssid': {'type': 'str'},
                'port6-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port6-ssid': {'type': 'str'},
                'port7-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port7-ssid': {'type': 'str'},
                'port8-mode': {'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port8-ssid': {'type': 'str'},
                'port-esl-mode': {'v_range': [['6.4.2', '']], 'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'], 'type': 'str'},
                'port-esl-ssid': {'v_range': [['6.4.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile_lan'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
