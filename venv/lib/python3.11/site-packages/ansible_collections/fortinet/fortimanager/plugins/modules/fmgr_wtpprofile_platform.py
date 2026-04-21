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
module: fmgr_wtpprofile_platform
short_description: WTP, FortiAP, or AP platform.
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
    wtpprofile_platform:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            type:
                type: str
                description: WTP, FortiAP or AP platform type.
                choices:
                    - '30B-50B'
                    - '60B'
                    - '80CM-81CM'
                    - '220A'
                    - '220B'
                    - '210B'
                    - '60C'
                    - '222B'
                    - '112B'
                    - '320B'
                    - '11C'
                    - '14C'
                    - '223B'
                    - '28C'
                    - '320C'
                    - '221C'
                    - '25D'
                    - '222C'
                    - '224D'
                    - '214B'
                    - '21D'
                    - '24D'
                    - '112D'
                    - '223C'
                    - '321C'
                    - 'C220C'
                    - 'C225C'
                    - 'S321C'
                    - 'S323C'
                    - 'FWF'
                    - 'S311C'
                    - 'S313C'
                    - 'AP-11N'
                    - 'S322C'
                    - 'S321CR'
                    - 'S322CR'
                    - 'S323CR'
                    - 'S421E'
                    - 'S422E'
                    - 'S423E'
                    - '421E'
                    - '423E'
                    - 'C221E'
                    - 'C226E'
                    - 'C23JD'
                    - 'C24JE'
                    - 'C21D'
                    - 'U421E'
                    - 'U423E'
                    - '221E'
                    - '222E'
                    - '223E'
                    - 'S221E'
                    - 'S223E'
                    - 'U221EV'
                    - 'U223EV'
                    - 'U321EV'
                    - 'U323EV'
                    - '224E'
                    - 'U422EV'
                    - 'U24JEV'
                    - '321E'
                    - 'U431F'
                    - 'U433F'
                    - '231E'
                    - '431F'
                    - '433F'
                    - '231F'
                    - '432F'
                    - '234F'
                    - '23JF'
                    - 'U231F'
                    - '831F'
                    - 'U234F'
                    - 'U432F'
                    - '431FL'
                    - '432FR'
                    - '433FL'
                    - '231FL'
                    - '231G'
                    - '233G'
                    - '431G'
                    - '433G'
                    - 'U231G'
                    - 'U441G'
                    - '234G'
                    - '432G'
                    - '441K'
                    - '443K'
                    - '241K'
                    - '243K'
                    - '231K'
                    - '23JK'
            mode:
                type: str
                description: Configure operation mode of 5G radios
                choices:
                    - 'dual-5G'
                    - 'single-5G'
            ddscan:
                type: str
                description: Enable/disable use of one radio for dedicated dual-band scanning to detect RF characterization and wireless threat management.
                choices:
                    - 'disable'
                    - 'enable'
            _local_platform_str:
                type: str
                description: Local platform str.
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
    - name: WTP, FortiAP, or AP platform.
      fortinet.fortimanager.fmgr_wtpprofile_platform:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        wtp_profile: <your own value>
        wtpprofile_platform:
          # type: <value in [30B-50B, 60B, 80CM-81CM, ...]>
          # mode: <value in [dual-5G, single-5G]>
          # ddscan: <value in [disable, enable]>
          # _local_platform_str: <string>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/platform',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/platform'
    ]
    url_params = ['adom', 'wtp-profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wtp-profile': {'type': 'str', 'api_name': 'wtp_profile'},
        'wtp_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'wtpprofile_platform': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'type': {
                    'choices': [
                        '30B-50B', '60B', '80CM-81CM', '220A', '220B', '210B', '60C', '222B', '112B', '320B', '11C', '14C', '223B', '28C', '320C',
                        '221C', '25D', '222C', '224D', '214B', '21D', '24D', '112D', '223C', '321C', 'C220C', 'C225C', 'S321C', 'S323C', 'FWF', 'S311C',
                        'S313C', 'AP-11N', 'S322C', 'S321CR', 'S322CR', 'S323CR', 'S421E', 'S422E', 'S423E', '421E', '423E', 'C221E', 'C226E', 'C23JD',
                        'C24JE', 'C21D', 'U421E', 'U423E', '221E', '222E', '223E', 'S221E', 'S223E', 'U221EV', 'U223EV', 'U321EV', 'U323EV', '224E',
                        'U422EV', 'U24JEV', '321E', 'U431F', 'U433F', '231E', '431F', '433F', '231F', '432F', '234F', '23JF', 'U231F', '831F', 'U234F',
                        'U432F', '431FL', '432FR', '433FL', '231FL', '231G', '233G', '431G', '433G', 'U231G', 'U441G', '234G', '432G', '441K', '443K',
                        '241K', '243K', '231K', '23JK'
                    ],
                    'type': 'str'
                },
                'mode': {'v_range': [['6.2.2', '']], 'choices': ['dual-5G', 'single-5G'], 'type': 'str'},
                'ddscan': {'v_range': [['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_local_platform_str': {'v_range': [['6.2.8', '6.2.13'], ['6.4.6', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile_platform'),
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
