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
module: fmgr_extendercontroller_simprofile
short_description: Extender controller sim profile
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    extendercontroller_simprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auto_switch_profile:
                aliases: ['auto-switch_profile']
                type: dict
                description: Auto switch profile.
                suboptions:
                    dataplan:
                        type: str
                        description: Dataplan.
                        choices:
                            - 'disable'
                            - 'enable'
                    disconnect:
                        type: str
                        description: Disconnect.
                        choices:
                            - 'disable'
                            - 'enable'
                    disconnect_period:
                        aliases: ['disconnect-period']
                        type: int
                        description: Disconnect period.
                    disconnect_threshold:
                        aliases: ['disconnect-threshold']
                        type: int
                        description: Disconnect threshold.
                    signal:
                        type: str
                        description: Signal.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_back:
                        aliases: ['switch-back']
                        type: list
                        elements: str
                        description: Switch back.
                        choices:
                            - 'time'
                            - 'timer'
                    switch_back_time:
                        aliases: ['switch-back-time']
                        type: str
                        description: Switch back time.
                    switch_back_timer:
                        aliases: ['switch-back-timer']
                        type: int
                        description: Switch back timer.
            conn_status:
                aliases: ['conn-status']
                type: int
                description: Conn status.
            default_sim:
                aliases: ['default-sim']
                type: str
                description: Default sim.
                choices:
                    - 'sim1'
                    - 'sim2'
                    - 'carrier'
                    - 'cost'
            description:
                type: str
                description: Description.
            gps:
                type: str
                description: Gps.
                choices:
                    - 'disable'
                    - 'enable'
            modem_id:
                aliases: ['modem-id']
                type: int
                description: Modem id.
            name:
                type: str
                description: Name.
                required: true
            preferred_carrier:
                aliases: ['preferred-carrier']
                type: str
                description: Preferred carrier.
            redundant_intf:
                aliases: ['redundant-intf']
                type: str
                description: Redundant intf.
            redundant_mode:
                aliases: ['redundant-mode']
                type: str
                description: Redundant mode.
                choices:
                    - 'disable'
                    - 'enable'
            sim1_pin:
                aliases: ['sim1-pin']
                type: str
                description: Sim1 pin.
                choices:
                    - 'disable'
                    - 'enable'
            sim1_pin_code:
                aliases: ['sim1-pin-code']
                type: raw
                description: (list) Sim1 pin code.
            sim2_pin:
                aliases: ['sim2-pin']
                type: str
                description: Sim2 pin.
                choices:
                    - 'disable'
                    - 'enable'
            sim2_pin_code:
                aliases: ['sim2-pin-code']
                type: raw
                description: (list) Sim2 pin code.
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Extender controller sim profile
      fortinet.fortimanager.fmgr_extendercontroller_simprofile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        extendercontroller_simprofile:
          name: "your value" # Required variable, string
          # auto_switch_profile:
          #   dataplan: <value in [disable, enable]>
          #   disconnect: <value in [disable, enable]>
          #   disconnect_period: <integer>
          #   disconnect_threshold: <integer>
          #   signal: <value in [disable, enable]>
          #   status: <value in [disable, enable]>
          #   switch_back:
          #     - "time"
          #     - "timer"
          #   switch_back_time: <string>
          #   switch_back_timer: <integer>
          # conn_status: <integer>
          # default_sim: <value in [sim1, sim2, carrier, ...]>
          # description: <string>
          # gps: <value in [disable, enable]>
          # modem_id: <integer>
          # preferred_carrier: <string>
          # redundant_intf: <string>
          # redundant_mode: <value in [disable, enable]>
          # sim1_pin: <value in [disable, enable]>
          # sim1_pin_code: <list or string>
          # sim2_pin: <value in [disable, enable]>
          # sim2_pin_code: <list or string>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/extender-controller/sim_profile',
        '/pm/config/global/obj/extender-controller/sim_profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'extendercontroller_simprofile': {
            'type': 'dict',
            'v_range': [['6.4.4', '']],
            'options': {
                'auto-switch_profile': {
                    'v_range': [['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'dataplan': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'disconnect': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'disconnect-period': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'disconnect-threshold': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'signal': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-back': {'v_range': [['6.4.5', '']], 'type': 'list', 'choices': ['time', 'timer'], 'elements': 'str'},
                        'switch-back-time': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'switch-back-timer': {'v_range': [['6.4.5', '']], 'type': 'int'}
                    }
                },
                'conn-status': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'default-sim': {'v_range': [['6.4.4', '']], 'choices': ['sim1', 'sim2', 'carrier', 'cost'], 'type': 'str'},
                'description': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'gps': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'modem-id': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'name': {'v_range': [['6.4.4', '']], 'required': True, 'type': 'str'},
                'preferred-carrier': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'redundant-intf': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'redundant-mode': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim1-pin': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim1-pin-code': {'v_range': [['6.4.4', '']], 'type': 'raw'},
                'sim2-pin': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim2-pin-code': {'v_range': [['6.4.4', '']], 'type': 'raw'},
                'status': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_simprofile'),
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
