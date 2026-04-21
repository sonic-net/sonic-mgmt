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
module: fmgr_extensioncontroller_extendervap
short_description: FortiExtender wifi vap configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10.0"
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
    extensioncontroller_extendervap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allowaccess:
                type: list
                elements: str
                description: Control management access to the managed extender.
                choices:
                    - 'http'
                    - 'ssh'
                    - 'telnet'
                    - 'snmp'
                    - 'https'
                    - 'ping'
            auth_server_address:
                aliases: ['auth-server-address']
                type: str
                description: Wi-Fi Authentication Server Address
            auth_server_port:
                aliases: ['auth-server-port']
                type: int
                description: Wi-Fi Authentication Server Port.
            auth_server_secret:
                aliases: ['auth-server-secret']
                type: str
                description: Wi-Fi Authentication Server Secret.
            broadcast_ssid:
                aliases: ['broadcast-ssid']
                type: str
                description: Wi-Fi broadcast SSID enable / disable.
                choices:
                    - 'disable'
                    - 'enable'
            bss_color_partial:
                aliases: ['bss-color-partial']
                type: str
                description: Wi-Fi 802.
                choices:
                    - 'disable'
                    - 'enable'
            dtim:
                type: int
                description: Wi-Fi DTIM
            end_ip:
                aliases: ['end-ip']
                type: str
                description: End ip address.
            ip_address:
                aliases: ['ip-address']
                type: list
                elements: str
                description: Extender ip address.
            max_clients:
                aliases: ['max-clients']
                type: int
                description: Wi-Fi max clients
            mu_mimo:
                aliases: ['mu-mimo']
                type: str
                description: Wi-Fi multi-user MIMO enable / disable, default = enable.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Wi-Fi VAP name.
                required: true
            passphrase:
                type: list
                elements: str
                description: Wi-Fi passphrase.
            pmf:
                type: str
                description: Wi-Fi pmf enable/disable, default = disable.
                choices:
                    - 'disabled'
                    - 'optional'
                    - 'required'
            rts_threshold:
                aliases: ['rts-threshold']
                type: int
                description: Wi-Fi RTS Threshold
            sae_password:
                aliases: ['sae-password']
                type: list
                elements: str
                description: Wi-Fi SAE Password.
            security:
                type: str
                description: Wi-Fi security.
                choices:
                    - 'OPEN'
                    - 'WPA2-Personal'
                    - 'WPA-WPA2-Personal'
                    - 'WPA3-SAE'
                    - 'WPA3-SAE-Transition'
                    - 'WPA2-Enterprise'
                    - 'WPA3-Enterprise-only'
                    - 'WPA3-Enterprise-transition'
                    - 'WPA3-Enterprise-192-bit'
            ssid:
                type: str
                description: Wi-Fi SSID.
            start_ip:
                aliases: ['start-ip']
                type: str
                description: Start ip address.
            target_wake_time:
                aliases: ['target-wake-time']
                type: str
                description: Wi-Fi 802.
                choices:
                    - 'disable'
                    - 'enable'
            type:
                type: str
                description: Wi-Fi VAP type local-vap / lan-extension-vap.
                choices:
                    - 'local-vap'
                    - 'lan-ext-vap'
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
    - name: FortiExtender wifi vap configuration.
      fortinet.fortimanager.fmgr_extensioncontroller_extendervap:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        extensioncontroller_extendervap:
          name: "your value" # Required variable, string
          # allowaccess:
          #   - "http"
          #   - "ssh"
          #   - "telnet"
          #   - "snmp"
          #   - "https"
          #   - "ping"
          # auth_server_address: <string>
          # auth_server_port: <integer>
          # auth_server_secret: <string>
          # broadcast_ssid: <value in [disable, enable]>
          # bss_color_partial: <value in [disable, enable]>
          # dtim: <integer>
          # end_ip: <string>
          # ip_address: <list or string>
          # max_clients: <integer>
          # mu_mimo: <value in [disable, enable]>
          # passphrase: <list or string>
          # pmf: <value in [disabled, optional, required]>
          # rts_threshold: <integer>
          # sae_password: <list or string>
          # security: <value in [OPEN, WPA2-Personal, WPA-WPA2-Personal, ...]>
          # ssid: <string>
          # start_ip: <string>
          # target_wake_time: <value in [disable, enable]>
          # type: <value in [local-vap, lan-ext-vap]>
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-vap',
        '/pm/config/global/obj/extension-controller/extender-vap'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'extensioncontroller_extendervap': {
            'type': 'dict',
            'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']],
            'options': {
                'allowaccess': {
                    'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']],
                    'type': 'list',
                    'choices': ['http', 'ssh', 'telnet', 'snmp', 'https', 'ping'],
                    'elements': 'str'
                },
                'auth-server-address': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                'auth-server-port': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'int'},
                'auth-server-secret': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'no_log': True, 'type': 'str'},
                'broadcast-ssid': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bss-color-partial': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dtim': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'int'},
                'end-ip': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                'ip-address': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'list', 'elements': 'str'},
                'max-clients': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'int'},
                'mu-mimo': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'required': True, 'type': 'str'},
                'passphrase': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'pmf': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disabled', 'optional', 'required'], 'type': 'str'},
                'rts-threshold': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'int'},
                'sae-password': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'security': {
                    'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']],
                    'choices': [
                        'OPEN', 'WPA2-Personal', 'WPA-WPA2-Personal', 'WPA3-SAE', 'WPA3-SAE-Transition', 'WPA2-Enterprise', 'WPA3-Enterprise-only',
                        'WPA3-Enterprise-transition', 'WPA3-Enterprise-192-bit'
                    ],
                    'type': 'str'
                },
                'ssid': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                'start-ip': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                'target-wake-time': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['local-vap', 'lan-ext-vap'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extendervap'),
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
