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
module: fmgr_mpskprofile
short_description: Configure MPSK profile.
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
    mpskprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            mpsk_concurrent_clients:
                aliases: ['mpsk-concurrent-clients']
                type: int
                description: Maximum number of concurrent clients that connect using the same passphrase in multiple PSK authentication
            mpsk_group:
                aliases: ['mpsk-group']
                type: list
                elements: dict
                description: Mpsk group.
                suboptions:
                    mpsk_key:
                        aliases: ['mpsk-key']
                        type: list
                        elements: dict
                        description: Mpsk key.
                        suboptions:
                            comment:
                                type: str
                                description: Comment.
                            concurrent_client_limit_type:
                                aliases: ['concurrent-client-limit-type']
                                type: str
                                description: MPSK client limit type options.
                                choices:
                                    - 'default'
                                    - 'unlimited'
                                    - 'specified'
                            concurrent_clients:
                                aliases: ['concurrent-clients']
                                type: int
                                description: Number of clients that can connect using this pre-shared key
                            mac:
                                type: str
                                description: MAC address.
                            mpsk_schedules:
                                aliases: ['mpsk-schedules']
                                type: raw
                                description: (list or str) Firewall schedule for MPSK passphrase.
                            name:
                                type: str
                                description: Pre-shared key name.
                            passphrase:
                                type: raw
                                description: (list) WPA Pre-shared key.
                            pmk:
                                type: raw
                                description: (list) WPA PMK.
                            key_type:
                                aliases: ['key-type']
                                type: str
                                description: Select the type of the key.
                                choices:
                                    - 'wpa2-personal'
                                    - 'wpa3-sae'
                            sae_password:
                                aliases: ['sae-password']
                                type: raw
                                description: (list) WPA3 SAE password.
                            sae_pk:
                                aliases: ['sae-pk']
                                type: str
                                description: Enable/disable WPA3 SAE-PK
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sae_private_key:
                                aliases: ['sae-private-key']
                                type: str
                                description: Private key used for WPA3 SAE-PK authentication.
                    name:
                        type: str
                        description: MPSK group name.
                    vlan_id:
                        aliases: ['vlan-id']
                        type: int
                        description: Optional VLAN ID.
                    vlan_type:
                        aliases: ['vlan-type']
                        type: str
                        description: MPSK group VLAN options.
                        choices:
                            - 'no-vlan'
                            - 'fixed-vlan'
            name:
                type: str
                description: MPSK profile name.
                required: true
            ssid:
                type: str
                description: SSID of the VAP in which the MPSK profile is configured.
            mpsk_external_server:
                aliases: ['mpsk-external-server']
                type: raw
                description: (list) RADIUS server to be used to authenticate MPSK users.
            mpsk_external_server_auth:
                aliases: ['mpsk-external-server-auth']
                type: str
                description: Enable/Disable MPSK external server authentication
                choices:
                    - 'disable'
                    - 'enable'
            mpsk_type:
                aliases: ['mpsk-type']
                type: str
                description: Select the security type of keys for this profile.
                choices:
                    - 'wpa2-personal'
                    - 'wpa3-sae'
                    - 'wpa3-sae-transition'
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
    - name: Configure MPSK profile.
      fortinet.fortimanager.fmgr_mpskprofile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        mpskprofile:
          name: "your value" # Required variable, string
          # mpsk_concurrent_clients: <integer>
          # mpsk_group:
          #   - mpsk_key:
          #       - comment: <string>
          #         concurrent_client_limit_type: <value in [default, unlimited, specified]>
          #         concurrent_clients: <integer>
          #         mac: <string>
          #         mpsk_schedules: <list or string>
          #         name: <string>
          #         passphrase: <list or string>
          #         pmk: <list or string>
          #         key_type: <value in [wpa2-personal, wpa3-sae]>
          #         sae_password: <list or string>
          #         sae_pk: <value in [disable, enable]>
          #         sae_private_key: <string>
          #     name: <string>
          #     vlan_id: <integer>
          #     vlan_type: <value in [no-vlan, fixed-vlan]>
          # ssid: <string>
          # mpsk_external_server: <list or string>
          # mpsk_external_server_auth: <value in [disable, enable]>
          # mpsk_type: <value in [wpa2-personal, wpa3-sae, wpa3-sae-transition]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile',
        '/pm/config/global/obj/wireless-controller/mpsk-profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'mpskprofile': {
            'type': 'dict',
            'v_range': [['6.4.2', '']],
            'options': {
                'mpsk-concurrent-clients': {'v_range': [['6.4.2', '']], 'type': 'int'},
                'mpsk-group': {
                    'v_range': [['6.4.2', '']],
                    'type': 'list',
                    'options': {
                        'mpsk-key': {
                            'v_range': [['6.4.2', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {
                                'comment': {'v_range': [['6.4.2', '']], 'type': 'str'},
                                'concurrent-client-limit-type': {
                                    'v_range': [['6.4.2', '']],
                                    'choices': ['default', 'unlimited', 'specified'],
                                    'type': 'str'
                                },
                                'concurrent-clients': {'v_range': [['6.4.2', '']], 'type': 'int'},
                                'mac': {'v_range': [['6.4.2', '']], 'type': 'str'},
                                'mpsk-schedules': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                                'name': {'v_range': [['6.4.2', '']], 'type': 'str'},
                                'passphrase': {'v_range': [['6.4.2', '']], 'no_log': True, 'type': 'raw'},
                                'pmk': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                                'key-type': {'v_range': [['7.4.3', '']], 'choices': ['wpa2-personal', 'wpa3-sae'], 'type': 'str'},
                                'sae-password': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'raw'},
                                'sae-pk': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'sae-private-key': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'name': {'v_range': [['6.4.2', '']], 'type': 'str'},
                        'vlan-id': {'v_range': [['6.4.2', '']], 'type': 'int'},
                        'vlan-type': {'v_range': [['6.4.2', '']], 'choices': ['no-vlan', 'fixed-vlan'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['6.4.2', '']], 'required': True, 'type': 'str'},
                'ssid': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'mpsk-external-server': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'mpsk-external-server-auth': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk-type': {'v_range': [['7.4.3', '']], 'choices': ['wpa2-personal', 'wpa3-sae', 'wpa3-sae-transition'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'mpskprofile'),
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
