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
module: fmgr_firewall_profileprotocoloptions_cifs
short_description: Configure CIFS protocol options.
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
    profile-protocol-options:
        description: Deprecated, please use "profile_protocol_options"
        type: str
    profile_protocol_options:
        description: The parameter (profile-protocol-options) in requested url.
        type: str
    firewall_profileprotocoloptions_cifs:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ports:
                type: raw
                description: (list) Ports to scan for content
            status:
                type: str
                description: Enable/disable the active status of scanning for this protocol.
                choices:
                    - 'disable'
                    - 'enable'
            options:
                type: list
                elements: str
                description: One or more options that can be applied to the session.
                choices:
                    - 'oversize'
            oversize_limit:
                aliases: ['oversize-limit']
                type: int
                description: Maximum in-memory file size that can be scanned
            scan_bzip2:
                aliases: ['scan-bzip2']
                type: str
                description: Enable/disable scanning of BZip2 compressed files.
                choices:
                    - 'disable'
                    - 'enable'
            tcp_window_maximum:
                aliases: ['tcp-window-maximum']
                type: int
                description: Maximum dynamic TCP window size
            tcp_window_minimum:
                aliases: ['tcp-window-minimum']
                type: int
                description: Minimum dynamic TCP window size
            tcp_window_size:
                aliases: ['tcp-window-size']
                type: int
                description: Set TCP static window size
            tcp_window_type:
                aliases: ['tcp-window-type']
                type: str
                description: Specify type of TCP window to use for this protocol.
                choices:
                    - 'system'
                    - 'static'
                    - 'dynamic'
                    - 'auto-tuning'
            uncompressed_nest_limit:
                aliases: ['uncompressed-nest-limit']
                type: int
                description: Maximum nested levels of compression that can be uncompressed and scanned
            uncompressed_oversize_limit:
                aliases: ['uncompressed-oversize-limit']
                type: int
                description: Maximum in-memory uncompressed file size that can be scanned
            domain_controller:
                aliases: ['domain-controller']
                type: str
                description: Domain for which to decrypt CIFS traffic.
            file_filter:
                aliases: ['file-filter']
                type: dict
                description: File filter.
                suboptions:
                    entries:
                        type: list
                        elements: dict
                        description: Entries.
                        suboptions:
                            action:
                                type: str
                                description: Action taken for matched file.
                                choices:
                                    - 'log'
                                    - 'block'
                            comment:
                                type: str
                                description: Comment.
                            direction:
                                type: str
                                description: Match files transmitted in the sessions originating or reply direction.
                                choices:
                                    - 'any'
                                    - 'incoming'
                                    - 'outgoing'
                            file_type:
                                aliases: ['file-type']
                                type: raw
                                description: (list) Select file type.
                            filter:
                                type: str
                                description: Add a file filter.
                            protocol:
                                type: list
                                elements: str
                                description: Protocols to apply with.
                                choices:
                                    - 'cifs'
                    log:
                        type: str
                        description: Enable/disable file filter logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable file filter.
                        choices:
                            - 'disable'
                            - 'enable'
            server_credential_type:
                aliases: ['server-credential-type']
                type: str
                description: CIFS server credential type.
                choices:
                    - 'none'
                    - 'credential-replication'
                    - 'credential-keytab'
            server_keytab:
                aliases: ['server-keytab']
                type: list
                elements: dict
                description: Server keytab.
                suboptions:
                    keytab:
                        type: str
                        description: Base64 encoded keytab file containing credential of the server.
                    password:
                        type: raw
                        description: (list) Password for keytab.
                    principal:
                        type: str
                        description: Service principal.
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
    - name: Configure CIFS protocol options.
      fortinet.fortimanager.fmgr_firewall_profileprotocoloptions_cifs:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile_protocol_options: <your own value>
        firewall_profileprotocoloptions_cifs:
          # ports: <list or integer>
          # status: <value in [disable, enable]>
          # options:
          #   - "oversize"
          # oversize_limit: <integer>
          # scan_bzip2: <value in [disable, enable]>
          # tcp_window_maximum: <integer>
          # tcp_window_minimum: <integer>
          # tcp_window_size: <integer>
          # tcp_window_type: <value in [system, static, dynamic, ...]>
          # uncompressed_nest_limit: <integer>
          # uncompressed_oversize_limit: <integer>
          # domain_controller: <string>
          # file_filter:
          #   entries:
          #     - action: <value in [log, block]>
          #       comment: <string>
          #       direction: <value in [any, incoming, outgoing]>
          #       file_type: <list or string>
          #       filter: <string>
          #       protocol:
          #         - "cifs"
          #   log: <value in [disable, enable]>
          #   status: <value in [disable, enable]>
          # server_credential_type: <value in [none, credential-replication, credential-keytab]>
          # server_keytab:
          #   - keytab: <string>
          #     password: <list or string>
          #     principal: <string>
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
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs'
    ]
    url_params = ['adom', 'profile-protocol-options']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile-protocol-options': {'type': 'str', 'api_name': 'profile_protocol_options'},
        'profile_protocol_options': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_profileprotocoloptions_cifs': {
            'type': 'dict',
            'v_range': [['6.2.0', '']],
            'options': {
                'ports': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'status': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'options': {'v_range': [['6.4.0', '']], 'type': 'list', 'choices': ['oversize'], 'elements': 'str'},
                'oversize-limit': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'scan-bzip2': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-window-maximum': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'tcp-window-minimum': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'tcp-window-size': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'tcp-window-type': {'v_range': [['6.4.0', '']], 'choices': ['system', 'static', 'dynamic', 'auto-tuning'], 'type': 'str'},
                'uncompressed-nest-limit': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'uncompressed-oversize-limit': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'domain-controller': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'file-filter': {
                    'v_range': [['6.4.2', '']],
                    'type': 'dict',
                    'options': {
                        'entries': {
                            'v_range': [['6.4.2', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['6.4.2', '']], 'choices': ['log', 'block'], 'type': 'str'},
                                'comment': {'v_range': [['6.4.2', '']], 'type': 'str'},
                                'direction': {'v_range': [['6.4.2', '']], 'choices': ['any', 'incoming', 'outgoing'], 'type': 'str'},
                                'file-type': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                                'filter': {'v_range': [['6.4.2', '']], 'type': 'str'},
                                'protocol': {'v_range': [['6.4.2', '']], 'type': 'list', 'choices': ['cifs'], 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'log': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'server-credential-type': {'v_range': [['6.4.2', '']], 'choices': ['none', 'credential-replication', 'credential-keytab'], 'type': 'str'},
                'server-keytab': {
                    'v_range': [['6.4.2', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {
                        'keytab': {'v_range': [['6.4.2', '']], 'no_log': True, 'type': 'str'},
                        'password': {'v_range': [['6.4.2', '']], 'no_log': True, 'type': 'raw'},
                        'principal': {'v_range': [['6.4.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions_cifs'),
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
