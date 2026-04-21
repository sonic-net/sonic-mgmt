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
module: fmgr_pm_pkg
short_description: Policy package or folder.
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
    pkg_path:
        description: The parameter (pkg_path) in requested url.
        type: str
        required: true
    pm_pkg:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: Name.
                required: true
            obj_ver:
                aliases: ['obj ver']
                type: int
                description: Obj ver.
            oid:
                type: int
                description: Oid.
            package_setting:
                aliases: ['package setting']
                type: dict
                description: Package setting.
                suboptions:
                    central_nat:
                        aliases: ['central-nat']
                        type: str
                        description: Central nat.
                        choices:
                            - 'disable'
                            - 'enable'
                    consolidated_firewall_mode:
                        aliases: ['consolidated-firewall-mode']
                        type: str
                        description: Consolidated firewall mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy_implicit_log:
                        aliases: ['fwpolicy-implicit-log']
                        type: str
                        description: Fwpolicy implicit log.
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy6_implicit_log:
                        aliases: ['fwpolicy6-implicit-log']
                        type: str
                        description: Fwpolicy6 implicit log.
                        choices:
                            - 'disable'
                            - 'enable'
                    inspection_mode:
                        aliases: ['inspection-mode']
                        type: str
                        description: Inspection mode.
                        choices:
                            - 'proxy'
                            - 'flow'
                    ngfw_mode:
                        aliases: ['ngfw-mode']
                        type: str
                        description: Ngfw mode.
                        choices:
                            - 'profile-based'
                            - 'policy-based'
                    ssl_ssh_profile:
                        aliases: ['ssl-ssh-profile']
                        type: str
                        description: Ssl ssh profile.
            scope_member:
                aliases: ['scope member']
                type: list
                elements: dict
                description: Scope member.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            type:
                type: str
                description: Type.
                choices:
                    - 'pkg'
                    - 'folder'
            package_settings:
                aliases: ['package settings']
                type: dict
                description: Package settings.
                suboptions:
                    central_nat:
                        aliases: ['central-nat']
                        type: str
                        description:
                            - disable -
                            - enable -
                        choices:
                            - 'disable'
                            - 'enable'
                    consolidated_firewall_mode:
                        aliases: ['consolidated-firewall-mode']
                        type: str
                        description:
                            - For flow-based policy package.
                            - disable -
                            - enable -
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy_implicit_log:
                        aliases: ['fwpolicy-implicit-log']
                        type: str
                        description:
                            - disable -
                            - enable -
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy6_implicit_log:
                        aliases: ['fwpolicy6-implicit-log']
                        type: str
                        description:
                            - disable -
                            - enable -
                        choices:
                            - 'disable'
                            - 'enable'
                    inspection_mode:
                        aliases: ['inspection-mode']
                        type: str
                        description:
                            - proxy -
                            - flow -
                        choices:
                            - 'proxy'
                            - 'flow'
                    ngfw_mode:
                        aliases: ['ngfw-mode']
                        type: str
                        description:
                            - For flow-based policy package.
                            - profile-based -
                            - policy-based -
                        choices:
                            - 'profile-based'
                            - 'policy-based'
                    policy_offload_level:
                        aliases: ['policy-offload-level']
                        type: str
                        description:
                            - disable -
                            - default -
                            - dos-offload -
                            - full-offload -
                        choices:
                            - 'disable'
                            - 'default'
                            - 'dos-offload'
                            - 'full-offload'
                    ssl_ssh_profile:
                        aliases: ['ssl-ssh-profile']
                        type: str
                        description: SSL-SSH profile required for NGFW-mode policy package.
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
    - name: Policy package or folder.
      fortinet.fortimanager.fmgr_pm_pkg:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        pkg_path: <your own value>
        state: present # <value in [present, absent]>
        pm_pkg:
          name: "your value" # Required variable, string
          # obj_ver: <integer>
          # oid: <integer>
          # package_setting:
          #   central_nat: <value in [disable, enable]>
          #   consolidated_firewall_mode: <value in [disable, enable]>
          #   fwpolicy_implicit_log: <value in [disable, enable]>
          #   fwpolicy6_implicit_log: <value in [disable, enable]>
          #   inspection_mode: <value in [proxy, flow]>
          #   ngfw_mode: <value in [profile-based, policy-based]>
          #   ssl_ssh_profile: <string>
          # scope_member:
          #   - name: <string>
          #     vdom: <string>
          # type: <value in [pkg, folder]>
          # package_settings:
          #   central_nat: <value in [disable, enable]>
          #   consolidated_firewall_mode: <value in [disable, enable]>
          #   fwpolicy_implicit_log: <value in [disable, enable]>
          #   fwpolicy6_implicit_log: <value in [disable, enable]>
          #   inspection_mode: <value in [proxy, flow]>
          #   ngfw_mode: <value in [profile-based, policy-based]>
          #   policy_offload_level: <value in [disable, default, dos-offload, ...]>
          #   ssl_ssh_profile: <string>
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
        '/pm/pkg/adom/{adom}/{pkg_path}',
        '/pm/pkg/global/{pkg_path}'
    ]
    url_params = ['adom', 'pkg_path']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg_path': {'required': True, 'type': 'str'},
        'pm_pkg': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'name': {'required': True, 'type': 'str'},
                'obj ver': {'type': 'int'},
                'oid': {'type': 'int'},
                'package setting': {
                    'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']],
                    'type': 'dict',
                    'options': {
                        'central-nat': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'consolidated-firewall-mode': {
                            'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'fwpolicy-implicit-log': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy6-implicit-log': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspection-mode': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                        'ngfw-mode': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['profile-based', 'policy-based'], 'type': 'str'},
                        'ssl-ssh-profile': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'type': 'str'}
                    }
                },
                'scope member': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'type': {'choices': ['pkg', 'folder'], 'type': 'str'},
                'package settings': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'central-nat': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'consolidated-firewall-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy-implicit-log': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy6-implicit-log': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspection-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                        'ngfw-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['profile-based', 'policy-based'], 'type': 'str'},
                        'policy-offload-level': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'choices': ['disable', 'default', 'dos-offload', 'full-offload'],
                            'type': 'str'
                        },
                        'ssl-ssh-profile': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pm_pkg'),
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
