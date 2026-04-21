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
module: fmgr_dynamic_interface
short_description: Dynamic interface
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
    dynamic_interface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            color:
                type: int
                description: Color.
            default_mapping:
                aliases: ['default-mapping']
                type: str
                description: Default mapping.
                choices:
                    - 'disable'
                    - 'enable'
            defmap_intf:
                aliases: ['defmap-intf']
                type: str
                description: Defmap intf.
            defmap_intrazone_deny:
                aliases: ['defmap-intrazone-deny']
                type: str
                description: Defmap intrazone deny.
                choices:
                    - 'disable'
                    - 'enable'
            defmap_zonemember:
                aliases: ['defmap-zonemember']
                type: raw
                description: (list) Defmap zonemember.
            description:
                type: str
                description: Description.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    egress_shaping_profile:
                        aliases: ['egress-shaping-profile']
                        type: raw
                        description: (list or str) Egress shaping profile.
                    intrazone_deny:
                        aliases: ['intrazone-deny']
                        type: str
                        description: Intrazone deny.
                        choices:
                            - 'disable'
                            - 'enable'
                    local_intf:
                        aliases: ['local-intf']
                        type: raw
                        description: (list) Local intf.
                    ingress_shaping_profile:
                        aliases: ['ingress-shaping-profile']
                        type: raw
                        description: (list or str) Ingress shaping profile.
            egress_shaping_profile:
                aliases: ['egress-shaping-profile']
                type: raw
                description: (list or str) Egress shaping profile.
            name:
                type: str
                description: Name.
                required: true
            single_intf:
                aliases: ['single-intf']
                type: str
                description: Single intf.
                choices:
                    - 'disable'
                    - 'enable'
            ingress_shaping_profile:
                aliases: ['ingress-shaping-profile']
                type: raw
                description: (list or str) Ingress shaping profile.
            platform_mapping:
                type: list
                elements: dict
                description: Platform mapping.
                suboptions:
                    egress_shaping_profile:
                        aliases: ['egress-shaping-profile']
                        type: raw
                        description: (list or str) Egress shaping profile.
                    ingress_shaping_profile:
                        aliases: ['ingress-shaping-profile']
                        type: raw
                        description: (list or str) Ingress shaping profile.
                    intf_zone:
                        aliases: ['intf-zone']
                        type: str
                        description: Intf zone.
                    intrazone_deny:
                        aliases: ['intrazone-deny']
                        type: str
                        description: Intrazone deny.
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: Name.
            wildcard:
                type: str
                description: Wildcard.
                choices:
                    - 'disable'
                    - 'enable'
            wildcard_intf:
                aliases: ['wildcard-intf']
                type: str
                description: Wildcard intf.
            zone_only:
                aliases: ['zone-only']
                type: str
                description: Zone only.
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
    - name: Dynamic interface
      fortinet.fortimanager.fmgr_dynamic_interface:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        dynamic_interface:
          name: "your value" # Required variable, string
          # color: <integer>
          # default_mapping: <value in [disable, enable]>
          # defmap_intf: <string>
          # defmap_intrazone_deny: <value in [disable, enable]>
          # defmap_zonemember: <list or string>
          # description: <string>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     egress_shaping_profile: <list or string>
          #     intrazone_deny: <value in [disable, enable]>
          #     local_intf: <list or string>
          #     ingress_shaping_profile: <list or string>
          # egress_shaping_profile: <list or string>
          # single_intf: <value in [disable, enable]>
          # ingress_shaping_profile: <list or string>
          # platform_mapping:
          #   - egress_shaping_profile: <list or string>
          #     ingress_shaping_profile: <list or string>
          #     intf_zone: <string>
          #     intrazone_deny: <value in [disable, enable]>
          #     name: <string>
          # wildcard: <value in [disable, enable]>
          # wildcard_intf: <string>
          # zone_only: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/dynamic/interface',
        '/pm/config/global/obj/dynamic/interface'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dynamic_interface': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'color': {'type': 'int'},
                'default-mapping': {'choices': ['disable', 'enable'], 'type': 'str'},
                'defmap-intf': {'type': 'str'},
                'defmap-intrazone-deny': {'choices': ['disable', 'enable'], 'type': 'str'},
                'defmap-zonemember': {'type': 'raw'},
                'description': {'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'egress-shaping-profile': {'type': 'raw'},
                        'intrazone-deny': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-intf': {'type': 'raw'},
                        'ingress-shaping-profile': {'v_range': [['6.2.2', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'egress-shaping-profile': {'type': 'raw'},
                'name': {'required': True, 'type': 'str'},
                'single-intf': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ingress-shaping-profile': {'v_range': [['6.2.2', '']], 'type': 'raw'},
                'platform_mapping': {
                    'v_range': [['6.4.1', '']],
                    'type': 'list',
                    'options': {
                        'egress-shaping-profile': {'v_range': [['6.4.1', '']], 'type': 'raw'},
                        'ingress-shaping-profile': {'v_range': [['6.4.1', '']], 'type': 'raw'},
                        'intf-zone': {'v_range': [['6.4.1', '']], 'type': 'str'},
                        'intrazone-deny': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'v_range': [['6.4.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'wildcard': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wildcard-intf': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'zone-only': {'v_range': [['6.4.7', '6.4.15'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dynamic_interface'),
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
