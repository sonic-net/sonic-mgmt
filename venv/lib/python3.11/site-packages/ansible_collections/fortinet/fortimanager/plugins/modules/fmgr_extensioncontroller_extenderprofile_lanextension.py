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
module: fmgr_extensioncontroller_extenderprofile_lanextension
short_description: FortiExtender lan extension configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    extender-profile:
        description: Deprecated, please use "extender_profile"
        type: str
    extender_profile:
        description: The parameter (extender-profile) in requested url.
        type: str
    extensioncontroller_extenderprofile_lanextension:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            backhaul:
                type: list
                elements: dict
                description: Backhaul.
                suboptions:
                    name:
                        type: str
                        description: FortiExtender LAN extension backhaul name.
                    port:
                        type: str
                        description: FortiExtender uplink port.
                        choices:
                            - 'wan'
                            - 'lte1'
                            - 'lte2'
                            - 'port1'
                            - 'port2'
                            - 'port3'
                            - 'port4'
                            - 'port5'
                            - 'sfp'
                    role:
                        type: str
                        description: FortiExtender uplink port.
                        choices:
                            - 'primary'
                            - 'secondary'
                    weight:
                        type: int
                        description: WRR weight parameter.
            backhaul_interface:
                aliases: ['backhaul-interface']
                type: str
                description: IPsec phase1 interface.
            backhaul_ip:
                aliases: ['backhaul-ip']
                type: str
                description: IPsec phase1 IPv4/FQDN.
            ipsec_tunnel:
                aliases: ['ipsec-tunnel']
                type: str
                description: IPsec tunnel name.
            link_loadbalance:
                aliases: ['link-loadbalance']
                type: str
                description: LAN extension link load balance strategy.
                choices:
                    - 'activebackup'
                    - 'loadbalance'
            downlinks:
                type: list
                elements: dict
                description: Downlinks.
                suboptions:
                    name:
                        type: str
                        description: FortiExtender LAN extension downlink config entry name.
                    port:
                        type: str
                        description: FortiExtender LAN extension downlink port.
                        choices:
                            - 'port1'
                            - 'port2'
                            - 'port3'
                            - 'port4'
                            - 'port5'
                            - 'lan1'
                            - 'lan2'
                    pvid:
                        type: int
                        description: FortiExtender LAN extension downlink PVID.
                    type:
                        type: str
                        description: FortiExtender LAN extension downlink type [port/vap].
                        choices:
                            - 'port'
                            - 'vap'
                    vap:
                        type: raw
                        description: (list) FortiExtender LAN extension downlink vap.
            traffic_split_services:
                aliases: ['traffic-split-services']
                type: list
                elements: dict
                description: Traffic split services.
                suboptions:
                    address:
                        type: raw
                        description: (list) Address selection.
                    name:
                        type: str
                        description: FortiExtender LAN extension tunnel split entry name.
                    service:
                        type: raw
                        description: (list) Service selection.
                    vsdb:
                        type: str
                        description: Select vsdb [enable/disable].
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
    - name: FortiExtender lan extension configuration.
      fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_lanextension:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        extender_profile: <your own value>
        extensioncontroller_extenderprofile_lanextension:
          # backhaul:
          #   - name: <string>
          #     port: <value in [wan, lte1, lte2, ...]>
          #     role: <value in [primary, secondary]>
          #     weight: <integer>
          # backhaul_interface: <string>
          # backhaul_ip: <string>
          # ipsec_tunnel: <string>
          # link_loadbalance: <value in [activebackup, loadbalance]>
          # downlinks:
          #   - name: <string>
          #     port: <value in [port1, port2, port3, ...]>
          #     pvid: <integer>
          #     type: <value in [port, vap]>
          #     vap: <list or string>
          # traffic_split_services:
          #   - address: <list or string>
          #     name: <string>
          #     service: <list or string>
          #     vsdb: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension'
    ]
    url_params = ['adom', 'extender-profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'extensioncontroller_extenderprofile_lanextension': {
            'type': 'dict',
            'v_range': [['7.2.1', '']],
            'options': {
                'backhaul': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'port': {
                            'v_range': [['7.2.1', '']],
                            'choices': ['wan', 'lte1', 'lte2', 'port1', 'port2', 'port3', 'port4', 'port5', 'sfp'],
                            'type': 'str'
                        },
                        'role': {'v_range': [['7.2.1', '']], 'choices': ['primary', 'secondary'], 'type': 'str'},
                        'weight': {'v_range': [['7.2.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'backhaul-interface': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'backhaul-ip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'ipsec-tunnel': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'link-loadbalance': {'v_range': [['7.2.1', '']], 'choices': ['activebackup', 'loadbalance'], 'type': 'str'},
                'downlinks': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'port': {'v_range': [['7.6.0', '']], 'choices': ['port1', 'port2', 'port3', 'port4', 'port5', 'lan1', 'lan2'], 'type': 'str'},
                        'pvid': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'type': {'v_range': [['7.6.0', '']], 'choices': ['port', 'vap'], 'type': 'str'},
                        'vap': {'v_range': [['7.6.0', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'traffic-split-services': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'address': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                        'name': {'v_range': [['7.6.2', '']], 'type': 'str'},
                        'service': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                        'vsdb': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_lanextension'),
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
