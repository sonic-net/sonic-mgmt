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
module: fmgr_pkg_firewall_centralsnatmap
short_description: Configure central SNAT policies.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_centralsnatmap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dst_addr:
                aliases: ['dst-addr']
                type: raw
                description: (list or str) Destination address name from available addresses.
            dstintf:
                type: raw
                description: (list or str) Destination interface name from available interfaces.
            nat:
                type: str
                description: Enable/disable source NAT.
                choices:
                    - 'disable'
                    - 'enable'
            nat_ippool:
                aliases: ['nat-ippool']
                type: raw
                description: (list or str) Name of the IP pools to be used to translate addresses from available IP Pools.
            nat_port:
                aliases: ['nat-port']
                type: str
                description: Translated port or port range
            orig_addr:
                aliases: ['orig-addr']
                type: raw
                description: (list or str) Original address.
            orig_port:
                aliases: ['orig-port']
                type: raw
                description: (int or str) Original TCP port
            policyid:
                type: int
                description: Policy ID.
                required: true
            protocol:
                type: int
                description: Integer value for the protocol type
            srcintf:
                type: raw
                description: (list or str) Source interface name from available interfaces.
            status:
                type: str
                description: Enable/disable the active status of this policy.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: Comment.
            dst_addr6:
                aliases: ['dst-addr6']
                type: raw
                description: (list or str) IPv6 Destination address.
            nat_ippool6:
                aliases: ['nat-ippool6']
                type: raw
                description: (list or str) IPv6 pools to be used for source NAT.
            orig_addr6:
                aliases: ['orig-addr6']
                type: raw
                description: (list or str) IPv6 Original address.
            type:
                type: str
                description: IPv4/IPv6 source NAT.
                choices:
                    - 'ipv4'
                    - 'ipv6'
            uuid:
                type: str
                description: Universally Unique Identifier
            nat46:
                type: str
                description: Enable/disable NAT46.
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            dst_port:
                aliases: ['dst-port']
                type: str
                description: Destination port or port range
            port_preserve:
                aliases: ['port-preserve']
                type: str
                description: Enable/disable preservation of the original source port from source NAT if it has not been used.
                choices:
                    - 'disable'
                    - 'enable'
            port_random:
                aliases: ['port-random']
                type: str
                description: Enable/disable random source port selection for source NAT.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure central SNAT policies.
      fortinet.fortimanager.fmgr_pkg_firewall_centralsnatmap:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_centralsnatmap:
          dst_addr: "ansible-test1"
          nat: enable
          orig_addr: "ansible-test1"
          policyid: 2
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the central SNAT policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_centralsnatmap"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            central_snat_map: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_centralsnatmap': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'dst-addr': {'type': 'raw'},
                'dstintf': {'type': 'raw'},
                'nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'nat-ippool': {'type': 'raw'},
                'nat-port': {'type': 'str'},
                'orig-addr': {'type': 'raw'},
                'orig-port': {'type': 'raw'},
                'policyid': {'required': True, 'type': 'int'},
                'protocol': {'type': 'int'},
                'srcintf': {'type': 'raw'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'dst-addr6': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'nat-ippool6': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'orig-addr6': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'type': {'v_range': [['6.4.0', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'uuid': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'nat46': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dst-port': {'v_range': [['7.2.6', '']], 'type': 'str'},
                'port-preserve': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port-random': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_centralsnatmap'),
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
