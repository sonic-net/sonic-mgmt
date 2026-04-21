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
module: fmgr_firewall_internetservicecustom
short_description: Configure custom Internet Services.
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
    firewall_internetservicecustom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            disable_entry:
                aliases: ['disable-entry']
                type: list
                elements: dict
                description: Disable entry.
                suboptions:
                    id:
                        type: int
                        description: Disable entry ID.
                    ip_range:
                        aliases: ['ip-range']
                        type: list
                        elements: dict
                        description: Ip range.
                        suboptions:
                            end_ip:
                                aliases: ['end-ip']
                                type: str
                                description: End IP address.
                            id:
                                type: int
                                description: Disable entry range ID.
                            start_ip:
                                aliases: ['start-ip']
                                type: str
                                description: Start IP address.
                    port:
                        type: raw
                        description: (list) Integer value for the TCP/IP port
                    protocol:
                        type: int
                        description: Integer value for the protocol type as defined by IANA
            entry:
                type: list
                elements: dict
                description: Entry.
                suboptions:
                    dst:
                        type: raw
                        description: (list or str) Destination address or address group name.
                    id:
                        type: int
                        description: Entry ID
                    port_range:
                        aliases: ['port-range']
                        type: list
                        elements: dict
                        description: Port range.
                        suboptions:
                            end_port:
                                aliases: ['end-port']
                                type: int
                                description: Integer value for ending TCP/UDP/SCTP destination port in range
                            id:
                                type: int
                                description: Custom entry port range ID.
                            start_port:
                                aliases: ['start-port']
                                type: int
                                description: Integer value for starting TCP/UDP/SCTP destination port in range
                    protocol:
                        type: int
                        description: Integer value for the protocol type as defined by IANA
                    addr_mode:
                        aliases: ['addr-mode']
                        type: str
                        description: Address mode
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    dst6:
                        type: raw
                        description: (list) Destination address6 or address6 group name.
            master_service_id:
                aliases: ['master-service-id']
                type: str
                description: Internet Service ID in the Internet Service database.
            name:
                type: str
                description: Internet Service name.
                required: true
            reputation:
                type: int
                description: Reputation level of the custom Internet Service.
            id:
                type: int
                description: Internet Service ID.
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
    - name: Configure custom Internet Services via Generic Module.
      fortinet.fortimanager.fmgr_generic:
        method: "set"
        params:
          - url: "/pm/config/adom/ansible/obj/firewall/internet-service-custom"
            data:
              - name: "ansible-test"
                comment: "ansible-comment"
    - name: Configure custom Internet Services.
      when: false
      fortinet.fortimanager.fmgr_firewall_internetservicecustom:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_internetservicecustom:
          comment: "ansible-comment"
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the custom Internet Services
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_internetservicecustom"
          params:
            adom: "ansible"
            internet_service_custom: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/internet-service-custom',
        '/pm/config/global/obj/firewall/internet-service-custom'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_internetservicecustom': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'disable-entry': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        'ip-range': {
                            'v_range': [['6.0.0', '7.2.1']],
                            'type': 'list',
                            'options': {
                                'end-ip': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                                'id': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                                'start-ip': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'port': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
                        'protocol': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'entry': {
                    'type': 'list',
                    'options': {
                        'dst': {'type': 'raw'},
                        'id': {'type': 'int'},
                        'port-range': {
                            'type': 'list',
                            'options': {'end-port': {'type': 'int'}, 'id': {'type': 'int'}, 'start-port': {'type': 'int'}},
                            'elements': 'dict'
                        },
                        'protocol': {'type': 'int'},
                        'addr-mode': {'v_range': [['7.2.1', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'dst6': {'v_range': [['7.2.1', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'master-service-id': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'reputation': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'id': {'v_range': [['6.4.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetservicecustom'),
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
