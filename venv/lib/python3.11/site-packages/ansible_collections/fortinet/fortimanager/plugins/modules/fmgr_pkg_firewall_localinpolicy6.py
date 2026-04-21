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
module: fmgr_pkg_firewall_localinpolicy6
short_description: Configure user defined IPv6 local-in policies.
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
    pkg_firewall_localinpolicy6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action performed on traffic matching the policy
                choices:
                    - 'deny'
                    - 'accept'
            dstaddr:
                type: raw
                description: (list or str) Destination address object from available options.
            intf:
                type: raw
                description: Incoming interface name from available options.
            policyid:
                type: int
                description: User defined local in policy ID.
                required: true
            schedule:
                type: str
                description: Schedule object from available options.
            service:
                type: raw
                description: (list or str) Service object from available options.
            srcaddr:
                type: raw
                description: (list or str) Source address object from available options.
            status:
                type: str
                description: Enable/disable this local-in policy.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: Comment.
            uuid:
                type: str
                description: Universally Unique Identifier
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled dstaddr specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            service_negate:
                aliases: ['service-negate']
                type: str
                description: When enabled service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled srcaddr specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            virtual_patch:
                aliases: ['virtual-patch']
                type: str
                description: Enable/disable the virtual patching feature.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src:
                aliases: ['internet-service6-src']
                type: str
                description: Enable/disable use of IPv6 Internet Services in source for this local-in policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src_custom:
                aliases: ['internet-service6-src-custom']
                type: raw
                description: (list) Custom IPv6 Internet Service source name.
            internet_service6_src_custom_group:
                aliases: ['internet-service6-src-custom-group']
                type: raw
                description: (list) Custom Internet Service6 source group name.
            internet_service6_src_group:
                aliases: ['internet-service6-src-group']
                type: raw
                description: (list) Internet Service6 source group name.
            internet_service6_src_name:
                aliases: ['internet-service6-src-name']
                type: raw
                description: (list) IPv6 Internet Service source name.
            internet_service6_src_negate:
                aliases: ['internet-service6-src-negate']
                type: str
                description: When enabled internet-service6-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: Enable/disable local-in traffic logging.
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
    - name: Configure user defined IPv6 local-in policies.
      fortinet.fortimanager.fmgr_pkg_firewall_localinpolicy6:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_localinpolicy6:
          action: deny # <value in [deny, accept]>
          dstaddr: all
          intf: any
          policyid: 1
          schedule: always
          service: ALL
          srcaddr: all
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
    - name: Retrieve all the user defined IPv6 local-in policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_localinpolicy6"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            local_in_policy6: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_localinpolicy6': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'accept'], 'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'intf': {'type': 'raw'},
                'policyid': {'required': True, 'type': 'int'},
                'schedule': {'type': 'str'},
                'service': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'uuid': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dstaddr-negate': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'service-negate': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr-negate': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-patch': {'v_range': [['7.2.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src-custom': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'internet-service6-src-custom-group': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'internet-service6-src-group': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'internet-service6-src-name': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'internet-service6-src-negate': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_localinpolicy6'),
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
