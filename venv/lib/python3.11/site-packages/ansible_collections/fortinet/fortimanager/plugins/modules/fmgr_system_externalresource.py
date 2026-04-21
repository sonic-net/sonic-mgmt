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
module: fmgr_system_externalresource
short_description: Configure external resource.
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
    system_externalresource:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            category:
                type: int
                description: User resource category.
            comments:
                type: str
                description: Comment.
            name:
                type: str
                description: External resource name.
                required: true
            refresh_rate:
                aliases: ['refresh-rate']
                type: int
                description: Time interval to refresh external resource
            resource:
                type: str
                description: URI of external resource.
            status:
                type: str
                description: Enable/disable user resource.
                choices:
                    - 'disable'
                    - 'enable'
            type:
                type: str
                description: User resource type.
                choices:
                    - 'category'
                    - 'address'
                    - 'domain'
                    - 'malware'
                    - 'url'
                    - 'mac-address'
                    - 'data'
                    - 'generic-address'
            password:
                type: raw
                description: (list) HTTP basic authentication password.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IPv4 address used to communicate with server.
            username:
                type: str
                description: HTTP basic authentication user name.
            interface:
                type: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            user_agent:
                aliases: ['user-agent']
                type: str
                description: Override HTTP User-Agent header used when retrieving this external resource.
            uuid:
                type: str
                description: Universally Unique Identifier
            server_identity_check:
                aliases: ['server-identity-check']
                type: str
                description: Certificate verification option.
                choices:
                    - 'none'
                    - 'basic'
                    - 'full'
            update_method:
                aliases: ['update-method']
                type: str
                description: External resource update method.
                choices:
                    - 'feed'
                    - 'push'
            address_comment_field:
                aliases: ['address-comment-field']
                type: str
                description: JSON Path to address description in generic address entry.
            address_data_field:
                aliases: ['address-data-field']
                type: str
                description: JSON Path to address data in generic address entry.
            address_name_field:
                aliases: ['address-name-field']
                type: str
                description: JSON Path to address name in generic address entry.
            client_cert:
                aliases: ['client-cert']
                type: raw
                description: (list) Client certificate name.
            client_cert_auth:
                aliases: ['client-cert-auth']
                type: str
                description: Enable/disable using client certificate for TLS authentication.
                choices:
                    - 'disable'
                    - 'enable'
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
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description: Source ip.
            namespace:
                type: str
                description: Generic external connector address namespace.
            object_array_path:
                aliases: ['object-array-path']
                type: str
                description: JSON Path to array of generic addresses in resource.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
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
    - name: Configure external resource.
      fortinet.fortimanager.fmgr_system_externalresource:
        bypass_validation: false
        adom: ansible
        state: present
        system_externalresource:
          category: 0
          comments: string
          name: string
          refresh_rate: 1
          resource: string
          status: disable
          type: category # <value in [category, address, domain, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the external resources
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_externalresource"
          params:
            adom: "ansible"
            external_resource: "your_value"
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
        '/pm/config/adom/{adom}/obj/system/external-resource',
        '/pm/config/global/obj/system/external-resource'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_externalresource': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'category': {'type': 'int'},
                'comments': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'refresh-rate': {'type': 'int'},
                'resource': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'choices': ['category', 'address', 'domain', 'malware', 'url', 'mac-address', 'data', 'generic-address'], 'type': 'str'},
                'password': {'v_range': [['6.2.0', '']], 'no_log': True, 'type': 'raw'},
                'source-ip': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'username': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'interface': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'interface-select-method': {'v_range': [['6.4.2', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'user-agent': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'uuid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'server-identity-check': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'choices': ['none', 'basic', 'full'], 'type': 'str'},
                'update-method': {'v_range': [['7.2.1', '']], 'choices': ['feed', 'push'], 'type': 'str'},
                'address-comment-field': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'address-data-field': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'address-name-field': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'client-cert': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'client-cert-auth': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'options': {'name': {'v_range': [['7.6.2', '']], 'type': 'str'}, 'vdom': {'v_range': [['7.6.2', '']], 'type': 'str'}},
                            'elements': 'dict'
                        },
                        'source-ip': {'v_range': [['7.6.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'namespace': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'object-array-path': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_externalresource'),
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
