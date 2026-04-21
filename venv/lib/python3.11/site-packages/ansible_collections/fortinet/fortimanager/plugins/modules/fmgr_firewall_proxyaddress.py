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
module: fmgr_firewall_proxyaddress
short_description: Web proxy address configuration.
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
    firewall_proxyaddress:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            case_sensitivity:
                aliases: ['case-sensitivity']
                type: str
                description: Enable to make the pattern case sensitive.
                choices:
                    - 'disable'
                    - 'enable'
            category:
                type: raw
                description: (list or str) FortiGuard category ID.
            color:
                type: int
                description: Integer value to determine the color of the icon in the GUI
            comment:
                type: str
                description: Optional comments.
            header:
                type: str
                description: HTTP header name as a regular expression.
            header_group:
                aliases: ['header-group']
                type: list
                elements: dict
                description: Header group.
                suboptions:
                    case_sensitivity:
                        aliases: ['case-sensitivity']
                        type: str
                        description: Case sensitivity in pattern.
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: HTTP header regular expression.
                    header_name:
                        aliases: ['header-name']
                        type: str
                        description: HTTP header.
                    id:
                        type: int
                        description: ID.
            header_name:
                aliases: ['header-name']
                type: str
                description: Name of HTTP header.
            host:
                type: str
                description: Address object for the host.
            host_regex:
                aliases: ['host-regex']
                type: str
                description: Host name as a regular expression.
            method:
                type: list
                elements: str
                description: HTTP request methods to be used.
                choices:
                    - 'delete'
                    - 'get'
                    - 'head'
                    - 'options'
                    - 'post'
                    - 'put'
                    - 'trace'
                    - 'connect'
                    - 'other'
                    - 'patch'
                    - 'update'
            name:
                type: str
                description: Address name.
                required: true
            path:
                type: str
                description: URL path as a regular expression.
            query:
                type: str
                description: Match the query part of the URL as a regular expression.
            referrer:
                type: str
                description: Enable/disable use of referrer field in the HTTP header to match the address.
                choices:
                    - 'disable'
                    - 'enable'
            tagging:
                type: list
                elements: dict
                description: Tagging.
                suboptions:
                    category:
                        type: str
                        description: Tag category.
                    name:
                        type: str
                        description: Tagging entry name.
                    tags:
                        type: raw
                        description: (list) Tags.
            type:
                type: str
                description: Proxy address type.
                choices:
                    - 'host-regex'
                    - 'url'
                    - 'category'
                    - 'method'
                    - 'ua'
                    - 'header'
                    - 'src-advanced'
                    - 'dst-advanced'
                    - 'url-list'
                    - 'saas'
            ua:
                type: list
                elements: str
                description: Names of browsers to be used as user agent.
                choices:
                    - 'chrome'
                    - 'ms'
                    - 'firefox'
                    - 'safari'
                    - 'other'
                    - 'ie'
                    - 'edge'
            uuid:
                type: str
                description: Universally Unique Identifier
            visibility:
                type: str
                description: Enable/disable visibility of the object in the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: Names of object-tags
            _image_base64:
                aliases: ['_image-base64']
                type: str
                description: Image base64.
            application:
                type: raw
                description: (list) SaaS application.
            ua_max_ver:
                aliases: ['ua-max-ver']
                type: str
                description: Maximum version of the user agent specified in dotted notation.
            ua_min_ver:
                aliases: ['ua-min-ver']
                type: str
                description: Minimum version of the user agent specified in dotted notation.
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
    - name: Web proxy address configuration.
      fortinet.fortimanager.fmgr_firewall_proxyaddress:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_proxyaddress:
          case_sensitivity: disable
          color: 1
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
    - name: Retrieve all the proxy addresses
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_proxyaddress"
          params:
            adom: "ansible"
            proxy_address: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/proxy-address',
        '/pm/config/global/obj/firewall/proxy-address'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_proxyaddress': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'case-sensitivity': {'choices': ['disable', 'enable'], 'type': 'str'},
                'category': {'type': 'raw'},
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'header': {'type': 'str'},
                'header-group': {
                    'type': 'list',
                    'options': {
                        'case-sensitivity': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'type': 'str'},
                        'header-name': {'type': 'str'},
                        'id': {'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'header-name': {'type': 'str'},
                'host': {'type': 'str'},
                'host-regex': {'type': 'str'},
                'method': {
                    'type': 'list',
                    'choices': ['delete', 'get', 'head', 'options', 'post', 'put', 'trace', 'connect', 'other', 'patch', 'update'],
                    'elements': 'str'
                },
                'name': {'required': True, 'type': 'str'},
                'path': {'type': 'str'},
                'query': {'type': 'str'},
                'referrer': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tagging': {
                    'type': 'list',
                    'options': {'category': {'type': 'str'}, 'name': {'type': 'str'}, 'tags': {'type': 'raw'}},
                    'elements': 'dict'
                },
                'type': {
                    'choices': ['host-regex', 'url', 'category', 'method', 'ua', 'header', 'src-advanced', 'dst-advanced', 'url-list', 'saas'],
                    'type': 'str'
                },
                'ua': {'type': 'list', 'choices': ['chrome', 'ms', 'firefox', 'safari', 'other', 'ie', 'edge'], 'elements': 'str'},
                'uuid': {'type': 'str'},
                'visibility': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.2.0', '6.4.15']], 'type': 'str'},
                '_image-base64': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'application': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'ua-max-ver': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'ua-min-ver': {'v_range': [['7.2.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_proxyaddress'),
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
