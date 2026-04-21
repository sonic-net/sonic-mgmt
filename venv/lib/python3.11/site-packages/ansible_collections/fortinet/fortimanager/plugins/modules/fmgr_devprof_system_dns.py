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
module: fmgr_devprof_system_dns
short_description: Configure DNS.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_dns:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cache_notfound_responses:
                aliases: ['cache-notfound-responses']
                type: str
                description: Enable/disable response from the DNS server when a record is not in cache.
                choices:
                    - 'disable'
                    - 'enable'
            dns_cache_limit:
                aliases: ['dns-cache-limit']
                type: int
                description: Maximum number of records in the DNS cache.
            dns_cache_ttl:
                aliases: ['dns-cache-ttl']
                type: int
                description: Duration in seconds that the DNS cache retains information.
            domain:
                type: raw
                description: (list or str) Domain name suffix for the IP addresses of the DNS server.
            ip6_primary:
                aliases: ['ip6-primary']
                type: str
                description: Primary DNS server IPv6 address.
            ip6_secondary:
                aliases: ['ip6-secondary']
                type: str
                description: Secondary DNS server IPv6 address.
            primary:
                type: str
                description: Primary DNS server IP address.
            secondary:
                type: str
                description: Secondary DNS server IP address.
            dns_over_tls:
                aliases: ['dns-over-tls']
                type: str
                description: Enable/disable/enforce DNS over TLS.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'enforce'
            retry:
                type: int
                description: Number of times to retry
            server_hostname:
                aliases: ['server-hostname']
                type: raw
                description: (list) DNS server host name list.
            ssl_certificate:
                aliases: ['ssl-certificate']
                type: str
                description: Name of local certificate for SSL connections.
            timeout:
                type: int
                description: DNS query timeout interval in seconds
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
    - name: Configure DNS.
      fortinet.fortimanager.fmgr_devprof_system_dns:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        devprof: <your own value>
        devprof_system_dns:
          # cache_notfound_responses: <value in [disable, enable]>
          # dns_cache_limit: <integer>
          # dns_cache_ttl: <integer>
          # domain: <list or string>
          # ip6_primary: <string>
          # ip6_secondary: <string>
          # primary: <string>
          # secondary: <string>
          # dns_over_tls: <value in [disable, enable, enforce]>
          # retry: <integer>
          # server_hostname: <list or string>
          # ssl_certificate: <string>
          # timeout: <integer>
          # interface: <string>
          # interface_select_method: <value in [auto, sdwan, specify]>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/dns'
    ]
    url_params = ['adom', 'devprof']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_dns': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']],
            'options': {
                'cache-notfound-responses': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dns-cache-limit': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'int'},
                'dns-cache-ttl': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'int'},
                'domain': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'raw'},
                'ip6-primary': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'str'},
                'ip6-secondary': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'str'},
                'primary': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'str'},
                'secondary': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'str'},
                'dns-over-tls': {'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1']], 'choices': ['disable', 'enable', 'enforce'], 'type': 'str'},
                'retry': {'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'int'},
                'server-hostname': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'raw'},
                'ssl-certificate': {'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'str'},
                'timeout': {'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1']], 'type': 'int'},
                'interface': {'v_range': [['6.2.5', '6.2.5'], ['6.2.7', '6.2.13'], ['6.4.1', '6.4.1']], 'type': 'str'},
                'interface-select-method': {
                    'v_range': [['6.2.5', '6.2.5'], ['6.2.7', '6.2.13'], ['6.4.1', '6.4.1']],
                    'choices': ['auto', 'sdwan', 'specify'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_dns'),
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
