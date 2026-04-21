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
module: fmgr_pkg_firewall_dospolicy6
short_description: Configure IPv6 DoS policies.
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
    pkg_firewall_dospolicy6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            anomaly:
                type: list
                elements: dict
                description: Anomaly.
                suboptions:
                    action:
                        type: str
                        description: Action taken when the threshold is reached.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'proxy'
                    log:
                        type: str
                        description: Enable/disable logging for this anomaly.
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: Anomaly name.
                    quarantine:
                        type: str
                        description: Quarantine method.
                        choices:
                            - 'none'
                            - 'attacker'
                            - 'both'
                            - 'interface'
                    quarantine_expiry:
                        aliases: ['quarantine-expiry']
                        type: str
                        description: Duration of quarantine, from 1 minute to 364 days, 23 hours, and 59 minutes from now.
                    quarantine_log:
                        aliases: ['quarantine-log']
                        type: str
                        description: Enable/disable quarantine logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable the active status of this anomaly sensor.
                        choices:
                            - 'disable'
                            - 'enable'
                    threshold:
                        type: int
                        description: Number of detected instances per minute which triggers action
                    threshold_default:
                        aliases: ['threshold(default)']
                        type: int
                        description: Threshold
                    synproxy_tos:
                        type: str
                        description: Determine TCP differentiated services code point value
                        choices:
                            - '0'
                            - '10'
                            - '12'
                            - '14'
                            - '18'
                            - '20'
                            - '22'
                            - '26'
                            - '28'
                            - '30'
                            - '34'
                            - '36'
                            - '38'
                            - '40'
                            - '46'
                            - '255'
                    synproxy_ttl:
                        type: str
                        description: Determine Time to live
                        choices:
                            - '32'
                            - '64'
                            - '128'
                            - '255'
                    synproxy_tcp_sack:
                        type: str
                        description: Enable/disable TCP selective acknowledage
                        choices:
                            - 'disable'
                            - 'enable'
                    synproxy_tcp_window:
                        type: str
                        description: Determine TCP Window size for packets replied by syn proxy module.
                        choices:
                            - '4096'
                            - '8192'
                            - '16384'
                            - '32768'
                    synproxy_tcp_timestamp:
                        type: str
                        description: Enable/disable TCP timestamp option for packets replied by syn proxy module.
                        choices:
                            - 'disable'
                            - 'enable'
                    synproxy_tcp_mss:
                        type: str
                        description: Determine TCP maximum segment size
                        choices:
                            - '0'
                            - '256'
                            - '512'
                            - '1024'
                            - '1300'
                            - '1360'
                            - '1460'
                            - '1500'
                    synproxy_tcp_windowscale:
                        type: str
                        description: Determine TCP window scale option value for packets replied by syn proxy module.
                        choices:
                            - '0'
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '6'
                            - '7'
                            - '8'
                            - '9'
                            - '10'
                            - '11'
                            - '12'
                            - '13'
                            - '14'
                    synproxy-tos:
                        type: str
                        description: Deprecated, please rename it to synproxy_tos. Determine TCP differentiated services code point value
                        choices:
                            - '0'
                            - '10'
                            - '12'
                            - '14'
                            - '18'
                            - '20'
                            - '22'
                            - '26'
                            - '28'
                            - '30'
                            - '34'
                            - '36'
                            - '38'
                            - '40'
                            - '46'
                            - '255'
                    synproxy-tcp-window:
                        type: str
                        description: Deprecated, please rename it to synproxy_tcp_window. Determine TCP Window size for packets replied by syn proxy mo...
                        choices:
                            - '4096'
                            - '8192'
                            - '16384'
                            - '32768'
                    synproxy-tcp-windowscale:
                        type: str
                        description: Deprecated, please rename it to synproxy_tcp_windowscale. Determine TCP window scale option value for packets repl...
                        choices:
                            - '0'
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '6'
                            - '7'
                            - '8'
                            - '9'
                            - '10'
                            - '11'
                            - '12'
                            - '13'
                            - '14'
                    synproxy-tcp-timestamp:
                        type: str
                        description: Deprecated, please rename it to synproxy_tcp_timestamp. Enable/disable TCP timestamp option for packets replied by...
                        choices:
                            - 'disable'
                            - 'enable'
                    synproxy-ttl:
                        type: str
                        description: Deprecated, please rename it to synproxy_ttl. Determine Time to live
                        choices:
                            - '32'
                            - '64'
                            - '128'
                            - '255'
                    synproxy-tcp-mss:
                        type: str
                        description: Deprecated, please rename it to synproxy_tcp_mss. Determine TCP maximum segment size
                        choices:
                            - '0'
                            - '256'
                            - '512'
                            - '1024'
                            - '1300'
                            - '1360'
                            - '1460'
                            - '1500'
                    synproxy-tcp-sack:
                        type: str
                        description: Deprecated, please rename it to synproxy_tcp_sack. Enable/disable TCP selective acknowledage
                        choices:
                            - 'disable'
                            - 'enable'
            comments:
                type: str
                description: Comment.
            dstaddr:
                type: raw
                description: (list or str) Destination address name from available addresses.
            interface:
                type: str
                description: Incoming interface name from available interfaces.
            policyid:
                type: int
                description: Policy ID.
                required: true
            service:
                type: raw
                description: (list or str) Service object from available options.
            srcaddr:
                type: raw
                description: (list or str) Source address name from available addresses.
            status:
                type: str
                description: Enable/disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            name:
                type: str
                description: Policy name.
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
    - name: Configure IPv6 DoS policies.
      fortinet.fortimanager.fmgr_pkg_firewall_dospolicy6:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_dospolicy6:
          comments: "ansible-comment"
          interface: "sslvpn_tun_intf"
          policyid: 1
          status: enable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv6 DoS policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_dospolicy6"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            DoS_policy6: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_dospolicy6': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'anomaly': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['pass', 'block', 'proxy'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'type': 'str'},
                        'quarantine': {'choices': ['none', 'attacker', 'both', 'interface'], 'type': 'str'},
                        'quarantine-expiry': {'type': 'str'},
                        'quarantine-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'threshold': {'type': 'int'},
                        'threshold(default)': {'type': 'int'},
                        'synproxy_tos': {
                            'v_range': [['6.2.5', '7.2.0']],
                            'choices': ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36', '38', '40', '46', '255'],
                            'type': 'str'
                        },
                        'synproxy_ttl': {'v_range': [['6.2.5', '7.2.0']], 'choices': ['32', '64', '128', '255'], 'type': 'str'},
                        'synproxy_tcp_sack': {'v_range': [['6.2.5', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'synproxy_tcp_window': {'v_range': [['6.2.5', '7.2.0']], 'choices': ['4096', '8192', '16384', '32768'], 'type': 'str'},
                        'synproxy_tcp_timestamp': {'v_range': [['6.2.5', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'synproxy_tcp_mss': {
                            'v_range': [['6.2.5', '7.2.0']],
                            'choices': ['0', '256', '512', '1024', '1300', '1360', '1460', '1500'],
                            'type': 'str'
                        },
                        'synproxy_tcp_windowscale': {
                            'v_range': [['6.2.5', '7.2.0']],
                            'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'],
                            'type': 'str'
                        },
                        'synproxy-tos': {
                            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36', '38', '40', '46', '255'],
                            'type': 'str'
                        },
                        'synproxy-tcp-window': {
                            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['4096', '8192', '16384', '32768'],
                            'type': 'str'
                        },
                        'synproxy-tcp-windowscale': {
                            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'],
                            'type': 'str'
                        },
                        'synproxy-tcp-timestamp': {
                            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'synproxy-ttl': {
                            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['32', '64', '128', '255'],
                            'type': 'str'
                        },
                        'synproxy-tcp-mss': {
                            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['0', '256', '512', '1024', '1300', '1360', '1460', '1500'],
                            'type': 'str'
                        },
                        'synproxy-tcp-sack': {
                            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'comments': {'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'interface': {'type': 'str'},
                'policyid': {'required': True, 'type': 'int'},
                'service': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['6.2.1', '7.2.0']], 'type': 'str'},
                'name': {'v_range': [['6.4.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_dospolicy6'),
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
