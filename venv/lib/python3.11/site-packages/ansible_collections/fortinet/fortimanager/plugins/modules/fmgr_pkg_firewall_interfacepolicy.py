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
module: fmgr_pkg_firewall_interfacepolicy
short_description: Configure IPv4 interface policies.
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
    pkg_firewall_interfacepolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            address_type:
                aliases: ['address-type']
                type: str
                description: Address type.
                choices:
                    - 'ipv4'
                    - 'ipv6'
            application_list:
                aliases: ['application-list']
                type: str
                description: Application list name.
            application_list_status:
                aliases: ['application-list-status']
                type: str
                description: Enable/disable application control.
                choices:
                    - 'disable'
                    - 'enable'
            av_profile:
                aliases: ['av-profile']
                type: str
                description: Antivirus profile.
            av_profile_status:
                aliases: ['av-profile-status']
                type: str
                description: Enable/disable antivirus.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: Comments.
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: str
                description: DLP sensor name.
            dlp_sensor_status:
                aliases: ['dlp-sensor-status']
                type: str
                description: Enable/disable DLP.
                choices:
                    - 'disable'
                    - 'enable'
            dsri:
                type: str
                description: Enable/disable DSRI.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Address object to limit traffic monitoring to network traffic sent to the specified address or range.
            interface:
                type: str
                description: Monitored interface name from available interfaces.
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: IPS sensor name.
            ips_sensor_status:
                aliases: ['ips-sensor-status']
                type: str
                description: Enable/disable IPS.
                choices:
                    - 'disable'
                    - 'enable'
            label:
                type: str
                description: Label.
            logtraffic:
                type: str
                description: Logging type to be used in this policy
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            policyid:
                type: int
                description: Policy ID.
                required: true
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Enable/disable scanning for connections to Botnet servers.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            service:
                type: raw
                description: (list or str) Service object from available options.
            spamfilter_profile:
                aliases: ['spamfilter-profile']
                type: str
                description: Antispam profile.
            spamfilter_profile_status:
                aliases: ['spamfilter-profile-status']
                type: str
                description: Enable/disable antispam.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr:
                type: raw
                description: (list or str) Address object to limit traffic monitoring to network traffic sent from the specified address or range.
            status:
                type: str
                description: Enable/disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: Web filter profile.
            webfilter_profile_status:
                aliases: ['webfilter-profile-status']
                type: str
                description: Enable/disable web filtering.
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter_profile:
                aliases: ['emailfilter-profile']
                type: str
                description: Email filter profile.
            emailfilter_profile_status:
                aliases: ['emailfilter-profile-status']
                type: str
                description: Enable/disable email filter.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            casi_profile:
                aliases: ['casi-profile']
                type: str
                description: CASI profile name.
            casi_profile_status:
                aliases: ['casi-profile-status']
                type: str
                description: Enable/disable CASI.
                choices:
                    - 'disable'
                    - 'enable'
            dlp_profile:
                aliases: ['dlp-profile']
                type: str
                description: DLP profile name.
            dlp_profile_status:
                aliases: ['dlp-profile-status']
                type: str
                description: Enable/disable DLP.
                choices:
                    - 'disable'
                    - 'enable'
            casb_profile:
                aliases: ['casb-profile']
                type: raw
                description: (list) CASB profile.
            casb_profile_status:
                aliases: ['casb-profile-status']
                type: str
                description: Enable/disable CASB.
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
    - name: Configure IPv4 interface policies.
      fortinet.fortimanager.fmgr_pkg_firewall_interfacepolicy:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_interfacepolicy:
          address_type: ipv4 # <value in [ipv4, ipv6]>
          comments: "ansible-comment"
          interface: sslvpn_tun_intf
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
    - name: Retrieve all the IPv4 interface policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_interfacepolicy"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            interface_policy: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_interfacepolicy': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
            'options': {
                'address-type': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'application-list': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'application-list-status': {
                    'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'av-profile': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'av-profile-status': {
                    'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'comments': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'dlp-sensor': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'dlp-sensor-status': {
                    'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'dsri': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'interface': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'ips-sensor': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'ips-sensor-status': {
                    'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'label': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'logtraffic': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'policyid': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'scan-botnet-connections': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'service': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'spamfilter-profile': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'spamfilter-profile-status': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'status': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-profile': {'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'webfilter-profile-status': {
                    'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'emailfilter-profile': {'v_range': [['6.2.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'emailfilter-profile-status': {
                    'v_range': [['6.2.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'uuid': {'v_range': [['6.2.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'casi-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'casi-profile-status': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dlp-profile': {'v_range': [['7.2.0', '7.2.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'dlp-profile-status': {
                    'v_range': [['7.2.0', '7.2.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'casb-profile': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'casb-profile-status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_interfacepolicy'),
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
