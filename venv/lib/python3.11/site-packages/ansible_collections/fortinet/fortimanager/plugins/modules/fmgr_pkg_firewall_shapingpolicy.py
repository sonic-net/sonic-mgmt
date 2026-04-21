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
module: fmgr_pkg_firewall_shapingpolicy
short_description: Configure shaping policies.
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
    pkg_firewall_shapingpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app_category:
                aliases: ['app-category']
                type: raw
                description: (list or str) IDs of one or more application categories that this shaper applies application control traffic shaping to.
            application:
                type: raw
                description: (list) IDs of one or more applications that this shaper applies application control traffic shaping to.
            dstaddr:
                type: raw
                description: (list or str) IPv4 destination address and address group names.
            dstaddr6:
                type: raw
                description: (list or str) IPv6 destination address and address group names.
            dstintf:
                type: raw
                description: (list or str) One or more outgoing
            groups:
                type: raw
                description: (list or str) Apply this traffic shaping policy to user groups that have authenticated with the FortiGate.
            id:
                type: int
                description: Shaping policy ID.
                required: true
            ip_version:
                aliases: ['ip-version']
                type: str
                description: Apply this traffic shaping policy to IPv4 or IPv6 traffic.
                choices:
                    - '4'
                    - '6'
            per_ip_shaper:
                aliases: ['per-ip-shaper']
                type: str
                description: Per-IP traffic shaper to apply with this policy.
            schedule:
                type: str
                description: Schedule name.
            service:
                type: raw
                description: (list or str) Service and service group names.
            srcaddr:
                type: raw
                description: (list or str) IPv4 source address and address group names.
            srcaddr6:
                type: raw
                description: (list or str) IPv6 source address and address group names.
            status:
                type: str
                description: Enable/disable this traffic shaping policy.
                choices:
                    - 'disable'
                    - 'enable'
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: str
                description: Traffic shaper to apply to traffic forwarded by the firewall policy.
            traffic_shaper_reverse:
                aliases: ['traffic-shaper-reverse']
                type: str
                description: Traffic shaper to apply to response traffic received by the firewall policy.
            url_category:
                aliases: ['url-category']
                type: raw
                description: (list or str) IDs of one or more FortiGuard Web Filtering categories that this shaper applies traffic shaping to.
            users:
                type: raw
                description: (list or str) Apply this traffic shaping policy to individual users that have authenticated with the FortiGate.
            app_group:
                aliases: ['app-group']
                type: raw
                description: (list or str) One or more application group names.
            class_id:
                aliases: ['class-id']
                type: raw
                description: (int or str) Traffic class ID.
            comment:
                type: str
                description: Comments.
            diffserv_forward:
                aliases: ['diffserv-forward']
                type: str
                description: Enable to change packets DiffServ values to the specified diffservcode-forward value.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv_reverse:
                aliases: ['diffserv-reverse']
                type: str
                description: Enable to change packets reverse
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode_forward:
                aliases: ['diffservcode-forward']
                type: str
                description: Change packets DiffServ to this value.
            diffservcode_rev:
                aliases: ['diffservcode-rev']
                type: str
                description: Change packets reverse
            internet_service:
                aliases: ['internet-service']
                type: str
                description: Enable/disable use of Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_custom:
                aliases: ['internet-service-custom']
                type: raw
                description: (list or str) Custom Internet Service name.
            internet_service_custom_group:
                aliases: ['internet-service-custom-group']
                type: raw
                description: (list or str) Custom Internet Service group name.
            internet_service_group:
                aliases: ['internet-service-group']
                type: raw
                description: (list or str) Internet Service group name.
            internet_service_id:
                aliases: ['internet-service-id']
                type: raw
                description: (list or str) Internet Service ID.
            internet_service_src:
                aliases: ['internet-service-src']
                type: str
                description: Enable/disable use of Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src_custom:
                aliases: ['internet-service-src-custom']
                type: raw
                description: (list or str) Custom Internet Service source name.
            internet_service_src_custom_group:
                aliases: ['internet-service-src-custom-group']
                type: raw
                description: (list or str) Custom Internet Service source group name.
            internet_service_src_group:
                aliases: ['internet-service-src-group']
                type: raw
                description: (list or str) Internet Service source group name.
            internet_service_src_id:
                aliases: ['internet-service-src-id']
                type: raw
                description: (list or str) Internet Service source ID.
            name:
                type: str
                description: Shaping policy name.
            srcintf:
                type: raw
                description: (list or str) One or more incoming
            tos:
                type: str
                description: ToS
            tos_mask:
                aliases: ['tos-mask']
                type: str
                description: Non-zero bit positions are used for comparison while zero bit positions are ignored.
            tos_negate:
                aliases: ['tos-negate']
                type: str
                description: Enable negated TOS match.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            internet_service_name:
                aliases: ['internet-service-name']
                type: raw
                description: (list or str) Internet Service ID.
            internet_service_src_name:
                aliases: ['internet-service-src-name']
                type: raw
                description: (list or str) Internet Service source name.
            cos:
                type: str
                description: VLAN CoS bit pattern.
            cos_mask:
                aliases: ['cos-mask']
                type: str
                description: VLAN CoS evaluated bits.
            traffic_type:
                aliases: ['traffic-type']
                type: str
                description: Traffic type.
                choices:
                    - 'forwarding'
                    - 'local-in'
                    - 'local-out'
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
    - name: Configure shaping policies.
      fortinet.fortimanager.fmgr_pkg_firewall_shapingpolicy:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_shapingpolicy:
          dstaddr: all
          dstintf: any
          id: 1
          ip_version: 4 # <value in [4, 6]>
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
    - name: Retrieve all the shaping policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_shapingpolicy"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            shaping_policy: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_shapingpolicy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'app-category': {'type': 'raw'},
                'application': {'type': 'raw'},
                'dstaddr': {'type': 'raw'},
                'dstaddr6': {'type': 'raw'},
                'dstintf': {'type': 'raw'},
                'groups': {'type': 'raw'},
                'id': {'required': True, 'type': 'int'},
                'ip-version': {'choices': ['4', '6'], 'type': 'str'},
                'per-ip-shaper': {'type': 'str'},
                'schedule': {'type': 'str'},
                'service': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'srcaddr6': {'type': 'raw'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'type': 'str'},
                'traffic-shaper-reverse': {'type': 'str'},
                'url-category': {'type': 'raw'},
                'users': {'type': 'raw'},
                'app-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'class-id': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'comment': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'diffserv-forward': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'diffservcode-rev': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'internet-service': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-custom-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-id': {'v_range': [['6.2.0', '7.6.2']], 'type': 'raw'},
                'internet-service-src': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-src-custom-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-src-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-src-id': {'v_range': [['6.2.0', '7.6.2']], 'type': 'raw'},
                'name': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'srcintf': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'tos': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'tos-mask': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'tos-negate': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'internet-service-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'cos': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'cos-mask': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'traffic-type': {'v_range': [['7.4.0', '']], 'choices': ['forwarding', 'local-in', 'local-out'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_shapingpolicy'),
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
