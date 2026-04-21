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
module: fmgr_pkg_header_shapingpolicy
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_header_shapingpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app_category:
                aliases: ['app-category']
                type: raw
                description: (list or str) App category.
            app_group:
                aliases: ['app-group']
                type: raw
                description: (list or str) App group.
            application:
                type: raw
                description: (list) Application.
            class_id:
                aliases: ['class-id']
                type: raw
                description: (int or str) Class id.
            comment:
                type: str
                description: Comment.
            diffserv_forward:
                aliases: ['diffserv-forward']
                type: str
                description: Diffserv forward.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv_reverse:
                aliases: ['diffserv-reverse']
                type: str
                description: Diffserv reverse.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode_forward:
                aliases: ['diffservcode-forward']
                type: str
                description: Diffservcode forward.
            diffservcode_rev:
                aliases: ['diffservcode-rev']
                type: str
                description: Diffservcode rev.
            dstaddr:
                type: raw
                description: (list or str) Dstaddr.
            dstaddr6:
                type: raw
                description: (list or str) Dstaddr6.
            dstintf:
                type: raw
                description: (list or str) Dstintf.
            groups:
                type: raw
                description: (list or str) Groups.
            id:
                type: int
                description: Id.
                required: true
            internet_service:
                aliases: ['internet-service']
                type: str
                description: Internet service.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_custom:
                aliases: ['internet-service-custom']
                type: raw
                description: (list or str) Internet service custom.
            internet_service_custom_group:
                aliases: ['internet-service-custom-group']
                type: raw
                description: (list or str) Internet service custom group.
            internet_service_group:
                aliases: ['internet-service-group']
                type: raw
                description: (list or str) Internet service group.
            internet_service_id:
                aliases: ['internet-service-id']
                type: raw
                description: (list or str) Internet service id.
            internet_service_src:
                aliases: ['internet-service-src']
                type: str
                description: Internet service src.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src_custom:
                aliases: ['internet-service-src-custom']
                type: raw
                description: (list or str) Internet service src custom.
            internet_service_src_custom_group:
                aliases: ['internet-service-src-custom-group']
                type: raw
                description: (list or str) Internet service src custom group.
            internet_service_src_group:
                aliases: ['internet-service-src-group']
                type: raw
                description: (list or str) Internet service src group.
            internet_service_src_id:
                aliases: ['internet-service-src-id']
                type: raw
                description: (list or str) Internet service src id.
            ip_version:
                aliases: ['ip-version']
                type: str
                description: Ip version.
                choices:
                    - '4'
                    - '6'
            per_ip_shaper:
                aliases: ['per-ip-shaper']
                type: str
                description: Per ip shaper.
            schedule:
                type: str
                description: Schedule.
            service:
                type: raw
                description: (list or str) Service.
            srcaddr:
                type: raw
                description: (list or str) Srcaddr.
            srcaddr6:
                type: raw
                description: (list or str) Srcaddr6.
            srcintf:
                type: raw
                description: (list or str) Srcintf.
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
            tos:
                type: str
                description: Tos.
            tos_mask:
                aliases: ['tos-mask']
                type: str
                description: Tos mask.
            tos_negate:
                aliases: ['tos-negate']
                type: str
                description: Tos negate.
                choices:
                    - 'disable'
                    - 'enable'
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: str
                description: Traffic shaper.
            traffic_shaper_reverse:
                aliases: ['traffic-shaper-reverse']
                type: str
                description: Traffic shaper reverse.
            url_category:
                aliases: ['url-category']
                type: raw
                description: (list or str) Url category.
            users:
                type: raw
                description: (list or str) Users.
            uuid:
                type: str
                description: Uuid.
            internet_service_name:
                aliases: ['internet-service-name']
                type: raw
                description: (list or str) Internet service name.
            internet_service_src_name:
                aliases: ['internet-service-src-name']
                type: raw
                description: (list or str) Internet service src name.
            class_id_reverse:
                aliases: ['class-id-reverse']
                type: int
                description: Class id reverse.
            service_type:
                aliases: ['service-type']
                type: str
                description: Service type.
                choices:
                    - 'service'
                    - 'internet-service'
            uuid_idx:
                aliases: ['uuid-idx']
                type: int
                description: Uuid idx.
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
            http_response_match:
                aliases: ['http-response-match']
                type: str
                description: Http response match.
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
    - name: Configure shaping policies.
      fortinet.fortimanager.fmgr_pkg_header_shapingpolicy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_header_shapingpolicy:
          id: 0 # Required variable, integer
          # app_category: <list or string>
          # app_group: <list or string>
          # application: <list or integer>
          # class_id: <integer or string>
          # comment: <string>
          # diffserv_forward: <value in [disable, enable]>
          # diffserv_reverse: <value in [disable, enable]>
          # diffservcode_forward: <string>
          # diffservcode_rev: <string>
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # dstintf: <list or string>
          # groups: <list or string>
          # internet_service: <value in [disable, enable]>
          # internet_service_custom: <list or string>
          # internet_service_custom_group: <list or string>
          # internet_service_group: <list or string>
          # internet_service_id: <list or string>
          # internet_service_src: <value in [disable, enable]>
          # internet_service_src_custom: <list or string>
          # internet_service_src_custom_group: <list or string>
          # internet_service_src_group: <list or string>
          # internet_service_src_id: <list or string>
          # ip_version: <value in [4, 6]>
          # per_ip_shaper: <string>
          # schedule: <string>
          # service: <list or string>
          # srcaddr: <list or string>
          # srcaddr6: <list or string>
          # srcintf: <list or string>
          # status: <value in [disable, enable]>
          # tos: <string>
          # tos_mask: <string>
          # tos_negate: <value in [disable, enable]>
          # traffic_shaper: <string>
          # traffic_shaper_reverse: <string>
          # url_category: <list or string>
          # users: <list or string>
          # uuid: <string>
          # internet_service_name: <list or string>
          # internet_service_src_name: <list or string>
          # class_id_reverse: <integer>
          # service_type: <value in [service, internet-service]>
          # uuid_idx: <integer>
          # cos: <string>
          # cos_mask: <string>
          # traffic_type: <value in [forwarding, local-in, local-out]>
          # http_response_match: <value in [disable, enable]>
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
        '/pm/config/global/pkg/{pkg}/global/header/shaping-policy'
    ]
    url_params = ['pkg']
    module_primary_key = 'id'
    module_arg_spec = {
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_header_shapingpolicy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'app-category': {'type': 'raw'},
                'app-group': {'type': 'raw'},
                'application': {'type': 'raw'},
                'class-id': {'type': 'raw'},
                'comment': {'type': 'str'},
                'diffserv-forward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'type': 'str'},
                'diffservcode-rev': {'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'dstaddr6': {'type': 'raw'},
                'dstintf': {'type': 'raw'},
                'groups': {'type': 'raw'},
                'id': {'required': True, 'type': 'int'},
                'internet-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'type': 'raw'},
                'internet-service-custom-group': {'type': 'raw'},
                'internet-service-group': {'type': 'raw'},
                'internet-service-id': {'type': 'raw'},
                'internet-service-src': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'type': 'raw'},
                'internet-service-src-custom-group': {'type': 'raw'},
                'internet-service-src-group': {'type': 'raw'},
                'internet-service-src-id': {'type': 'raw'},
                'ip-version': {'choices': ['4', '6'], 'type': 'str'},
                'per-ip-shaper': {'type': 'str'},
                'schedule': {'type': 'str'},
                'service': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'srcaddr6': {'type': 'raw'},
                'srcintf': {'type': 'raw'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tos': {'type': 'str'},
                'tos-mask': {'type': 'str'},
                'tos-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'type': 'str'},
                'traffic-shaper-reverse': {'type': 'str'},
                'url-category': {'type': 'raw'},
                'users': {'type': 'raw'},
                'uuid': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'internet-service-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'class-id-reverse': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'service-type': {'v_range': [['7.0.3', '']], 'choices': ['service', 'internet-service'], 'type': 'str'},
                'uuid-idx': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'cos': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'cos-mask': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'traffic-type': {'v_range': [['7.4.0', '']], 'choices': ['forwarding', 'local-in', 'local-out'], 'type': 'str'},
                'http-response-match': {'v_range': [['7.4.7', '7.4.7']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = [
        {
            'attribute_path': ['pkg_header_shapingpolicy', 'id'],
            'lambda': 'int($) >= 1073741824',
            'fail_action': 'warn',
            'hint_message': 'id should be larger than 2^30, i.e. 1073741824, otherwise it will be ignored.'
        }
    ]

    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_header_shapingpolicy'),
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
