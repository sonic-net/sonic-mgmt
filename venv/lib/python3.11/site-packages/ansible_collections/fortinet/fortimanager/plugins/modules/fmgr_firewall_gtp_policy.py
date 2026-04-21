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
module: fmgr_firewall_gtp_policy
short_description: Policy.
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
    gtp:
        description: The parameter (gtp) in requested url.
        type: str
        required: true
    firewall_gtp_policy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action.
                choices:
                    - 'allow'
                    - 'deny'
            apn_sel_mode:
                aliases: ['apn-sel-mode']
                type: list
                elements: str
                description: APN selection mode.
                choices:
                    - 'ms'
                    - 'net'
                    - 'vrf'
            apnmember:
                type: raw
                description: (list or str) APN member.
            id:
                type: int
                description: ID.
                required: true
            imei:
                type: str
                description: IMEI
            imsi:
                type: str
                description: IMSI prefix.
            max_apn_restriction:
                aliases: ['max-apn-restriction']
                type: str
                description: Maximum APN restriction value.
                choices:
                    - 'all'
                    - 'public-1'
                    - 'public-2'
                    - 'private-1'
                    - 'private-2'
            messages:
                type: list
                elements: str
                description: GTP messages.
                choices:
                    - 'create-req'
                    - 'create-res'
                    - 'update-req'
                    - 'update-res'
            msisdn:
                type: str
                description: MSISDN prefix.
            rai:
                type: str
                description: RAI pattern.
            rat_type:
                aliases: ['rat-type']
                type: list
                elements: str
                description: RAT Type.
                choices:
                    - 'any'
                    - 'utran'
                    - 'geran'
                    - 'wlan'
                    - 'gan'
                    - 'hspa'
                    - 'eutran'
                    - 'virtual'
                    - 'nbiot'
            uli:
                type: str
                description: ULI pattern.
            imsi_prefix:
                aliases: ['imsi-prefix']
                type: str
                description: IMSI prefix.
            msisdn_prefix:
                aliases: ['msisdn-prefix']
                type: str
                description: MSISDN prefix.
            apn:
                type: str
                description: APN subfix.
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
    - name: Policy.
      fortinet.fortimanager.fmgr_firewall_gtp_policy:
        bypass_validation: false
        adom: FortiCarrier # This is FOC-only object, need a FortiCarrier adom
        gtp: "ansible-test" # name
        state: present
        firewall_gtp_policy:
          action: allow # <value in [allow, deny]>
          apn_sel_mode:
            - ms
            - net
            - vrf
          id: 1
          max_apn_restriction: public-1 # <value in [all, public-1, public-2, ...]>
          messages:
            - create-req
            - create-res
            - update-req
            - update-res
          rat_type:
            - any
            - utran
            - geran
            - wlan
            - gan
            - hspa
            - eutran
            - virtual
            - nbiot

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the policies in the GTP
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_gtp_policy"
          params:
            adom: "FortiCarrier" # This is FOC-only object, need a FortiCarrier adom
            gtp: "ansible-test" # name
            policy: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy',
        '/pm/config/global/obj/firewall/gtp/{gtp}/policy'
    ]
    url_params = ['adom', 'gtp']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'gtp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp_policy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['allow', 'deny'], 'type': 'str'},
                'apn-sel-mode': {'type': 'list', 'choices': ['ms', 'net', 'vrf'], 'elements': 'str'},
                'apnmember': {'type': 'raw'},
                'id': {'required': True, 'type': 'int'},
                'imei': {'type': 'str'},
                'imsi': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'max-apn-restriction': {'choices': ['all', 'public-1', 'public-2', 'private-1', 'private-2'], 'type': 'str'},
                'messages': {'type': 'list', 'choices': ['create-req', 'create-res', 'update-req', 'update-res'], 'elements': 'str'},
                'msisdn': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'rai': {'type': 'str'},
                'rat-type': {'type': 'list', 'choices': ['any', 'utran', 'geran', 'wlan', 'gan', 'hspa', 'eutran', 'virtual', 'nbiot'], 'elements': 'str'},
                'uli': {'type': 'str'},
                'imsi-prefix': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'msisdn-prefix': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'apn': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_policy'),
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
