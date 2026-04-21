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
module: fmgr_extendercontroller_dataplan
short_description: FortiExtender dataplan configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    extendercontroller_dataplan:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            apn:
                type: str
                description: APN configuration.
            auth_type:
                aliases: ['auth-type']
                type: str
                description: Authentication type.
                choices:
                    - 'none'
                    - 'pap'
                    - 'chap'
            billing_date:
                aliases: ['billing-date']
                type: int
                description: Billing day of the month
            capacity:
                type: int
                description: Capacity in MB
            carrier:
                type: str
                description: Carrier configuration.
            iccid:
                type: str
                description: ICCID configuration.
            modem_id:
                aliases: ['modem-id']
                type: str
                description: Dataplans modem specifics, if any.
                choices:
                    - 'all'
                    - 'modem1'
                    - 'modem2'
            monthly_fee:
                aliases: ['monthly-fee']
                type: int
                description: Monthly fee of dataplan
            name:
                type: str
                description: FortiExtender dataplan name
                required: true
            overage:
                type: str
                description: Enable/disable dataplan overage detection.
                choices:
                    - 'disable'
                    - 'enable'
            password:
                type: raw
                description: (list) Password.
            pdn:
                type: str
                description: PDN type.
                choices:
                    - 'ipv4-only'
                    - 'ipv6-only'
                    - 'ipv4-ipv6'
            preferred_subnet:
                aliases: ['preferred-subnet']
                type: int
                description: Preferred subnet mask
            private_network:
                aliases: ['private-network']
                type: str
                description: Enable/disable dataplan private network support.
                choices:
                    - 'disable'
                    - 'enable'
            signal_period:
                aliases: ['signal-period']
                type: int
                description: Signal period
            signal_threshold:
                aliases: ['signal-threshold']
                type: int
                description: Signal threshold.
            slot:
                type: str
                description: SIM slot configuration.
                choices:
                    - 'sim1'
                    - 'sim2'
            status:
                type: str
                description: FortiExtender dataplan
                choices:
                    - 'disable'
                    - 'enable'
            type:
                type: str
                description: Type preferences configuration.
                choices:
                    - 'carrier'
                    - 'slot'
                    - 'iccid'
                    - 'generic'
            username:
                type: str
                description: Username.
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
    - name: FortiExtender dataplan configuration.
      fortinet.fortimanager.fmgr_extendercontroller_dataplan:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        extendercontroller_dataplan:
          name: "your value" # Required variable, string
          # apn: <string>
          # auth_type: <value in [none, pap, chap]>
          # billing_date: <integer>
          # capacity: <integer>
          # carrier: <string>
          # iccid: <string>
          # modem_id: <value in [all, modem1, modem2]>
          # monthly_fee: <integer>
          # overage: <value in [disable, enable]>
          # password: <list or string>
          # pdn: <value in [ipv4-only, ipv6-only, ipv4-ipv6]>
          # preferred_subnet: <integer>
          # private_network: <value in [disable, enable]>
          # signal_period: <integer>
          # signal_threshold: <integer>
          # slot: <value in [sim1, sim2]>
          # status: <value in [disable, enable]>
          # type: <value in [carrier, slot, iccid, ...]>
          # username: <string>
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
        '/pm/config/adom/{adom}/obj/extender-controller/dataplan',
        '/pm/config/global/obj/extender-controller/dataplan'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'extendercontroller_dataplan': {
            'type': 'dict',
            'v_range': [['6.4.4', '']],
            'options': {
                'apn': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'auth-type': {'v_range': [['6.4.4', '']], 'choices': ['none', 'pap', 'chap'], 'type': 'str'},
                'billing-date': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'capacity': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'carrier': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'iccid': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'modem-id': {'v_range': [['6.4.4', '']], 'choices': ['all', 'modem1', 'modem2'], 'type': 'str'},
                'monthly-fee': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'name': {'v_range': [['6.4.4', '']], 'required': True, 'type': 'str'},
                'overage': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'password': {'v_range': [['6.4.4', '']], 'no_log': True, 'type': 'raw'},
                'pdn': {'v_range': [['6.4.4', '']], 'choices': ['ipv4-only', 'ipv6-only', 'ipv4-ipv6'], 'type': 'str'},
                'preferred-subnet': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'private-network': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'signal-period': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'signal-threshold': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'slot': {'v_range': [['6.4.4', '']], 'choices': ['sim1', 'sim2'], 'type': 'str'},
                'status': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['6.4.4', '']], 'choices': ['carrier', 'slot', 'iccid', 'generic'], 'type': 'str'},
                'username': {'v_range': [['6.4.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_dataplan'),
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
