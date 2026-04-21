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
module: fmgr_system_report_setting
short_description: Report settings.
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
    system_report_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            aggregate_report:
                aliases: ['aggregate-report']
                type: str
                description:
                    - Enable/disable including a group report along with the per-device reports.
                    - disable - Exclude a group report along with the per-device reports.
                    - enable - Include a group report along with the per-device reports.
                choices:
                    - 'disable'
                    - 'enable'
            hcache_lossless:
                aliases: ['hcache-lossless']
                type: str
                description:
                    - Usableness of ready-with-loss hcaches.
                    - disable - Use ready-with-loss hcaches.
                    - enable - Do not use ready-with-loss hcaches.
                choices:
                    - 'disable'
                    - 'enable'
            ldap_cache_timeout:
                aliases: ['ldap-cache-timeout']
                type: int
                description: LDAP cache timeout in minutes, default 60, 0 means not use cache.
            max_table_rows:
                aliases: ['max-table-rows']
                type: int
                description: Maximum number of rows can be generated in a single table.
            report_priority:
                aliases: ['report-priority']
                type: str
                description:
                    - Priority of sql report.
                    - high - High
                    - low - Low
                    - auto - Auto
                choices:
                    - 'high'
                    - 'low'
                    - 'auto'
            template_auto_install:
                aliases: ['template-auto-install']
                type: str
                description:
                    - The language used for new ADOMs
                    - default - Default.
                    - english - English.
                choices:
                    - 'default'
                    - 'english'
            week_start:
                aliases: ['week-start']
                type: str
                description:
                    - Day of the week on which the week starts.
                    - sun - Sunday.
                    - mon - Monday.
                choices:
                    - 'sun'
                    - 'mon'
            capwap_port:
                aliases: ['capwap-port']
                type: int
                description: Exclude capwap traffic by port.
            capwap_service:
                aliases: ['capwap-service']
                type: str
                description: Exclude capwap traffic by service.
            exclude_capwap:
                aliases: ['exclude-capwap']
                type: str
                description:
                    - Exclude capwap traffic.
                    - disable - Disable.
                    - by-port - By port.
                    - by-service - By service.
                choices:
                    - 'disable'
                    - 'by-port'
                    - 'by-service'
            max_rpt_pdf_rows:
                aliases: ['max-rpt-pdf-rows']
                type: int
                description: Maximum number of rows can be generated in a single pdf.
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
    - name: Report settings.
      fortinet.fortimanager.fmgr_system_report_setting:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_report_setting:
          # aggregate_report: <value in [disable, enable]>
          # hcache_lossless: <value in [disable, enable]>
          # ldap_cache_timeout: <integer>
          # max_table_rows: <integer>
          # report_priority: <value in [high, low, auto]>
          # template_auto_install: <value in [default, english]>
          # week_start: <value in [sun, mon]>
          # capwap_port: <integer>
          # capwap_service: <string>
          # exclude_capwap: <value in [disable, by-port, by-service]>
          # max_rpt_pdf_rows: <integer>
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
        '/cli/global/system/report/setting'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_report_setting': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'aggregate-report': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hcache-lossless': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ldap-cache-timeout': {'type': 'int'},
                'max-table-rows': {'type': 'int'},
                'report-priority': {'choices': ['high', 'low', 'auto'], 'type': 'str'},
                'template-auto-install': {'choices': ['default', 'english'], 'type': 'str'},
                'week-start': {'choices': ['sun', 'mon'], 'type': 'str'},
                'capwap-port': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'capwap-service': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'exclude-capwap': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'by-port', 'by-service'], 'type': 'str'},
                'max-rpt-pdf-rows': {'v_range': [['7.0.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_report_setting'),
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
