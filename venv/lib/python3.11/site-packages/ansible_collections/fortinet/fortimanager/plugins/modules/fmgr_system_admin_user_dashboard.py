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
module: fmgr_system_admin_user_dashboard
short_description: Custom dashboard widgets.
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
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    user:
        description: The parameter (user) in requested url.
        type: str
        required: true
    system_admin_user_dashboard:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            column:
                type: int
                description: Widgets column ID.
            diskio_content_type:
                aliases: ['diskio-content-type']
                type: str
                description:
                    - Disk I/O Monitor widgets chart type.
                    - util - bandwidth utilization.
                    - iops - the number of I/O requests.
                    - blks - the amount of data of I/O requests.
                choices:
                    - 'util'
                    - 'iops'
                    - 'blks'
            diskio_period:
                aliases: ['diskio-period']
                type: str
                description:
                    - Disk I/O Monitor widgets data period.
                    - 1hour - 1 hour.
                    - 8hour - 8 hour.
                    - 24hour - 24 hour.
                choices:
                    - '1hour'
                    - '8hour'
                    - '24hour'
            log_rate_period:
                aliases: ['log-rate-period']
                type: str
                description:
                    - Log receive monitor widgets data period.
                    - 2min  - 2 minutes.
                    - 1hour - 1 hour.
                    - 6hours - 6 hours.
                choices:
                    - '2min'
                    - '1hour'
                    - '6hours'
            log_rate_topn:
                aliases: ['log-rate-topn']
                type: str
                description:
                    - Log receive monitor widgets number of top items to display.
                    - 1 - Top 1.
                    - 2 - Top 2.
                    - 3 - Top 3.
                    - 4 - Top 4.
                    - 5 - Top 5.
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
            log_rate_type:
                aliases: ['log-rate-type']
                type: str
                description:
                    - Log receive monitor widgets statistics breakdown options.
                    - log - Show log rates for each log type.
                    - device - Show log rates for each device.
                choices:
                    - 'log'
                    - 'device'
            moduleid:
                type: int
                description: Widget ID.
                required: true
            name:
                type: str
                description: Widget name.
            num_entries:
                aliases: ['num-entries']
                type: int
                description: Number of entries.
            refresh_interval:
                aliases: ['refresh-interval']
                type: int
                description: Widgets refresh interval.
            res_cpu_display:
                aliases: ['res-cpu-display']
                type: str
                description:
                    - Widgets CPU display type.
                    - average  - Average usage of CPU.
                    - each - Each usage of CPU.
                choices:
                    - 'average'
                    - 'each'
            res_period:
                aliases: ['res-period']
                type: str
                description:
                    - Widgets data period.
                    - 10min  - Last 10 minutes.
                    - hour - Last hour.
                    - day - Last day.
                choices:
                    - '10min'
                    - 'hour'
                    - 'day'
            res_view_type:
                aliases: ['res-view-type']
                type: str
                description:
                    - Widgets data view type.
                    - real-time  - Real-time view.
                    - history - History view.
                choices:
                    - 'real-time'
                    - 'history'
            status:
                type: str
                description:
                    - Widgets opened/closed state.
                    - close - Widget closed.
                    - open - Widget opened.
                choices:
                    - 'close'
                    - 'open'
            tabid:
                type: int
                description: ID of tab where widget is displayed.
            time_period:
                aliases: ['time-period']
                type: str
                description:
                    - Log Database Monitor widgets data period.
                    - 1hour - 1 hour.
                    - 8hour - 8 hour.
                    - 24hour - 24 hour.
                choices:
                    - '1hour'
                    - '8hour'
                    - '24hour'
            widget_type:
                aliases: ['widget-type']
                type: str
                description:
                    - Widget type.
                    - top-lograte - Log Receive Monitor.
                    - sysres - System resources.
                    - sysinfo - System Information.
                    - licinfo - License Information.
                    - jsconsole - CLI Console.
                    - sysop - Unit Operation.
                    - alert - Alert Message Console.
                    - statistics - Statistics.
                    - rpteng - Report Engine.
                    - raid - Disk Monitor.
                    - logrecv - Logs/Data Received.
                    - devsummary - Device Summary.
                    - logdb-perf - Log Database Performance Monitor.
                    - logdb-lag - Log Database Lag Time.
                    - disk-io - Disk I/O.
                    - log-rcvd-fwd - Log receive and forwarding Monitor.
                choices:
                    - 'top-lograte'
                    - 'sysres'
                    - 'sysinfo'
                    - 'licinfo'
                    - 'jsconsole'
                    - 'sysop'
                    - 'alert'
                    - 'statistics'
                    - 'rpteng'
                    - 'raid'
                    - 'logrecv'
                    - 'devsummary'
                    - 'logdb-perf'
                    - 'logdb-lag'
                    - 'disk-io'
                    - 'log-rcvd-fwd'
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
    - name: Custom dashboard widgets.
      fortinet.fortimanager.fmgr_system_admin_user_dashboard:
        bypass_validation: false
        user: ansible-test
        state: present
        system_admin_user_dashboard:
          column: 1
          diskio_content_type: util # <value in [util, iops, blks]>
          diskio_period: 1hour # <value in [1hour, 8hour, 24hour]>
          log_rate_period: 1hour # <value in [2min , 1hour, 6hours]>
          log_rate_topn: 5 # <value in [1, 2, 3, ...]>
          log_rate_type: device # <value in [log, device]>
          moduleid: 10
          name: ansible-test-dashboard
          num_entries: 10
          refresh_interval: 0
          res_cpu_display: "each" # <value in [average , each]>
          res_period: 10min # <value in [10min , hour, day]>
          res_view_type: history # <value in [real-time , history]>
          status: open # <value in [close, open]>
          tabid: 1
          time_period: 1hour # <value in [1hour, 8hour, 24hour]>
          widget_type: sysres # <value in [top-lograte, sysres, sysinfo, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dashboard widgets
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_admin_user_dashboard"
          params:
            user: "ansible-test"
            dashboard: "your_value"
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
        '/cli/global/system/admin/user/{user}/dashboard'
    ]
    url_params = ['user']
    module_primary_key = 'moduleid'
    module_arg_spec = {
        'user': {'required': True, 'type': 'str'},
        'system_admin_user_dashboard': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'column': {'type': 'int'},
                'diskio-content-type': {'choices': ['util', 'iops', 'blks'], 'type': 'str'},
                'diskio-period': {'choices': ['1hour', '8hour', '24hour'], 'type': 'str'},
                'log-rate-period': {'choices': ['2min', '1hour', '6hours'], 'type': 'str'},
                'log-rate-topn': {'choices': ['1', '2', '3', '4', '5'], 'type': 'str'},
                'log-rate-type': {'choices': ['log', 'device'], 'type': 'str'},
                'moduleid': {'required': True, 'type': 'int'},
                'name': {'type': 'str'},
                'num-entries': {'type': 'int'},
                'refresh-interval': {'type': 'int'},
                'res-cpu-display': {'choices': ['average', 'each'], 'type': 'str'},
                'res-period': {'choices': ['10min', 'hour', 'day'], 'type': 'str'},
                'res-view-type': {'choices': ['real-time', 'history'], 'type': 'str'},
                'status': {'choices': ['close', 'open'], 'type': 'str'},
                'tabid': {'type': 'int'},
                'time-period': {'choices': ['1hour', '8hour', '24hour'], 'type': 'str'},
                'widget-type': {
                    'choices': [
                        'top-lograte', 'sysres', 'sysinfo', 'licinfo', 'jsconsole', 'sysop', 'alert', 'statistics', 'rpteng', 'raid', 'logrecv',
                        'devsummary', 'logdb-perf', 'logdb-lag', 'disk-io', 'log-rcvd-fwd'
                    ],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_user_dashboard'),
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
