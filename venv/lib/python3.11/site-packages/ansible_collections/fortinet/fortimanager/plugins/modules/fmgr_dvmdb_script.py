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
module: fmgr_dvmdb_script
short_description: Script table.
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
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    dvmdb_script:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            content:
                type: str
                description: The full content of the script result log.
            desc:
                type: str
                description: Desc.
            filter_build:
                type: int
                description: The value will be ignored in add/set/update requests if filter_ostype is not set.
            filter_device:
                type: int
                description: Name or id of an existing device in the database.
            filter_hostname:
                type: str
                description: The value has no effect if target is adom_database.
            filter_ostype:
                type: str
                description: The value has no effect if target is adom_database.
                choices:
                    - 'unknown'
                    - 'fos'
            filter_osver:
                type: str
                description: The value will be ignored in add/set/update requests if filter_ostype is not set.
                choices:
                    - 'unknown'
                    - '4.00'
                    - '5.00'
                    - '6.00'
            filter_platform:
                type: str
                description: The value will be ignored in add/set/update requests if filter_ostype is not set.
            filter_serial:
                type: str
                description: The value has no effect if target is adom_database.
            modification_time:
                type: str
                description: It is a read-only attribute indicating the time when the script was created or modified.
            name:
                type: str
                description: Name.
                required: true
            script_schedule:
                type: list
                elements: dict
                description: Script schedule.
                suboptions:
                    datetime:
                        type: str
                        description:
                            - Indicates the date and time of the schedule.
                            - onetime
                            - daily
                            - weekly
                            - monthly
                    day_of_week:
                        type: str
                        description: Day of week.
                        choices:
                            - 'unknown'
                            - 'sun'
                            - 'mon'
                            - 'tue'
                            - 'wed'
                            - 'thu'
                            - 'fri'
                            - 'sat'
                    device:
                        type: int
                        description: Name or id of an existing device in the database.
                    name:
                        type: str
                        description: Name.
                    run_on_db:
                        type: str
                        description: Indicates if the scheduled script should be executed on device database.
                        choices:
                            - 'disable'
                            - 'enable'
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'auto'
                            - 'onetime'
                            - 'daily'
                            - 'weekly'
                            - 'monthly'
            target:
                type: str
                description: Target.
                choices:
                    - 'device_database'
                    - 'remote_device'
                    - 'adom_database'
            type:
                type: str
                description: Type.
                choices:
                    - 'cli'
                    - 'tcl'
                    - 'cligrp'
'''

EXAMPLES = '''
- name: Apply a script to device
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
    device_adom: "root"
    script_name: "FooScript"
    device_name: "CustomHostName"
    device_vdom: "root"
  tasks:
    - name: Create a Script to later execute
      fortinet.fortimanager.fmgr_dvmdb_script:
        adom: "{{ device_adom }}"
        state: "present"
        dvmdb_script:
          name: "{{ script_name }}"
          desc: "A script created via Ansible"
          content: |
            config system global
                set remoteauthtimeout 80
            end
          type: "cli"
    - name: Run the Script
      fortinet.fortimanager.fmgr_dvmdb_script_execute:
        adom: "{{ device_adom }}"
        dvmdb_script_execute:
          adom: "{{ device_adom }}"
          script: "{{ script_name }}"
          scope:
            - name: "{{ device_name }}"
              vdom: "{{ device_vdom }}"
      register: running_task
    - name: Inspect the Task Status
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "task_task"
          params:
            task: "{{ running_task.meta.response_data.task }}"
      register: taskinfo
      until: taskinfo.meta.response_data.percent == 100
      retries: 30
      delay: 3
      failed_when: taskinfo.meta.response_data.state == 'error'

- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Script table.
      fortinet.fortimanager.fmgr_dvmdb_script:
        bypass_validation: false
        adom: ansible
        state: present
        dvmdb_script:
          content: "ansiblt-test"
          name: "ansible-test"
          target: device_database
          type: cli

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the scripts in the device
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "dvmdb_script"
          params:
            adom: "ansible"
            script: "your_value"

- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Enable workspace mode
      fortinet.fortimanager.fmgr_system_global:
        system_global:
          adom_status: enable
          workspace_mode: normal

    - name: Script table.
      fortinet.fortimanager.fmgr_dvmdb_script:
        bypass_validation: false
        adom: root
        state: present
        workspace_locking_adom: "root"
        dvmdb_script:
          content: "ansiblt-test"
          name: "fooscript000"
          target: device_database
          type: cli

    - name: Verify script table
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "dvmdb_script"
          params:
            adom: "root"
            script: "fooscript000"
      register: info
      failed_when: info.meta.response_code != 0

    - name: Restore workspace mode
      fortinet.fortimanager.fmgr_system_global:
        system_global:
          adom_status: enable
          workspace_mode: disabled
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
        '/dvmdb/adom/{adom}/script',
        '/dvmdb/global/script',
        '/dvmdb/script'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'dvmdb_script': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'content': {'type': 'str'},
                'desc': {'type': 'str'},
                'filter_build': {'type': 'int'},
                'filter_device': {'type': 'int'},
                'filter_hostname': {'type': 'str'},
                'filter_ostype': {'choices': ['unknown', 'fos'], 'type': 'str'},
                'filter_osver': {'choices': ['unknown', '4.00', '5.00', '6.00'], 'type': 'str'},
                'filter_platform': {'type': 'str'},
                'filter_serial': {'type': 'str'},
                'modification_time': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'script_schedule': {
                    'type': 'list',
                    'options': {
                        'datetime': {'type': 'str'},
                        'day_of_week': {'choices': ['unknown', 'sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'], 'type': 'str'},
                        'device': {'type': 'int'},
                        'name': {'type': 'str'},
                        'run_on_db': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'choices': ['auto', 'onetime', 'daily', 'weekly', 'monthly'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'target': {'choices': ['device_database', 'remote_device', 'adom_database'], 'type': 'str'},
                'type': {'choices': ['cli', 'tcl', 'cligrp'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_script'),
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
