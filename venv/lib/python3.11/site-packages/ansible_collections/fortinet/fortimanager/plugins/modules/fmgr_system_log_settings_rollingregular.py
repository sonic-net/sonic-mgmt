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
module: fmgr_system_log_settings_rollingregular
short_description: Log rolling policy for device logs.
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
    system_log_settings_rollingregular:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            days:
                type: list
                elements: str
                description:
                    - Log files rolling schedule
                    - sun - Sunday.
                    - mon - Monday.
                    - tue - Tuesday.
                    - wed - Wednesday.
                    - thu - Thursday.
                    - fri - Friday.
                    - sat - Saturday.
                choices:
                    - 'sun'
                    - 'mon'
                    - 'tue'
                    - 'wed'
                    - 'thu'
                    - 'fri'
                    - 'sat'
            del_files:
                aliases: ['del-files']
                type: str
                description:
                    - Enable/disable log file deletion after uploading.
                    - disable - Disable log file deletion.
                    - enable - Enable log file deletion.
                choices:
                    - 'disable'
                    - 'enable'
            directory:
                type: str
                description: Upload server directory, for Unix server, use absolute
            file_size:
                aliases: ['file-size']
                type: int
                description: Roll log files when they reach this size
            gzip_format:
                aliases: ['gzip-format']
                type: str
                description:
                    - Enable/disable compression of uploaded log files.
                    - disable - Disable compression.
                    - enable - Enable compression.
                choices:
                    - 'disable'
                    - 'enable'
            hour:
                type: int
                description: Log files rolling schedule
            ip:
                type: str
                description: Upload server IP address.
            ip2:
                type: str
                description: Upload server IP2 address.
            ip3:
                type: str
                description: Upload server IP3 address.
            log_format:
                aliases: ['log-format']
                type: str
                description:
                    - Format of uploaded log files.
                    - native - Native format
                    - text - Text format
                    - csv - CSV
                choices:
                    - 'native'
                    - 'text'
                    - 'csv'
            min:
                type: int
                description: Log files rolling schedule
            password:
                type: raw
                description: (list) Upload server login password.
            password2:
                type: raw
                description: (list) Upload server login password2.
            password3:
                type: raw
                description: (list) Upload server login password3.
            server_type:
                aliases: ['server-type']
                type: str
                description:
                    - Upload server type.
                    - ftp - Upload via FTP.
                    - sftp - Upload via SFTP.
                    - scp - Upload via SCP.
                choices:
                    - 'ftp'
                    - 'sftp'
                    - 'scp'
            upload:
                type: str
                description:
                    - Enable/disable log file uploads.
                    - disable - Disable log files uploading.
                    - enable - Enable log files uploading.
                choices:
                    - 'disable'
                    - 'enable'
            upload_hour:
                aliases: ['upload-hour']
                type: int
                description: Log files upload schedule
            upload_mode:
                aliases: ['upload-mode']
                type: str
                description:
                    - Upload mode with multiple servers.
                    - backup - Servers are attempted and used one after the other upon failure to connect.
                    - mirror - All configured servers are attempted and used.
                choices:
                    - 'backup'
                    - 'mirror'
            upload_trigger:
                aliases: ['upload-trigger']
                type: str
                description:
                    - Event triggering log files upload.
                    - on-roll - Upload log files after they are rolled.
                    - on-schedule - Upload log files daily.
                choices:
                    - 'on-roll'
                    - 'on-schedule'
            username:
                type: str
                description: Upload server login username.
            username2:
                type: str
                description: Upload server login username2.
            username3:
                type: str
                description: Upload server login username3.
            when:
                type: str
                description:
                    - Roll log files periodically.
                    - none - Do not roll log files periodically.
                    - daily - Roll log files daily.
                    - weekly - Roll log files on certain days of week.
                choices:
                    - 'none'
                    - 'daily'
                    - 'weekly'
            port:
                type: int
                description: Upload server IP1 port number.
            port2:
                type: int
                description: Upload server IP2 port number.
            port3:
                type: int
                description: Upload server IP3 port number.
            rolling_upgrade_status:
                aliases: ['rolling-upgrade-status']
                type: int
                description: Rolling upgrade status
            server:
                type: str
                description: Upload server FQDN/IP.
            server2:
                type: str
                description: Upload server2 FQDN/IP.
            server3:
                type: str
                description: Upload server3 FQDN/IP.
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
    - name: Log rolling policy for device logs.
      fortinet.fortimanager.fmgr_system_log_settings_rollingregular:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_log_settings_rollingregular:
          # days:
          #   - "sun"
          #   - "mon"
          #   - "tue"
          #   - "wed"
          #   - "thu"
          #   - "fri"
          #   - "sat"
          # del_files: <value in [disable, enable]>
          # directory: <string>
          # file_size: <integer>
          # gzip_format: <value in [disable, enable]>
          # hour: <integer>
          # ip: <string>
          # ip2: <string>
          # ip3: <string>
          # log_format: <value in [native, text, csv]>
          # min: <integer>
          # password: <list or string>
          # password2: <list or string>
          # password3: <list or string>
          # server_type: <value in [ftp, sftp, scp]>
          # upload: <value in [disable, enable]>
          # upload_hour: <integer>
          # upload_mode: <value in [backup, mirror]>
          # upload_trigger: <value in [on-roll, on-schedule]>
          # username: <string>
          # username2: <string>
          # username3: <string>
          # when: <value in [none, daily, weekly]>
          # port: <integer>
          # port2: <integer>
          # port3: <integer>
          # rolling_upgrade_status: <integer>
          # server: <string>
          # server2: <string>
          # server3: <string>
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
        '/cli/global/system/log/settings/rolling-regular'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_log_settings_rollingregular': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'days': {'type': 'list', 'choices': ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'], 'elements': 'str'},
                'del-files': {'choices': ['disable', 'enable'], 'type': 'str'},
                'directory': {'type': 'str'},
                'file-size': {'type': 'int'},
                'gzip-format': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hour': {'type': 'int'},
                'ip': {'v_range': [['6.0.0', '7.0.14']], 'type': 'str'},
                'ip2': {'v_range': [['6.0.0', '7.0.14']], 'type': 'str'},
                'ip3': {'v_range': [['6.0.0', '7.0.14']], 'type': 'str'},
                'log-format': {'choices': ['native', 'text', 'csv'], 'type': 'str'},
                'min': {'type': 'int'},
                'password': {'no_log': True, 'type': 'raw'},
                'password2': {'no_log': True, 'type': 'raw'},
                'password3': {'no_log': True, 'type': 'raw'},
                'server-type': {'choices': ['ftp', 'sftp', 'scp'], 'type': 'str'},
                'upload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'upload-hour': {'type': 'int'},
                'upload-mode': {'choices': ['backup', 'mirror'], 'type': 'str'},
                'upload-trigger': {'choices': ['on-roll', 'on-schedule'], 'type': 'str'},
                'username': {'type': 'str'},
                'username2': {'type': 'str'},
                'username3': {'type': 'str'},
                'when': {'choices': ['none', 'daily', 'weekly'], 'type': 'str'},
                'port': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'port2': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'port3': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'rolling-upgrade-status': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'server': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'server2': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'server3': {'v_range': [['7.2.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_log_settings_rollingregular'),
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
