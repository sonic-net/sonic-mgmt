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
module: fmgr_dvm_cmd_discover_device
short_description: Probe a remote device and retrieve its device information and system status.
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
    dvm_cmd_discover_device:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            device:
                type: dict
                description: Device.
                suboptions:
                    adm_pass:
                        type: str
                        description: Adm pass.
                    adm_usr:
                        type: str
                        description: Adm usr.
                    ip:
                        type: str
                        description: Ip.
'''

EXAMPLES = '''
- name: Add a FOS device to FMG
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
    fos_user: "admin"
    fos_pass: "password"
    fos_ip: "192.168.190.151"
  tasks:
    - name: Discover device
      fortinet.fortimanager.fmgr_dvm_cmd_discover_device:
        bypass_validation: true
        dvm_cmd_discover_device:
          device:
            adm_pass: "{{ fos_pass }}"
            adm_usr: "{{ fos_user }}"
            ip: "{{ fos_ip }}"
      register: probed_device
    - name: Add device
      fortinet.fortimanager.fmgr_dvm_cmd_add_device:
        bypass_validation: true
        dvm_cmd_add_device:
          adom: "root"
          flags:
            - "create_task"
            - "nonblocking"
          device:
            adm_usr: "{{ probed_device.meta.response_data.device.adm_usr }}"
            adm_pass: "{{ probed_device.meta.response_data.device.adm_pass }}"
            desc: "The device is added via FortiManager Ansible"
            ip: "{{ probed_device.meta.response_data.device.ip }}"
            mgmt_mode: "fmg"
            name: "{{ probed_device.meta.response_data.device.name }}"
            sn: "{{ probed_device.meta.response_data.device.sn }}"
      register: installing_task
    - name: Poll the task of adding device
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "task_task"
          params:
            task: "{{ installing_task.meta.response_data.taskid }}"
      register: taskinfo
      until: taskinfo.meta.response_data.percent == 100
      retries: 30
      delay: 5
      failed_when: taskinfo.meta.response_data.state == 'error' and 'devsnexist' not in taskinfo.meta.response_data.line[0].detail

- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Probe a remote device and retrieve its device information and system status.
      fortinet.fortimanager.fmgr_dvm_cmd_discover_device:
        bypass_validation: false
        dvm_cmd_discover_device:
          device:
            adm_pass: fortinet # device password
            adm_usr: admin # device user name
            ip: 0.0.0.0 # device ip
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
        '/dvm/cmd/discover/device'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'dvm_cmd_discover_device': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'device': {'type': 'dict', 'options': {'adm_pass': {'no_log': True, 'type': 'str'}, 'adm_usr': {'type': 'str'}, 'ip': {'type': 'str'}}}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvm_cmd_discover_device'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('exec', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_exec()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
