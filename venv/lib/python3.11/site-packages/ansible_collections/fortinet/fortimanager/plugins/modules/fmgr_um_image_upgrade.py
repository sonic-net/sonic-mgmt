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
module: fmgr_um_image_upgrade
short_description: The older API for updating the firmware of specific device.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    um_image_upgrade:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: Adom.
            create_task:
                type: str
                description: Create task.
            device:
                type: list
                elements: dict
                description: Device.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            flags:
                type: str
                description: Flags.
                choices:
                    - 'f_boot_alt_partition'
                    - 'f_skip_retrieve'
                    - 'f_skip_multi_steps'
                    - 'f_skip_fortiguard_img'
                    - 'f_preview'
            image:
                type: dict
                description: Image.
                suboptions:
                    build:
                        type: str
                        description: Build.
                    id:
                        type: raw
                        description: (list) Id.
                    model:
                        type: str
                        description: Model.
                    release:
                        type: str
                        description: Release.
            schedule_time:
                type: str
                description: Schedule time.
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
    - name: The older API for updating the firmware of specific device.
      fortinet.fortimanager.fmgr_um_image_upgrade:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        um_image_upgrade:
          # adom: <string>
          # create_task: <string>
          # device:
          #   - name: <string>
          #     vdom: <string>
          # flags: <value in [f_boot_alt_partition, f_skip_retrieve, f_skip_multi_steps, ...]>
          # image:
          #   build: <string>
          #   id: <list or string>
          #   model: <string>
          #   release: <string>
          # schedule_time: <string>
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
        '/um/image/upgrade'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'um_image_upgrade': {
            'type': 'dict',
            'v_range': [['7.2.1', '']],
            'options': {
                'adom': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'create_task': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'device': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.2.1', '']], 'type': 'str'}, 'vdom': {'v_range': [['7.2.1', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'flags': {
                    'v_range': [['7.2.1', '']],
                    'choices': ['f_boot_alt_partition', 'f_skip_retrieve', 'f_skip_multi_steps', 'f_skip_fortiguard_img', 'f_preview'],
                    'type': 'str'
                },
                'image': {
                    'v_range': [['7.2.1', '']],
                    'type': 'dict',
                    'options': {
                        'build': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'model': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'release': {'v_range': [['7.2.1', '']], 'type': 'str'}
                    }
                },
                'schedule_time': {'v_range': [['7.2.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'um_image_upgrade'),
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
