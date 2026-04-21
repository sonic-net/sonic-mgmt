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
module: fmgr_fmupdate_fwmsetting_upgradetimeout
short_description: Configure the timeout value of image upgrade process.
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
    fmupdate_fwmsetting_upgradetimeout:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            check_status_timeout:
                aliases: ['check-status-timeout']
                type: int
                description: Timeout for checking status after tunnnel is up.
            ctrl_check_status_timeout:
                aliases: ['ctrl-check-status-timeout']
                type: int
                description: Timeout for checking fap/fsw/fext status after request upgrade.
            ctrl_put_image_by_fds_timeout:
                aliases: ['ctrl-put-image-by-fds-timeout']
                type: int
                description: Timeout for waiting device get fap/fsw/fext image from fortiguard.
            ha_sync_timeout:
                aliases: ['ha-sync-timeout']
                type: int
                description: Timeout for waiting HA sync.
            license_check_timeout:
                aliases: ['license-check-timeout']
                type: int
                description: Timeout for waiting fortigate check license.
            prepare_image_timeout:
                aliases: ['prepare-image-timeout']
                type: int
                description: Timeout for preparing image.
            put_image_by_fds_timeout:
                aliases: ['put-image-by-fds-timeout']
                type: int
                description: Timeout for waiting device get image from fortiguard.
            put_image_timeout:
                aliases: ['put-image-timeout']
                type: int
                description: Timeout for waiting send image over tunnel.
            reboot_of_fsck_timeout:
                aliases: ['reboot-of-fsck-timeout']
                type: int
                description: Timeout for waiting fortigate reboot.
            reboot_of_upgrade_timeout:
                aliases: ['reboot-of-upgrade-timeout']
                type: int
                description: Timeout for waiting fortigate reboot after image upgrade.
            retrieve_timeout:
                aliases: ['retrieve-timeout']
                type: int
                description: Timeout for waiting retrieve.
            rpc_timeout:
                aliases: ['rpc-timeout']
                type: int
                description: Timeout for waiting fortigate rpc response.
            total_timeout:
                aliases: ['total-timeout']
                type: int
                description: Timeout for the whole fortigate upgrade
            health_check_timeout:
                aliases: ['health-check-timeout']
                type: int
                description: Timeout for waiting retrieve.
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
    - name: Configure the timeout value of image upgrade process.
      fortinet.fortimanager.fmgr_fmupdate_fwmsetting_upgradetimeout:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        fmupdate_fwmsetting_upgradetimeout:
          # check_status_timeout: <integer>
          # ctrl_check_status_timeout: <integer>
          # ctrl_put_image_by_fds_timeout: <integer>
          # ha_sync_timeout: <integer>
          # license_check_timeout: <integer>
          # prepare_image_timeout: <integer>
          # put_image_by_fds_timeout: <integer>
          # put_image_timeout: <integer>
          # reboot_of_fsck_timeout: <integer>
          # reboot_of_upgrade_timeout: <integer>
          # retrieve_timeout: <integer>
          # rpc_timeout: <integer>
          # total_timeout: <integer>
          # health_check_timeout: <integer>
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
        '/cli/global/fmupdate/fwm-setting/upgrade-timeout'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'fmupdate_fwmsetting_upgradetimeout': {
            'type': 'dict',
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']],
            'options': {
                'check-status-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'ctrl-check-status-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'ctrl-put-image-by-fds-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'ha-sync-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'license-check-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'prepare-image-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'put-image-by-fds-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'put-image-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'reboot-of-fsck-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'reboot-of-upgrade-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'retrieve-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'rpc-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'total-timeout': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'health-check-timeout': {'v_range': [['7.4.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_fwmsetting_upgradetimeout'),
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
