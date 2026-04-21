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
module: fmgr_fmupdate_fwmsetting
short_description: Configure firmware management settings.
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
    fmupdate_fwmsetting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            fds_image_timeout:
                aliases: ['fds-image-timeout']
                type: int
                description: Timer for fgt download image from fortiguard
            max_fds_retry:
                aliases: ['max-fds-retry']
                type: int
                description: The retries when fgt download from fds fail
            multiple_steps_interval:
                aliases: ['multiple-steps-interval']
                type: int
                description: Waiting time between multiple steps upgrade
            skip_disk_check:
                aliases: ['skip-disk-check']
                type: str
                description:
                    - skip disk check when upgrade image.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            auto_scan_fgt_disk:
                aliases: ['auto-scan-fgt-disk']
                type: str
                description:
                    - auto scan fgt disk if needed.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            check_fgt_disk:
                aliases: ['check-fgt-disk']
                type: str
                description:
                    - check fgt disk before upgrade image.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fds_failover_fmg:
                aliases: ['fds-failover-fmg']
                type: str
                description:
                    - using fmg local image file is download from fds fails.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            immx_source:
                aliases: ['immx-source']
                type: str
                description:
                    - Configure which of IMMX file to be used for choosing upgrade pach.
                    - fmg - Use IMMX file for FortiManager
                    - fgt - Use IMMX file for FortiGate
                    - cloud - Use IMMX file for FortiCloud
                choices:
                    - 'fmg'
                    - 'fgt'
                    - 'cloud'
            log:
                type: str
                description:
                    - Configure log setting for fwm daemon
                    - fwm - FWM daemon log
                    - fwm_dm - FWM and Deployment service log
                    - fwm_dm_json - FWM and Deployment service log with JSON data between FMG-FGT
                choices:
                    - 'fwm'
                    - 'fwm_dm'
                    - 'fwm_dm_json'
            upgrade_timeout:
                aliases: ['upgrade-timeout']
                type: dict
                description: Upgrade timeout.
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
            retry_interval:
                aliases: ['retry-interval']
                type: int
                description: Waiting time for resending request to device
            retry_max:
                aliases: ['retry-max']
                type: int
                description: Max retry times
            health_check:
                aliases: ['health-check']
                type: str
                description:
                    - do health check after upgrade
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            max_device_history:
                aliases: ['max-device-history']
                type: int
                description: Max number of device upgrade report
            max_profile_history:
                aliases: ['max-profile-history']
                type: int
                description: Max number of profile upgrade report
            retrieve:
                type: str
                description:
                    - do retrieve after upgrade
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            revision_diff:
                aliases: ['revision-diff']
                type: str
                description:
                    - calculate diff script after upgrade
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            send_image_retry:
                aliases: ['send-image-retry']
                type: int
                description: Retry send image when failed
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
    - name: Configure firmware management settings.
      fortinet.fortimanager.fmgr_fmupdate_fwmsetting:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        fmupdate_fwmsetting:
          # fds_image_timeout: <integer>
          # max_fds_retry: <integer>
          # multiple_steps_interval: <integer>
          # skip_disk_check: <value in [disable, enable]>
          # auto_scan_fgt_disk: <value in [disable, enable]>
          # check_fgt_disk: <value in [disable, enable]>
          # fds_failover_fmg: <value in [disable, enable]>
          # immx_source: <value in [fmg, fgt, cloud]>
          # log: <value in [fwm, fwm_dm, fwm_dm_json]>
          # upgrade_timeout:
          #   check_status_timeout: <integer>
          #   ctrl_check_status_timeout: <integer>
          #   ctrl_put_image_by_fds_timeout: <integer>
          #   ha_sync_timeout: <integer>
          #   license_check_timeout: <integer>
          #   prepare_image_timeout: <integer>
          #   put_image_by_fds_timeout: <integer>
          #   put_image_timeout: <integer>
          #   reboot_of_fsck_timeout: <integer>
          #   reboot_of_upgrade_timeout: <integer>
          #   retrieve_timeout: <integer>
          #   rpc_timeout: <integer>
          #   total_timeout: <integer>
          #   health_check_timeout: <integer>
          # retry_interval: <integer>
          # retry_max: <integer>
          # health_check: <value in [disable, enable]>
          # max_device_history: <integer>
          # max_profile_history: <integer>
          # retrieve: <value in [disable, enable]>
          # revision_diff: <value in [disable, enable]>
          # send_image_retry: <integer>
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
        '/cli/global/fmupdate/fwm-setting'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'fmupdate_fwmsetting': {
            'type': 'dict',
            'v_range': [['6.2.2', '']],
            'options': {
                'fds-image-timeout': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'max-fds-retry': {'v_range': [['6.2.2', '6.2.3']], 'type': 'int'},
                'multiple-steps-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'skip-disk-check': {'v_range': [['6.2.2', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-scan-fgt-disk': {'v_range': [['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'check-fgt-disk': {'v_range': [['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fds-failover-fmg': {'v_range': [['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'immx-source': {'v_range': [['6.4.2', '']], 'choices': ['fmg', 'fgt', 'cloud'], 'type': 'str'},
                'log': {'v_range': [['6.4.8', '6.4.15'], ['7.0.1', '']], 'choices': ['fwm', 'fwm_dm', 'fwm_dm_json'], 'type': 'str'},
                'upgrade-timeout': {
                    'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']],
                    'type': 'dict',
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
                },
                'retry-interval': {'v_range': [['7.0.10', '7.0.14'], ['7.2.5', '7.2.11'], ['7.4.2', '']], 'type': 'int'},
                'retry-max': {'v_range': [['7.0.10', '7.0.14'], ['7.2.5', '7.2.11'], ['7.4.2', '']], 'type': 'int'},
                'health-check': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-device-history': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'max-profile-history': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'retrieve': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'revision-diff': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'send-image-retry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_fwmsetting'),
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
