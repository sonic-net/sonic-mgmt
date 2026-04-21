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
module: fmgr_firewall_mmsprofile_notification
short_description: Notification configuration.
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
    mms-profile:
        description: Deprecated, please use "mms_profile"
        type: str
    mms_profile:
        description: The parameter (mms-profile) in requested url.
        type: str
    firewall_mmsprofile_notification:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            alert_int:
                aliases: ['alert-int']
                type: int
                description: Alert notification send interval.
            alert_int_mode:
                aliases: ['alert-int-mode']
                type: str
                description: Alert notification interval mode.
                choices:
                    - 'hours'
                    - 'minutes'
            alert_src_msisdn:
                aliases: ['alert-src-msisdn']
                type: str
                description: Specify from address for alert messages.
            alert_status:
                aliases: ['alert-status']
                type: str
                description: Alert notification status.
                choices:
                    - 'disable'
                    - 'enable'
            bword_int:
                aliases: ['bword-int']
                type: int
                description: Banned word notification send interval.
            bword_int_mode:
                aliases: ['bword-int-mode']
                type: str
                description: Banned word notification interval mode.
                choices:
                    - 'hours'
                    - 'minutes'
            bword_status:
                aliases: ['bword-status']
                type: str
                description: Banned word notification status.
                choices:
                    - 'disable'
                    - 'enable'
            carrier_endpoint_bwl_int:
                aliases: ['carrier-endpoint-bwl-int']
                type: int
                description: Carrier end point black/white list notification send interval.
            carrier_endpoint_bwl_int_mode:
                aliases: ['carrier-endpoint-bwl-int-mode']
                type: str
                description: Carrier end point black/white list notification interval mode.
                choices:
                    - 'hours'
                    - 'minutes'
            carrier_endpoint_bwl_status:
                aliases: ['carrier-endpoint-bwl-status']
                type: str
                description: Carrier end point black/white list notification status.
                choices:
                    - 'disable'
                    - 'enable'
            days_allowed:
                aliases: ['days-allowed']
                type: list
                elements: str
                description: Weekdays on which notification messages may be sent.
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            detect_server:
                aliases: ['detect-server']
                type: str
                description: Enable/disable automatic server address determination.
                choices:
                    - 'disable'
                    - 'enable'
            dupe_int:
                aliases: ['dupe-int']
                type: int
                description: Duplicate notification send interval.
            dupe_int_mode:
                aliases: ['dupe-int-mode']
                type: str
                description: Duplicate notification interval mode.
                choices:
                    - 'hours'
                    - 'minutes'
            dupe_status:
                aliases: ['dupe-status']
                type: str
                description: Duplicate notification status.
                choices:
                    - 'disable'
                    - 'enable'
            file_block_int:
                aliases: ['file-block-int']
                type: int
                description: File block notification send interval.
            file_block_int_mode:
                aliases: ['file-block-int-mode']
                type: str
                description: File block notification interval mode.
                choices:
                    - 'hours'
                    - 'minutes'
            file_block_status:
                aliases: ['file-block-status']
                type: str
                description: File block notification status.
                choices:
                    - 'disable'
                    - 'enable'
            flood_int:
                aliases: ['flood-int']
                type: int
                description: Flood notification send interval.
            flood_int_mode:
                aliases: ['flood-int-mode']
                type: str
                description: Flood notification interval mode.
                choices:
                    - 'hours'
                    - 'minutes'
            flood_status:
                aliases: ['flood-status']
                type: str
                description: Flood notification status.
                choices:
                    - 'disable'
                    - 'enable'
            from_in_header:
                aliases: ['from-in-header']
                type: str
                description: Enable/disable insertion of from address in HTTP header.
                choices:
                    - 'disable'
                    - 'enable'
            mms_checksum_int:
                aliases: ['mms-checksum-int']
                type: int
                description: MMS checksum notification send interval.
            mms_checksum_int_mode:
                aliases: ['mms-checksum-int-mode']
                type: str
                description: MMS checksum notification interval mode.
                choices:
                    - 'hours'
                    - 'minutes'
            mms_checksum_status:
                aliases: ['mms-checksum-status']
                type: str
                description: MMS checksum notification status.
                choices:
                    - 'disable'
                    - 'enable'
            mmsc_hostname:
                aliases: ['mmsc-hostname']
                type: str
                description: Host name or IP address of the MMSC.
            mmsc_password:
                aliases: ['mmsc-password']
                type: raw
                description: (list) Password required for authentication with the MMSC.
            mmsc_port:
                aliases: ['mmsc-port']
                type: int
                description: Port used on the MMSC for sending MMS messages
            mmsc_url:
                aliases: ['mmsc-url']
                type: str
                description: URL used on the MMSC for sending MMS messages.
            mmsc_username:
                aliases: ['mmsc-username']
                type: str
                description: User name required for authentication with the MMSC.
            msg_protocol:
                aliases: ['msg-protocol']
                type: str
                description: Protocol to use for sending notification messages.
                choices:
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            msg_type:
                aliases: ['msg-type']
                type: str
                description: MM7 message type.
                choices:
                    - 'submit-req'
                    - 'deliver-req'
            protocol:
                type: str
                description: Protocol.
            rate_limit:
                aliases: ['rate-limit']
                type: int
                description: Rate limit for sending notification messages
            tod_window_duration:
                aliases: ['tod-window-duration']
                type: str
                description: Time of day window duration.
            tod_window_end:
                aliases: ['tod-window-end']
                type: str
                description: Obsolete.
            tod_window_start:
                aliases: ['tod-window-start']
                type: str
                description: Time of day window start.
            user_domain:
                aliases: ['user-domain']
                type: str
                description: Domain name to which the user addresses belong.
            vas_id:
                aliases: ['vas-id']
                type: str
                description: VAS identifier.
            vasp_id:
                aliases: ['vasp-id']
                type: str
                description: VASP identifier.
            virus_int:
                aliases: ['virus-int']
                type: int
                description: Virus notification send interval.
            virus_int_mode:
                aliases: ['virus-int-mode']
                type: str
                description: Virus notification interval mode.
                choices:
                    - 'hours'
                    - 'minutes'
            virus_status:
                aliases: ['virus-status']
                type: str
                description: Virus notification status.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Notification configuration.
      fortinet.fortimanager.fmgr_firewall_mmsprofile_notification:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        mms_profile: <your own value>
        firewall_mmsprofile_notification:
          # alert_int: <integer>
          # alert_int_mode: <value in [hours, minutes]>
          # alert_src_msisdn: <string>
          # alert_status: <value in [disable, enable]>
          # bword_int: <integer>
          # bword_int_mode: <value in [hours, minutes]>
          # bword_status: <value in [disable, enable]>
          # carrier_endpoint_bwl_int: <integer>
          # carrier_endpoint_bwl_int_mode: <value in [hours, minutes]>
          # carrier_endpoint_bwl_status: <value in [disable, enable]>
          # days_allowed:
          #   - "sunday"
          #   - "monday"
          #   - "tuesday"
          #   - "wednesday"
          #   - "thursday"
          #   - "friday"
          #   - "saturday"
          # detect_server: <value in [disable, enable]>
          # dupe_int: <integer>
          # dupe_int_mode: <value in [hours, minutes]>
          # dupe_status: <value in [disable, enable]>
          # file_block_int: <integer>
          # file_block_int_mode: <value in [hours, minutes]>
          # file_block_status: <value in [disable, enable]>
          # flood_int: <integer>
          # flood_int_mode: <value in [hours, minutes]>
          # flood_status: <value in [disable, enable]>
          # from_in_header: <value in [disable, enable]>
          # mms_checksum_int: <integer>
          # mms_checksum_int_mode: <value in [hours, minutes]>
          # mms_checksum_status: <value in [disable, enable]>
          # mmsc_hostname: <string>
          # mmsc_password: <list or string>
          # mmsc_port: <integer>
          # mmsc_url: <string>
          # mmsc_username: <string>
          # msg_protocol: <value in [mm1, mm3, mm4, ...]>
          # msg_type: <value in [submit-req, deliver-req]>
          # protocol: <string>
          # rate_limit: <integer>
          # tod_window_duration: <string>
          # tod_window_end: <string>
          # tod_window_start: <string>
          # user_domain: <string>
          # vas_id: <string>
          # vasp_id: <string>
          # virus_int: <integer>
          # virus_int_mode: <value in [hours, minutes]>
          # virus_status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notification',
        '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notification'
    ]
    url_params = ['adom', 'mms-profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'mms-profile': {'type': 'str', 'api_name': 'mms_profile'},
        'mms_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_mmsprofile_notification': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'alert-int': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'alert-int-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                'alert-src-msisdn': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'alert-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bword-int': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'bword-int-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                'bword-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'carrier-endpoint-bwl-int': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'carrier-endpoint-bwl-int-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                'carrier-endpoint-bwl-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'days-allowed': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'elements': 'str'
                },
                'detect-server': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dupe-int': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'dupe-int-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                'dupe-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'file-block-int': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'file-block-int-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                'file-block-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'flood-int': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'flood-int-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                'flood-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'from-in-header': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-checksum-int': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'mms-checksum-int-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                'mms-checksum-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mmsc-hostname': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'mmsc-password': {'v_range': [['6.0.0', '7.6.2']], 'no_log': True, 'type': 'raw'},
                'mmsc-port': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'mmsc-url': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'mmsc-username': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'msg-protocol': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['mm1', 'mm3', 'mm4', 'mm7'], 'type': 'str'},
                'msg-type': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['submit-req', 'deliver-req'], 'type': 'str'},
                'protocol': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'rate-limit': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'tod-window-duration': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'tod-window-end': {'v_range': [['6.0.0', '7.2.0']], 'type': 'str'},
                'tod-window-start': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'user-domain': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'vas-id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'vasp-id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'virus-int': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'virus-int-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                'virus-status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_mmsprofile_notification'),
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
