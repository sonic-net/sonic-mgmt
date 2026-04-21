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
module: fmgr_devprof_system_centralmanagement
short_description: Configure central management.
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
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_centralmanagement:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            include_default_servers:
                aliases: ['include-default-servers']
                type: str
                description: Enable/disable inclusion of public FortiGuard servers in the override server list.
                choices:
                    - 'disable'
                    - 'enable'
            server_list:
                aliases: ['server-list']
                type: list
                elements: dict
                description: Server list.
                suboptions:
                    addr_type:
                        aliases: ['addr-type']
                        type: str
                        description: Indicate whether the FortiGate communicates with the override server using an IPv4 address, an IPv6 address or a FQDN.
                        choices:
                            - 'fqdn'
                            - 'ipv4'
                            - 'ipv6'
                    fqdn:
                        type: str
                        description: FQDN address of override server.
                    id:
                        type: int
                        description: ID.
                    server_address:
                        aliases: ['server-address']
                        type: str
                        description: IPv4 address of override server.
                    server_address6:
                        aliases: ['server-address6']
                        type: str
                        description: IPv6 address of override server.
                    server_type:
                        aliases: ['server-type']
                        type: list
                        elements: str
                        description: FortiGuard service type.
                        choices:
                            - 'update'
                            - 'rating'
                            - 'iot-query'
                            - 'iot-collect'
                            - 'vpatch-query'
            ltefw_upgrade_time:
                aliases: ['ltefw-upgrade-time']
                type: str
                description: Schedule next LTE firmware upgrade time
            vdom:
                type: raw
                description: (list) Virtual domain
            allow_remote_firmware_upgrade:
                aliases: ['allow-remote-firmware-upgrade']
                type: str
                description: Enable/disable remotely upgrading the firmware on this FortiGate from the central management server.
                choices:
                    - 'disable'
                    - 'enable'
            local_cert:
                aliases: ['local-cert']
                type: str
                description: Certificate to be used by FGFM protocol.
            allow_push_firmware:
                aliases: ['allow-push-firmware']
                type: str
                description: Enable/disable allowing the central management server to push firmware updates to this FortiGate.
                choices:
                    - 'disable'
                    - 'enable'
            ltefw_upgrade_frequency:
                aliases: ['ltefw-upgrade-frequency']
                type: str
                description: Set LTE firmware auto pushdown frequency.
                choices:
                    - 'everyHour'
                    - 'every12hour'
                    - 'everyDay'
                    - 'everyWeek'
            mode:
                type: str
                description: Central management mode.
                choices:
                    - 'normal'
                    - 'backup'
            serial_number:
                aliases: ['serial-number']
                type: raw
                description: (list) Serial number.
            fmg_source_ip6:
                aliases: ['fmg-source-ip6']
                type: str
                description: IPv6 source address that this FortiGate uses when communicating with FortiManager.
            allow_monitor:
                aliases: ['allow-monitor']
                type: str
                description: Enable/disable allowing the central management server to remotely monitor this FortiGate unit.
                choices:
                    - 'disable'
                    - 'enable'
            allow_push_configuration:
                aliases: ['allow-push-configuration']
                type: str
                description: Enable/disable allowing the central management server to push configuration changes to this FortiGate.
                choices:
                    - 'disable'
                    - 'enable'
            ca_cert:
                aliases: ['ca-cert']
                type: str
                description: CA certificate to be used by FGFM protocol.
            fmg_update_port:
                aliases: ['fmg-update-port']
                type: str
                description: Port used to communicate with FortiManager that is acting as a FortiGuard update server.
                choices:
                    - '443'
                    - '8890'
            use_elbc_vdom:
                aliases: ['use-elbc-vdom']
                type: str
                description: Enable/disable use of special ELBC config sync VDOM to connect to FortiManager.
                choices:
                    - 'disable'
                    - 'enable'
            allow_remote_lte_firmware_upgrade:
                aliases: ['allow-remote-lte-firmware-upgrade']
                type: str
                description: Enable/disable remotely upgrading the lte firmware on this FortiGate from the central management server.
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: raw
                description: (list) Specify outgoing interface to reach server.
            schedule_script_restore:
                aliases: ['schedule-script-restore']
                type: str
                description: Enable/disable allowing the central management server to restore the scripts stored on this FortiGate.
                choices:
                    - 'disable'
                    - 'enable'
            schedule_config_restore:
                aliases: ['schedule-config-restore']
                type: str
                description: Enable/disable allowing the central management server to restore the configuration of this FortiGate.
                choices:
                    - 'disable'
                    - 'enable'
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            type:
                type: str
                description: Central management type.
                choices:
                    - 'fortimanager'
                    - 'fortiguard'
                    - 'none'
            fmg_source_ip:
                aliases: ['fmg-source-ip']
                type: str
                description: IPv4 source address that this FortiGate uses when communicating with FortiManager.
            fortigate_cloud_sso_default_profile:
                aliases: ['fortigate-cloud-sso-default-profile']
                type: raw
                description: (list) Override access profile.
            fmg:
                type: raw
                description: (list) IP address or FQDN of the FortiManager.
            enc_algorithm:
                aliases: ['enc-algorithm']
                type: str
                description: Encryption strength for communications between the FortiGate and central management.
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
            allow_remote_modem_firmware_upgrade:
                aliases: ['allow-remote-modem-firmware-upgrade']
                type: str
                description: Enable/disable remotely upgrading the internal cellular modem firmware on this FortiGate from the central management server.
                choices:
                    - 'disable'
                    - 'enable'
            modem_upgrade_frequency:
                aliases: ['modem-upgrade-frequency']
                type: str
                description: Set internal cellular modem firmware auto pushdown frequency.
                choices:
                    - 'everyHour'
                    - 'every12hour'
                    - 'everyDay'
                    - 'everyWeek'
            modem_upgrade_time:
                aliases: ['modem-upgrade-time']
                type: str
                description: Schedule next internal cellular modem firmware upgrade time
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
            fmg_update_http_header:
                aliases: ['fmg-update-http-header']
                type: str
                description: Enable/disable inclusion of HTTP header in update request.
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
    - name: Configure central management.
      fortinet.fortimanager.fmgr_devprof_system_centralmanagement:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        devprof: <your own value>
        devprof_system_centralmanagement:
          # include_default_servers: <value in [disable, enable]>
          # server_list:
          #   - addr_type: <value in [fqdn, ipv4, ipv6]>
          #     fqdn: <string>
          #     id: <integer>
          #     server_address: <string>
          #     server_address6: <string>
          #     server_type:
          #       - "update"
          #       - "rating"
          #       - "iot-query"
          #       - "iot-collect"
          #       - "vpatch-query"
          # ltefw_upgrade_time: <string>
          # vdom: <list or string>
          # allow_remote_firmware_upgrade: <value in [disable, enable]>
          # local_cert: <string>
          # allow_push_firmware: <value in [disable, enable]>
          # ltefw_upgrade_frequency: <value in [everyHour, every12hour, everyDay, ...]>
          # mode: <value in [normal, backup]>
          # serial_number: <list or string>
          # fmg_source_ip6: <string>
          # allow_monitor: <value in [disable, enable]>
          # allow_push_configuration: <value in [disable, enable]>
          # ca_cert: <string>
          # fmg_update_port: <value in [443, 8890]>
          # use_elbc_vdom: <value in [disable, enable]>
          # allow_remote_lte_firmware_upgrade: <value in [disable, enable]>
          # interface: <list or string>
          # schedule_script_restore: <value in [disable, enable]>
          # schedule_config_restore: <value in [disable, enable]>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # type: <value in [fortimanager, fortiguard, none]>
          # fmg_source_ip: <string>
          # fortigate_cloud_sso_default_profile: <list or string>
          # fmg: <list or string>
          # enc_algorithm: <value in [default, high, low]>
          # allow_remote_modem_firmware_upgrade: <value in [disable, enable]>
          # modem_upgrade_frequency: <value in [everyHour, every12hour, everyDay, ...]>
          # modem_upgrade_time: <string>
          # vrf_select: <integer>
          # fmg_update_http_header: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management'
    ]
    url_params = ['adom', 'devprof']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_centralmanagement': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'include-default-servers': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'server-list': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'type': 'list',
                    'options': {
                        'addr-type': {
                            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                            'choices': ['fqdn', 'ipv4', 'ipv6'],
                            'type': 'str'
                        },
                        'fqdn': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                        'server-address': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                        'server-address6': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                        'server-type': {
                            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                            'type': 'list',
                            'choices': ['update', 'rating', 'iot-query', 'iot-collect', 'vpatch-query'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ltefw-upgrade-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'allow-remote-firmware-upgrade': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-cert': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'allow-push-firmware': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ltefw-upgrade-frequency': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['everyHour', 'every12hour', 'everyDay', 'everyWeek'],
                    'type': 'str'
                },
                'mode': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['normal', 'backup'], 'type': 'str'},
                'serial-number': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'fmg-source-ip6': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'allow-monitor': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allow-push-configuration': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ca-cert': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'fmg-update-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['443', '8890'], 'type': 'str'},
                'use-elbc-vdom': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allow-remote-lte-firmware-upgrade': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'schedule-script-restore': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'schedule-config-restore': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'type': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['fortimanager', 'fortiguard', 'none'], 'type': 'str'},
                'fmg-source-ip': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'fortigate-cloud-sso-default-profile': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'fmg': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'enc-algorithm': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['default', 'high', 'low'], 'type': 'str'},
                'allow-remote-modem-firmware-upgrade': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'modem-upgrade-frequency': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['everyHour', 'every12hour', 'everyDay', 'everyWeek'],
                    'type': 'str'
                },
                'modem-upgrade-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'fmg-update-http-header': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_centralmanagement'),
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
