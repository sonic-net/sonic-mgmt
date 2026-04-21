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
module: fmgr_fsp_vlan_dhcpserver
short_description: Configure DHCP servers.
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
    vlan:
        description: The parameter (vlan) in requested url.
        type: str
        required: true
    fsp_vlan_dhcpserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auto_configuration:
                aliases: ['auto-configuration']
                type: str
                description: Auto configuration.
                choices:
                    - 'disable'
                    - 'enable'
            conflicted_ip_timeout:
                aliases: ['conflicted-ip-timeout']
                type: int
                description: Conflicted ip timeout.
            ddns_auth:
                aliases: ['ddns-auth']
                type: str
                description: Ddns auth.
                choices:
                    - 'disable'
                    - 'tsig'
            ddns_key:
                aliases: ['ddns-key']
                type: raw
                description: (list or str) Ddns key.
            ddns_keyname:
                aliases: ['ddns-keyname']
                type: str
                description: Ddns keyname.
            ddns_server_ip:
                aliases: ['ddns-server-ip']
                type: str
                description: Ddns server ip.
            ddns_ttl:
                aliases: ['ddns-ttl']
                type: int
                description: Ddns ttl.
            ddns_update:
                aliases: ['ddns-update']
                type: str
                description: Ddns update.
                choices:
                    - 'disable'
                    - 'enable'
            ddns_update_override:
                aliases: ['ddns-update-override']
                type: str
                description: Ddns update override.
                choices:
                    - 'disable'
                    - 'enable'
            ddns_zone:
                aliases: ['ddns-zone']
                type: str
                description: Ddns zone.
            default_gateway:
                aliases: ['default-gateway']
                type: str
                description: Default gateway.
            dns_server1:
                aliases: ['dns-server1']
                type: str
                description: Dns server1.
            dns_server2:
                aliases: ['dns-server2']
                type: str
                description: Dns server2.
            dns_server3:
                aliases: ['dns-server3']
                type: str
                description: Dns server3.
            dns_service:
                aliases: ['dns-service']
                type: str
                description: Dns service.
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            domain:
                type: str
                description: Domain.
            enable:
                type: str
                description: Enable.
                choices:
                    - 'disable'
                    - 'enable'
            exclude_range:
                aliases: ['exclude-range']
                type: list
                elements: dict
                description: Exclude range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End ip.
                    id:
                        type: int
                        description: Id.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start ip.
                    vci_match:
                        aliases: ['vci-match']
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        aliases: ['vci-string']
                        type: raw
                        description: (list) One or more VCI strings in quotes separated by spaces.
                    lease_time:
                        aliases: ['lease-time']
                        type: int
                        description: Lease time in seconds, 0 means default lease time.
                    uci_match:
                        aliases: ['uci-match']
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        aliases: ['uci-string']
                        type: raw
                        description: (list) One or more UCI strings in quotes separated by spaces.
            filename:
                type: str
                description: Filename.
            forticlient_on_net_status:
                aliases: ['forticlient-on-net-status']
                type: str
                description: Forticlient on net status.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: Id.
            interface:
                type: str
                description: Interface.
            ip_mode:
                aliases: ['ip-mode']
                type: str
                description: Ip mode.
                choices:
                    - 'range'
                    - 'usrgrp'
            ip_range:
                aliases: ['ip-range']
                type: list
                elements: dict
                description: Ip range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End ip.
                    id:
                        type: int
                        description: Id.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start ip.
                    vci_match:
                        aliases: ['vci-match']
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        aliases: ['vci-string']
                        type: raw
                        description: (list) One or more VCI strings in quotes separated by spaces.
                    lease_time:
                        aliases: ['lease-time']
                        type: int
                        description: Lease time in seconds, 0 means default lease time.
                    uci_match:
                        aliases: ['uci-match']
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        aliases: ['uci-string']
                        type: raw
                        description: (list) One or more UCI strings in quotes separated by spaces.
            ipsec_lease_hold:
                aliases: ['ipsec-lease-hold']
                type: int
                description: Ipsec lease hold.
            lease_time:
                aliases: ['lease-time']
                type: int
                description: Lease time.
            mac_acl_default_action:
                aliases: ['mac-acl-default-action']
                type: str
                description: Mac acl default action.
                choices:
                    - 'assign'
                    - 'block'
            netmask:
                type: str
                description: Netmask.
            next_server:
                aliases: ['next-server']
                type: str
                description: Next server.
            ntp_server1:
                aliases: ['ntp-server1']
                type: str
                description: Ntp server1.
            ntp_server2:
                aliases: ['ntp-server2']
                type: str
                description: Ntp server2.
            ntp_server3:
                aliases: ['ntp-server3']
                type: str
                description: Ntp server3.
            ntp_service:
                aliases: ['ntp-service']
                type: str
                description: Ntp service.
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            option1:
                type: raw
                description: (list) Option1.
            option2:
                type: raw
                description: (list) Option2.
            option3:
                type: raw
                description: (list) Option3.
            option4:
                type: str
                description: Option4.
            option5:
                type: str
                description: Option5.
            option6:
                type: str
                description: Option6.
            options:
                type: list
                elements: dict
                description: Options.
                suboptions:
                    code:
                        type: int
                        description: Code.
                    id:
                        type: int
                        description: Id.
                    ip:
                        type: raw
                        description: (list) Ip.
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'hex'
                            - 'string'
                            - 'ip'
                            - 'fqdn'
                    value:
                        type: str
                        description: Value.
                    vci_match:
                        aliases: ['vci-match']
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        aliases: ['vci-string']
                        type: raw
                        description: (list) One or more VCI strings in quotes separated by spaces.
                    uci_match:
                        aliases: ['uci-match']
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        aliases: ['uci-string']
                        type: raw
                        description: (list) One or more UCI strings in quotes separated by spaces.
            reserved_address:
                aliases: ['reserved-address']
                type: list
                elements: dict
                description: Reserved address.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'assign'
                            - 'block'
                            - 'reserved'
                    circuit_id:
                        aliases: ['circuit-id']
                        type: str
                        description: Circuit id.
                    circuit_id_type:
                        aliases: ['circuit-id-type']
                        type: str
                        description: Circuit id type.
                        choices:
                            - 'hex'
                            - 'string'
                    description:
                        type: str
                        description: Description.
                    id:
                        type: int
                        description: Id.
                    ip:
                        type: str
                        description: Ip.
                    mac:
                        type: str
                        description: Mac.
                    remote_id:
                        aliases: ['remote-id']
                        type: str
                        description: Remote id.
                    remote_id_type:
                        aliases: ['remote-id-type']
                        type: str
                        description: Remote id type.
                        choices:
                            - 'hex'
                            - 'string'
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'mac'
                            - 'option82'
            server_type:
                aliases: ['server-type']
                type: str
                description: Server type.
                choices:
                    - 'regular'
                    - 'ipsec'
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
            tftp_server:
                aliases: ['tftp-server']
                type: raw
                description: (list) Tftp server.
            timezone:
                type: str
                description: Timezone.
                choices:
                    - '00'
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '39'
                    - '40'
                    - '41'
                    - '42'
                    - '43'
                    - '44'
                    - '45'
                    - '46'
                    - '47'
                    - '48'
                    - '49'
                    - '50'
                    - '51'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '61'
                    - '62'
                    - '63'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '73'
                    - '74'
                    - '75'
                    - '76'
                    - '77'
                    - '78'
                    - '79'
                    - '80'
                    - '81'
                    - '82'
                    - '83'
                    - '84'
                    - '85'
                    - '86'
                    - '87'
            timezone_option:
                aliases: ['timezone-option']
                type: str
                description: Timezone option.
                choices:
                    - 'disable'
                    - 'default'
                    - 'specify'
            vci_match:
                aliases: ['vci-match']
                type: str
                description: Vci match.
                choices:
                    - 'disable'
                    - 'enable'
            vci_string:
                aliases: ['vci-string']
                type: raw
                description: (list) Vci string.
            wifi_ac1:
                aliases: ['wifi-ac1']
                type: str
                description: Wifi ac1.
            wifi_ac2:
                aliases: ['wifi-ac2']
                type: str
                description: Wifi ac2.
            wifi_ac3:
                aliases: ['wifi-ac3']
                type: str
                description: Wifi ac3.
            wins_server1:
                aliases: ['wins-server1']
                type: str
                description: Wins server1.
            wins_server2:
                aliases: ['wins-server2']
                type: str
                description: Wins server2.
            dns_server4:
                aliases: ['dns-server4']
                type: str
                description: Dns server4.
            wifi_ac_service:
                aliases: ['wifi-ac-service']
                type: str
                description: Wifi ac service.
                choices:
                    - 'specify'
                    - 'local'
            auto_managed_status:
                aliases: ['auto-managed-status']
                type: str
                description: Auto managed status.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_settings_from_fortiipam:
                aliases: ['dhcp-settings-from-fortiipam']
                type: str
                description: Dhcp settings from fortiipam.
                choices:
                    - 'disable'
                    - 'enable'
            relay_agent:
                aliases: ['relay-agent']
                type: str
                description: Relay agent IP.
            shared_subnet:
                aliases: ['shared-subnet']
                type: str
                description: Enable/disable shared subnet.
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
    - name: Configure DHCP servers.
      fortinet.fortimanager.fmgr_fsp_vlan_dhcpserver:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        vlan: <your own value>
        fsp_vlan_dhcpserver:
          # auto_configuration: <value in [disable, enable]>
          # conflicted_ip_timeout: <integer>
          # ddns_auth: <value in [disable, tsig]>
          # ddns_key: <list or string>
          # ddns_keyname: <string>
          # ddns_server_ip: <string>
          # ddns_ttl: <integer>
          # ddns_update: <value in [disable, enable]>
          # ddns_update_override: <value in [disable, enable]>
          # ddns_zone: <string>
          # default_gateway: <string>
          # dns_server1: <string>
          # dns_server2: <string>
          # dns_server3: <string>
          # dns_service: <value in [default, specify, local]>
          # domain: <string>
          # enable: <value in [disable, enable]>
          # exclude_range:
          #   - end_ip: <string>
          #     id: <integer>
          #     start_ip: <string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          #     lease_time: <integer>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          # filename: <string>
          # forticlient_on_net_status: <value in [disable, enable]>
          # id: <integer>
          # interface: <string>
          # ip_mode: <value in [range, usrgrp]>
          # ip_range:
          #   - end_ip: <string>
          #     id: <integer>
          #     start_ip: <string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          #     lease_time: <integer>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          # ipsec_lease_hold: <integer>
          # lease_time: <integer>
          # mac_acl_default_action: <value in [assign, block]>
          # netmask: <string>
          # next_server: <string>
          # ntp_server1: <string>
          # ntp_server2: <string>
          # ntp_server3: <string>
          # ntp_service: <value in [default, specify, local]>
          # option1: <list or string>
          # option2: <list or string>
          # option3: <list or string>
          # option4: <string>
          # option5: <string>
          # option6: <string>
          # options:
          #   - code: <integer>
          #     id: <integer>
          #     ip: <list or string>
          #     type: <value in [hex, string, ip, ...]>
          #     value: <string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          # reserved_address:
          #   - action: <value in [assign, block, reserved]>
          #     circuit_id: <string>
          #     circuit_id_type: <value in [hex, string]>
          #     description: <string>
          #     id: <integer>
          #     ip: <string>
          #     mac: <string>
          #     remote_id: <string>
          #     remote_id_type: <value in [hex, string]>
          #     type: <value in [mac, option82]>
          # server_type: <value in [regular, ipsec]>
          # status: <value in [disable, enable]>
          # tftp_server: <list or string>
          # timezone: <value in [00, 01, 02, ...]>
          # timezone_option: <value in [disable, default, specify]>
          # vci_match: <value in [disable, enable]>
          # vci_string: <list or string>
          # wifi_ac1: <string>
          # wifi_ac2: <string>
          # wifi_ac3: <string>
          # wins_server1: <string>
          # wins_server2: <string>
          # dns_server4: <string>
          # wifi_ac_service: <value in [specify, local]>
          # auto_managed_status: <value in [disable, enable]>
          # dhcp_settings_from_fortiipam: <value in [disable, enable]>
          # relay_agent: <string>
          # shared_subnet: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server'
    ]
    url_params = ['adom', 'vlan']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fsp_vlan_dhcpserver': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'auto-configuration': {'choices': ['disable', 'enable'], 'type': 'str'},
                'conflicted-ip-timeout': {'type': 'int'},
                'ddns-auth': {'choices': ['disable', 'tsig'], 'type': 'str'},
                'ddns-key': {'no_log': True, 'type': 'raw'},
                'ddns-keyname': {'no_log': True, 'type': 'str'},
                'ddns-server-ip': {'type': 'str'},
                'ddns-ttl': {'type': 'int'},
                'ddns-update': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-update-override': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-zone': {'type': 'str'},
                'default-gateway': {'type': 'str'},
                'dns-server1': {'type': 'str'},
                'dns-server2': {'type': 'str'},
                'dns-server3': {'type': 'str'},
                'dns-service': {'choices': ['default', 'specify', 'local'], 'type': 'str'},
                'domain': {'type': 'str'},
                'enable': {'choices': ['disable', 'enable'], 'type': 'str'},
                'exclude-range': {
                    'type': 'list',
                    'options': {
                        'end-ip': {'type': 'str'},
                        'id': {'type': 'int'},
                        'start-ip': {'type': 'str'},
                        'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'lease-time': {'v_range': [['7.2.2', '']], 'type': 'int'},
                        'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'filename': {'type': 'str'},
                'forticlient-on-net-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'type': 'int'},
                'interface': {'v_range': [['6.0.0', '6.2.1']], 'type': 'str'},
                'ip-mode': {'choices': ['range', 'usrgrp'], 'type': 'str'},
                'ip-range': {
                    'type': 'list',
                    'options': {
                        'end-ip': {'type': 'str'},
                        'id': {'type': 'int'},
                        'start-ip': {'type': 'str'},
                        'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'lease-time': {'v_range': [['7.2.2', '']], 'type': 'int'},
                        'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'ipsec-lease-hold': {'type': 'int'},
                'lease-time': {'type': 'int'},
                'mac-acl-default-action': {'choices': ['assign', 'block'], 'type': 'str'},
                'netmask': {'type': 'str'},
                'next-server': {'type': 'str'},
                'ntp-server1': {'type': 'str'},
                'ntp-server2': {'type': 'str'},
                'ntp-server3': {'type': 'str'},
                'ntp-service': {'choices': ['default', 'specify', 'local'], 'type': 'str'},
                'option1': {'type': 'raw'},
                'option2': {'type': 'raw'},
                'option3': {'type': 'raw'},
                'option4': {'type': 'str'},
                'option5': {'type': 'str'},
                'option6': {'type': 'str'},
                'options': {
                    'type': 'list',
                    'options': {
                        'code': {'type': 'int'},
                        'id': {'type': 'int'},
                        'ip': {'type': 'raw'},
                        'type': {'choices': ['hex', 'string', 'ip', 'fqdn'], 'type': 'str'},
                        'value': {'type': 'str'},
                        'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'reserved-address': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['assign', 'block', 'reserved'], 'type': 'str'},
                        'circuit-id': {'type': 'str'},
                        'circuit-id-type': {'choices': ['hex', 'string'], 'type': 'str'},
                        'description': {'type': 'str'},
                        'id': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'mac': {'type': 'str'},
                        'remote-id': {'type': 'str'},
                        'remote-id-type': {'choices': ['hex', 'string'], 'type': 'str'},
                        'type': {'choices': ['mac', 'option82'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-type': {'choices': ['regular', 'ipsec'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tftp-server': {'type': 'raw'},
                'timezone': {
                    'choices': [
                        '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20',
                        '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41',
                        '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62',
                        '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83',
                        '84', '85', '86', '87'
                    ],
                    'type': 'str'
                },
                'timezone-option': {'choices': ['disable', 'default', 'specify'], 'type': 'str'},
                'vci-match': {'choices': ['disable', 'enable'], 'type': 'str'},
                'vci-string': {'type': 'raw'},
                'wifi-ac1': {'type': 'str'},
                'wifi-ac2': {'type': 'str'},
                'wifi-ac3': {'type': 'str'},
                'wins-server1': {'type': 'str'},
                'wins-server2': {'type': 'str'},
                'dns-server4': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'wifi-ac-service': {'v_range': [['6.2.2', '']], 'choices': ['specify', 'local'], 'type': 'str'},
                'auto-managed-status': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-settings-from-fortiipam': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'relay-agent': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'shared-subnet': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dhcpserver'),
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
