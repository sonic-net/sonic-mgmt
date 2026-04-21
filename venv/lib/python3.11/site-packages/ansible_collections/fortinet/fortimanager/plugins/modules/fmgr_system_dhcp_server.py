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
module: fmgr_system_dhcp_server
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
    system_dhcp_server:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auto_configuration:
                aliases: ['auto-configuration']
                type: str
                description: Enable/disable auto configuration.
                choices:
                    - 'disable'
                    - 'enable'
            conflicted_ip_timeout:
                aliases: ['conflicted-ip-timeout']
                type: int
                description: Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.
            ddns_auth:
                aliases: ['ddns-auth']
                type: str
                description: DDNS authentication mode.
                choices:
                    - 'disable'
                    - 'tsig'
            ddns_key:
                aliases: ['ddns-key']
                type: raw
                description: (list or str) DDNS update key
            ddns_keyname:
                aliases: ['ddns-keyname']
                type: str
                description: DDNS update key name.
            ddns_server_ip:
                aliases: ['ddns-server-ip']
                type: str
                description: DDNS server IP.
            ddns_ttl:
                aliases: ['ddns-ttl']
                type: int
                description: TTL.
            ddns_update:
                aliases: ['ddns-update']
                type: str
                description: Enable/disable DDNS update for DHCP.
                choices:
                    - 'disable'
                    - 'enable'
            ddns_update_override:
                aliases: ['ddns-update-override']
                type: str
                description: Enable/disable DDNS update override for DHCP.
                choices:
                    - 'disable'
                    - 'enable'
            ddns_zone:
                aliases: ['ddns-zone']
                type: str
                description: Zone of your domain name
            default_gateway:
                aliases: ['default-gateway']
                type: str
                description: Default gateway IP address assigned by the DHCP server.
            dns_server1:
                aliases: ['dns-server1']
                type: str
                description: DNS server 1.
            dns_server2:
                aliases: ['dns-server2']
                type: str
                description: DNS server 2.
            dns_server3:
                aliases: ['dns-server3']
                type: str
                description: DNS server 3.
            dns_service:
                aliases: ['dns-service']
                type: str
                description: Options for assigning DNS servers to DHCP clients.
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            domain:
                type: str
                description: Domain name suffix for the IP addresses that the DHCP server assigns to clients.
            exclude_range:
                aliases: ['exclude-range']
                type: list
                elements: dict
                description: Exclude range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End of IP range.
                    id:
                        type: int
                        description: ID.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start of IP range.
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
                description: Name of the boot file on the TFTP server.
            forticlient_on_net_status:
                aliases: ['forticlient-on-net-status']
                type: str
                description: Enable/disable FortiClient-On-Net service for this DHCP server.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: ID.
                required: true
            interface:
                type: str
                description: DHCP server can assign IP configurations to clients connected to this interface.
            ip_mode:
                aliases: ['ip-mode']
                type: str
                description: Method used to assign client IP.
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
                        description: End of IP range.
                    id:
                        type: int
                        description: ID.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start of IP range.
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
                description: DHCP over IPsec leases expire this many seconds after tunnel down
            lease_time:
                aliases: ['lease-time']
                type: int
                description: Lease time in seconds, 0 means unlimited.
            mac_acl_default_action:
                aliases: ['mac-acl-default-action']
                type: str
                description: MAC access control default action
                choices:
                    - 'assign'
                    - 'block'
            netmask:
                type: str
                description: Netmask assigned by the DHCP server.
            next_server:
                aliases: ['next-server']
                type: str
                description: IP address of a server
            ntp_server1:
                aliases: ['ntp-server1']
                type: str
                description: NTP server 1.
            ntp_server2:
                aliases: ['ntp-server2']
                type: str
                description: NTP server 2.
            ntp_server3:
                aliases: ['ntp-server3']
                type: str
                description: NTP server 3.
            ntp_service:
                aliases: ['ntp-service']
                type: str
                description: Options for assigning Network Time Protocol
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            options:
                type: list
                elements: dict
                description: Options.
                suboptions:
                    code:
                        type: int
                        description: DHCP option code.
                    id:
                        type: int
                        description: ID.
                    ip:
                        type: raw
                        description: (list) DHCP option IPs.
                    type:
                        type: str
                        description: DHCP option type.
                        choices:
                            - 'hex'
                            - 'string'
                            - 'ip'
                            - 'fqdn'
                    value:
                        type: str
                        description: DHCP option value.
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
                        description: Options for the DHCP server to configure the client with the reserved MAC address.
                        choices:
                            - 'assign'
                            - 'block'
                            - 'reserved'
                    description:
                        type: str
                        description: Description.
                    id:
                        type: int
                        description: ID.
                    ip:
                        type: str
                        description: IP address to be reserved for the MAC address.
                    mac:
                        type: str
                        description: MAC address of the client that will get the reserved IP address.
                    circuit_id:
                        aliases: ['circuit-id']
                        type: str
                        description: Option 82 circuit-ID of the client that will get the reserved IP address.
                    circuit_id_type:
                        aliases: ['circuit-id-type']
                        type: str
                        description: DHCP option type.
                        choices:
                            - 'hex'
                            - 'string'
                    remote_id:
                        aliases: ['remote-id']
                        type: str
                        description: Option 82 remote-ID of the client that will get the reserved IP address.
                    remote_id_type:
                        aliases: ['remote-id-type']
                        type: str
                        description: DHCP option type.
                        choices:
                            - 'hex'
                            - 'string'
                    type:
                        type: str
                        description: DHCP reserved-address type.
                        choices:
                            - 'mac'
                            - 'option82'
            server_type:
                aliases: ['server-type']
                type: str
                description: DHCP server can be a normal DHCP server or an IPsec DHCP server.
                choices:
                    - 'regular'
                    - 'ipsec'
            status:
                type: str
                description: Enable/disable this DHCP configuration.
                choices:
                    - 'disable'
                    - 'enable'
            tftp_server:
                aliases: ['tftp-server']
                type: raw
                description: (list) One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.
            timezone:
                type: str
                description: Select the time zone to be assigned to DHCP clients.
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
                description: Options for the DHCP server to set the clients time zone.
                choices:
                    - 'disable'
                    - 'default'
                    - 'specify'
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
            wifi_ac1:
                aliases: ['wifi-ac1']
                type: str
                description: WiFi Access Controller 1 IP address
            wifi_ac2:
                aliases: ['wifi-ac2']
                type: str
                description: WiFi Access Controller 2 IP address
            wifi_ac3:
                aliases: ['wifi-ac3']
                type: str
                description: WiFi Access Controller 3 IP address
            wins_server1:
                aliases: ['wins-server1']
                type: str
                description: WINS server 1.
            wins_server2:
                aliases: ['wins-server2']
                type: str
                description: WINS server 2.
            dns_server4:
                aliases: ['dns-server4']
                type: str
                description: DNS server 4.
            wifi_ac_service:
                aliases: ['wifi-ac-service']
                type: str
                description: Options for assigning WiFi Access Controllers to DHCP clients
                choices:
                    - 'specify'
                    - 'local'
            auto_managed_status:
                aliases: ['auto-managed-status']
                type: str
                description: Enable/disable use of this DHCP server once this interface has been assigned an IP address from FortiIPAM.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_settings_from_fortiipam:
                aliases: ['dhcp-settings-from-fortiipam']
                type: str
                description: Enable/disable populating of DHCP server settings from FortiIPAM.
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
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure DHCP servers.
      fortinet.fortimanager.fmgr_system_dhcp_server:
        bypass_validation: false
        adom: ansible
        state: present
        system_dhcp_server:
          auto_configuration: enable # <value in [disable, enable]>
          default_gateway: "222.222.222.1"
          filename: ansible-file
          id: 1
          interface: any
          ip_mode: range # <value in [range, usrgrp]>
          ip_range:
            - end_ip: 222.222.222.22
              id: 1
              start_ip: 222.222.222.2
          netmask: 255.255.255.0
          server_type: regular # <value in [regular, ipsec]>
          status: disable # <value in [disable, enable]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the DHCP servers
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_dhcp_server"
          params:
            adom: "ansible"
            server: "your_value"
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
        '/pm/config/adom/{adom}/obj/system/dhcp/server',
        '/pm/config/global/obj/system/dhcp/server'
    ]
    url_params = ['adom']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_dhcp_server': {
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
                'id': {'required': True, 'type': 'int'},
                'interface': {'type': 'str'},
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
                        'description': {'type': 'str'},
                        'id': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'mac': {'type': 'str'},
                        'circuit-id': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'circuit-id-type': {'v_range': [['6.2.0', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                        'remote-id': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'remote-id-type': {'v_range': [['6.2.0', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                        'type': {'v_range': [['6.2.0', '']], 'choices': ['mac', 'option82'], 'type': 'str'}
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

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_server'),
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
