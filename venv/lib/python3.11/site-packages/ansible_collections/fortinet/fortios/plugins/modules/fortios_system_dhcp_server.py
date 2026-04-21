#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_system_dhcp_server
short_description: Configure DHCP servers in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system_dhcp feature and server category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - We highly recommend using your own value as the id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    system_dhcp_server:
        description:
            - Configure DHCP servers.
        default: null
        type: dict
        suboptions:
            auto_configuration:
                description:
                    - Enable/disable auto configuration.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            auto_managed_status:
                description:
                    - Enable/disable use of this DHCP server once this interface has been assigned an IP address from FortiIPAM.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            conflicted_ip_timeout:
                description:
                    - Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.
                type: int
            ddns_auth:
                description:
                    - DDNS authentication mode.
                type: str
                choices:
                    - 'disable'
                    - 'tsig'
            ddns_key:
                description:
                    - DDNS update key (base 64 encoding).
                type: str
            ddns_keyname:
                description:
                    - DDNS update key name.
                type: str
            ddns_server_ip:
                description:
                    - DDNS server IP.
                type: str
            ddns_ttl:
                description:
                    - TTL.
                type: int
            ddns_update:
                description:
                    - Enable/disable DDNS update for DHCP.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ddns_update_override:
                description:
                    - Enable/disable DDNS update override for DHCP.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ddns_zone:
                description:
                    - Zone of your domain name (ex. DDNS.com).
                type: str
            default_gateway:
                description:
                    - Default gateway IP address assigned by the DHCP server.
                type: str
            dhcp_settings_from_fortiipam:
                description:
                    - Enable/disable populating of DHCP server settings from FortiIPAM.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dns_server1:
                description:
                    - DNS server 1.
                type: str
            dns_server2:
                description:
                    - DNS server 2.
                type: str
            dns_server3:
                description:
                    - DNS server 3.
                type: str
            dns_server4:
                description:
                    - DNS server 4.
                type: str
            dns_service:
                description:
                    - Options for assigning DNS servers to DHCP clients.
                type: str
                choices:
                    - 'local'
                    - 'default'
                    - 'specify'
            domain:
                description:
                    - Domain name suffix for the IP addresses that the DHCP server assigns to clients.
                type: str
            exclude_range:
                description:
                    - Exclude one or more ranges of IP addresses from being assigned to clients.
                type: list
                elements: dict
                suboptions:
                    end_ip:
                        description:
                            - End of IP range.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    lease_time:
                        description:
                            - Lease time in seconds, 0 means default lease time.
                        type: int
                    start_ip:
                        description:
                            - Start of IP range.
                        type: str
                    uci_match:
                        description:
                            - Enable/disable user class identifier (UCI) matching. When enabled only DHCP requests with a matching UCI are served with this
                               range.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        description:
                            - One or more UCI strings in quotes separated by spaces.
                        type: list
                        elements: dict
                        suboptions:
                            uci_string:
                                description:
                                    - UCI strings.
                                required: true
                                type: str
                    vci_match:
                        description:
                            - Enable/disable vendor class identifier (VCI) matching. When enabled only DHCP requests with a matching VCI are served with this
                               range.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        description:
                            - One or more VCI strings in quotes separated by spaces.
                        type: list
                        elements: dict
                        suboptions:
                            vci_string:
                                description:
                                    - VCI strings.
                                required: true
                                type: str
            filename:
                description:
                    - Name of the boot file on the TFTP server.
                type: str
            forticlient_on_net_status:
                description:
                    - Enable/disable FortiClient-On-Net service for this DHCP server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            id:
                description:
                    - ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            interface:
                description:
                    - DHCP server can assign IP configurations to clients connected to this interface. Source system.interface.name.
                type: str
            ip_mode:
                description:
                    - Method used to assign client IP.
                type: str
                choices:
                    - 'range'
                    - 'usrgrp'
            ip_range:
                description:
                    - DHCP IP range configuration.
                type: list
                elements: dict
                suboptions:
                    end_ip:
                        description:
                            - End of IP range.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    lease_time:
                        description:
                            - Lease time in seconds, 0 means default lease time.
                        type: int
                    start_ip:
                        description:
                            - Start of IP range.
                        type: str
                    uci_match:
                        description:
                            - Enable/disable user class identifier (UCI) matching. When enabled only DHCP requests with a matching UCI are served with this
                               range.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        description:
                            - One or more UCI strings in quotes separated by spaces.
                        type: list
                        elements: dict
                        suboptions:
                            uci_string:
                                description:
                                    - UCI strings.
                                required: true
                                type: str
                    vci_match:
                        description:
                            - Enable/disable vendor class identifier (VCI) matching. When enabled only DHCP requests with a matching VCI are served with this
                               range.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        description:
                            - One or more VCI strings in quotes separated by spaces.
                        type: list
                        elements: dict
                        suboptions:
                            vci_string:
                                description:
                                    - VCI strings.
                                required: true
                                type: str
            ipsec_lease_hold:
                description:
                    - DHCP over IPsec leases expire this many seconds after tunnel down (0 to disable forced-expiry).
                type: int
            lease_time:
                description:
                    - Lease time in seconds, 0 means unlimited.
                type: int
            mac_acl_default_action:
                description:
                    - MAC access control default action (allow or block assigning IP settings).
                type: str
                choices:
                    - 'assign'
                    - 'block'
            netmask:
                description:
                    - Netmask assigned by the DHCP server.
                type: str
            next_server:
                description:
                    - IP address of a server (for example, a TFTP sever) that DHCP clients can download a boot file from.
                type: str
            ntp_server1:
                description:
                    - NTP server 1.
                type: str
            ntp_server2:
                description:
                    - NTP server 2.
                type: str
            ntp_server3:
                description:
                    - NTP server 3.
                type: str
            ntp_service:
                description:
                    - Options for assigning Network Time Protocol (NTP) servers to DHCP clients.
                type: str
                choices:
                    - 'local'
                    - 'default'
                    - 'specify'
            options:
                description:
                    - DHCP options.
                type: list
                elements: dict
                suboptions:
                    code:
                        description:
                            - DHCP option code.
                        type: int
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip:
                        description:
                            - DHCP option IPs.
                        type: list
                        elements: str
                    type:
                        description:
                            - DHCP option type.
                        type: str
                        choices:
                            - 'hex'
                            - 'string'
                            - 'ip'
                            - 'fqdn'
                    uci_match:
                        description:
                            - Enable/disable user class identifier (UCI) matching. When enabled only DHCP requests with a matching UCI are served with this
                               option.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    uci_string:
                        description:
                            - One or more UCI strings in quotes separated by spaces.
                        type: list
                        elements: dict
                        suboptions:
                            uci_string:
                                description:
                                    - UCI strings.
                                required: true
                                type: str
                    value:
                        description:
                            - DHCP option value.
                        type: str
                    vci_match:
                        description:
                            - Enable/disable vendor class identifier (VCI) matching. When enabled only DHCP requests with a matching VCI are served with this
                               option.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        description:
                            - One or more VCI strings in quotes separated by spaces.
                        type: list
                        elements: dict
                        suboptions:
                            vci_string:
                                description:
                                    - VCI strings.
                                required: true
                                type: str
            relay_agent:
                description:
                    - Relay agent IP.
                type: str
            reserved_address:
                description:
                    - Options for the DHCP server to assign IP settings to specific MAC addresses.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Options for the DHCP server to configure the client with the reserved MAC address.
                        type: str
                        choices:
                            - 'assign'
                            - 'block'
                            - 'reserved'
                    circuit_id:
                        description:
                            - Option 82 circuit-ID of the client that will get the reserved IP address.
                        type: str
                    circuit_id_type:
                        description:
                            - DHCP option type.
                        type: str
                        choices:
                            - 'hex'
                            - 'string'
                    description:
                        description:
                            - Description.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip:
                        description:
                            - IP address to be reserved for the MAC address.
                        type: str
                    mac:
                        description:
                            - MAC address of the client that will get the reserved IP address.
                        type: str
                    remote_id:
                        description:
                            - Option 82 remote-ID of the client that will get the reserved IP address.
                        type: str
                    remote_id_type:
                        description:
                            - DHCP option type.
                        type: str
                        choices:
                            - 'hex'
                            - 'string'
                    type:
                        description:
                            - DHCP reserved-address type.
                        type: str
                        choices:
                            - 'mac'
                            - 'option82'
            server_type:
                description:
                    - DHCP server can be a normal DHCP server or an IPsec DHCP server.
                type: str
                choices:
                    - 'regular'
                    - 'ipsec'
            shared_subnet:
                description:
                    - Enable/disable shared subnet.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            status:
                description:
                    - Enable/disable this DHCP configuration.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            tftp_server:
                description:
                    - One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.
                type: list
                elements: dict
                suboptions:
                    tftp_server:
                        description:
                            - TFTP server.
                        required: true
                        type: str
            timezone:
                description:
                    - Select the time zone to be assigned to DHCP clients. Source system.timezone.name.
                type: str
                choices:
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '81'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '74'
                    - '14'
                    - '77'
                    - '15'
                    - '87'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '75'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '80'
                    - '79'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '78'
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
                    - '83'
                    - '84'
                    - '40'
                    - '85'
                    - '39'
                    - '41'
                    - '42'
                    - '43'
                    - '44'
                    - '45'
                    - '46'
                    - '47'
                    - '51'
                    - '48'
                    - '49'
                    - '50'
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
                    - '00'
                    - '82'
                    - '73'
                    - '86'
                    - '76'
            timezone_option:
                description:
                    - Options for the DHCP server to set the client"s time zone.
                type: str
                choices:
                    - 'disable'
                    - 'default'
                    - 'specify'
            vci_match:
                description:
                    - Enable/disable vendor class identifier (VCI) matching. When enabled only DHCP requests with a matching VCI are served.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            vci_string:
                description:
                    - One or more VCI strings in quotes separated by spaces.
                type: list
                elements: dict
                suboptions:
                    vci_string:
                        description:
                            - VCI strings.
                        required: true
                        type: str
            wifi_ac_service:
                description:
                    - Options for assigning WiFi access controllers to DHCP clients.
                type: str
                choices:
                    - 'specify'
                    - 'local'
            wifi_ac1:
                description:
                    - WiFi Access Controller 1 IP address (DHCP option 138, RFC 5417).
                type: str
            wifi_ac2:
                description:
                    - WiFi Access Controller 2 IP address (DHCP option 138, RFC 5417).
                type: str
            wifi_ac3:
                description:
                    - WiFi Access Controller 3 IP address (DHCP option 138, RFC 5417).
                type: str
            wins_server1:
                description:
                    - WINS server 1.
                type: str
            wins_server2:
                description:
                    - WINS server 2.
                type: str
"""

EXAMPLES = """
- name: Configure DHCP servers.
  fortinet.fortios.fortios_system_dhcp_server:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_dhcp_server:
          auto_configuration: "disable"
          auto_managed_status: "disable"
          conflicted_ip_timeout: "1800"
          ddns_auth: "disable"
          ddns_key: "<your_own_value>"
          ddns_keyname: "<your_own_value>"
          ddns_server_ip: "<your_own_value>"
          ddns_ttl: "300"
          ddns_update: "disable"
          ddns_update_override: "disable"
          ddns_zone: "<your_own_value>"
          default_gateway: "<your_own_value>"
          dhcp_settings_from_fortiipam: "disable"
          dns_server1: "<your_own_value>"
          dns_server2: "<your_own_value>"
          dns_server3: "<your_own_value>"
          dns_server4: "<your_own_value>"
          dns_service: "local"
          domain: "<your_own_value>"
          exclude_range:
              -
                  end_ip: "<your_own_value>"
                  id: "24"
                  lease_time: "0"
                  start_ip: "<your_own_value>"
                  uci_match: "disable"
                  uci_string:
                      -
                          uci_string: "<your_own_value>"
                  vci_match: "disable"
                  vci_string:
                      -
                          vci_string: "<your_own_value>"
          filename: "<your_own_value>"
          forticlient_on_net_status: "disable"
          id: "35"
          interface: "<your_own_value> (source system.interface.name)"
          ip_mode: "range"
          ip_range:
              -
                  end_ip: "<your_own_value>"
                  id: "40"
                  lease_time: "0"
                  start_ip: "<your_own_value>"
                  uci_match: "disable"
                  uci_string:
                      -
                          uci_string: "<your_own_value>"
                  vci_match: "disable"
                  vci_string:
                      -
                          vci_string: "<your_own_value>"
          ipsec_lease_hold: "60"
          lease_time: "604800"
          mac_acl_default_action: "assign"
          netmask: "<your_own_value>"
          next_server: "<your_own_value>"
          ntp_server1: "<your_own_value>"
          ntp_server2: "<your_own_value>"
          ntp_server3: "<your_own_value>"
          ntp_service: "local"
          options:
              -
                  code: "0"
                  id: "60"
                  ip: "<your_own_value>"
                  type: "hex"
                  uci_match: "disable"
                  uci_string:
                      -
                          uci_string: "<your_own_value>"
                  value: "<your_own_value>"
                  vci_match: "disable"
                  vci_string:
                      -
                          vci_string: "<your_own_value>"
          relay_agent: "<your_own_value>"
          reserved_address:
              -
                  action: "assign"
                  circuit_id: "<your_own_value>"
                  circuit_id_type: "hex"
                  description: "<your_own_value>"
                  id: "76"
                  ip: "<your_own_value>"
                  mac: "<your_own_value>"
                  remote_id: "<your_own_value>"
                  remote_id_type: "hex"
                  type: "mac"
          server_type: "regular"
          shared_subnet: "disable"
          status: "disable"
          tftp_server:
              -
                  tftp_server: "<your_own_value>"
          timezone: "01"
          timezone_option: "disable"
          vci_match: "disable"
          vci_string:
              -
                  vci_string: "<your_own_value>"
          wifi_ac_service: "specify"
          wifi_ac1: "<your_own_value>"
          wifi_ac2: "<your_own_value>"
          wifi_ac3: "<your_own_value>"
          wins_server1: "<your_own_value>"
          wins_server2: "<your_own_value>"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_system_dhcp_server_data(json):
    option_list = [
        "auto_configuration",
        "auto_managed_status",
        "conflicted_ip_timeout",
        "ddns_auth",
        "ddns_key",
        "ddns_keyname",
        "ddns_server_ip",
        "ddns_ttl",
        "ddns_update",
        "ddns_update_override",
        "ddns_zone",
        "default_gateway",
        "dhcp_settings_from_fortiipam",
        "dns_server1",
        "dns_server2",
        "dns_server3",
        "dns_server4",
        "dns_service",
        "domain",
        "exclude_range",
        "filename",
        "forticlient_on_net_status",
        "id",
        "interface",
        "ip_mode",
        "ip_range",
        "ipsec_lease_hold",
        "lease_time",
        "mac_acl_default_action",
        "netmask",
        "next_server",
        "ntp_server1",
        "ntp_server2",
        "ntp_server3",
        "ntp_service",
        "options",
        "relay_agent",
        "reserved_address",
        "server_type",
        "shared_subnet",
        "status",
        "tftp_server",
        "timezone",
        "timezone_option",
        "vci_match",
        "vci_string",
        "wifi_ac_service",
        "wifi_ac1",
        "wifi_ac2",
        "wifi_ac3",
        "wins_server1",
        "wins_server2",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["options", "ip"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def system_dhcp_server(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_dhcp_server_data = data["system_dhcp_server"]

    filtered_data = filter_system_dhcp_server_data(system_dhcp_server_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system.dhcp", "server", filtered_data, vdom=vdom)
        current_data = fos.get("system.dhcp", "server", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["system_dhcp_server"] = filtered_data
    fos.do_member_operation(
        "system.dhcp",
        "server",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system.dhcp", "server", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("system.dhcp", "server", mkey=converted_data["id"], vdom=vdom)
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_system_dhcp(data, fos, check_mode):

    if data["system_dhcp_server"]:
        resp = system_dhcp_server(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_dhcp_server"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "lease_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "mac_acl_default_action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "assign"}, {"value": "block"}],
        },
        "forticlient_on_net_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "dns_service": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "local"}, {"value": "default"}, {"value": "specify"}],
        },
        "dns_server1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dns_server2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dns_server3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dns_server4": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "wifi_ac_service": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "specify"}, {"value": "local"}],
        },
        "wifi_ac1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wifi_ac2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wifi_ac3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ntp_service": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "local"}, {"value": "default"}, {"value": "specify"}],
        },
        "ntp_server1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ntp_server2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ntp_server3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "domain": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wins_server1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wins_server2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "default_gateway": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "next_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "netmask": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "vci_match": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "vci_string": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vci_string": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.1", ""]],
                },
                "uci_match": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "uci_string": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "uci_string": {
                            "v_range": [["v7.2.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.4", ""]],
                },
                "lease_time": {"v_range": [["v7.2.4", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "timezone_option": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "default"},
                {"value": "specify"},
            ],
        },
        "timezone": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "01", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "02", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "03", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "04", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "05", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "81", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "06", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "07", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "08", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "09", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "10", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "11", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "12", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "13", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "74", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "14", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "77", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "15", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "87", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "16", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "17", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "18", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "19", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "20", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "75", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "21", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "22", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "23", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "24", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "80", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "79", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "25", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "26", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "27", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "28", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "78", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "29", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "30", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "31", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "32", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "33", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "34", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "35", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "36", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "37", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "38", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "83", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "84", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "40", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "85", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "39", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "41", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "42", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "43", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "44", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "45", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "46", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "47", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "51", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "48", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "49", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "50", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "52", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "53", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "54", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "55", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "56", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "57", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "58", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "59", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "60", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "61", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "62", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "63", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "64", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "65", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "66", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "67", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "68", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "69", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "70", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "71", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "72", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "00", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "82", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "73", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "86", "v_range": [["v6.0.0", "v7.4.1"]]},
                {"value": "76", "v_range": [["v6.0.0", "v7.4.1"]]},
            ],
        },
        "tftp_server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "tftp_server": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "filename": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "options": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "code": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "hex"},
                        {"value": "string"},
                        {"value": "ip"},
                        {"value": "fqdn"},
                    ],
                },
                "value": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ip": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "vci_match": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "vci_string": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vci_string": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.1", ""]],
                },
                "uci_match": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "uci_string": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "uci_string": {
                            "v_range": [["v7.2.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.4", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "server_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "regular"}, {"value": "ipsec"}],
        },
        "ip_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "range"}, {"value": "usrgrp"}],
        },
        "conflicted_ip_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipsec_lease_hold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auto_configuration": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "dhcp_settings_from_fortiipam": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auto_managed_status": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ddns_update": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ddns_update_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ddns_server_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_zone": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "tsig"}],
        },
        "ddns_keyname": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "vci_match": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "vci_string": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vci_string": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "exclude_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "vci_match": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "vci_string": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vci_string": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.1", ""]],
                },
                "uci_match": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "uci_string": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "uci_string": {
                            "v_range": [["v7.2.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.4", ""]],
                },
                "lease_time": {"v_range": [["v7.2.4", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "shared_subnet": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "relay_agent": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "reserved_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "mac"}, {"value": "option82"}],
                },
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "mac": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "assign"},
                        {"value": "block"},
                        {"value": "reserved"},
                    ],
                },
                "circuit_id_type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "hex"}, {"value": "string"}],
                },
                "circuit_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "remote_id_type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "hex"}, {"value": "string"}],
                },
                "remote_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "id"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "system_dhcp_server": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_dhcp_server"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dhcp_server"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_dhcp_server"
        )

        is_error, has_changed, result, diff = fortios_system_dhcp(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
