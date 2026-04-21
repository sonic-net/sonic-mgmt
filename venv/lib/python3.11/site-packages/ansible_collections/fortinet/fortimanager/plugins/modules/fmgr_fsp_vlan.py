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
module: fmgr_fsp_vlan
short_description: FortiSwitch VLAN template.
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
    fsp_vlan:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _dhcp_status:
                aliases: ['_dhcp-status']
                type: str
                description: Dhcp status.
                choices:
                    - 'disable'
                    - 'enable'
            auth:
                type: str
                description: Auth.
                choices:
                    - 'radius'
                    - 'usergroup'
            color:
                type: int
                description: Color.
            comments:
                type: str
                description: Comments.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _dhcp_status:
                        aliases: ['_dhcp-status']
                        type: str
                        description: Dhcp status.
                        choices:
                            - 'disable'
                            - 'enable'
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    dhcp_server:
                        aliases: ['dhcp-server']
                        type: dict
                        description: Dhcp server.
                        suboptions:
                            auto_configuration:
                                aliases: ['auto-configuration']
                                type: str
                                description: Enable/disable auto configuration.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            auto_managed_status:
                                aliases: ['auto-managed-status']
                                type: str
                                description: Enable/disable use of this DHCP server once this interface has been assigned an IP address from FortiIPAM.
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
                            dhcp_settings_from_fortiipam:
                                aliases: ['dhcp-settings-from-fortiipam']
                                type: str
                                description: Enable/disable populating of DHCP server settings from FortiIPAM.
                                choices:
                                    - 'disable'
                                    - 'enable'
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
                            dns_server4:
                                aliases: ['dns-server4']
                                type: str
                                description: DNS server 4.
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
                            wifi_ac_service:
                                aliases: ['wifi-ac-service']
                                type: str
                                description: Options for assigning WiFi Access Controllers to DHCP clients
                                choices:
                                    - 'specify'
                                    - 'local'
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
                    interface:
                        type: dict
                        description: Interface.
                        suboptions:
                            dhcp_relay_agent_option:
                                aliases: ['dhcp-relay-agent-option']
                                type: str
                                description: Dhcp relay agent option.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp_relay_ip:
                                aliases: ['dhcp-relay-ip']
                                type: raw
                                description: (list) Dhcp relay ip.
                            dhcp_relay_service:
                                aliases: ['dhcp-relay-service']
                                type: str
                                description: Dhcp relay service.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp_relay_type:
                                aliases: ['dhcp-relay-type']
                                type: str
                                description: Dhcp relay type.
                                choices:
                                    - 'regular'
                                    - 'ipsec'
                            ip:
                                type: str
                                description: Ip.
                            ipv6:
                                type: dict
                                description: Ipv6.
                                suboptions:
                                    autoconf:
                                        type: str
                                        description: Enable/disable address auto config.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6_client_options:
                                        aliases: ['dhcp6-client-options']
                                        type: list
                                        elements: str
                                        description: Dhcp6 client options.
                                        choices:
                                            - 'rapid'
                                            - 'iapd'
                                            - 'iana'
                                            - 'dns'
                                            - 'dnsname'
                                    dhcp6_information_request:
                                        aliases: ['dhcp6-information-request']
                                        type: str
                                        description: Enable/disable DHCPv6 information request.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6_prefix_delegation:
                                        aliases: ['dhcp6-prefix-delegation']
                                        type: str
                                        description: Enable/disable DHCPv6 prefix delegation.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6_prefix_hint:
                                        aliases: ['dhcp6-prefix-hint']
                                        type: str
                                        description: DHCPv6 prefix that will be used as a hint to the upstream DHCPv6 server.
                                    dhcp6_prefix_hint_plt:
                                        aliases: ['dhcp6-prefix-hint-plt']
                                        type: int
                                        description: DHCPv6 prefix hint preferred life time
                                    dhcp6_prefix_hint_vlt:
                                        aliases: ['dhcp6-prefix-hint-vlt']
                                        type: int
                                        description: DHCPv6 prefix hint valid life time
                                    dhcp6_relay_ip:
                                        aliases: ['dhcp6-relay-ip']
                                        type: str
                                        description: DHCPv6 relay IP address.
                                    dhcp6_relay_service:
                                        aliases: ['dhcp6-relay-service']
                                        type: str
                                        description: Enable/disable DHCPv6 relay.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6_relay_type:
                                        aliases: ['dhcp6-relay-type']
                                        type: str
                                        description: DHCPv6 relay type.
                                        choices:
                                            - 'regular'
                                    icmp6_send_redirect:
                                        aliases: ['icmp6-send-redirect']
                                        type: str
                                        description: Enable/disable sending of ICMPv6 redirects.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    interface_identifier:
                                        aliases: ['interface-identifier']
                                        type: str
                                        description: IPv6 interface identifier.
                                    ip6_address:
                                        aliases: ['ip6-address']
                                        type: str
                                        description: Primary IPv6 address prefix, syntax
                                    ip6_allowaccess:
                                        aliases: ['ip6-allowaccess']
                                        type: list
                                        elements: str
                                        description: Allow management access to the interface.
                                        choices:
                                            - 'https'
                                            - 'ping'
                                            - 'ssh'
                                            - 'snmp'
                                            - 'http'
                                            - 'telnet'
                                            - 'fgfm'
                                            - 'capwap'
                                            - 'fabric'
                                    ip6_default_life:
                                        aliases: ['ip6-default-life']
                                        type: int
                                        description: Default life
                                    ip6_delegated_prefix_list:
                                        aliases: ['ip6-delegated-prefix-list']
                                        type: list
                                        elements: dict
                                        description: Ip6 delegated prefix list.
                                        suboptions:
                                            autonomous_flag:
                                                aliases: ['autonomous-flag']
                                                type: str
                                                description: Enable/disable the autonomous flag.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            onlink_flag:
                                                aliases: ['onlink-flag']
                                                type: str
                                                description: Enable/disable the onlink flag.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            prefix_id:
                                                aliases: ['prefix-id']
                                                type: int
                                                description: Prefix ID.
                                            rdnss:
                                                type: raw
                                                description: (list) Recursive DNS server option.
                                            rdnss_service:
                                                aliases: ['rdnss-service']
                                                type: str
                                                description: Recursive DNS service option.
                                                choices:
                                                    - 'delegated'
                                                    - 'default'
                                                    - 'specify'
                                            subnet:
                                                type: str
                                                description: Add subnet ID to routing prefix.
                                            upstream_interface:
                                                aliases: ['upstream-interface']
                                                type: str
                                                description: Name of the interface that provides delegated information.
                                            delegated_prefix_iaid:
                                                aliases: ['delegated-prefix-iaid']
                                                type: int
                                                description: IAID of obtained delegated-prefix from the upstream interface.
                                    ip6_dns_server_override:
                                        aliases: ['ip6-dns-server-override']
                                        type: str
                                        description: Enable/disable using the DNS server acquired by DHCP.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6_extra_addr:
                                        aliases: ['ip6-extra-addr']
                                        type: list
                                        elements: dict
                                        description: Ip6 extra addr.
                                        suboptions:
                                            prefix:
                                                type: str
                                                description: IPv6 address prefix.
                                    ip6_hop_limit:
                                        aliases: ['ip6-hop-limit']
                                        type: int
                                        description: Hop limit
                                    ip6_link_mtu:
                                        aliases: ['ip6-link-mtu']
                                        type: int
                                        description: IPv6 link MTU.
                                    ip6_manage_flag:
                                        aliases: ['ip6-manage-flag']
                                        type: str
                                        description: Enable/disable the managed flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6_max_interval:
                                        aliases: ['ip6-max-interval']
                                        type: int
                                        description: IPv6 maximum interval
                                    ip6_min_interval:
                                        aliases: ['ip6-min-interval']
                                        type: int
                                        description: IPv6 minimum interval
                                    ip6_mode:
                                        aliases: ['ip6-mode']
                                        type: str
                                        description: Addressing mode
                                        choices:
                                            - 'static'
                                            - 'dhcp'
                                            - 'pppoe'
                                            - 'delegated'
                                    ip6_other_flag:
                                        aliases: ['ip6-other-flag']
                                        type: str
                                        description: Enable/disable the other IPv6 flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6_prefix_list:
                                        aliases: ['ip6-prefix-list']
                                        type: list
                                        elements: dict
                                        description: Ip6 prefix list.
                                        suboptions:
                                            autonomous_flag:
                                                aliases: ['autonomous-flag']
                                                type: str
                                                description: Enable/disable the autonomous flag.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            dnssl:
                                                type: raw
                                                description: (list) DNS search list option.
                                            onlink_flag:
                                                aliases: ['onlink-flag']
                                                type: str
                                                description: Enable/disable the onlink flag.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            preferred_life_time:
                                                aliases: ['preferred-life-time']
                                                type: int
                                                description: Preferred life time
                                            prefix:
                                                type: str
                                                description: IPv6 prefix.
                                            rdnss:
                                                type: raw
                                                description: (list) Recursive DNS server option.
                                            valid_life_time:
                                                aliases: ['valid-life-time']
                                                type: int
                                                description: Valid life time
                                    ip6_reachable_time:
                                        aliases: ['ip6-reachable-time']
                                        type: int
                                        description: IPv6 reachable time
                                    ip6_retrans_time:
                                        aliases: ['ip6-retrans-time']
                                        type: int
                                        description: IPv6 retransmit time
                                    ip6_send_adv:
                                        aliases: ['ip6-send-adv']
                                        type: str
                                        description: Enable/disable sending advertisements about the interface.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6_subnet:
                                        aliases: ['ip6-subnet']
                                        type: str
                                        description: Subnet to routing prefix, syntax
                                    ip6_upstream_interface:
                                        aliases: ['ip6-upstream-interface']
                                        type: str
                                        description: Interface name providing delegated information.
                                    nd_cert:
                                        aliases: ['nd-cert']
                                        type: str
                                        description: Neighbor discovery certificate.
                                    nd_cga_modifier:
                                        aliases: ['nd-cga-modifier']
                                        type: str
                                        description: Neighbor discovery CGA modifier.
                                    nd_mode:
                                        aliases: ['nd-mode']
                                        type: str
                                        description: Neighbor discovery mode.
                                        choices:
                                            - 'basic'
                                            - 'SEND-compatible'
                                    nd_security_level:
                                        aliases: ['nd-security-level']
                                        type: int
                                        description: Neighbor discovery security level
                                    nd_timestamp_delta:
                                        aliases: ['nd-timestamp-delta']
                                        type: int
                                        description: Neighbor discovery timestamp delta value
                                    nd_timestamp_fuzz:
                                        aliases: ['nd-timestamp-fuzz']
                                        type: int
                                        description: Neighbor discovery timestamp fuzz factor
                                    unique_autoconf_addr:
                                        aliases: ['unique-autoconf-addr']
                                        type: str
                                        description: Enable/disable unique auto config address.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrip6_link_local:
                                        type: str
                                        description: Link-local IPv6 address of virtual router.
                                    vrrp_virtual_mac6:
                                        aliases: ['vrrp-virtual-mac6']
                                        type: str
                                        description: Enable/disable virtual MAC for VRRP.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrrp6:
                                        type: list
                                        elements: dict
                                        description: Vrrp6.
                                        suboptions:
                                            accept_mode:
                                                aliases: ['accept-mode']
                                                type: str
                                                description: Enable/disable accept mode.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            adv_interval:
                                                aliases: ['adv-interval']
                                                type: int
                                                description: Advertisement interval
                                            preempt:
                                                type: str
                                                description: Enable/disable preempt mode.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            priority:
                                                type: int
                                                description: Priority of the virtual router
                                            start_time:
                                                aliases: ['start-time']
                                                type: int
                                                description: Startup time
                                            status:
                                                type: str
                                                description: Enable/disable VRRP.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            vrdst6:
                                                type: str
                                                description: Monitor the route to this destination.
                                            vrgrp:
                                                type: int
                                                description: VRRP group ID
                                            vrid:
                                                type: int
                                                description: Virtual router identifier
                                            vrip6:
                                                type: str
                                                description: IPv6 address of the virtual router.
                                            ignore_default_route:
                                                aliases: ['ignore-default-route']
                                                type: str
                                                description: Enable/disable ignoring of default route when checking destination.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            vrdst_priority:
                                                aliases: ['vrdst-priority']
                                                type: int
                                                description: Priority of the virtual router when the virtual router destination becomes unreachable
                                    cli_conn6_status:
                                        aliases: ['cli-conn6-status']
                                        type: int
                                        description: Cli conn6 status.
                                    ip6_prefix_mode:
                                        aliases: ['ip6-prefix-mode']
                                        type: str
                                        description: Assigning a prefix from DHCP or RA.
                                        choices:
                                            - 'dhcp6'
                                            - 'ra'
                                    ra_send_mtu:
                                        aliases: ['ra-send-mtu']
                                        type: str
                                        description: Enable/disable sending link MTU in RA packet.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6_delegated_prefix_iaid:
                                        aliases: ['ip6-delegated-prefix-iaid']
                                        type: int
                                        description: IAID of obtained delegated-prefix from the upstream interface.
                                    dhcp6_relay_source_interface:
                                        aliases: ['dhcp6-relay-source-interface']
                                        type: str
                                        description: Enable/disable use of address on this interface as the source address of the relay message.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6_relay_interface_id:
                                        aliases: ['dhcp6-relay-interface-id']
                                        type: str
                                        description: DHCP6 relay interface ID.
                                    dhcp6_relay_source_ip:
                                        aliases: ['dhcp6-relay-source-ip']
                                        type: str
                                        description: IPv6 address used by the DHCP6 relay as its source IP.
                                    ip6_adv_rio:
                                        aliases: ['ip6-adv-rio']
                                        type: str
                                        description: Enable/disable sending advertisements with route information option.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6_route_pref:
                                        aliases: ['ip6-route-pref']
                                        type: str
                                        description: Set route preference to the interface
                                        choices:
                                            - 'medium'
                                            - 'high'
                                            - 'low'
                            secondary_IP:
                                aliases: ['secondary-IP']
                                type: str
                                description: Secondary IP.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            secondaryip:
                                type: list
                                elements: dict
                                description: Secondaryip.
                                suboptions:
                                    allowaccess:
                                        type: list
                                        elements: str
                                        description: Management access settings for the secondary IP address.
                                        choices:
                                            - 'https'
                                            - 'ping'
                                            - 'ssh'
                                            - 'snmp'
                                            - 'http'
                                            - 'telnet'
                                            - 'fgfm'
                                            - 'auto-ipsec'
                                            - 'radius-acct'
                                            - 'probe-response'
                                            - 'capwap'
                                            - 'dnp'
                                            - 'ftm'
                                            - 'fabric'
                                            - 'speed-test'
                                            - 'icond'
                                            - 'scim'
                                    detectprotocol:
                                        type: list
                                        elements: str
                                        description: Protocols used to detect the server.
                                        choices:
                                            - 'ping'
                                            - 'tcp-echo'
                                            - 'udp-echo'
                                    detectserver:
                                        type: str
                                        description: Gateways ping server for this IP.
                                    gwdetect:
                                        type: str
                                        description: Enable/disable detect gateway alive for first.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ha_priority:
                                        aliases: ['ha-priority']
                                        type: int
                                        description: HA election priority for the PING server.
                                    id:
                                        type: int
                                        description: ID.
                                    ip:
                                        type: str
                                        description: Secondary IP address of the interface.
                                    ping_serv_status:
                                        aliases: ['ping-serv-status']
                                        type: int
                                        description: Ping serv status.
                                    seq:
                                        type: int
                                        description: Seq.
                                    secip_relay_ip:
                                        aliases: ['secip-relay-ip']
                                        type: str
                                        description: DHCP relay IP address.
                            vlanid:
                                type: int
                                description: Vlanid.
                            dhcp_relay_interface_select_method:
                                aliases: ['dhcp-relay-interface-select-method']
                                type: str
                                description: Dhcp relay interface select method.
                                choices:
                                    - 'auto'
                                    - 'sdwan'
                                    - 'specify'
                            vrrp:
                                type: list
                                elements: dict
                                description: Vrrp.
                                suboptions:
                                    accept_mode:
                                        aliases: ['accept-mode']
                                        type: str
                                        description: Enable/disable accept mode.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    adv_interval:
                                        aliases: ['adv-interval']
                                        type: int
                                        description: Advertisement interval
                                    ignore_default_route:
                                        aliases: ['ignore-default-route']
                                        type: str
                                        description: Enable/disable ignoring of default route when checking destination.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    preempt:
                                        type: str
                                        description: Enable/disable preempt mode.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    priority:
                                        type: int
                                        description: Priority of the virtual router
                                    proxy_arp:
                                        aliases: ['proxy-arp']
                                        type: list
                                        elements: dict
                                        description: Proxy arp.
                                        suboptions:
                                            id:
                                                type: int
                                                description: ID.
                                            ip:
                                                type: str
                                                description: Set IP addresses of proxy ARP.
                                    start_time:
                                        aliases: ['start-time']
                                        type: int
                                        description: Startup time
                                    status:
                                        type: str
                                        description: Enable/disable this VRRP configuration.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    version:
                                        type: str
                                        description: VRRP version.
                                        choices:
                                            - '2'
                                            - '3'
                                    vrdst:
                                        type: raw
                                        description: (list) Monitor the route to this destination.
                                    vrdst_priority:
                                        aliases: ['vrdst-priority']
                                        type: int
                                        description: Priority of the virtual router when the virtual router destination becomes unreachable
                                    vrgrp:
                                        type: int
                                        description: VRRP group ID
                                    vrid:
                                        type: int
                                        description: Virtual router identifier
                                    vrip:
                                        type: str
                                        description: IP address of the virtual router.
                            allowaccess:
                                type: list
                                elements: str
                                description: Allowaccess.
                                choices:
                                    - 'https'
                                    - 'ping'
                                    - 'ssh'
                                    - 'snmp'
                                    - 'http'
                                    - 'telnet'
                                    - 'fgfm'
                                    - 'radius-acct'
                                    - 'probe-response'
                                    - 'dnp'
                                    - 'ftm'
                                    - 'fabric'
                                    - 'speed-test'
                                    - 'icond'
                                    - 'scim'
                            dhcp_relay_request_all_server:
                                aliases: ['dhcp-relay-request-all-server']
                                type: str
                                description: Dhcp relay request all server.
                                choices:
                                    - 'disable'
                                    - 'enable'
            name:
                type: str
                description: Name.
                required: true
            portal_message_override_group:
                aliases: ['portal-message-override-group']
                type: str
                description: Portal message override group.
            radius_server:
                aliases: ['radius-server']
                type: str
                description: Radius server.
            security:
                type: str
                description: Security.
                choices:
                    - 'open'
                    - 'captive-portal'
                    - '8021x'
            selected_usergroups:
                aliases: ['selected-usergroups']
                type: str
                description: Selected usergroups.
            usergroup:
                type: str
                description: Usergroup.
            vdom:
                type: str
                description: Vdom.
            vlanid:
                type: int
                description: Vlanid.
            dhcp_server:
                aliases: ['dhcp-server']
                type: dict
                description: Dhcp server.
                suboptions:
                    auto_configuration:
                        aliases: ['auto-configuration']
                        type: str
                        description: Enable/disable auto configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_managed_status:
                        aliases: ['auto-managed-status']
                        type: str
                        description: Enable/disable use of this DHCP server once this interface has been assigned an IP address from FortiIPAM.
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
                    dhcp_settings_from_fortiipam:
                        aliases: ['dhcp-settings-from-fortiipam']
                        type: str
                        description: Enable/disable populating of DHCP server settings from FortiIPAM.
                        choices:
                            - 'disable'
                            - 'enable'
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
                    dns_server4:
                        aliases: ['dns-server4']
                        type: str
                        description: DNS server 4.
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
                    wifi_ac_service:
                        aliases: ['wifi-ac-service']
                        type: str
                        description: Options for assigning WiFi Access Controllers to DHCP clients
                        choices:
                            - 'specify'
                            - 'local'
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
            interface:
                type: dict
                description: Interface.
                suboptions:
                    ac_name:
                        aliases: ['ac-name']
                        type: str
                        description: PPPoE server name.
                    aggregate:
                        type: str
                        description: Aggregate.
                    algorithm:
                        type: str
                        description: Frame distribution algorithm.
                        choices:
                            - 'L2'
                            - 'L3'
                            - 'L4'
                            - 'LB'
                            - 'Source-MAC'
                    alias:
                        type: str
                        description: Alias will be displayed with the interface name to make it easier to distinguish.
                    allowaccess:
                        type: list
                        elements: str
                        description: Permitted types of management access to this interface.
                        choices:
                            - 'https'
                            - 'ping'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'fgfm'
                            - 'auto-ipsec'
                            - 'radius-acct'
                            - 'probe-response'
                            - 'capwap'
                            - 'dnp'
                            - 'ftm'
                            - 'fabric'
                            - 'speed-test'
                    ap_discover:
                        aliases: ['ap-discover']
                        type: str
                        description: Enable/disable automatic registration of unknown FortiAP devices.
                        choices:
                            - 'disable'
                            - 'enable'
                    arpforward:
                        type: str
                        description: Enable/disable ARP forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    atm_protocol:
                        aliases: ['atm-protocol']
                        type: str
                        description: ATM protocol.
                        choices:
                            - 'none'
                            - 'ipoa'
                    auth_type:
                        aliases: ['auth-type']
                        type: str
                        description: PPP authentication type to use.
                        choices:
                            - 'auto'
                            - 'pap'
                            - 'chap'
                            - 'mschapv1'
                            - 'mschapv2'
                    auto_auth_extension_device:
                        aliases: ['auto-auth-extension-device']
                        type: str
                        description: Enable/disable automatic authorization of dedicated Fortinet extension device on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    bandwidth_measure_time:
                        aliases: ['bandwidth-measure-time']
                        type: int
                        description: Bandwidth measure time
                    bfd:
                        type: str
                        description: Bidirectional Forwarding Detection
                        choices:
                            - 'global'
                            - 'enable'
                            - 'disable'
                    bfd_desired_min_tx:
                        aliases: ['bfd-desired-min-tx']
                        type: int
                        description: BFD desired minimal transmit interval.
                    bfd_detect_mult:
                        aliases: ['bfd-detect-mult']
                        type: int
                        description: BFD detection multiplier.
                    bfd_required_min_rx:
                        aliases: ['bfd-required-min-rx']
                        type: int
                        description: BFD required minimal receive interval.
                    broadcast_forticlient_discovery:
                        aliases: ['broadcast-forticlient-discovery']
                        type: str
                        description: Enable/disable broadcasting FortiClient discovery messages.
                        choices:
                            - 'disable'
                            - 'enable'
                    broadcast_forward:
                        aliases: ['broadcast-forward']
                        type: str
                        description: Enable/disable broadcast forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    captive_portal:
                        aliases: ['captive-portal']
                        type: int
                        description: Enable/disable captive portal.
                    cli_conn_status:
                        aliases: ['cli-conn-status']
                        type: int
                        description: Cli conn status.
                    color:
                        type: int
                        description: Color of icon on the GUI.
                    ddns:
                        type: str
                        description: Ddns.
                        choices:
                            - 'disable'
                            - 'enable'
                    ddns_auth:
                        aliases: ['ddns-auth']
                        type: str
                        description: Ddns auth.
                        choices:
                            - 'disable'
                            - 'tsig'
                    ddns_domain:
                        aliases: ['ddns-domain']
                        type: str
                        description: Ddns domain.
                    ddns_key:
                        aliases: ['ddns-key']
                        type: raw
                        description: (list or str) Ddns key.
                    ddns_keyname:
                        aliases: ['ddns-keyname']
                        type: str
                        description: Ddns keyname.
                    ddns_password:
                        aliases: ['ddns-password']
                        type: raw
                        description: (list) Ddns password.
                    ddns_server:
                        aliases: ['ddns-server']
                        type: str
                        description: Ddns server.
                        choices:
                            - 'dhs.org'
                            - 'dyndns.org'
                            - 'dyns.net'
                            - 'tzo.com'
                            - 'ods.org'
                            - 'vavic.com'
                            - 'now.net.cn'
                            - 'dipdns.net'
                            - 'easydns.com'
                            - 'genericDDNS'
                    ddns_server_ip:
                        aliases: ['ddns-server-ip']
                        type: str
                        description: Ddns server ip.
                    ddns_sn:
                        aliases: ['ddns-sn']
                        type: str
                        description: Ddns sn.
                    ddns_ttl:
                        aliases: ['ddns-ttl']
                        type: int
                        description: Ddns ttl.
                    ddns_username:
                        aliases: ['ddns-username']
                        type: str
                        description: Ddns username.
                    ddns_zone:
                        aliases: ['ddns-zone']
                        type: str
                        description: Ddns zone.
                    dedicated_to:
                        aliases: ['dedicated-to']
                        type: str
                        description: Configure interface for single purpose.
                        choices:
                            - 'none'
                            - 'management'
                    defaultgw:
                        type: str
                        description: Enable to get the gateway IP from the DHCP or PPPoE server.
                        choices:
                            - 'disable'
                            - 'enable'
                    description:
                        type: str
                        description: Description.
                    detected_peer_mtu:
                        aliases: ['detected-peer-mtu']
                        type: int
                        description: Detected peer mtu.
                    detectprotocol:
                        type: list
                        elements: str
                        description: Protocols used to detect the server.
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                    detectserver:
                        type: str
                        description: Gateways ping server for this IP.
                    device_access_list:
                        aliases: ['device-access-list']
                        type: raw
                        description: (list or str) Device access list.
                    device_identification:
                        aliases: ['device-identification']
                        type: str
                        description: Enable/disable passively gathering of device identity information about the devices on the network connected to th...
                        choices:
                            - 'disable'
                            - 'enable'
                    device_identification_active_scan:
                        aliases: ['device-identification-active-scan']
                        type: str
                        description: Enable/disable active gathering of device identity information about the devices on the network connected to this ...
                        choices:
                            - 'disable'
                            - 'enable'
                    device_netscan:
                        aliases: ['device-netscan']
                        type: str
                        description: Enable/disable inclusion of devices detected on this interface in network vulnerability scans.
                        choices:
                            - 'disable'
                            - 'enable'
                    device_user_identification:
                        aliases: ['device-user-identification']
                        type: str
                        description: Enable/disable passive gathering of user identity information about users on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    devindex:
                        type: int
                        description: Devindex.
                    dhcp_client_identifier:
                        aliases: ['dhcp-client-identifier']
                        type: str
                        description: DHCP client identifier.
                    dhcp_relay_agent_option:
                        aliases: ['dhcp-relay-agent-option']
                        type: str
                        description: Enable/disable DHCP relay agent option.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_relay_interface:
                        aliases: ['dhcp-relay-interface']
                        type: str
                        description: Specify outgoing interface to reach server.
                    dhcp_relay_interface_select_method:
                        aliases: ['dhcp-relay-interface-select-method']
                        type: str
                        description: Specify how to select outgoing interface to reach server.
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    dhcp_relay_ip:
                        aliases: ['dhcp-relay-ip']
                        type: raw
                        description: (list) DHCP relay IP address.
                    dhcp_relay_service:
                        aliases: ['dhcp-relay-service']
                        type: str
                        description: Enable/disable allowing this interface to act as a DHCP relay.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_relay_type:
                        aliases: ['dhcp-relay-type']
                        type: str
                        description: DHCP relay type
                        choices:
                            - 'regular'
                            - 'ipsec'
                    dhcp_renew_time:
                        aliases: ['dhcp-renew-time']
                        type: int
                        description: DHCP renew time in seconds
                    disc_retry_timeout:
                        aliases: ['disc-retry-timeout']
                        type: int
                        description: Time in seconds to wait before retrying to start a PPPoE discovery, 0 means no timeout.
                    disconnect_threshold:
                        aliases: ['disconnect-threshold']
                        type: int
                        description: Time in milliseconds to wait before sending a notification that this interface is down or disconnected.
                    distance:
                        type: int
                        description: Distance for routes learned through PPPoE or DHCP, lower distance indicates preferred route.
                    dns_query:
                        aliases: ['dns-query']
                        type: str
                        description: Dns query.
                        choices:
                            - 'disable'
                            - 'recursive'
                            - 'non-recursive'
                    dns_server_override:
                        aliases: ['dns-server-override']
                        type: str
                        description: Enable/disable use DNS acquired by DHCP or PPPoE.
                        choices:
                            - 'disable'
                            - 'enable'
                    drop_fragment:
                        aliases: ['drop-fragment']
                        type: str
                        description: Enable/disable drop fragment packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    drop_overlapped_fragment:
                        aliases: ['drop-overlapped-fragment']
                        type: str
                        description: Enable/disable drop overlapped fragment packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    egress_cos:
                        aliases: ['egress-cos']
                        type: str
                        description: Override outgoing CoS in user VLAN tag.
                        choices:
                            - 'disable'
                            - 'cos0'
                            - 'cos1'
                            - 'cos2'
                            - 'cos3'
                            - 'cos4'
                            - 'cos5'
                            - 'cos6'
                            - 'cos7'
                    egress_shaping_profile:
                        aliases: ['egress-shaping-profile']
                        type: str
                        description: Outgoing traffic shaping profile.
                    eip:
                        type: str
                        description: Eip.
                    endpoint_compliance:
                        aliases: ['endpoint-compliance']
                        type: str
                        description: Enable/disable endpoint compliance enforcement.
                        choices:
                            - 'disable'
                            - 'enable'
                    estimated_downstream_bandwidth:
                        aliases: ['estimated-downstream-bandwidth']
                        type: int
                        description: Estimated maximum downstream bandwidth
                    estimated_upstream_bandwidth:
                        aliases: ['estimated-upstream-bandwidth']
                        type: int
                        description: Estimated maximum upstream bandwidth
                    explicit_ftp_proxy:
                        aliases: ['explicit-ftp-proxy']
                        type: str
                        description: Enable/disable the explicit FTP proxy on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    explicit_web_proxy:
                        aliases: ['explicit-web-proxy']
                        type: str
                        description: Enable/disable the explicit web proxy on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    external:
                        type: str
                        description: Enable/disable identifying the interface as an external interface
                        choices:
                            - 'disable'
                            - 'enable'
                    fail_action_on_extender:
                        aliases: ['fail-action-on-extender']
                        type: str
                        description: Action on extender when interface fail .
                        choices:
                            - 'soft-restart'
                            - 'hard-restart'
                            - 'reboot'
                    fail_alert_interfaces:
                        aliases: ['fail-alert-interfaces']
                        type: raw
                        description: (list or str) Names of the FortiGate interfaces to which the link failure alert is sent.
                    fail_alert_method:
                        aliases: ['fail-alert-method']
                        type: str
                        description: Select link-failed-signal or link-down method to alert about a failed link.
                        choices:
                            - 'link-failed-signal'
                            - 'link-down'
                    fail_detect:
                        aliases: ['fail-detect']
                        type: str
                        description: Enable/disable fail detection features for this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    fail_detect_option:
                        aliases: ['fail-detect-option']
                        type: list
                        elements: str
                        description: Options for detecting that this interface has failed.
                        choices:
                            - 'detectserver'
                            - 'link-down'
                    fdp:
                        type: str
                        description: Fdp.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortiheartbeat:
                        type: str
                        description: Enable/disable FortiHeartBeat
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink:
                        type: str
                        description: Enable FortiLink to dedicate this interface to manage other Fortinet devices.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink_backup_link:
                        aliases: ['fortilink-backup-link']
                        type: int
                        description: Fortilink backup link.
                    fortilink_neighbor_detect:
                        aliases: ['fortilink-neighbor-detect']
                        type: str
                        description: Protocol for FortiGate neighbor discovery.
                        choices:
                            - 'lldp'
                            - 'fortilink'
                    fortilink_split_interface:
                        aliases: ['fortilink-split-interface']
                        type: str
                        description: Enable/disable FortiLink split interface to connect member link to different FortiSwitch in stack for uplink redun...
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink_stacking:
                        aliases: ['fortilink-stacking']
                        type: str
                        description: Enable/disable FortiLink switch-stacking on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    forward_domain:
                        aliases: ['forward-domain']
                        type: int
                        description: Transparent mode forward domain.
                    forward_error_correction:
                        aliases: ['forward-error-correction']
                        type: str
                        description: Enable/disable forward error correction
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'rs-fec'
                            - 'base-r-fec'
                            - 'fec-cl91'
                            - 'fec-cl74'
                            - 'rs-544'
                            - 'none'
                            - 'cl91-rs-fec'
                            - 'cl74-fc-fec'
                            - 'auto'
                            - 'rs-fec544'
                    fp_anomaly:
                        aliases: ['fp-anomaly']
                        type: list
                        elements: str
                        description: Pass or drop different types of anomalies using Fastpath
                        choices:
                            - 'drop_tcp_fin_noack'
                            - 'pass_winnuke'
                            - 'pass_tcpland'
                            - 'pass_udpland'
                            - 'pass_icmpland'
                            - 'pass_ipland'
                            - 'pass_iprr'
                            - 'pass_ipssrr'
                            - 'pass_iplsrr'
                            - 'pass_ipstream'
                            - 'pass_ipsecurity'
                            - 'pass_iptimestamp'
                            - 'pass_ipunknown_option'
                            - 'pass_ipunknown_prot'
                            - 'pass_icmp_frag'
                            - 'pass_tcp_no_flag'
                            - 'pass_tcp_fin_noack'
                            - 'drop_winnuke'
                            - 'drop_tcpland'
                            - 'drop_udpland'
                            - 'drop_icmpland'
                            - 'drop_ipland'
                            - 'drop_iprr'
                            - 'drop_ipssrr'
                            - 'drop_iplsrr'
                            - 'drop_ipstream'
                            - 'drop_ipsecurity'
                            - 'drop_iptimestamp'
                            - 'drop_ipunknown_option'
                            - 'drop_ipunknown_prot'
                            - 'drop_icmp_frag'
                            - 'drop_tcp_no_flag'
                    fp_disable:
                        aliases: ['fp-disable']
                        type: list
                        elements: str
                        description: Fp disable.
                        choices:
                            - 'all'
                            - 'ipsec'
                            - 'none'
                    gateway_address:
                        aliases: ['gateway-address']
                        type: str
                        description: Gateway address
                    gi_gk:
                        aliases: ['gi-gk']
                        type: str
                        description: Enable/disable Gi Gatekeeper.
                        choices:
                            - 'disable'
                            - 'enable'
                    gwaddr:
                        type: str
                        description: Gateway address
                    gwdetect:
                        type: str
                        description: Enable/disable detect gateway alive for first.
                        choices:
                            - 'disable'
                            - 'enable'
                    ha_priority:
                        aliases: ['ha-priority']
                        type: int
                        description: HA election priority for the PING server.
                    icmp_accept_redirect:
                        aliases: ['icmp-accept-redirect']
                        type: str
                        description: Enable/disable ICMP accept redirect.
                        choices:
                            - 'disable'
                            - 'enable'
                    icmp_redirect:
                        aliases: ['icmp-redirect']
                        type: str
                        description: Enable/disable ICMP redirect.
                        choices:
                            - 'disable'
                            - 'enable'
                    icmp_send_redirect:
                        aliases: ['icmp-send-redirect']
                        type: str
                        description: Enable/disable sending of ICMP redirects.
                        choices:
                            - 'disable'
                            - 'enable'
                    ident_accept:
                        aliases: ['ident-accept']
                        type: str
                        description: Enable/disable authentication for this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    idle_timeout:
                        aliases: ['idle-timeout']
                        type: int
                        description: PPPoE auto disconnect after idle timeout seconds, 0 means no timeout.
                    if_mdix:
                        aliases: ['if-mdix']
                        type: str
                        description: Interface MDIX mode
                        choices:
                            - 'auto'
                            - 'normal'
                            - 'crossover'
                    if_media:
                        aliases: ['if-media']
                        type: str
                        description: Select interface media type
                        choices:
                            - 'auto'
                            - 'copper'
                            - 'fiber'
                    in_force_vlan_cos:
                        aliases: ['in-force-vlan-cos']
                        type: int
                        description: In force vlan cos.
                    inbandwidth:
                        type: int
                        description: Bandwidth limit for incoming traffic
                    ingress_cos:
                        aliases: ['ingress-cos']
                        type: str
                        description: Override incoming CoS in user VLAN tag on VLAN interface or assign a priority VLAN tag on physical interface.
                        choices:
                            - 'disable'
                            - 'cos0'
                            - 'cos1'
                            - 'cos2'
                            - 'cos3'
                            - 'cos4'
                            - 'cos5'
                            - 'cos6'
                            - 'cos7'
                    ingress_shaping_profile:
                        aliases: ['ingress-shaping-profile']
                        type: str
                        description: Incoming traffic shaping profile.
                    ingress_spillover_threshold:
                        aliases: ['ingress-spillover-threshold']
                        type: int
                        description: Ingress Spillover threshold
                    internal:
                        type: int
                        description: Implicitly created.
                    ip:
                        type: str
                        description: Interface IPv4 address and subnet mask, syntax
                    ip_managed_by_fortiipam:
                        aliases: ['ip-managed-by-fortiipam']
                        type: str
                        description: Enable/disable automatic IP address assignment of this interface by FortiIPAM.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'inherit-global'
                    ipmac:
                        type: str
                        description: Enable/disable IP/MAC binding.
                        choices:
                            - 'disable'
                            - 'enable'
                    ips_sniffer_mode:
                        aliases: ['ips-sniffer-mode']
                        type: str
                        description: Enable/disable the use of this interface as a one-armed sniffer.
                        choices:
                            - 'disable'
                            - 'enable'
                    ipunnumbered:
                        type: str
                        description: Unnumbered IP used for PPPoE interfaces for which no unique local address is provided.
                    ipv6:
                        type: dict
                        description: Ipv6.
                        suboptions:
                            autoconf:
                                type: str
                                description: Enable/disable address auto config.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6_client_options:
                                aliases: ['dhcp6-client-options']
                                type: list
                                elements: str
                                description: Dhcp6 client options.
                                choices:
                                    - 'rapid'
                                    - 'iapd'
                                    - 'iana'
                                    - 'dns'
                                    - 'dnsname'
                            dhcp6_information_request:
                                aliases: ['dhcp6-information-request']
                                type: str
                                description: Enable/disable DHCPv6 information request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6_prefix_delegation:
                                aliases: ['dhcp6-prefix-delegation']
                                type: str
                                description: Enable/disable DHCPv6 prefix delegation.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6_prefix_hint:
                                aliases: ['dhcp6-prefix-hint']
                                type: str
                                description: DHCPv6 prefix that will be used as a hint to the upstream DHCPv6 server.
                            dhcp6_prefix_hint_plt:
                                aliases: ['dhcp6-prefix-hint-plt']
                                type: int
                                description: DHCPv6 prefix hint preferred life time
                            dhcp6_prefix_hint_vlt:
                                aliases: ['dhcp6-prefix-hint-vlt']
                                type: int
                                description: DHCPv6 prefix hint valid life time
                            dhcp6_relay_ip:
                                aliases: ['dhcp6-relay-ip']
                                type: str
                                description: DHCPv6 relay IP address.
                            dhcp6_relay_service:
                                aliases: ['dhcp6-relay-service']
                                type: str
                                description: Enable/disable DHCPv6 relay.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6_relay_type:
                                aliases: ['dhcp6-relay-type']
                                type: str
                                description: DHCPv6 relay type.
                                choices:
                                    - 'regular'
                            icmp6_send_redirect:
                                aliases: ['icmp6-send-redirect']
                                type: str
                                description: Enable/disable sending of ICMPv6 redirects.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            interface_identifier:
                                aliases: ['interface-identifier']
                                type: str
                                description: IPv6 interface identifier.
                            ip6_address:
                                aliases: ['ip6-address']
                                type: str
                                description: Primary IPv6 address prefix, syntax
                            ip6_allowaccess:
                                aliases: ['ip6-allowaccess']
                                type: list
                                elements: str
                                description: Allow management access to the interface.
                                choices:
                                    - 'https'
                                    - 'ping'
                                    - 'ssh'
                                    - 'snmp'
                                    - 'http'
                                    - 'telnet'
                                    - 'fgfm'
                                    - 'capwap'
                                    - 'fabric'
                            ip6_default_life:
                                aliases: ['ip6-default-life']
                                type: int
                                description: Default life
                            ip6_delegated_prefix_list:
                                aliases: ['ip6-delegated-prefix-list']
                                type: list
                                elements: dict
                                description: Ip6 delegated prefix list.
                                suboptions:
                                    autonomous_flag:
                                        aliases: ['autonomous-flag']
                                        type: str
                                        description: Enable/disable the autonomous flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    onlink_flag:
                                        aliases: ['onlink-flag']
                                        type: str
                                        description: Enable/disable the onlink flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    prefix_id:
                                        aliases: ['prefix-id']
                                        type: int
                                        description: Prefix ID.
                                    rdnss:
                                        type: raw
                                        description: (list) Recursive DNS server option.
                                    rdnss_service:
                                        aliases: ['rdnss-service']
                                        type: str
                                        description: Recursive DNS service option.
                                        choices:
                                            - 'delegated'
                                            - 'default'
                                            - 'specify'
                                    subnet:
                                        type: str
                                        description: Add subnet ID to routing prefix.
                                    upstream_interface:
                                        aliases: ['upstream-interface']
                                        type: str
                                        description: Name of the interface that provides delegated information.
                                    delegated_prefix_iaid:
                                        aliases: ['delegated-prefix-iaid']
                                        type: int
                                        description: IAID of obtained delegated-prefix from the upstream interface.
                            ip6_dns_server_override:
                                aliases: ['ip6-dns-server-override']
                                type: str
                                description: Enable/disable using the DNS server acquired by DHCP.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6_extra_addr:
                                aliases: ['ip6-extra-addr']
                                type: list
                                elements: dict
                                description: Ip6 extra addr.
                                suboptions:
                                    prefix:
                                        type: str
                                        description: IPv6 address prefix.
                            ip6_hop_limit:
                                aliases: ['ip6-hop-limit']
                                type: int
                                description: Hop limit
                            ip6_link_mtu:
                                aliases: ['ip6-link-mtu']
                                type: int
                                description: IPv6 link MTU.
                            ip6_manage_flag:
                                aliases: ['ip6-manage-flag']
                                type: str
                                description: Enable/disable the managed flag.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6_max_interval:
                                aliases: ['ip6-max-interval']
                                type: int
                                description: IPv6 maximum interval
                            ip6_min_interval:
                                aliases: ['ip6-min-interval']
                                type: int
                                description: IPv6 minimum interval
                            ip6_mode:
                                aliases: ['ip6-mode']
                                type: str
                                description: Addressing mode
                                choices:
                                    - 'static'
                                    - 'dhcp'
                                    - 'pppoe'
                                    - 'delegated'
                            ip6_other_flag:
                                aliases: ['ip6-other-flag']
                                type: str
                                description: Enable/disable the other IPv6 flag.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6_prefix_list:
                                aliases: ['ip6-prefix-list']
                                type: list
                                elements: dict
                                description: Ip6 prefix list.
                                suboptions:
                                    autonomous_flag:
                                        aliases: ['autonomous-flag']
                                        type: str
                                        description: Enable/disable the autonomous flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dnssl:
                                        type: raw
                                        description: (list) DNS search list option.
                                    onlink_flag:
                                        aliases: ['onlink-flag']
                                        type: str
                                        description: Enable/disable the onlink flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    preferred_life_time:
                                        aliases: ['preferred-life-time']
                                        type: int
                                        description: Preferred life time
                                    prefix:
                                        type: str
                                        description: IPv6 prefix.
                                    rdnss:
                                        type: raw
                                        description: (list) Recursive DNS server option.
                                    valid_life_time:
                                        aliases: ['valid-life-time']
                                        type: int
                                        description: Valid life time
                            ip6_reachable_time:
                                aliases: ['ip6-reachable-time']
                                type: int
                                description: IPv6 reachable time
                            ip6_retrans_time:
                                aliases: ['ip6-retrans-time']
                                type: int
                                description: IPv6 retransmit time
                            ip6_send_adv:
                                aliases: ['ip6-send-adv']
                                type: str
                                description: Enable/disable sending advertisements about the interface.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6_subnet:
                                aliases: ['ip6-subnet']
                                type: str
                                description: Subnet to routing prefix, syntax
                            ip6_upstream_interface:
                                aliases: ['ip6-upstream-interface']
                                type: str
                                description: Interface name providing delegated information.
                            nd_cert:
                                aliases: ['nd-cert']
                                type: str
                                description: Neighbor discovery certificate.
                            nd_cga_modifier:
                                aliases: ['nd-cga-modifier']
                                type: str
                                description: Neighbor discovery CGA modifier.
                            nd_mode:
                                aliases: ['nd-mode']
                                type: str
                                description: Neighbor discovery mode.
                                choices:
                                    - 'basic'
                                    - 'SEND-compatible'
                            nd_security_level:
                                aliases: ['nd-security-level']
                                type: int
                                description: Neighbor discovery security level
                            nd_timestamp_delta:
                                aliases: ['nd-timestamp-delta']
                                type: int
                                description: Neighbor discovery timestamp delta value
                            nd_timestamp_fuzz:
                                aliases: ['nd-timestamp-fuzz']
                                type: int
                                description: Neighbor discovery timestamp fuzz factor
                            unique_autoconf_addr:
                                aliases: ['unique-autoconf-addr']
                                type: str
                                description: Enable/disable unique auto config address.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vrip6_link_local:
                                type: str
                                description: Link-local IPv6 address of virtual router.
                            vrrp_virtual_mac6:
                                aliases: ['vrrp-virtual-mac6']
                                type: str
                                description: Enable/disable virtual MAC for VRRP.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vrrp6:
                                type: list
                                elements: dict
                                description: Vrrp6.
                                suboptions:
                                    accept_mode:
                                        aliases: ['accept-mode']
                                        type: str
                                        description: Enable/disable accept mode.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    adv_interval:
                                        aliases: ['adv-interval']
                                        type: int
                                        description: Advertisement interval
                                    preempt:
                                        type: str
                                        description: Enable/disable preempt mode.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    priority:
                                        type: int
                                        description: Priority of the virtual router
                                    start_time:
                                        aliases: ['start-time']
                                        type: int
                                        description: Startup time
                                    status:
                                        type: str
                                        description: Enable/disable VRRP.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrdst6:
                                        type: str
                                        description: Monitor the route to this destination.
                                    vrgrp:
                                        type: int
                                        description: VRRP group ID
                                    vrid:
                                        type: int
                                        description: Virtual router identifier
                                    vrip6:
                                        type: str
                                        description: IPv6 address of the virtual router.
                                    ignore_default_route:
                                        aliases: ['ignore-default-route']
                                        type: str
                                        description: Enable/disable ignoring of default route when checking destination.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrdst_priority:
                                        aliases: ['vrdst-priority']
                                        type: int
                                        description: Priority of the virtual router when the virtual router destination becomes unreachable
                            cli_conn6_status:
                                aliases: ['cli-conn6-status']
                                type: int
                                description: Cli conn6 status.
                            ip6_prefix_mode:
                                aliases: ['ip6-prefix-mode']
                                type: str
                                description: Assigning a prefix from DHCP or RA.
                                choices:
                                    - 'dhcp6'
                                    - 'ra'
                            ra_send_mtu:
                                aliases: ['ra-send-mtu']
                                type: str
                                description: Enable/disable sending link MTU in RA packet.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6_delegated_prefix_iaid:
                                aliases: ['ip6-delegated-prefix-iaid']
                                type: int
                                description: IAID of obtained delegated-prefix from the upstream interface.
                            dhcp6_relay_source_interface:
                                aliases: ['dhcp6-relay-source-interface']
                                type: str
                                description: Enable/disable use of address on this interface as the source address of the relay message.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6_relay_interface_id:
                                aliases: ['dhcp6-relay-interface-id']
                                type: str
                                description: DHCP6 relay interface ID.
                            dhcp6_relay_source_ip:
                                aliases: ['dhcp6-relay-source-ip']
                                type: str
                                description: IPv6 address used by the DHCP6 relay as its source IP.
                            ip6_adv_rio:
                                aliases: ['ip6-adv-rio']
                                type: str
                                description: Enable/disable sending advertisements with route information option.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6_route_pref:
                                aliases: ['ip6-route-pref']
                                type: str
                                description: Set route preference to the interface
                                choices:
                                    - 'medium'
                                    - 'high'
                                    - 'low'
                    l2forward:
                        type: str
                        description: Enable/disable l2 forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    l2tp_client:
                        aliases: ['l2tp-client']
                        type: str
                        description: Enable/disable this interface as a Layer 2 Tunnelling Protocol
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp_ha_slave:
                        aliases: ['lacp-ha-slave']
                        type: str
                        description: LACP HA slave.
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp_mode:
                        aliases: ['lacp-mode']
                        type: str
                        description: LACP mode.
                        choices:
                            - 'static'
                            - 'passive'
                            - 'active'
                    lacp_speed:
                        aliases: ['lacp-speed']
                        type: str
                        description: How often the interface sends LACP messages.
                        choices:
                            - 'slow'
                            - 'fast'
                    lcp_echo_interval:
                        aliases: ['lcp-echo-interval']
                        type: int
                        description: Time in seconds between PPPoE Link Control Protocol
                    lcp_max_echo_fails:
                        aliases: ['lcp-max-echo-fails']
                        type: int
                        description: Maximum missed LCP echo messages before disconnect.
                    link_up_delay:
                        aliases: ['link-up-delay']
                        type: int
                        description: Number of milliseconds to wait before considering a link is up.
                    listen_forticlient_connection:
                        aliases: ['listen-forticlient-connection']
                        type: str
                        description: Listen forticlient connection.
                        choices:
                            - 'disable'
                            - 'enable'
                    lldp_network_policy:
                        aliases: ['lldp-network-policy']
                        type: str
                        description: LLDP-MED network policy profile.
                    lldp_reception:
                        aliases: ['lldp-reception']
                        type: str
                        description: Enable/disable Link Layer Discovery Protocol
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vdom'
                    lldp_transmission:
                        aliases: ['lldp-transmission']
                        type: str
                        description: Enable/disable Link Layer Discovery Protocol
                        choices:
                            - 'enable'
                            - 'disable'
                            - 'vdom'
                    log:
                        type: str
                        description: Log.
                        choices:
                            - 'disable'
                            - 'enable'
                    macaddr:
                        type: str
                        description: Change the interfaces MAC address.
                    managed_subnetwork_size:
                        aliases: ['managed-subnetwork-size']
                        type: str
                        description: Number of IP addresses to be allocated by FortiIPAM and used by this FortiGate units DHCP server settings.
                        choices:
                            - '256'
                            - '512'
                            - '1024'
                            - '2048'
                            - '4096'
                            - '8192'
                            - '16384'
                            - '32768'
                            - '65536'
                            - '32'
                            - '64'
                            - '128'
                            - '4'
                            - '8'
                            - '16'
                            - '131072'
                            - '262144'
                            - '524288'
                            - '1048576'
                            - '2097152'
                            - '4194304'
                            - '8388608'
                            - '16777216'
                    management_ip:
                        aliases: ['management-ip']
                        type: str
                        description: High Availability in-band management IP address of this interface.
                    max_egress_burst_rate:
                        aliases: ['max-egress-burst-rate']
                        type: int
                        description: Max egress burst rate
                    max_egress_rate:
                        aliases: ['max-egress-rate']
                        type: int
                        description: Max egress rate
                    measured_downstream_bandwidth:
                        aliases: ['measured-downstream-bandwidth']
                        type: int
                        description: Measured downstream bandwidth
                    measured_upstream_bandwidth:
                        aliases: ['measured-upstream-bandwidth']
                        type: int
                        description: Measured upstream bandwidth
                    mediatype:
                        type: str
                        description: Select SFP media interface type
                        choices:
                            - 'serdes-sfp'
                            - 'sgmii-sfp'
                            - 'cfp2-sr10'
                            - 'cfp2-lr4'
                            - 'serdes-copper-sfp'
                            - 'sr'
                            - 'cr'
                            - 'lr'
                            - 'qsfp28-sr4'
                            - 'qsfp28-lr4'
                            - 'qsfp28-cr4'
                            - 'sr4'
                            - 'cr4'
                            - 'lr4'
                            - 'none'
                            - 'gmii'
                            - 'sgmii'
                            - 'sr2'
                            - 'lr2'
                            - 'cr2'
                            - 'sr8'
                            - 'lr8'
                            - 'cr8'
                            - 'dr'
                    member:
                        type: raw
                        description: (list or str) Physical interfaces that belong to the aggregate or redundant interface.
                    min_links:
                        aliases: ['min-links']
                        type: int
                        description: Minimum number of aggregated ports that must be up.
                    min_links_down:
                        aliases: ['min-links-down']
                        type: str
                        description: Action to take when less than the configured minimum number of links are active.
                        choices:
                            - 'operational'
                            - 'administrative'
                    mode:
                        type: str
                        description: Addressing mode
                        choices:
                            - 'static'
                            - 'dhcp'
                            - 'pppoe'
                            - 'pppoa'
                            - 'ipoa'
                            - 'eoa'
                    monitor_bandwidth:
                        aliases: ['monitor-bandwidth']
                        type: str
                        description: Enable monitoring bandwidth on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    mtu:
                        type: int
                        description: MTU value for this interface.
                    mtu_override:
                        aliases: ['mtu-override']
                        type: str
                        description: Enable to set a custom MTU for this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    mux_type:
                        aliases: ['mux-type']
                        type: str
                        description: Multiplexer type
                        choices:
                            - 'llc-encaps'
                            - 'vc-encaps'
                    name:
                        type: str
                        description: Name.
                    ndiscforward:
                        type: str
                        description: Enable/disable NDISC forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    netbios_forward:
                        aliases: ['netbios-forward']
                        type: str
                        description: Enable/disable NETBIOS forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    netflow_sampler:
                        aliases: ['netflow-sampler']
                        type: str
                        description: Enable/disable NetFlow on this interface and set the data that NetFlow collects
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'both'
                    np_qos_profile:
                        aliases: ['np-qos-profile']
                        type: int
                        description: NP QoS profile ID.
                    npu_fastpath:
                        aliases: ['npu-fastpath']
                        type: str
                        description: Npu fastpath.
                        choices:
                            - 'disable'
                            - 'enable'
                    nst:
                        type: str
                        description: Nst.
                        choices:
                            - 'disable'
                            - 'enable'
                    out_force_vlan_cos:
                        aliases: ['out-force-vlan-cos']
                        type: int
                        description: Out force vlan cos.
                    outbandwidth:
                        type: int
                        description: Bandwidth limit for outgoing traffic
                    padt_retry_timeout:
                        aliases: ['padt-retry-timeout']
                        type: int
                        description: PPPoE Active Discovery Terminate
                    password:
                        type: raw
                        description: (list) PPPoE accounts password.
                    peer_interface:
                        aliases: ['peer-interface']
                        type: raw
                        description: (list or str) Peer interface.
                    phy_mode:
                        aliases: ['phy-mode']
                        type: str
                        description: DSL physical mode.
                        choices:
                            - 'auto'
                            - 'adsl'
                            - 'vdsl'
                            - 'adsl-auto'
                            - 'vdsl2'
                            - 'adsl2+'
                            - 'adsl2'
                            - 'g.dmt'
                            - 't1.413'
                            - 'g.lite'
                            - 'g-dmt'
                            - 't1-413'
                            - 'g-lite'
                    ping_serv_status:
                        aliases: ['ping-serv-status']
                        type: int
                        description: Ping serv status.
                    poe:
                        type: str
                        description: Enable/disable PoE status.
                        choices:
                            - 'disable'
                            - 'enable'
                    polling_interval:
                        aliases: ['polling-interval']
                        type: int
                        description: SFlow polling interval
                    pppoe_unnumbered_negotiate:
                        aliases: ['pppoe-unnumbered-negotiate']
                        type: str
                        description: Enable/disable PPPoE unnumbered negotiation.
                        choices:
                            - 'disable'
                            - 'enable'
                    pptp_auth_type:
                        aliases: ['pptp-auth-type']
                        type: str
                        description: PPTP authentication type.
                        choices:
                            - 'auto'
                            - 'pap'
                            - 'chap'
                            - 'mschapv1'
                            - 'mschapv2'
                    pptp_client:
                        aliases: ['pptp-client']
                        type: str
                        description: Enable/disable PPTP client.
                        choices:
                            - 'disable'
                            - 'enable'
                    pptp_password:
                        aliases: ['pptp-password']
                        type: raw
                        description: (list) PPTP password.
                    pptp_server_ip:
                        aliases: ['pptp-server-ip']
                        type: str
                        description: PPTP server IP address.
                    pptp_timeout:
                        aliases: ['pptp-timeout']
                        type: int
                        description: Idle timer in minutes
                    pptp_user:
                        aliases: ['pptp-user']
                        type: str
                        description: PPTP user name.
                    preserve_session_route:
                        aliases: ['preserve-session-route']
                        type: str
                        description: Enable/disable preservation of session route when dirty.
                        choices:
                            - 'disable'
                            - 'enable'
                    priority:
                        type: int
                        description: Priority of learned routes.
                    priority_override:
                        aliases: ['priority-override']
                        type: str
                        description: Enable/disable fail back to higher priority port once recovered.
                        choices:
                            - 'disable'
                            - 'enable'
                    proxy_captive_portal:
                        aliases: ['proxy-captive-portal']
                        type: str
                        description: Enable/disable proxy captive portal on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    redundant_interface:
                        aliases: ['redundant-interface']
                        type: str
                        description: Redundant interface.
                    remote_ip:
                        aliases: ['remote-ip']
                        type: str
                        description: Remote IP address of tunnel.
                    replacemsg_override_group:
                        aliases: ['replacemsg-override-group']
                        type: str
                        description: Replacement message override group.
                    retransmission:
                        type: str
                        description: Enable/disable DSL retransmission.
                        choices:
                            - 'disable'
                            - 'enable'
                    ring_rx:
                        aliases: ['ring-rx']
                        type: int
                        description: RX ring size.
                    ring_tx:
                        aliases: ['ring-tx']
                        type: int
                        description: TX ring size.
                    role:
                        type: str
                        description: Interface role.
                        choices:
                            - 'lan'
                            - 'wan'
                            - 'dmz'
                            - 'undefined'
                    sample_direction:
                        aliases: ['sample-direction']
                        type: str
                        description: Data that NetFlow collects
                        choices:
                            - 'rx'
                            - 'tx'
                            - 'both'
                    sample_rate:
                        aliases: ['sample-rate']
                        type: int
                        description: SFlow sample rate
                    scan_botnet_connections:
                        aliases: ['scan-botnet-connections']
                        type: str
                        description: Enable monitoring or blocking connections to Botnet servers through this interface.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    secondary_IP:
                        aliases: ['secondary-IP']
                        type: str
                        description: Enable/disable adding a secondary IP to this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    secondaryip:
                        type: list
                        elements: dict
                        description: Secondaryip.
                        suboptions:
                            allowaccess:
                                type: list
                                elements: str
                                description: Management access settings for the secondary IP address.
                                choices:
                                    - 'https'
                                    - 'ping'
                                    - 'ssh'
                                    - 'snmp'
                                    - 'http'
                                    - 'telnet'
                                    - 'fgfm'
                                    - 'auto-ipsec'
                                    - 'radius-acct'
                                    - 'probe-response'
                                    - 'capwap'
                                    - 'dnp'
                                    - 'ftm'
                                    - 'fabric'
                                    - 'speed-test'
                                    - 'icond'
                                    - 'scim'
                            detectprotocol:
                                type: list
                                elements: str
                                description: Protocols used to detect the server.
                                choices:
                                    - 'ping'
                                    - 'tcp-echo'
                                    - 'udp-echo'
                            detectserver:
                                type: str
                                description: Gateways ping server for this IP.
                            gwdetect:
                                type: str
                                description: Enable/disable detect gateway alive for first.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ha_priority:
                                aliases: ['ha-priority']
                                type: int
                                description: HA election priority for the PING server.
                            id:
                                type: int
                                description: ID.
                            ip:
                                type: str
                                description: Secondary IP address of the interface.
                            ping_serv_status:
                                aliases: ['ping-serv-status']
                                type: int
                                description: Ping serv status.
                            seq:
                                type: int
                                description: Seq.
                            secip_relay_ip:
                                aliases: ['secip-relay-ip']
                                type: str
                                description: DHCP relay IP address.
                    security_8021x_dynamic_vlan_id:
                        aliases: ['security-8021x-dynamic-vlan-id']
                        type: int
                        description: VLAN ID for virtual switch.
                    security_8021x_master:
                        aliases: ['security-8021x-master']
                        type: str
                        description: '802.'
                    security_8021x_mode:
                        aliases: ['security-8021x-mode']
                        type: str
                        description: '802.'
                        choices:
                            - 'default'
                            - 'dynamic-vlan'
                            - 'fallback'
                            - 'slave'
                    security_exempt_list:
                        aliases: ['security-exempt-list']
                        type: str
                        description: Name of security-exempt-list.
                    security_external_logout:
                        aliases: ['security-external-logout']
                        type: str
                        description: URL of external authentication logout server.
                    security_external_web:
                        aliases: ['security-external-web']
                        type: str
                        description: URL of external authentication web server.
                    security_groups:
                        aliases: ['security-groups']
                        type: raw
                        description: (list or str) User groups that can authenticate with the captive portal.
                    security_mac_auth_bypass:
                        aliases: ['security-mac-auth-bypass']
                        type: str
                        description: Enable/disable MAC authentication bypass.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'mac-auth-only'
                    security_mode:
                        aliases: ['security-mode']
                        type: str
                        description: Turn on captive portal authentication for this interface.
                        choices:
                            - 'none'
                            - 'captive-portal'
                            - '802.1X'
                    security_redirect_url:
                        aliases: ['security-redirect-url']
                        type: str
                        description: URL redirection after disclaimer/authentication.
                    service_name:
                        aliases: ['service-name']
                        type: str
                        description: PPPoE service name.
                    sflow_sampler:
                        aliases: ['sflow-sampler']
                        type: str
                        description: Enable/disable sFlow on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    speed:
                        type: str
                        description: Interface speed.
                        choices:
                            - 'auto'
                            - '10full'
                            - '10half'
                            - '100full'
                            - '100half'
                            - '1000full'
                            - '1000half'
                            - '10000full'
                            - '1000auto'
                            - '10000auto'
                            - '40000full'
                            - '100Gfull'
                            - '25000full'
                            - '40000auto'
                            - '25000auto'
                            - '100Gauto'
                            - '400Gfull'
                            - '400Gauto'
                            - '50000full'
                            - '2500auto'
                            - '5000auto'
                            - '50000auto'
                            - '200Gfull'
                            - '200Gauto'
                            - '100auto'
                    spillover_threshold:
                        aliases: ['spillover-threshold']
                        type: int
                        description: Egress Spillover threshold
                    src_check:
                        aliases: ['src-check']
                        type: str
                        description: Enable/disable source IP check.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Bring the interface up or shut the interface down.
                        choices:
                            - 'down'
                            - 'up'
                    stp:
                        type: str
                        description: Enable/disable STP.
                        choices:
                            - 'disable'
                            - 'enable'
                    stp_ha_slave:
                        aliases: ['stp-ha-slave']
                        type: str
                        description: Control STP behaviour on HA slave.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'priority-adjust'
                    stpforward:
                        type: str
                        description: Enable/disable STP forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    stpforward_mode:
                        aliases: ['stpforward-mode']
                        type: str
                        description: Configure STP forwarding mode.
                        choices:
                            - 'rpl-all-ext-id'
                            - 'rpl-bridge-ext-id'
                            - 'rpl-nothing'
                    strip_priority_vlan_tag:
                        aliases: ['strip-priority-vlan-tag']
                        type: str
                        description: Strip priority vlan tag.
                        choices:
                            - 'disable'
                            - 'enable'
                    subst:
                        type: str
                        description: Enable to always send packets from this interface to a destination MAC address.
                        choices:
                            - 'disable'
                            - 'enable'
                    substitute_dst_mac:
                        aliases: ['substitute-dst-mac']
                        type: str
                        description: Destination MAC address that all packets are sent to from this interface.
                    swc_first_create:
                        aliases: ['swc-first-create']
                        type: int
                        description: Initial create for switch-controller VLANs.
                    swc_vlan:
                        aliases: ['swc-vlan']
                        type: int
                        description: Swc vlan.
                    switch:
                        type: str
                        description: Switch.
                    switch_controller_access_vlan:
                        aliases: ['switch-controller-access-vlan']
                        type: str
                        description: Block FortiSwitch port-to-port traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_arp_inspection:
                        aliases: ['switch-controller-arp-inspection']
                        type: str
                        description: Enable/disable FortiSwitch ARP inspection.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'monitor'
                    switch_controller_auth:
                        aliases: ['switch-controller-auth']
                        type: str
                        description: Switch controller authentication.
                        choices:
                            - 'radius'
                            - 'usergroup'
                    switch_controller_dhcp_snooping:
                        aliases: ['switch-controller-dhcp-snooping']
                        type: str
                        description: Switch controller DHCP snooping.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_dhcp_snooping_option82:
                        aliases: ['switch-controller-dhcp-snooping-option82']
                        type: str
                        description: Switch controller DHCP snooping option82.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_dhcp_snooping_verify_mac:
                        aliases: ['switch-controller-dhcp-snooping-verify-mac']
                        type: str
                        description: Switch controller DHCP snooping verify MAC.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_feature:
                        aliases: ['switch-controller-feature']
                        type: str
                        description: Interfaces purpose when assigning traffic
                        choices:
                            - 'none'
                            - 'default-vlan'
                            - 'quarantine'
                            - 'sniffer'
                            - 'voice'
                            - 'camera'
                            - 'rspan'
                            - 'video'
                            - 'nac'
                            - 'nac-segment'
                    switch_controller_igmp_snooping:
                        aliases: ['switch-controller-igmp-snooping']
                        type: str
                        description: Switch controller IGMP snooping.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_igmp_snooping_fast_leave:
                        aliases: ['switch-controller-igmp-snooping-fast-leave']
                        type: str
                        description: Switch controller IGMP snooping fast-leave.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_igmp_snooping_proxy:
                        aliases: ['switch-controller-igmp-snooping-proxy']
                        type: str
                        description: Switch controller IGMP snooping proxy.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_iot_scanning:
                        aliases: ['switch-controller-iot-scanning']
                        type: str
                        description: Enable/disable managed FortiSwitch IoT scanning.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_learning_limit:
                        aliases: ['switch-controller-learning-limit']
                        type: int
                        description: Limit the number of dynamic MAC addresses on this VLAN
                    switch_controller_mgmt_vlan:
                        aliases: ['switch-controller-mgmt-vlan']
                        type: int
                        description: VLAN to use for FortiLink management purposes.
                    switch_controller_nac:
                        aliases: ['switch-controller-nac']
                        type: str
                        description: Integrated NAC settings for managed FortiSwitch.
                    switch_controller_radius_server:
                        aliases: ['switch-controller-radius-server']
                        type: str
                        description: RADIUS server name for this FortiSwitch VLAN.
                    switch_controller_rspan_mode:
                        aliases: ['switch-controller-rspan-mode']
                        type: str
                        description: Stop Layer2 MAC learning and interception of BPDUs and other packets on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_source_ip:
                        aliases: ['switch-controller-source-ip']
                        type: str
                        description: Source IP address used in FortiLink over L3 connections.
                        choices:
                            - 'outbound'
                            - 'fixed'
                    switch_controller_traffic_policy:
                        aliases: ['switch-controller-traffic-policy']
                        type: str
                        description: Switch controller traffic policy for the VLAN.
                    tc_mode:
                        aliases: ['tc-mode']
                        type: str
                        description: DSL transfer mode.
                        choices:
                            - 'ptm'
                            - 'atm'
                    tcp_mss:
                        aliases: ['tcp-mss']
                        type: int
                        description: TCP maximum segment size.
                    trunk:
                        type: str
                        description: Enable/disable VLAN trunk.
                        choices:
                            - 'disable'
                            - 'enable'
                    trust_ip_1:
                        aliases: ['trust-ip-1']
                        type: str
                        description: Trusted host for dedicated management traffic
                    trust_ip_2:
                        aliases: ['trust-ip-2']
                        type: str
                        description: Trusted host for dedicated management traffic
                    trust_ip_3:
                        aliases: ['trust-ip-3']
                        type: str
                        description: Trusted host for dedicated management traffic
                    trust_ip6_1:
                        aliases: ['trust-ip6-1']
                        type: str
                        description: Trusted IPv6 host for dedicated management traffic
                    trust_ip6_2:
                        aliases: ['trust-ip6-2']
                        type: str
                        description: Trusted IPv6 host for dedicated management traffic
                    trust_ip6_3:
                        aliases: ['trust-ip6-3']
                        type: str
                        description: Trusted IPv6 host for dedicated management traffic
                    type:
                        type: str
                        description: Interface type.
                        choices:
                            - 'physical'
                            - 'vlan'
                            - 'aggregate'
                            - 'redundant'
                            - 'tunnel'
                            - 'wireless'
                            - 'vdom-link'
                            - 'loopback'
                            - 'switch'
                            - 'hard-switch'
                            - 'hdlc'
                            - 'vap-switch'
                            - 'wl-mesh'
                            - 'fortilink'
                            - 'switch-vlan'
                            - 'fctrl-trunk'
                            - 'tdm'
                            - 'fext-wan'
                            - 'vxlan'
                            - 'emac-vlan'
                            - 'geneve'
                            - 'ssl'
                            - 'lan-extension'
                    username:
                        type: str
                        description: Username of the PPPoE account, provided by your ISP.
                    vci:
                        type: int
                        description: Virtual Channel ID
                    vectoring:
                        type: str
                        description: Enable/disable DSL vectoring.
                        choices:
                            - 'disable'
                            - 'enable'
                    vindex:
                        type: int
                        description: Vindex.
                    vlan_protocol:
                        aliases: ['vlan-protocol']
                        type: str
                        description: Ethernet protocol of VLAN.
                        choices:
                            - '8021q'
                            - '8021ad'
                    vlanforward:
                        type: str
                        description: Enable/disable traffic forwarding between VLANs on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    vlanid:
                        type: int
                        description: VLAN ID
                    vpi:
                        type: int
                        description: Virtual Path ID
                    vrf:
                        type: int
                        description: Virtual Routing Forwarding ID.
                    vrrp:
                        type: list
                        elements: dict
                        description: Vrrp.
                        suboptions:
                            accept_mode:
                                aliases: ['accept-mode']
                                type: str
                                description: Enable/disable accept mode.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            adv_interval:
                                aliases: ['adv-interval']
                                type: int
                                description: Advertisement interval
                            ignore_default_route:
                                aliases: ['ignore-default-route']
                                type: str
                                description: Enable/disable ignoring of default route when checking destination.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            preempt:
                                type: str
                                description: Enable/disable preempt mode.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            priority:
                                type: int
                                description: Priority of the virtual router
                            start_time:
                                aliases: ['start-time']
                                type: int
                                description: Startup time
                            status:
                                type: str
                                description: Enable/disable this VRRP configuration.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            version:
                                type: str
                                description: VRRP version.
                                choices:
                                    - '2'
                                    - '3'
                            vrdst:
                                type: raw
                                description: (list) Monitor the route to this destination.
                            vrdst_priority:
                                aliases: ['vrdst-priority']
                                type: int
                                description: Priority of the virtual router when the virtual router destination becomes unreachable
                            vrgrp:
                                type: int
                                description: VRRP group ID
                            vrid:
                                type: int
                                description: Virtual router identifier
                            vrip:
                                type: str
                                description: IP address of the virtual router.
                            proxy_arp:
                                aliases: ['proxy-arp']
                                type: list
                                elements: dict
                                description: Proxy arp.
                                suboptions:
                                    id:
                                        type: int
                                        description: ID.
                                    ip:
                                        type: str
                                        description: Set IP addresses of proxy ARP.
                    vrrp_virtual_mac:
                        aliases: ['vrrp-virtual-mac']
                        type: str
                        description: Enable/disable use of virtual MAC for VRRP.
                        choices:
                            - 'disable'
                            - 'enable'
                    wccp:
                        type: str
                        description: Enable/disable WCCP on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    weight:
                        type: int
                        description: Default weight for static routes
                    wifi_5g_threshold:
                        aliases: ['wifi-5g-threshold']
                        type: str
                        description: Minimal signal strength to be considered as a good 5G AP.
                    wifi_acl:
                        aliases: ['wifi-acl']
                        type: str
                        description: Access control for MAC addresses in the MAC list.
                        choices:
                            - 'deny'
                            - 'allow'
                    wifi_ap_band:
                        aliases: ['wifi-ap-band']
                        type: str
                        description: How to select the AP to connect.
                        choices:
                            - 'any'
                            - '5g-preferred'
                            - '5g-only'
                    wifi_auth:
                        aliases: ['wifi-auth']
                        type: str
                        description: WiFi authentication.
                        choices:
                            - 'PSK'
                            - 'RADIUS'
                            - 'radius'
                            - 'usergroup'
                    wifi_auto_connect:
                        aliases: ['wifi-auto-connect']
                        type: str
                        description: Enable/disable WiFi network auto connect.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi_auto_save:
                        aliases: ['wifi-auto-save']
                        type: str
                        description: Enable/disable WiFi network automatic save.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi_broadcast_ssid:
                        aliases: ['wifi-broadcast-ssid']
                        type: str
                        description: Enable/disable SSID broadcast in the beacon.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi_encrypt:
                        aliases: ['wifi-encrypt']
                        type: str
                        description: Data encryption.
                        choices:
                            - 'TKIP'
                            - 'AES'
                    wifi_fragment_threshold:
                        aliases: ['wifi-fragment-threshold']
                        type: int
                        description: WiFi fragment threshold
                    wifi_key:
                        aliases: ['wifi-key']
                        type: raw
                        description: (list) WiFi WEP Key.
                    wifi_keyindex:
                        aliases: ['wifi-keyindex']
                        type: int
                        description: WEP key index
                    wifi_mac_filter:
                        aliases: ['wifi-mac-filter']
                        type: str
                        description: Enable/disable MAC filter status.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi_passphrase:
                        aliases: ['wifi-passphrase']
                        type: raw
                        description: (list) WiFi pre-shared key for WPA.
                    wifi_radius_server:
                        aliases: ['wifi-radius-server']
                        type: str
                        description: WiFi RADIUS server for WPA.
                    wifi_rts_threshold:
                        aliases: ['wifi-rts-threshold']
                        type: int
                        description: WiFi RTS threshold
                    wifi_security:
                        aliases: ['wifi-security']
                        type: str
                        description: Wireless access security of SSID.
                        choices:
                            - 'None'
                            - 'WEP64'
                            - 'wep64'
                            - 'WEP128'
                            - 'wep128'
                            - 'WPA_PSK'
                            - 'WPA_RADIUS'
                            - 'WPA'
                            - 'WPA2'
                            - 'WPA2_AUTO'
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'wpa-only-personal'
                            - 'wpa-only-enterprise'
                            - 'wpa2-only-personal'
                            - 'wpa2-only-enterprise'
                    wifi_ssid:
                        aliases: ['wifi-ssid']
                        type: str
                        description: IEEE 802.
                    wifi_usergroup:
                        aliases: ['wifi-usergroup']
                        type: str
                        description: WiFi user group for WPA.
                    wins_ip:
                        aliases: ['wins-ip']
                        type: str
                        description: WINS server IP.
                    dhcp_relay_request_all_server:
                        aliases: ['dhcp-relay-request-all-server']
                        type: str
                        description: Enable/disable sending of DHCP requests to all servers.
                        choices:
                            - 'disable'
                            - 'enable'
                    stp_ha_secondary:
                        aliases: ['stp-ha-secondary']
                        type: str
                        description: Control STP behaviour on HA secondary.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'priority-adjust'
                    switch_controller_dynamic:
                        aliases: ['switch-controller-dynamic']
                        type: str
                        description: Integrated FortiLink settings for managed FortiSwitch.
                    auth_cert:
                        aliases: ['auth-cert']
                        type: str
                        description: HTTPS server certificate.
                    auth_portal_addr:
                        aliases: ['auth-portal-addr']
                        type: str
                        description: Address of captive portal.
                    dhcp_classless_route_addition:
                        aliases: ['dhcp-classless-route-addition']
                        type: str
                        description: Enable/disable addition of classless static routes retrieved from DHCP server.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_relay_link_selection:
                        aliases: ['dhcp-relay-link-selection']
                        type: str
                        description: DHCP relay link selection.
                    dns_server_protocol:
                        aliases: ['dns-server-protocol']
                        type: list
                        elements: str
                        description: DNS transport protocols.
                        choices:
                            - 'cleartext'
                            - 'dot'
                            - 'doh'
                    eap_ca_cert:
                        aliases: ['eap-ca-cert']
                        type: str
                        description: EAP CA certificate name.
                    eap_identity:
                        aliases: ['eap-identity']
                        type: str
                        description: EAP identity.
                    eap_method:
                        aliases: ['eap-method']
                        type: str
                        description: EAP method.
                        choices:
                            - 'tls'
                            - 'peap'
                    eap_password:
                        aliases: ['eap-password']
                        type: raw
                        description: (list) EAP password.
                    eap_supplicant:
                        aliases: ['eap-supplicant']
                        type: str
                        description: Enable/disable EAP-Supplicant.
                        choices:
                            - 'disable'
                            - 'enable'
                    eap_user_cert:
                        aliases: ['eap-user-cert']
                        type: str
                        description: EAP user certificate name.
                    ike_saml_server:
                        aliases: ['ike-saml-server']
                        type: str
                        description: Configure IKE authentication SAML server.
                    lacp_ha_secondary:
                        aliases: ['lacp-ha-secondary']
                        type: str
                        description: Lacp ha secondary.
                        choices:
                            - 'disable'
                            - 'enable'
                    pvc_atm_qos:
                        aliases: ['pvc-atm-qos']
                        type: str
                        description: SFP-DSL ADSL Fallback PVC ATM QoS.
                        choices:
                            - 'cbr'
                            - 'rt-vbr'
                            - 'nrt-vbr'
                            - 'ubr'
                    pvc_chan:
                        aliases: ['pvc-chan']
                        type: int
                        description: SFP-DSL ADSL Fallback PVC Channel.
                    pvc_crc:
                        aliases: ['pvc-crc']
                        type: int
                        description: SFP-DSL ADSL Fallback PVC CRC Option
                    pvc_pcr:
                        aliases: ['pvc-pcr']
                        type: int
                        description: SFP-DSL ADSL Fallback PVC Packet Cell Rate in cells
                    pvc_scr:
                        aliases: ['pvc-scr']
                        type: int
                        description: SFP-DSL ADSL Fallback PVC Sustainable Cell Rate in cells
                    pvc_vlan_id:
                        aliases: ['pvc-vlan-id']
                        type: int
                        description: SFP-DSL ADSL Fallback PVC VLAN ID.
                    pvc_vlan_rx_id:
                        aliases: ['pvc-vlan-rx-id']
                        type: int
                        description: SFP-DSL ADSL Fallback PVC VLANID RX.
                    pvc_vlan_rx_op:
                        aliases: ['pvc-vlan-rx-op']
                        type: str
                        description: SFP-DSL ADSL Fallback PVC VLAN RX op.
                        choices:
                            - 'pass-through'
                            - 'replace'
                            - 'remove'
                    pvc_vlan_tx_id:
                        aliases: ['pvc-vlan-tx-id']
                        type: int
                        description: SFP-DSL ADSL Fallback PVC VLAN ID TX.
                    pvc_vlan_tx_op:
                        aliases: ['pvc-vlan-tx-op']
                        type: str
                        description: SFP-DSL ADSL Fallback PVC VLAN TX op.
                        choices:
                            - 'pass-through'
                            - 'replace'
                            - 'remove'
                    reachable_time:
                        aliases: ['reachable-time']
                        type: int
                        description: IPv4 reachable time in milliseconds
                    select_profile_30a_35b:
                        aliases: ['select-profile-30a-35b']
                        type: str
                        description: Select VDSL Profile 30a or 35b.
                        choices:
                            - '30A'
                            - '35B'
                            - '30a'
                            - '35b'
                    sfp_dsl:
                        aliases: ['sfp-dsl']
                        type: str
                        description: Enable/disable SFP DSL.
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp_dsl_adsl_fallback:
                        aliases: ['sfp-dsl-adsl-fallback']
                        type: str
                        description: Enable/disable SFP DSL ADSL fallback.
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp_dsl_autodetect:
                        aliases: ['sfp-dsl-autodetect']
                        type: str
                        description: Enable/disable SFP DSL MAC address autodetect.
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp_dsl_mac:
                        aliases: ['sfp-dsl-mac']
                        type: str
                        description: SFP DSL MAC address.
                    sw_algorithm:
                        aliases: ['sw-algorithm']
                        type: str
                        description: Frame distribution algorithm for switch.
                        choices:
                            - 'l2'
                            - 'l3'
                            - 'eh'
                            - 'default'
                    system_id:
                        aliases: ['system-id']
                        type: str
                        description: Define a system ID for the aggregate interface.
                    system_id_type:
                        aliases: ['system-id-type']
                        type: str
                        description: Method in which system ID is generated.
                        choices:
                            - 'auto'
                            - 'user'
                    vlan_id:
                        aliases: ['vlan-id']
                        type: int
                        description: Vlan ID
                    vlan_op_mode:
                        aliases: ['vlan-op-mode']
                        type: str
                        description: Configure DSL 802.
                        choices:
                            - 'tag'
                            - 'untag'
                            - 'passthrough'
                    generic_receive_offload:
                        aliases: ['generic-receive-offload']
                        type: str
                        description: Generic receive offload.
                        choices:
                            - 'disable'
                            - 'enable'
                    interconnect_profile:
                        aliases: ['interconnect-profile']
                        type: str
                        description: Set interconnect profile.
                        choices:
                            - 'default'
                            - 'profile1'
                            - 'profile2'
                    large_receive_offload:
                        aliases: ['large-receive-offload']
                        type: str
                        description: Large receive offload.
                        choices:
                            - 'disable'
                            - 'enable'
                    annex:
                        type: str
                        description: Set xDSL annex type.
                        choices:
                            - 'a'
                            - 'b'
                            - 'j'
                            - 'bjm'
                            - 'i'
                            - 'al'
                            - 'm'
                            - 'aijlm'
                            - 'bj'
                    aggregate_type:
                        aliases: ['aggregate-type']
                        type: str
                        description: Type of aggregation.
                        choices:
                            - 'physical'
                            - 'vxlan'
                    switch_controller_netflow_collect:
                        aliases: ['switch-controller-netflow-collect']
                        type: str
                        description: NetFlow collection and processing.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi_dns_server1:
                        aliases: ['wifi-dns-server1']
                        type: str
                        description: DNS server 1.
                    wifi_dns_server2:
                        aliases: ['wifi-dns-server2']
                        type: str
                        description: DNS server 2.
                    wifi_gateway:
                        aliases: ['wifi-gateway']
                        type: str
                        description: IPv4 default gateway IP address.
                    default_purdue_level:
                        aliases: ['default-purdue-level']
                        type: str
                        description: Default purdue level of device detected on this interface.
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '1.5'
                            - '2.5'
                            - '3.5'
                            - '5.5'
                    dhcp_broadcast_flag:
                        aliases: ['dhcp-broadcast-flag']
                        type: str
                        description: Enable/disable setting of the broadcast flag in messages sent by the DHCP client
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_smart_relay:
                        aliases: ['dhcp-smart-relay']
                        type: str
                        description: Enable/disable DHCP smart relay.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_offloading:
                        aliases: ['switch-controller-offloading']
                        type: str
                        description: Switch controller offloading.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_offloading_gw:
                        aliases: ['switch-controller-offloading-gw']
                        type: str
                        description: Switch controller offloading gw.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_offloading_ip:
                        aliases: ['switch-controller-offloading-ip']
                        type: str
                        description: Switch controller offloading ip.
                    dhcp_relay_circuit_id:
                        aliases: ['dhcp-relay-circuit-id']
                        type: str
                        description: DHCP relay circuit ID.
                    dhcp_relay_source_ip:
                        aliases: ['dhcp-relay-source-ip']
                        type: str
                        description: IP address used by the DHCP relay as its source IP.
                    switch_controller_offload:
                        aliases: ['switch-controller-offload']
                        type: str
                        description: Enable/disable managed FortiSwitch routing offload.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_offload_gw:
                        aliases: ['switch-controller-offload-gw']
                        type: str
                        description: Enable/disable managed FortiSwitch routing offload gateway.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_offload_ip:
                        aliases: ['switch-controller-offload-ip']
                        type: str
                        description: IP for routing offload on FortiSwitch.
                    mirroring_direction:
                        aliases: ['mirroring-direction']
                        type: str
                        description: Port mirroring direction.
                        choices:
                            - 'rx'
                            - 'tx'
                            - 'both'
                    mirroring_port:
                        aliases: ['mirroring-port']
                        type: str
                        description: Mirroring port.
                    port_mirroring:
                        aliases: ['port-mirroring']
                        type: str
                        description: Enable/disable NP port mirroring.
                        choices:
                            - 'disable'
                            - 'enable'
                    security_8021x_member_mode:
                        aliases: ['security-8021x-member-mode']
                        type: str
                        description: '802.'
                        choices:
                            - 'disable'
                            - 'switch'
                    stp_edge:
                        aliases: ['stp-edge']
                        type: str
                        description: Enable/disable as STP edge port.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_relay_allow_no_end_option:
                        aliases: ['dhcp-relay-allow-no-end-option']
                        type: str
                        description: Enable/disable relaying DHCP messages with no end option.
                        choices:
                            - 'disable'
                            - 'enable'
                    netflow_sample_rate:
                        aliases: ['netflow-sample-rate']
                        type: int
                        description: NetFlow sample rate.
                    netflow_sampler_id:
                        aliases: ['netflow-sampler-id']
                        type: int
                        description: Netflow sampler ID.
                    pppoe_egress_cos:
                        aliases: ['pppoe-egress-cos']
                        type: str
                        description: CoS in VLAN tag for outgoing PPPoE/PPP packets.
                        choices:
                            - 'cos0'
                            - 'cos1'
                            - 'cos2'
                            - 'cos3'
                            - 'cos4'
                            - 'cos5'
                            - 'cos6'
                            - 'cos7'
                    security_ip_auth_bypass:
                        aliases: ['security-ip-auth-bypass']
                        type: str
                        description: Enable/disable IP authentication bypass.
                        choices:
                            - 'disable'
                            - 'enable'
                    virtual_mac:
                        aliases: ['virtual-mac']
                        type: str
                        description: Change the interfaces virtual MAC address.
                    dhcp_relay_vrf_select:
                        aliases: ['dhcp-relay-vrf-select']
                        type: int
                        description: VRF ID used for connection to server.
                    exclude_signatures:
                        aliases: ['exclude-signatures']
                        type: list
                        elements: str
                        description: Exclude IOT or OT application signatures.
                        choices:
                            - 'iot'
                            - 'ot'
                    profiles:
                        type: list
                        elements: str
                        description: Set allowed VDSL profiles.
                        choices:
                            - '8a'
                            - '8b'
                            - '8c'
                            - '8d'
                            - '12a'
                            - '12b'
                            - '17a'
                            - '30a'
                            - '35b'
                    telemetry_discover:
                        aliases: ['telemetry-discover']
                        type: str
                        description: Enable/disable automatic registration of unknown FortiTelemetry agents.
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
    - name: FortiSwitch VLAN template.
      fortinet.fortimanager.fmgr_fsp_vlan:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        fsp_vlan:
          name: "your value" # Required variable, string
          # _dhcp_status: <value in [disable, enable]>
          # auth: <value in [radius, usergroup]>
          # color: <integer>
          # comments: <string>
          # dynamic_mapping:
          #   - _dhcp_status: <value in [disable, enable]>
          #     _scope:
          #       - name: <string>
          #         vdom: <string>
          #     dhcp_server:
          #       auto_configuration: <value in [disable, enable]>
          #       auto_managed_status: <value in [disable, enable]>
          #       conflicted_ip_timeout: <integer>
          #       ddns_auth: <value in [disable, tsig]>
          #       ddns_key: <list or string>
          #       ddns_keyname: <string>
          #       ddns_server_ip: <string>
          #       ddns_ttl: <integer>
          #       ddns_update: <value in [disable, enable]>
          #       ddns_update_override: <value in [disable, enable]>
          #       ddns_zone: <string>
          #       default_gateway: <string>
          #       dhcp_settings_from_fortiipam: <value in [disable, enable]>
          #       dns_server1: <string>
          #       dns_server2: <string>
          #       dns_server3: <string>
          #       dns_server4: <string>
          #       dns_service: <value in [default, specify, local]>
          #       domain: <string>
          #       enable: <value in [disable, enable]>
          #       exclude_range:
          #         - end_ip: <string>
          #           id: <integer>
          #           start_ip: <string>
          #           vci_match: <value in [disable, enable]>
          #           vci_string: <list or string>
          #           lease_time: <integer>
          #           uci_match: <value in [disable, enable]>
          #           uci_string: <list or string>
          #       filename: <string>
          #       forticlient_on_net_status: <value in [disable, enable]>
          #       id: <integer>
          #       ip_mode: <value in [range, usrgrp]>
          #       ip_range:
          #         - end_ip: <string>
          #           id: <integer>
          #           start_ip: <string>
          #           vci_match: <value in [disable, enable]>
          #           vci_string: <list or string>
          #           lease_time: <integer>
          #           uci_match: <value in [disable, enable]>
          #           uci_string: <list or string>
          #       ipsec_lease_hold: <integer>
          #       lease_time: <integer>
          #       mac_acl_default_action: <value in [assign, block]>
          #       netmask: <string>
          #       next_server: <string>
          #       ntp_server1: <string>
          #       ntp_server2: <string>
          #       ntp_server3: <string>
          #       ntp_service: <value in [default, specify, local]>
          #       option1: <list or string>
          #       option2: <list or string>
          #       option3: <list or string>
          #       option4: <string>
          #       option5: <string>
          #       option6: <string>
          #       options:
          #         - code: <integer>
          #           id: <integer>
          #           ip: <list or string>
          #           type: <value in [hex, string, ip, ...]>
          #           value: <string>
          #           vci_match: <value in [disable, enable]>
          #           vci_string: <list or string>
          #           uci_match: <value in [disable, enable]>
          #           uci_string: <list or string>
          #       reserved_address:
          #         - action: <value in [assign, block, reserved]>
          #           circuit_id: <string>
          #           circuit_id_type: <value in [hex, string]>
          #           description: <string>
          #           id: <integer>
          #           ip: <string>
          #           mac: <string>
          #           remote_id: <string>
          #           remote_id_type: <value in [hex, string]>
          #           type: <value in [mac, option82]>
          #       server_type: <value in [regular, ipsec]>
          #       status: <value in [disable, enable]>
          #       tftp_server: <list or string>
          #       timezone: <value in [00, 01, 02, ...]>
          #       timezone_option: <value in [disable, default, specify]>
          #       vci_match: <value in [disable, enable]>
          #       vci_string: <list or string>
          #       wifi_ac_service: <value in [specify, local]>
          #       wifi_ac1: <string>
          #       wifi_ac2: <string>
          #       wifi_ac3: <string>
          #       wins_server1: <string>
          #       wins_server2: <string>
          #       relay_agent: <string>
          #       shared_subnet: <value in [disable, enable]>
          #     interface:
          #       dhcp_relay_agent_option: <value in [disable, enable]>
          #       dhcp_relay_ip: <list or string>
          #       dhcp_relay_service: <value in [disable, enable]>
          #       dhcp_relay_type: <value in [regular, ipsec]>
          #       ip: <string>
          #       ipv6:
          #         autoconf: <value in [disable, enable]>
          #         dhcp6_client_options:
          #           - "rapid"
          #           - "iapd"
          #           - "iana"
          #           - "dns"
          #           - "dnsname"
          #         dhcp6_information_request: <value in [disable, enable]>
          #         dhcp6_prefix_delegation: <value in [disable, enable]>
          #         dhcp6_prefix_hint: <string>
          #         dhcp6_prefix_hint_plt: <integer>
          #         dhcp6_prefix_hint_vlt: <integer>
          #         dhcp6_relay_ip: <string>
          #         dhcp6_relay_service: <value in [disable, enable]>
          #         dhcp6_relay_type: <value in [regular]>
          #         icmp6_send_redirect: <value in [disable, enable]>
          #         interface_identifier: <string>
          #         ip6_address: <string>
          #         ip6_allowaccess:
          #           - "https"
          #           - "ping"
          #           - "ssh"
          #           - "snmp"
          #           - "http"
          #           - "telnet"
          #           - "fgfm"
          #           - "capwap"
          #           - "fabric"
          #         ip6_default_life: <integer>
          #         ip6_delegated_prefix_list:
          #           - autonomous_flag: <value in [disable, enable]>
          #             onlink_flag: <value in [disable, enable]>
          #             prefix_id: <integer>
          #             rdnss: <list or string>
          #             rdnss_service: <value in [delegated, default, specify]>
          #             subnet: <string>
          #             upstream_interface: <string>
          #             delegated_prefix_iaid: <integer>
          #         ip6_dns_server_override: <value in [disable, enable]>
          #         ip6_extra_addr:
          #           - prefix: <string>
          #         ip6_hop_limit: <integer>
          #         ip6_link_mtu: <integer>
          #         ip6_manage_flag: <value in [disable, enable]>
          #         ip6_max_interval: <integer>
          #         ip6_min_interval: <integer>
          #         ip6_mode: <value in [static, dhcp, pppoe, ...]>
          #         ip6_other_flag: <value in [disable, enable]>
          #         ip6_prefix_list:
          #           - autonomous_flag: <value in [disable, enable]>
          #             dnssl: <list or string>
          #             onlink_flag: <value in [disable, enable]>
          #             preferred_life_time: <integer>
          #             prefix: <string>
          #             rdnss: <list or string>
          #             valid_life_time: <integer>
          #         ip6_reachable_time: <integer>
          #         ip6_retrans_time: <integer>
          #         ip6_send_adv: <value in [disable, enable]>
          #         ip6_subnet: <string>
          #         ip6_upstream_interface: <string>
          #         nd_cert: <string>
          #         nd_cga_modifier: <string>
          #         nd_mode: <value in [basic, SEND-compatible]>
          #         nd_security_level: <integer>
          #         nd_timestamp_delta: <integer>
          #         nd_timestamp_fuzz: <integer>
          #         unique_autoconf_addr: <value in [disable, enable]>
          #         vrip6_link_local: <string>
          #         vrrp_virtual_mac6: <value in [disable, enable]>
          #         vrrp6:
          #           - accept_mode: <value in [disable, enable]>
          #             adv_interval: <integer>
          #             preempt: <value in [disable, enable]>
          #             priority: <integer>
          #             start_time: <integer>
          #             status: <value in [disable, enable]>
          #             vrdst6: <string>
          #             vrgrp: <integer>
          #             vrid: <integer>
          #             vrip6: <string>
          #             ignore_default_route: <value in [disable, enable]>
          #             vrdst_priority: <integer>
          #         cli_conn6_status: <integer>
          #         ip6_prefix_mode: <value in [dhcp6, ra]>
          #         ra_send_mtu: <value in [disable, enable]>
          #         ip6_delegated_prefix_iaid: <integer>
          #         dhcp6_relay_source_interface: <value in [disable, enable]>
          #         dhcp6_relay_interface_id: <string>
          #         dhcp6_relay_source_ip: <string>
          #         ip6_adv_rio: <value in [disable, enable]>
          #         ip6_route_pref: <value in [medium, high, low]>
          #       secondary_IP: <value in [disable, enable]>
          #       secondaryip:
          #         - allowaccess:
          #             - "https"
          #             - "ping"
          #             - "ssh"
          #             - "snmp"
          #             - "http"
          #             - "telnet"
          #             - "fgfm"
          #             - "auto-ipsec"
          #             - "radius-acct"
          #             - "probe-response"
          #             - "capwap"
          #             - "dnp"
          #             - "ftm"
          #             - "fabric"
          #             - "speed-test"
          #             - "icond"
          #             - "scim"
          #           detectprotocol:
          #             - "ping"
          #             - "tcp-echo"
          #             - "udp-echo"
          #           detectserver: <string>
          #           gwdetect: <value in [disable, enable]>
          #           ha_priority: <integer>
          #           id: <integer>
          #           ip: <string>
          #           ping_serv_status: <integer>
          #           seq: <integer>
          #           secip_relay_ip: <string>
          #       vlanid: <integer>
          #       dhcp_relay_interface_select_method: <value in [auto, sdwan, specify]>
          #       vrrp:
          #         - accept_mode: <value in [disable, enable]>
          #           adv_interval: <integer>
          #           ignore_default_route: <value in [disable, enable]>
          #           preempt: <value in [disable, enable]>
          #           priority: <integer>
          #           proxy_arp:
          #             - id: <integer>
          #               ip: <string>
          #           start_time: <integer>
          #           status: <value in [disable, enable]>
          #           version: <value in [2, 3]>
          #           vrdst: <list or string>
          #           vrdst_priority: <integer>
          #           vrgrp: <integer>
          #           vrid: <integer>
          #           vrip: <string>
          #       allowaccess:
          #         - "https"
          #         - "ping"
          #         - "ssh"
          #         - "snmp"
          #         - "http"
          #         - "telnet"
          #         - "fgfm"
          #         - "radius-acct"
          #         - "probe-response"
          #         - "dnp"
          #         - "ftm"
          #         - "fabric"
          #         - "speed-test"
          #         - "icond"
          #         - "scim"
          #       dhcp_relay_request_all_server: <value in [disable, enable]>
          # portal_message_override_group: <string>
          # radius_server: <string>
          # security: <value in [open, captive-portal, 8021x]>
          # selected_usergroups: <string>
          # usergroup: <string>
          # vdom: <string>
          # vlanid: <integer>
          # dhcp_server:
          #   auto_configuration: <value in [disable, enable]>
          #   auto_managed_status: <value in [disable, enable]>
          #   conflicted_ip_timeout: <integer>
          #   ddns_auth: <value in [disable, tsig]>
          #   ddns_key: <list or string>
          #   ddns_keyname: <string>
          #   ddns_server_ip: <string>
          #   ddns_ttl: <integer>
          #   ddns_update: <value in [disable, enable]>
          #   ddns_update_override: <value in [disable, enable]>
          #   ddns_zone: <string>
          #   default_gateway: <string>
          #   dhcp_settings_from_fortiipam: <value in [disable, enable]>
          #   dns_server1: <string>
          #   dns_server2: <string>
          #   dns_server3: <string>
          #   dns_server4: <string>
          #   dns_service: <value in [default, specify, local]>
          #   domain: <string>
          #   enable: <value in [disable, enable]>
          #   exclude_range:
          #     - end_ip: <string>
          #       id: <integer>
          #       start_ip: <string>
          #       vci_match: <value in [disable, enable]>
          #       vci_string: <list or string>
          #       lease_time: <integer>
          #       uci_match: <value in [disable, enable]>
          #       uci_string: <list or string>
          #   filename: <string>
          #   forticlient_on_net_status: <value in [disable, enable]>
          #   id: <integer>
          #   ip_mode: <value in [range, usrgrp]>
          #   ip_range:
          #     - end_ip: <string>
          #       id: <integer>
          #       start_ip: <string>
          #       vci_match: <value in [disable, enable]>
          #       vci_string: <list or string>
          #       lease_time: <integer>
          #       uci_match: <value in [disable, enable]>
          #       uci_string: <list or string>
          #   ipsec_lease_hold: <integer>
          #   lease_time: <integer>
          #   mac_acl_default_action: <value in [assign, block]>
          #   netmask: <string>
          #   next_server: <string>
          #   ntp_server1: <string>
          #   ntp_server2: <string>
          #   ntp_server3: <string>
          #   ntp_service: <value in [default, specify, local]>
          #   option1: <list or string>
          #   option2: <list or string>
          #   option3: <list or string>
          #   option4: <string>
          #   option5: <string>
          #   option6: <string>
          #   options:
          #     - code: <integer>
          #       id: <integer>
          #       ip: <list or string>
          #       type: <value in [hex, string, ip, ...]>
          #       value: <string>
          #       vci_match: <value in [disable, enable]>
          #       vci_string: <list or string>
          #       uci_match: <value in [disable, enable]>
          #       uci_string: <list or string>
          #   reserved_address:
          #     - action: <value in [assign, block, reserved]>
          #       circuit_id: <string>
          #       circuit_id_type: <value in [hex, string]>
          #       description: <string>
          #       id: <integer>
          #       ip: <string>
          #       mac: <string>
          #       remote_id: <string>
          #       remote_id_type: <value in [hex, string]>
          #       type: <value in [mac, option82]>
          #   server_type: <value in [regular, ipsec]>
          #   status: <value in [disable, enable]>
          #   tftp_server: <list or string>
          #   timezone: <value in [00, 01, 02, ...]>
          #   timezone_option: <value in [disable, default, specify]>
          #   vci_match: <value in [disable, enable]>
          #   vci_string: <list or string>
          #   wifi_ac_service: <value in [specify, local]>
          #   wifi_ac1: <string>
          #   wifi_ac2: <string>
          #   wifi_ac3: <string>
          #   wins_server1: <string>
          #   wins_server2: <string>
          #   relay_agent: <string>
          #   shared_subnet: <value in [disable, enable]>
          # interface:
          #   ac_name: <string>
          #   aggregate: <string>
          #   algorithm: <value in [L2, L3, L4, ...]>
          #   alias: <string>
          #   allowaccess:
          #     - "https"
          #     - "ping"
          #     - "ssh"
          #     - "snmp"
          #     - "http"
          #     - "telnet"
          #     - "fgfm"
          #     - "auto-ipsec"
          #     - "radius-acct"
          #     - "probe-response"
          #     - "capwap"
          #     - "dnp"
          #     - "ftm"
          #     - "fabric"
          #     - "speed-test"
          #   ap_discover: <value in [disable, enable]>
          #   arpforward: <value in [disable, enable]>
          #   atm_protocol: <value in [none, ipoa]>
          #   auth_type: <value in [auto, pap, chap, ...]>
          #   auto_auth_extension_device: <value in [disable, enable]>
          #   bandwidth_measure_time: <integer>
          #   bfd: <value in [global, enable, disable]>
          #   bfd_desired_min_tx: <integer>
          #   bfd_detect_mult: <integer>
          #   bfd_required_min_rx: <integer>
          #   broadcast_forticlient_discovery: <value in [disable, enable]>
          #   broadcast_forward: <value in [disable, enable]>
          #   captive_portal: <integer>
          #   cli_conn_status: <integer>
          #   color: <integer>
          #   ddns: <value in [disable, enable]>
          #   ddns_auth: <value in [disable, tsig]>
          #   ddns_domain: <string>
          #   ddns_key: <list or string>
          #   ddns_keyname: <string>
          #   ddns_password: <list or string>
          #   ddns_server: <value in [dhs.org, dyndns.org, dyns.net, ...]>
          #   ddns_server_ip: <string>
          #   ddns_sn: <string>
          #   ddns_ttl: <integer>
          #   ddns_username: <string>
          #   ddns_zone: <string>
          #   dedicated_to: <value in [none, management]>
          #   defaultgw: <value in [disable, enable]>
          #   description: <string>
          #   detected_peer_mtu: <integer>
          #   detectprotocol:
          #     - "ping"
          #     - "tcp-echo"
          #     - "udp-echo"
          #   detectserver: <string>
          #   device_access_list: <list or string>
          #   device_identification: <value in [disable, enable]>
          #   device_identification_active_scan: <value in [disable, enable]>
          #   device_netscan: <value in [disable, enable]>
          #   device_user_identification: <value in [disable, enable]>
          #   devindex: <integer>
          #   dhcp_client_identifier: <string>
          #   dhcp_relay_agent_option: <value in [disable, enable]>
          #   dhcp_relay_interface: <string>
          #   dhcp_relay_interface_select_method: <value in [auto, sdwan, specify]>
          #   dhcp_relay_ip: <list or string>
          #   dhcp_relay_service: <value in [disable, enable]>
          #   dhcp_relay_type: <value in [regular, ipsec]>
          #   dhcp_renew_time: <integer>
          #   disc_retry_timeout: <integer>
          #   disconnect_threshold: <integer>
          #   distance: <integer>
          #   dns_query: <value in [disable, recursive, non-recursive]>
          #   dns_server_override: <value in [disable, enable]>
          #   drop_fragment: <value in [disable, enable]>
          #   drop_overlapped_fragment: <value in [disable, enable]>
          #   egress_cos: <value in [disable, cos0, cos1, ...]>
          #   egress_shaping_profile: <string>
          #   eip: <string>
          #   endpoint_compliance: <value in [disable, enable]>
          #   estimated_downstream_bandwidth: <integer>
          #   estimated_upstream_bandwidth: <integer>
          #   explicit_ftp_proxy: <value in [disable, enable]>
          #   explicit_web_proxy: <value in [disable, enable]>
          #   external: <value in [disable, enable]>
          #   fail_action_on_extender: <value in [soft-restart, hard-restart, reboot]>
          #   fail_alert_interfaces: <list or string>
          #   fail_alert_method: <value in [link-failed-signal, link-down]>
          #   fail_detect: <value in [disable, enable]>
          #   fail_detect_option:
          #     - "detectserver"
          #     - "link-down"
          #   fdp: <value in [disable, enable]>
          #   fortiheartbeat: <value in [disable, enable]>
          #   fortilink: <value in [disable, enable]>
          #   fortilink_backup_link: <integer>
          #   fortilink_neighbor_detect: <value in [lldp, fortilink]>
          #   fortilink_split_interface: <value in [disable, enable]>
          #   fortilink_stacking: <value in [disable, enable]>
          #   forward_domain: <integer>
          #   forward_error_correction: <value in [disable, enable, rs-fec, ...]>
          #   fp_anomaly:
          #     - "drop_tcp_fin_noack"
          #     - "pass_winnuke"
          #     - "pass_tcpland"
          #     - "pass_udpland"
          #     - "pass_icmpland"
          #     - "pass_ipland"
          #     - "pass_iprr"
          #     - "pass_ipssrr"
          #     - "pass_iplsrr"
          #     - "pass_ipstream"
          #     - "pass_ipsecurity"
          #     - "pass_iptimestamp"
          #     - "pass_ipunknown_option"
          #     - "pass_ipunknown_prot"
          #     - "pass_icmp_frag"
          #     - "pass_tcp_no_flag"
          #     - "pass_tcp_fin_noack"
          #     - "drop_winnuke"
          #     - "drop_tcpland"
          #     - "drop_udpland"
          #     - "drop_icmpland"
          #     - "drop_ipland"
          #     - "drop_iprr"
          #     - "drop_ipssrr"
          #     - "drop_iplsrr"
          #     - "drop_ipstream"
          #     - "drop_ipsecurity"
          #     - "drop_iptimestamp"
          #     - "drop_ipunknown_option"
          #     - "drop_ipunknown_prot"
          #     - "drop_icmp_frag"
          #     - "drop_tcp_no_flag"
          #   fp_disable:
          #     - "all"
          #     - "ipsec"
          #     - "none"
          #   gateway_address: <string>
          #   gi_gk: <value in [disable, enable]>
          #   gwaddr: <string>
          #   gwdetect: <value in [disable, enable]>
          #   ha_priority: <integer>
          #   icmp_accept_redirect: <value in [disable, enable]>
          #   icmp_redirect: <value in [disable, enable]>
          #   icmp_send_redirect: <value in [disable, enable]>
          #   ident_accept: <value in [disable, enable]>
          #   idle_timeout: <integer>
          #   if_mdix: <value in [auto, normal, crossover]>
          #   if_media: <value in [auto, copper, fiber]>
          #   in_force_vlan_cos: <integer>
          #   inbandwidth: <integer>
          #   ingress_cos: <value in [disable, cos0, cos1, ...]>
          #   ingress_shaping_profile: <string>
          #   ingress_spillover_threshold: <integer>
          #   internal: <integer>
          #   ip: <string>
          #   ip_managed_by_fortiipam: <value in [disable, enable, inherit-global]>
          #   ipmac: <value in [disable, enable]>
          #   ips_sniffer_mode: <value in [disable, enable]>
          #   ipunnumbered: <string>
          #   ipv6:
          #     autoconf: <value in [disable, enable]>
          #     dhcp6_client_options:
          #       - "rapid"
          #       - "iapd"
          #       - "iana"
          #       - "dns"
          #       - "dnsname"
          #     dhcp6_information_request: <value in [disable, enable]>
          #     dhcp6_prefix_delegation: <value in [disable, enable]>
          #     dhcp6_prefix_hint: <string>
          #     dhcp6_prefix_hint_plt: <integer>
          #     dhcp6_prefix_hint_vlt: <integer>
          #     dhcp6_relay_ip: <string>
          #     dhcp6_relay_service: <value in [disable, enable]>
          #     dhcp6_relay_type: <value in [regular]>
          #     icmp6_send_redirect: <value in [disable, enable]>
          #     interface_identifier: <string>
          #     ip6_address: <string>
          #     ip6_allowaccess:
          #       - "https"
          #       - "ping"
          #       - "ssh"
          #       - "snmp"
          #       - "http"
          #       - "telnet"
          #       - "fgfm"
          #       - "capwap"
          #       - "fabric"
          #     ip6_default_life: <integer>
          #     ip6_delegated_prefix_list:
          #       - autonomous_flag: <value in [disable, enable]>
          #         onlink_flag: <value in [disable, enable]>
          #         prefix_id: <integer>
          #         rdnss: <list or string>
          #         rdnss_service: <value in [delegated, default, specify]>
          #         subnet: <string>
          #         upstream_interface: <string>
          #         delegated_prefix_iaid: <integer>
          #     ip6_dns_server_override: <value in [disable, enable]>
          #     ip6_extra_addr:
          #       - prefix: <string>
          #     ip6_hop_limit: <integer>
          #     ip6_link_mtu: <integer>
          #     ip6_manage_flag: <value in [disable, enable]>
          #     ip6_max_interval: <integer>
          #     ip6_min_interval: <integer>
          #     ip6_mode: <value in [static, dhcp, pppoe, ...]>
          #     ip6_other_flag: <value in [disable, enable]>
          #     ip6_prefix_list:
          #       - autonomous_flag: <value in [disable, enable]>
          #         dnssl: <list or string>
          #         onlink_flag: <value in [disable, enable]>
          #         preferred_life_time: <integer>
          #         prefix: <string>
          #         rdnss: <list or string>
          #         valid_life_time: <integer>
          #     ip6_reachable_time: <integer>
          #     ip6_retrans_time: <integer>
          #     ip6_send_adv: <value in [disable, enable]>
          #     ip6_subnet: <string>
          #     ip6_upstream_interface: <string>
          #     nd_cert: <string>
          #     nd_cga_modifier: <string>
          #     nd_mode: <value in [basic, SEND-compatible]>
          #     nd_security_level: <integer>
          #     nd_timestamp_delta: <integer>
          #     nd_timestamp_fuzz: <integer>
          #     unique_autoconf_addr: <value in [disable, enable]>
          #     vrip6_link_local: <string>
          #     vrrp_virtual_mac6: <value in [disable, enable]>
          #     vrrp6:
          #       - accept_mode: <value in [disable, enable]>
          #         adv_interval: <integer>
          #         preempt: <value in [disable, enable]>
          #         priority: <integer>
          #         start_time: <integer>
          #         status: <value in [disable, enable]>
          #         vrdst6: <string>
          #         vrgrp: <integer>
          #         vrid: <integer>
          #         vrip6: <string>
          #         ignore_default_route: <value in [disable, enable]>
          #         vrdst_priority: <integer>
          #     cli_conn6_status: <integer>
          #     ip6_prefix_mode: <value in [dhcp6, ra]>
          #     ra_send_mtu: <value in [disable, enable]>
          #     ip6_delegated_prefix_iaid: <integer>
          #     dhcp6_relay_source_interface: <value in [disable, enable]>
          #     dhcp6_relay_interface_id: <string>
          #     dhcp6_relay_source_ip: <string>
          #     ip6_adv_rio: <value in [disable, enable]>
          #     ip6_route_pref: <value in [medium, high, low]>
          #   l2forward: <value in [disable, enable]>
          #   l2tp_client: <value in [disable, enable]>
          #   lacp_ha_slave: <value in [disable, enable]>
          #   lacp_mode: <value in [static, passive, active]>
          #   lacp_speed: <value in [slow, fast]>
          #   lcp_echo_interval: <integer>
          #   lcp_max_echo_fails: <integer>
          #   link_up_delay: <integer>
          #   listen_forticlient_connection: <value in [disable, enable]>
          #   lldp_network_policy: <string>
          #   lldp_reception: <value in [disable, enable, vdom]>
          #   lldp_transmission: <value in [enable, disable, vdom]>
          #   log: <value in [disable, enable]>
          #   macaddr: <string>
          #   managed_subnetwork_size: <value in [256, 512, 1024, ...]>
          #   management_ip: <string>
          #   max_egress_burst_rate: <integer>
          #   max_egress_rate: <integer>
          #   measured_downstream_bandwidth: <integer>
          #   measured_upstream_bandwidth: <integer>
          #   mediatype: <value in [serdes-sfp, sgmii-sfp, cfp2-sr10, ...]>
          #   member: <list or string>
          #   min_links: <integer>
          #   min_links_down: <value in [operational, administrative]>
          #   mode: <value in [static, dhcp, pppoe, ...]>
          #   monitor_bandwidth: <value in [disable, enable]>
          #   mtu: <integer>
          #   mtu_override: <value in [disable, enable]>
          #   mux_type: <value in [llc-encaps, vc-encaps]>
          #   name: <string>
          #   ndiscforward: <value in [disable, enable]>
          #   netbios_forward: <value in [disable, enable]>
          #   netflow_sampler: <value in [disable, tx, rx, ...]>
          #   np_qos_profile: <integer>
          #   npu_fastpath: <value in [disable, enable]>
          #   nst: <value in [disable, enable]>
          #   out_force_vlan_cos: <integer>
          #   outbandwidth: <integer>
          #   padt_retry_timeout: <integer>
          #   password: <list or string>
          #   peer_interface: <list or string>
          #   phy_mode: <value in [auto, adsl, vdsl, ...]>
          #   ping_serv_status: <integer>
          #   poe: <value in [disable, enable]>
          #   polling_interval: <integer>
          #   pppoe_unnumbered_negotiate: <value in [disable, enable]>
          #   pptp_auth_type: <value in [auto, pap, chap, ...]>
          #   pptp_client: <value in [disable, enable]>
          #   pptp_password: <list or string>
          #   pptp_server_ip: <string>
          #   pptp_timeout: <integer>
          #   pptp_user: <string>
          #   preserve_session_route: <value in [disable, enable]>
          #   priority: <integer>
          #   priority_override: <value in [disable, enable]>
          #   proxy_captive_portal: <value in [disable, enable]>
          #   redundant_interface: <string>
          #   remote_ip: <string>
          #   replacemsg_override_group: <string>
          #   retransmission: <value in [disable, enable]>
          #   ring_rx: <integer>
          #   ring_tx: <integer>
          #   role: <value in [lan, wan, dmz, ...]>
          #   sample_direction: <value in [rx, tx, both]>
          #   sample_rate: <integer>
          #   scan_botnet_connections: <value in [disable, block, monitor]>
          #   secondary_IP: <value in [disable, enable]>
          #   secondaryip:
          #     - allowaccess:
          #         - "https"
          #         - "ping"
          #         - "ssh"
          #         - "snmp"
          #         - "http"
          #         - "telnet"
          #         - "fgfm"
          #         - "auto-ipsec"
          #         - "radius-acct"
          #         - "probe-response"
          #         - "capwap"
          #         - "dnp"
          #         - "ftm"
          #         - "fabric"
          #         - "speed-test"
          #         - "icond"
          #         - "scim"
          #       detectprotocol:
          #         - "ping"
          #         - "tcp-echo"
          #         - "udp-echo"
          #       detectserver: <string>
          #       gwdetect: <value in [disable, enable]>
          #       ha_priority: <integer>
          #       id: <integer>
          #       ip: <string>
          #       ping_serv_status: <integer>
          #       seq: <integer>
          #       secip_relay_ip: <string>
          #   security_8021x_dynamic_vlan_id: <integer>
          #   security_8021x_master: <string>
          #   security_8021x_mode: <value in [default, dynamic-vlan, fallback, ...]>
          #   security_exempt_list: <string>
          #   security_external_logout: <string>
          #   security_external_web: <string>
          #   security_groups: <list or string>
          #   security_mac_auth_bypass: <value in [disable, enable, mac-auth-only]>
          #   security_mode: <value in [none, captive-portal, 802.1X]>
          #   security_redirect_url: <string>
          #   service_name: <string>
          #   sflow_sampler: <value in [disable, enable]>
          #   speed: <value in [auto, 10full, 10half, ...]>
          #   spillover_threshold: <integer>
          #   src_check: <value in [disable, enable]>
          #   status: <value in [down, up]>
          #   stp: <value in [disable, enable]>
          #   stp_ha_slave: <value in [disable, enable, priority-adjust]>
          #   stpforward: <value in [disable, enable]>
          #   stpforward_mode: <value in [rpl-all-ext-id, rpl-bridge-ext-id, rpl-nothing]>
          #   strip_priority_vlan_tag: <value in [disable, enable]>
          #   subst: <value in [disable, enable]>
          #   substitute_dst_mac: <string>
          #   swc_first_create: <integer>
          #   swc_vlan: <integer>
          #   switch: <string>
          #   switch_controller_access_vlan: <value in [disable, enable]>
          #   switch_controller_arp_inspection: <value in [disable, enable, monitor]>
          #   switch_controller_auth: <value in [radius, usergroup]>
          #   switch_controller_dhcp_snooping: <value in [disable, enable]>
          #   switch_controller_dhcp_snooping_option82: <value in [disable, enable]>
          #   switch_controller_dhcp_snooping_verify_mac: <value in [disable, enable]>
          #   switch_controller_feature: <value in [none, default-vlan, quarantine, ...]>
          #   switch_controller_igmp_snooping: <value in [disable, enable]>
          #   switch_controller_igmp_snooping_fast_leave: <value in [disable, enable]>
          #   switch_controller_igmp_snooping_proxy: <value in [disable, enable]>
          #   switch_controller_iot_scanning: <value in [disable, enable]>
          #   switch_controller_learning_limit: <integer>
          #   switch_controller_mgmt_vlan: <integer>
          #   switch_controller_nac: <string>
          #   switch_controller_radius_server: <string>
          #   switch_controller_rspan_mode: <value in [disable, enable]>
          #   switch_controller_source_ip: <value in [outbound, fixed]>
          #   switch_controller_traffic_policy: <string>
          #   tc_mode: <value in [ptm, atm]>
          #   tcp_mss: <integer>
          #   trunk: <value in [disable, enable]>
          #   trust_ip_1: <string>
          #   trust_ip_2: <string>
          #   trust_ip_3: <string>
          #   trust_ip6_1: <string>
          #   trust_ip6_2: <string>
          #   trust_ip6_3: <string>
          #   type: <value in [physical, vlan, aggregate, ...]>
          #   username: <string>
          #   vci: <integer>
          #   vectoring: <value in [disable, enable]>
          #   vindex: <integer>
          #   vlan_protocol: <value in [8021q, 8021ad]>
          #   vlanforward: <value in [disable, enable]>
          #   vlanid: <integer>
          #   vpi: <integer>
          #   vrf: <integer>
          #   vrrp:
          #     - accept_mode: <value in [disable, enable]>
          #       adv_interval: <integer>
          #       ignore_default_route: <value in [disable, enable]>
          #       preempt: <value in [disable, enable]>
          #       priority: <integer>
          #       start_time: <integer>
          #       status: <value in [disable, enable]>
          #       version: <value in [2, 3]>
          #       vrdst: <list or string>
          #       vrdst_priority: <integer>
          #       vrgrp: <integer>
          #       vrid: <integer>
          #       vrip: <string>
          #       proxy_arp:
          #         - id: <integer>
          #           ip: <string>
          #   vrrp_virtual_mac: <value in [disable, enable]>
          #   wccp: <value in [disable, enable]>
          #   weight: <integer>
          #   wifi_5g_threshold: <string>
          #   wifi_acl: <value in [deny, allow]>
          #   wifi_ap_band: <value in [any, 5g-preferred, 5g-only]>
          #   wifi_auth: <value in [PSK, RADIUS, radius, ...]>
          #   wifi_auto_connect: <value in [disable, enable]>
          #   wifi_auto_save: <value in [disable, enable]>
          #   wifi_broadcast_ssid: <value in [disable, enable]>
          #   wifi_encrypt: <value in [TKIP, AES]>
          #   wifi_fragment_threshold: <integer>
          #   wifi_key: <list or string>
          #   wifi_keyindex: <integer>
          #   wifi_mac_filter: <value in [disable, enable]>
          #   wifi_passphrase: <list or string>
          #   wifi_radius_server: <string>
          #   wifi_rts_threshold: <integer>
          #   wifi_security: <value in [None, WEP64, wep64, ...]>
          #   wifi_ssid: <string>
          #   wifi_usergroup: <string>
          #   wins_ip: <string>
          #   dhcp_relay_request_all_server: <value in [disable, enable]>
          #   stp_ha_secondary: <value in [disable, enable, priority-adjust]>
          #   switch_controller_dynamic: <string>
          #   auth_cert: <string>
          #   auth_portal_addr: <string>
          #   dhcp_classless_route_addition: <value in [disable, enable]>
          #   dhcp_relay_link_selection: <string>
          #   dns_server_protocol:
          #     - "cleartext"
          #     - "dot"
          #     - "doh"
          #   eap_ca_cert: <string>
          #   eap_identity: <string>
          #   eap_method: <value in [tls, peap]>
          #   eap_password: <list or string>
          #   eap_supplicant: <value in [disable, enable]>
          #   eap_user_cert: <string>
          #   ike_saml_server: <string>
          #   lacp_ha_secondary: <value in [disable, enable]>
          #   pvc_atm_qos: <value in [cbr, rt-vbr, nrt-vbr, ...]>
          #   pvc_chan: <integer>
          #   pvc_crc: <integer>
          #   pvc_pcr: <integer>
          #   pvc_scr: <integer>
          #   pvc_vlan_id: <integer>
          #   pvc_vlan_rx_id: <integer>
          #   pvc_vlan_rx_op: <value in [pass-through, replace, remove]>
          #   pvc_vlan_tx_id: <integer>
          #   pvc_vlan_tx_op: <value in [pass-through, replace, remove]>
          #   reachable_time: <integer>
          #   select_profile_30a_35b: <value in [30A, 35B, 30a, ...]>
          #   sfp_dsl: <value in [disable, enable]>
          #   sfp_dsl_adsl_fallback: <value in [disable, enable]>
          #   sfp_dsl_autodetect: <value in [disable, enable]>
          #   sfp_dsl_mac: <string>
          #   sw_algorithm: <value in [l2, l3, eh, ...]>
          #   system_id: <string>
          #   system_id_type: <value in [auto, user]>
          #   vlan_id: <integer>
          #   vlan_op_mode: <value in [tag, untag, passthrough]>
          #   generic_receive_offload: <value in [disable, enable]>
          #   interconnect_profile: <value in [default, profile1, profile2]>
          #   large_receive_offload: <value in [disable, enable]>
          #   annex: <value in [a, b, j, ...]>
          #   aggregate_type: <value in [physical, vxlan]>
          #   switch_controller_netflow_collect: <value in [disable, enable]>
          #   wifi_dns_server1: <string>
          #   wifi_dns_server2: <string>
          #   wifi_gateway: <string>
          #   default_purdue_level: <value in [1, 2, 3, ...]>
          #   dhcp_broadcast_flag: <value in [disable, enable]>
          #   dhcp_smart_relay: <value in [disable, enable]>
          #   switch_controller_offloading: <value in [disable, enable]>
          #   switch_controller_offloading_gw: <value in [disable, enable]>
          #   switch_controller_offloading_ip: <string>
          #   dhcp_relay_circuit_id: <string>
          #   dhcp_relay_source_ip: <string>
          #   switch_controller_offload: <value in [disable, enable]>
          #   switch_controller_offload_gw: <value in [disable, enable]>
          #   switch_controller_offload_ip: <string>
          #   mirroring_direction: <value in [rx, tx, both]>
          #   mirroring_port: <string>
          #   port_mirroring: <value in [disable, enable]>
          #   security_8021x_member_mode: <value in [disable, switch]>
          #   stp_edge: <value in [disable, enable]>
          #   dhcp_relay_allow_no_end_option: <value in [disable, enable]>
          #   netflow_sample_rate: <integer>
          #   netflow_sampler_id: <integer>
          #   pppoe_egress_cos: <value in [cos0, cos1, cos2, ...]>
          #   security_ip_auth_bypass: <value in [disable, enable]>
          #   virtual_mac: <string>
          #   dhcp_relay_vrf_select: <integer>
          #   exclude_signatures:
          #     - "iot"
          #     - "ot"
          #   profiles:
          #     - "8a"
          #     - "8b"
          #     - "8c"
          #     - "8d"
          #     - "12a"
          #     - "12b"
          #     - "17a"
          #     - "30a"
          #     - "35b"
          #   telemetry_discover: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan',
        '/pm/config/global/obj/fsp/vlan'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fsp_vlan': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_dhcp-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'auth': {'v_range': [['6.0.0', '6.2.1']], 'choices': ['radius', 'usergroup'], 'type': 'str'},
                'color': {'type': 'int'},
                'comments': {'v_range': [['6.0.0', '6.2.1']], 'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_dhcp-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'dhcp-server': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'dict',
                            'options': {
                                'auto-configuration': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'auto-managed-status': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'conflicted-ip-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ddns-auth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'tsig'], 'type': 'str'},
                                'ddns-key': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                                'ddns-keyname': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'str'},
                                'ddns-server-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ddns-ttl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ddns-update': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ddns-update-override': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ddns-zone': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'default-gateway': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'dhcp-settings-from-fortiipam': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'dns-server1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'dns-server2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'dns-server3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'dns-server4': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'dns-service': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['default', 'specify', 'local'],
                                    'type': 'str'
                                },
                                'domain': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'enable': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'exclude-range': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {
                                        'end-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'start-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                        'lease-time': {'v_range': [['7.2.2', '']], 'type': 'int'},
                                        'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                                    },
                                    'elements': 'dict'
                                },
                                'filename': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'forticlient-on-net-status': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['disable', 'enable'],
                                    'type': 'str'
                                },
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['range', 'usrgrp'], 'type': 'str'},
                                'ip-range': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {
                                        'end-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'start-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                        'lease-time': {'v_range': [['7.2.2', '']], 'type': 'int'},
                                        'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                                    },
                                    'elements': 'dict'
                                },
                                'ipsec-lease-hold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'lease-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'mac-acl-default-action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['assign', 'block'], 'type': 'str'},
                                'netmask': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'next-server': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ntp-server1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ntp-server2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ntp-server3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ntp-service': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['default', 'specify', 'local'],
                                    'type': 'str'
                                },
                                'option1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'option2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'option3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'option4': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'option5': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'option6': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'options': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {
                                        'code': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                        'type': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['hex', 'string', 'ip', 'fqdn'],
                                            'type': 'str'
                                        },
                                        'value': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                        'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                                    },
                                    'elements': 'dict'
                                },
                                'reserved-address': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {
                                        'action': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['assign', 'block', 'reserved'],
                                            'type': 'str'
                                        },
                                        'circuit-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'circuit-id-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                                        'description': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'mac': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'remote-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'remote-id-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                                        'type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['mac', 'option82'], 'type': 'str'}
                                    },
                                    'elements': 'dict'
                                },
                                'server-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'tftp-server': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'timezone': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': [
                                        '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18',
                                        '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37',
                                        '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56',
                                        '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75',
                                        '76', '77', '78', '79', '80', '81', '82', '83', '84', '85', '86', '87'
                                    ],
                                    'type': 'str'
                                },
                                'timezone-option': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['disable', 'default', 'specify'],
                                    'type': 'str'
                                },
                                'vci-match': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'vci-string': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'wifi-ac-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['specify', 'local'], 'type': 'str'},
                                'wifi-ac1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'wifi-ac2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'wifi-ac3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'wins-server1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'wins-server2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'relay-agent': {'v_range': [['7.4.0', '']], 'type': 'str'},
                                'shared-subnet': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'interface': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'dict',
                            'options': {
                                'dhcp-relay-agent-option': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['disable', 'enable'],
                                    'type': 'str'
                                },
                                'dhcp-relay-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'dhcp-relay-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'dhcp-relay-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                                'ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ipv6': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'dict',
                                    'options': {
                                        'autoconf': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'dhcp6-client-options': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'type': 'list',
                                            'choices': ['rapid', 'iapd', 'iana', 'dns', 'dnsname'],
                                            'elements': 'str'
                                        },
                                        'dhcp6-information-request': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'dhcp6-prefix-delegation': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'dhcp6-prefix-hint': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'dhcp6-prefix-hint-plt': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'dhcp6-prefix-hint-vlt': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'dhcp6-relay-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'dhcp6-relay-service': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'dhcp6-relay-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['regular'], 'type': 'str'},
                                        'icmp6-send-redirect': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'interface-identifier': {'v_range': [['6.4.5', '']], 'type': 'str'},
                                        'ip6-address': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'ip6-allowaccess': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'type': 'list',
                                            'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'capwap', 'fabric'],
                                            'elements': 'str'
                                        },
                                        'ip6-default-life': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip6-delegated-prefix-list': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'type': 'list',
                                            'options': {
                                                'autonomous-flag': {
                                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                                    'choices': ['disable', 'enable'],
                                                    'type': 'str'
                                                },
                                                'onlink-flag': {
                                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                                    'choices': ['disable', 'enable'],
                                                    'type': 'str'
                                                },
                                                'prefix-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                                'rdnss': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                                'rdnss-service': {
                                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                                    'choices': ['delegated', 'default', 'specify'],
                                                    'type': 'str'
                                                },
                                                'subnet': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                                'upstream-interface': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                                'delegated-prefix-iaid': {'v_range': [['7.0.2', '']], 'type': 'int'}
                                            },
                                            'elements': 'dict'
                                        },
                                        'ip6-dns-server-override': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'ip6-extra-addr': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'type': 'list',
                                            'options': {'prefix': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'}},
                                            'elements': 'dict'
                                        },
                                        'ip6-hop-limit': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip6-link-mtu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip6-manage-flag': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'ip6-max-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip6-min-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip6-mode': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['static', 'dhcp', 'pppoe', 'delegated'],
                                            'type': 'str'
                                        },
                                        'ip6-other-flag': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'ip6-prefix-list': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'type': 'list',
                                            'options': {
                                                'autonomous-flag': {
                                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                                    'choices': ['disable', 'enable'],
                                                    'type': 'str'
                                                },
                                                'dnssl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                                'onlink-flag': {
                                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                                    'choices': ['disable', 'enable'],
                                                    'type': 'str'
                                                },
                                                'preferred-life-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                                'prefix': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                                'rdnss': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                                'valid-life-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}
                                            },
                                            'elements': 'dict'
                                        },
                                        'ip6-reachable-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip6-retrans-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip6-send-adv': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'ip6-subnet': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'ip6-upstream-interface': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'nd-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'nd-cga-modifier': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'nd-mode': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['basic', 'SEND-compatible'],
                                            'type': 'str'
                                        },
                                        'nd-security-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'nd-timestamp-delta': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'nd-timestamp-fuzz': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'unique-autoconf-addr': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'vrip6_link_local': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'vrrp-virtual-mac6': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'vrrp6': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'type': 'list',
                                            'options': {
                                                'accept-mode': {
                                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                                    'choices': ['disable', 'enable'],
                                                    'type': 'str'
                                                },
                                                'adv-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                                'preempt': {
                                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                                    'choices': ['disable', 'enable'],
                                                    'type': 'str'
                                                },
                                                'priority': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                                'start-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                                'status': {
                                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                                    'choices': ['disable', 'enable'],
                                                    'type': 'str'
                                                },
                                                'vrdst6': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                                'vrgrp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                                'vrid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                                'vrip6': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                                'ignore-default-route': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                                'vrdst-priority': {'v_range': [['7.6.0', '']], 'type': 'int'}
                                            },
                                            'elements': 'dict'
                                        },
                                        'cli-conn6-status': {'v_range': [['7.0.0', '']], 'type': 'int'},
                                        'ip6-prefix-mode': {'v_range': [['7.0.0', '']], 'choices': ['dhcp6', 'ra'], 'type': 'str'},
                                        'ra-send-mtu': {'v_range': [['6.4.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'ip6-delegated-prefix-iaid': {'v_range': [['7.0.2', '']], 'type': 'int'},
                                        'dhcp6-relay-source-interface': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'dhcp6-relay-interface-id': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                        'dhcp6-relay-source-ip': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                        'ip6-adv-rio': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'ip6-route-pref': {'v_range': [['7.6.2', '']], 'choices': ['medium', 'high', 'low'], 'type': 'str'}
                                    }
                                },
                                'secondary-IP': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'secondaryip': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {
                                        'allowaccess': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'type': 'list',
                                            'choices': [
                                                'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec', 'radius-acct', 'probe-response',
                                                'capwap', 'dnp', 'ftm', 'fabric', 'speed-test', 'icond', 'scim'
                                            ],
                                            'elements': 'str'
                                        },
                                        'detectprotocol': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']],
                                            'type': 'list',
                                            'choices': ['ping', 'tcp-echo', 'udp-echo'],
                                            'elements': 'str'
                                        },
                                        'detectserver': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'str'},
                                        'gwdetect': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'ha-priority': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'int'},
                                        'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'ping-serv-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'int'},
                                        'seq': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'secip-relay-ip': {'v_range': [['7.4.0', '']], 'type': 'str'}
                                    },
                                    'elements': 'dict'
                                },
                                'vlanid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'dhcp-relay-interface-select-method': {
                                    'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '']],
                                    'choices': ['auto', 'sdwan', 'specify'],
                                    'type': 'str'
                                },
                                'vrrp': {
                                    'v_range': [['7.4.0', '']],
                                    'type': 'list',
                                    'options': {
                                        'accept-mode': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'adv-interval': {'v_range': [['7.4.0', '']], 'type': 'int'},
                                        'ignore-default-route': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'preempt': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'priority': {'v_range': [['7.4.0', '']], 'type': 'int'},
                                        'proxy-arp': {
                                            'v_range': [['7.4.0', '']],
                                            'type': 'list',
                                            'options': {
                                                'id': {'v_range': [['7.4.0', '']], 'type': 'int'},
                                                'ip': {'v_range': [['7.4.0', '']], 'type': 'str'}
                                            },
                                            'elements': 'dict'
                                        },
                                        'start-time': {'v_range': [['7.4.0', '']], 'type': 'int'},
                                        'status': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'version': {'v_range': [['7.4.0', '']], 'choices': ['2', '3'], 'type': 'str'},
                                        'vrdst': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                                        'vrdst-priority': {'v_range': [['7.4.0', '']], 'type': 'int'},
                                        'vrgrp': {'v_range': [['7.4.0', '']], 'type': 'int'},
                                        'vrid': {'v_range': [['7.4.0', '']], 'type': 'int'},
                                        'vrip': {'v_range': [['7.4.0', '']], 'type': 'str'}
                                    },
                                    'elements': 'dict'
                                },
                                'allowaccess': {
                                    'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']],
                                    'type': 'list',
                                    'choices': [
                                        'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'radius-acct', 'probe-response', 'dnp', 'ftm',
                                        'fabric', 'speed-test', 'icond', 'scim'
                                    ],
                                    'elements': 'str'
                                },
                                'dhcp-relay-request-all-server': {
                                    'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']],
                                    'choices': ['disable', 'enable'],
                                    'type': 'str'
                                }
                            }
                        }
                    },
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'},
                'portal-message-override-group': {'v_range': [['6.0.0', '6.2.1']], 'type': 'str'},
                'radius-server': {'v_range': [['6.0.0', '6.2.1']], 'type': 'str'},
                'security': {'v_range': [['6.0.0', '6.2.1']], 'choices': ['open', 'captive-portal', '8021x'], 'type': 'str'},
                'selected-usergroups': {'v_range': [['6.0.0', '6.2.1']], 'type': 'str'},
                'usergroup': {'v_range': [['6.0.0', '6.2.1']], 'type': 'str'},
                'vdom': {'type': 'str'},
                'vlanid': {'type': 'int'},
                'dhcp-server': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'auto-configuration': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-managed-status': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'conflicted-ip-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ddns-auth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'tsig'], 'type': 'str'},
                        'ddns-key': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'ddns-keyname': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'str'},
                        'ddns-server-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ddns-ttl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ddns-update': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ddns-update-override': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ddns-zone': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'default-gateway': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dhcp-settings-from-fortiipam': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dns-server1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dns-server2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dns-server3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dns-server4': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dns-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['default', 'specify', 'local'], 'type': 'str'},
                        'domain': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'enable': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'exclude-range': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'end-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'start-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'lease-time': {'v_range': [['7.2.2', '']], 'type': 'int'},
                                'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                            },
                            'elements': 'dict'
                        },
                        'filename': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'forticlient-on-net-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ip-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['range', 'usrgrp'], 'type': 'str'},
                        'ip-range': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'end-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'start-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'lease-time': {'v_range': [['7.2.2', '']], 'type': 'int'},
                                'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                            },
                            'elements': 'dict'
                        },
                        'ipsec-lease-hold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'lease-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mac-acl-default-action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['assign', 'block'], 'type': 'str'},
                        'netmask': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'next-server': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ntp-server1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ntp-server2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ntp-server3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ntp-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['default', 'specify', 'local'], 'type': 'str'},
                        'option1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'option2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'option3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'option4': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'option5': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'option6': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'code': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hex', 'string', 'ip', 'fqdn'], 'type': 'str'},
                                'value': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
                            },
                            'elements': 'dict'
                        },
                        'reserved-address': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['assign', 'block', 'reserved'], 'type': 'str'},
                                'circuit-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'circuit-id-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                                'description': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'mac': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'remote-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'remote-id-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                                'type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['mac', 'option82'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'server-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tftp-server': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'timezone': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19',
                                '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39',
                                '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59',
                                '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79',
                                '80', '81', '82', '83', '84', '85', '86', '87'
                            ],
                            'type': 'str'
                        },
                        'timezone-option': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'default', 'specify'], 'type': 'str'},
                        'vci-match': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'wifi-ac-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['specify', 'local'], 'type': 'str'},
                        'wifi-ac1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'wifi-ac2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'wifi-ac3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'wins-server1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'wins-server2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'relay-agent': {'v_range': [['7.4.0', '']], 'type': 'str'},
                        'shared-subnet': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'interface': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'ac-name': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'aggregate': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'algorithm': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['L2', 'L3', 'L4', 'LB', 'Source-MAC'], 'type': 'str'},
                        'alias': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'allowaccess': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec', 'radius-acct', 'probe-response', 'capwap', 'dnp',
                                'ftm', 'fabric', 'speed-test'
                            ],
                            'elements': 'str'
                        },
                        'ap-discover': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'arpforward': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'atm-protocol': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['none', 'ipoa'], 'type': 'str'},
                        'auth-type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['auto', 'pap', 'chap', 'mschapv1', 'mschapv2'],
                            'type': 'str'
                        },
                        'auto-auth-extension-device': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bandwidth-measure-time': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'bfd': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['global', 'enable', 'disable'], 'type': 'str'},
                        'bfd-desired-min-tx': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'bfd-detect-mult': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'bfd-required-min-rx': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'broadcast-forticlient-discovery': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'broadcast-forward': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'captive-portal': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'cli-conn-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'color': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ddns': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ddns-auth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'tsig'], 'type': 'str'},
                        'ddns-domain': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ddns-key': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'ddns-keyname': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'str'},
                        'ddns-password': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'ddns-server': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                'dhs.org', 'dyndns.org', 'dyns.net', 'tzo.com', 'ods.org', 'vavic.com', 'now.net.cn', 'dipdns.net', 'easydns.com',
                                'genericDDNS'
                            ],
                            'type': 'str'
                        },
                        'ddns-server-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ddns-sn': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ddns-ttl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ddns-username': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ddns-zone': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dedicated-to': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['none', 'management'], 'type': 'str'},
                        'defaultgw': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'description': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'detected-peer-mtu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'detectprotocol': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['ping', 'tcp-echo', 'udp-echo'],
                            'elements': 'str'
                        },
                        'detectserver': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'device-access-list': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'device-identification': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'device-identification-active-scan': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'device-netscan': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'device-user-identification': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'devindex': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'dhcp-client-identifier': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dhcp-relay-agent-option': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-relay-interface': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dhcp-relay-interface-select-method': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'dhcp-relay-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'dhcp-relay-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-relay-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                        'dhcp-renew-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'disc-retry-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'disconnect-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'distance': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'dns-query': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'recursive', 'non-recursive'],
                            'type': 'str'
                        },
                        'dns-server-override': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drop-fragment': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drop-overlapped-fragment': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'egress-cos': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'cos0', 'cos1', 'cos2', 'cos3', 'cos4', 'cos5', 'cos6', 'cos7'],
                            'type': 'str'
                        },
                        'egress-shaping-profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'eip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'endpoint-compliance': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'estimated-downstream-bandwidth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'estimated-upstream-bandwidth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'explicit-ftp-proxy': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'explicit-web-proxy': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fail-action-on-extender': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['soft-restart', 'hard-restart', 'reboot'],
                            'type': 'str'
                        },
                        'fail-alert-interfaces': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'fail-alert-method': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['link-failed-signal', 'link-down'],
                            'type': 'str'
                        },
                        'fail-detect': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fail-detect-option': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['detectserver', 'link-down'],
                            'elements': 'str'
                        },
                        'fdp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiheartbeat': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortilink': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortilink-backup-link': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fortilink-neighbor-detect': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['lldp', 'fortilink'], 'type': 'str'},
                        'fortilink-split-interface': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortilink-stacking': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'forward-domain': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'forward-error-correction': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                'disable', 'enable', 'rs-fec', 'base-r-fec', 'fec-cl91', 'fec-cl74', 'rs-544', 'none', 'cl91-rs-fec', 'cl74-fc-fec',
                                'auto', 'rs-fec544'
                            ],
                            'type': 'str'
                        },
                        'fp-anomaly': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'drop_tcp_fin_noack', 'pass_winnuke', 'pass_tcpland', 'pass_udpland', 'pass_icmpland', 'pass_ipland', 'pass_iprr',
                                'pass_ipssrr', 'pass_iplsrr', 'pass_ipstream', 'pass_ipsecurity', 'pass_iptimestamp', 'pass_ipunknown_option',
                                'pass_ipunknown_prot', 'pass_icmp_frag', 'pass_tcp_no_flag', 'pass_tcp_fin_noack', 'drop_winnuke', 'drop_tcpland',
                                'drop_udpland', 'drop_icmpland', 'drop_ipland', 'drop_iprr', 'drop_ipssrr', 'drop_iplsrr', 'drop_ipstream',
                                'drop_ipsecurity', 'drop_iptimestamp', 'drop_ipunknown_option', 'drop_ipunknown_prot', 'drop_icmp_frag',
                                'drop_tcp_no_flag'
                            ],
                            'elements': 'str'
                        },
                        'fp-disable': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['all', 'ipsec', 'none'],
                            'elements': 'str'
                        },
                        'gateway-address': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'gi-gk': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'gwaddr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'str'},
                        'gwdetect': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ha-priority': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'icmp-accept-redirect': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'icmp-redirect': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'icmp-send-redirect': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ident-accept': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'idle-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'if-mdix': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['auto', 'normal', 'crossover'], 'type': 'str'},
                        'if-media': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['auto', 'copper', 'fiber'], 'type': 'str'},
                        'in-force-vlan-cos': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'inbandwidth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ingress-cos': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'cos0', 'cos1', 'cos2', 'cos3', 'cos4', 'cos5', 'cos6', 'cos7'],
                            'type': 'str'
                        },
                        'ingress-shaping-profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ingress-spillover-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'internal': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ip-managed-by-fortiipam': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable', 'inherit-global'], 'type': 'str'},
                        'ipmac': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ips-sniffer-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ipunnumbered': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ipv6': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'dict',
                            'options': {
                                'autoconf': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'dhcp6-client-options': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'choices': ['rapid', 'iapd', 'iana', 'dns', 'dnsname'],
                                    'elements': 'str'
                                },
                                'dhcp6-information-request': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['disable', 'enable'],
                                    'type': 'str'
                                },
                                'dhcp6-prefix-delegation': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['disable', 'enable'],
                                    'type': 'str'
                                },
                                'dhcp6-prefix-hint': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'dhcp6-prefix-hint-plt': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'dhcp6-prefix-hint-vlt': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'dhcp6-relay-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'dhcp6-relay-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'dhcp6-relay-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['regular'], 'type': 'str'},
                                'icmp6-send-redirect': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'interface-identifier': {'v_range': [['6.4.5', '']], 'type': 'str'},
                                'ip6-address': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ip6-allowaccess': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'capwap', 'fabric'],
                                    'elements': 'str'
                                },
                                'ip6-default-life': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip6-delegated-prefix-list': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {
                                        'autonomous-flag': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'onlink-flag': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'prefix-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'rdnss': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                        'rdnss-service': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['delegated', 'default', 'specify'],
                                            'type': 'str'
                                        },
                                        'subnet': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'upstream-interface': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'delegated-prefix-iaid': {'v_range': [['7.0.2', '']], 'type': 'int'}
                                    },
                                    'elements': 'dict'
                                },
                                'ip6-dns-server-override': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['disable', 'enable'],
                                    'type': 'str'
                                },
                                'ip6-extra-addr': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {'prefix': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'}},
                                    'elements': 'dict'
                                },
                                'ip6-hop-limit': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip6-link-mtu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip6-manage-flag': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ip6-max-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip6-min-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip6-mode': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'choices': ['static', 'dhcp', 'pppoe', 'delegated'],
                                    'type': 'str'
                                },
                                'ip6-other-flag': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ip6-prefix-list': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {
                                        'autonomous-flag': {
                                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                            'choices': ['disable', 'enable'],
                                            'type': 'str'
                                        },
                                        'dnssl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                        'onlink-flag': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'preferred-life-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'prefix': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'rdnss': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                        'valid-life-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}
                                    },
                                    'elements': 'dict'
                                },
                                'ip6-reachable-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip6-retrans-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip6-send-adv': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ip6-subnet': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ip6-upstream-interface': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'nd-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'nd-cga-modifier': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'nd-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['basic', 'SEND-compatible'], 'type': 'str'},
                                'nd-security-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'nd-timestamp-delta': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'nd-timestamp-fuzz': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'unique-autoconf-addr': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'vrip6_link_local': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'vrrp-virtual-mac6': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'vrrp6': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'options': {
                                        'accept-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'adv-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'preempt': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'priority': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'start-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'vrdst6': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'vrgrp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'vrid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                        'vrip6': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                        'ignore-default-route': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'vrdst-priority': {'v_range': [['7.6.0', '']], 'type': 'int'}
                                    },
                                    'elements': 'dict'
                                },
                                'cli-conn6-status': {'v_range': [['7.0.0', '']], 'type': 'int'},
                                'ip6-prefix-mode': {'v_range': [['7.0.0', '']], 'choices': ['dhcp6', 'ra'], 'type': 'str'},
                                'ra-send-mtu': {'v_range': [['6.4.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ip6-delegated-prefix-iaid': {'v_range': [['7.0.2', '']], 'type': 'int'},
                                'dhcp6-relay-source-interface': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'dhcp6-relay-interface-id': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                'dhcp6-relay-source-ip': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                'ip6-adv-rio': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ip6-route-pref': {'v_range': [['7.6.2', '']], 'choices': ['medium', 'high', 'low'], 'type': 'str'}
                            }
                        },
                        'l2forward': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'l2tp-client': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'lacp-ha-slave': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'lacp-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['static', 'passive', 'active'], 'type': 'str'},
                        'lacp-speed': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['slow', 'fast'], 'type': 'str'},
                        'lcp-echo-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'lcp-max-echo-fails': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'link-up-delay': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'listen-forticlient-connection': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'lldp-network-policy': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'lldp-reception': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable', 'vdom'], 'type': 'str'},
                        'lldp-transmission': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['enable', 'disable', 'vdom'], 'type': 'str'},
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'macaddr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'managed-subnetwork-size': {
                            'v_range': [['6.4.5', '']],
                            'choices': [
                                '256', '512', '1024', '2048', '4096', '8192', '16384', '32768', '65536', '32', '64', '128', '4', '8', '16', '131072',
                                '262144', '524288', '1048576', '2097152', '4194304', '8388608', '16777216'
                            ],
                            'type': 'str'
                        },
                        'management-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'max-egress-burst-rate': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-egress-rate': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'measured-downstream-bandwidth': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'measured-upstream-bandwidth': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'mediatype': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                'serdes-sfp', 'sgmii-sfp', 'cfp2-sr10', 'cfp2-lr4', 'serdes-copper-sfp', 'sr', 'cr', 'lr', 'qsfp28-sr4', 'qsfp28-lr4',
                                'qsfp28-cr4', 'sr4', 'cr4', 'lr4', 'none', 'gmii', 'sgmii', 'sr2', 'lr2', 'cr2', 'sr8', 'lr8', 'cr8', 'dr'
                            ],
                            'type': 'str'
                        },
                        'member': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'min-links': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'min-links-down': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['operational', 'administrative'], 'type': 'str'},
                        'mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['static', 'dhcp', 'pppoe', 'pppoa', 'ipoa', 'eoa'],
                            'type': 'str'
                        },
                        'monitor-bandwidth': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mtu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mtu-override': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mux-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['llc-encaps', 'vc-encaps'], 'type': 'str'},
                        'name': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ndiscforward': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'netbios-forward': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'netflow-sampler': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'tx', 'rx', 'both'], 'type': 'str'},
                        'np-qos-profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'npu-fastpath': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nst': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'out-force-vlan-cos': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'outbandwidth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'padt-retry-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'password': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'peer-interface': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'phy-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                'auto', 'adsl', 'vdsl', 'adsl-auto', 'vdsl2', 'adsl2+', 'adsl2', 'g.dmt', 't1.413', 'g.lite', 'g-dmt', 't1-413',
                                'g-lite'
                            ],
                            'type': 'str'
                        },
                        'ping-serv-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'int'},
                        'poe': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'polling-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'pppoe-unnumbered-negotiate': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pptp-auth-type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['auto', 'pap', 'chap', 'mschapv1', 'mschapv2'],
                            'type': 'str'
                        },
                        'pptp-client': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pptp-password': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'pptp-server-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'pptp-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'pptp-user': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'preserve-session-route': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'priority': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'priority-override': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'proxy-captive-portal': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'redundant-interface': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'remote-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'replacemsg-override-group': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'retransmission': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ring-rx': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ring-tx': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'role': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['lan', 'wan', 'dmz', 'undefined'], 'type': 'str'},
                        'sample-direction': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['rx', 'tx', 'both'], 'type': 'str'},
                        'sample-rate': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'scan-botnet-connections': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'secondary-IP': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'secondaryip': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'allowaccess': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                                    'type': 'list',
                                    'choices': [
                                        'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec', 'radius-acct', 'probe-response',
                                        'capwap', 'dnp', 'ftm', 'fabric', 'speed-test', 'icond', 'scim'
                                    ],
                                    'elements': 'str'
                                },
                                'detectprotocol': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']],
                                    'type': 'list',
                                    'choices': ['ping', 'tcp-echo', 'udp-echo'],
                                    'elements': 'str'
                                },
                                'detectserver': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'str'},
                                'gwdetect': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ha-priority': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'int'},
                                'id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'ping-serv-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'int'},
                                'seq': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'secip-relay-ip': {'v_range': [['7.4.0', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'security-8021x-dynamic-vlan-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'security-8021x-master': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'security-8021x-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['default', 'dynamic-vlan', 'fallback', 'slave'],
                            'type': 'str'
                        },
                        'security-exempt-list': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'security-external-logout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'security-external-web': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'security-groups': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'security-mac-auth-bypass': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'mac-auth-only'],
                            'type': 'str'
                        },
                        'security-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['none', 'captive-portal', '802.1X'], 'type': 'str'},
                        'security-redirect-url': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'service-name': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'sflow-sampler': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'speed': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                'auto', '10full', '10half', '100full', '100half', '1000full', '1000half', '10000full', '1000auto', '10000auto',
                                '40000full', '100Gfull', '25000full', '40000auto', '25000auto', '100Gauto', '400Gfull', '400Gauto', '50000full',
                                '2500auto', '5000auto', '50000auto', '200Gfull', '200Gauto', '100auto'
                            ],
                            'type': 'str'
                        },
                        'spillover-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'src-check': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['down', 'up'], 'type': 'str'},
                        'stp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'stp-ha-slave': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'priority-adjust'],
                            'type': 'str'
                        },
                        'stpforward': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'stpforward-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['rpl-all-ext-id', 'rpl-bridge-ext-id', 'rpl-nothing'],
                            'type': 'str'
                        },
                        'strip-priority-vlan-tag': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'subst': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'substitute-dst-mac': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'swc-first-create': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'swc-vlan': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'switch': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'switch-controller-access-vlan': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'switch-controller-arp-inspection': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'monitor'],
                            'type': 'str'
                        },
                        'switch-controller-auth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['radius', 'usergroup'], 'type': 'str'},
                        'switch-controller-dhcp-snooping': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'switch-controller-dhcp-snooping-option82': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'switch-controller-dhcp-snooping-verify-mac': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'switch-controller-feature': {
                            'v_range': [['6.4.5', '']],
                            'choices': ['none', 'default-vlan', 'quarantine', 'sniffer', 'voice', 'camera', 'rspan', 'video', 'nac', 'nac-segment'],
                            'type': 'str'
                        },
                        'switch-controller-igmp-snooping': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'switch-controller-igmp-snooping-fast-leave': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'switch-controller-igmp-snooping-proxy': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'switch-controller-iot-scanning': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-controller-learning-limit': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'switch-controller-mgmt-vlan': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'switch-controller-nac': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'switch-controller-radius-server': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'switch-controller-rspan-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-controller-source-ip': {'v_range': [['6.4.5', '']], 'choices': ['outbound', 'fixed'], 'type': 'str'},
                        'switch-controller-traffic-policy': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'tc-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['ptm', 'atm'], 'type': 'str'},
                        'tcp-mss': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'trunk': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trust-ip-1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'trust-ip-2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'trust-ip-3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'trust-ip6-1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'trust-ip6-2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'trust-ip6-3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                'physical', 'vlan', 'aggregate', 'redundant', 'tunnel', 'wireless', 'vdom-link', 'loopback', 'switch', 'hard-switch',
                                'hdlc', 'vap-switch', 'wl-mesh', 'fortilink', 'switch-vlan', 'fctrl-trunk', 'tdm', 'fext-wan', 'vxlan', 'emac-vlan',
                                'geneve', 'ssl', 'lan-extension'
                            ],
                            'type': 'str'
                        },
                        'username': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'vci': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'vectoring': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vindex': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'vlan-protocol': {'v_range': [['6.4.5', '']], 'choices': ['8021q', '8021ad'], 'type': 'str'},
                        'vlanforward': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vlanid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'vpi': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'vrf': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'vrrp': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'accept-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'adv-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'ignore-default-route': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'preempt': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'priority': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'start-time': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'version': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['2', '3'], 'type': 'str'},
                                'vrdst': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                                'vrdst-priority': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'vrgrp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'vrid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                                'vrip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                                'proxy-arp': {
                                    'v_range': [['7.4.0', '']],
                                    'type': 'list',
                                    'options': {'id': {'v_range': [['7.4.0', '']], 'type': 'int'}, 'ip': {'v_range': [['7.4.0', '']], 'type': 'str'}},
                                    'elements': 'dict'
                                }
                            },
                            'elements': 'dict'
                        },
                        'vrrp-virtual-mac': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'wccp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'weight': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'wifi-5g-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'wifi-acl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                        'wifi-ap-band': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['any', '5g-preferred', '5g-only'], 'type': 'str'},
                        'wifi-auth': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['PSK', 'RADIUS', 'radius', 'usergroup'], 'type': 'str'},
                        'wifi-auto-connect': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'wifi-auto-save': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'wifi-broadcast-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'wifi-encrypt': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['TKIP', 'AES'], 'type': 'str'},
                        'wifi-fragment-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'wifi-key': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'wifi-keyindex': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'int'},
                        'wifi-mac-filter': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'wifi-passphrase': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'wifi-radius-server': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'wifi-rts-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'wifi-security': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                'None', 'WEP64', 'wep64', 'WEP128', 'wep128', 'WPA_PSK', 'WPA_RADIUS', 'WPA', 'WPA2', 'WPA2_AUTO', 'open',
                                'wpa-personal', 'wpa-enterprise', 'wpa-only-personal', 'wpa-only-enterprise', 'wpa2-only-personal',
                                'wpa2-only-enterprise'
                            ],
                            'type': 'str'
                        },
                        'wifi-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'wifi-usergroup': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'wins-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'dhcp-relay-request-all-server': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.6', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'stp-ha-secondary': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable', 'priority-adjust'], 'type': 'str'},
                        'switch-controller-dynamic': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'auth-cert': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'auth-portal-addr': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'dhcp-classless-route-addition': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-relay-link-selection': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'dns-server-protocol': {'v_range': [['7.0.3', '']], 'type': 'list', 'choices': ['cleartext', 'dot', 'doh'], 'elements': 'str'},
                        'eap-ca-cert': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'eap-identity': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'eap-method': {'v_range': [['7.2.0', '']], 'choices': ['tls', 'peap'], 'type': 'str'},
                        'eap-password': {'v_range': [['7.2.0', '']], 'no_log': True, 'type': 'raw'},
                        'eap-supplicant': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'eap-user-cert': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'ike-saml-server': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'lacp-ha-secondary': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pvc-atm-qos': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'choices': ['cbr', 'rt-vbr', 'nrt-vbr', 'ubr'], 'type': 'str'},
                        'pvc-chan': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                        'pvc-crc': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                        'pvc-pcr': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                        'pvc-scr': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                        'pvc-vlan-id': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                        'pvc-vlan-rx-id': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                        'pvc-vlan-rx-op': {
                            'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']],
                            'choices': ['pass-through', 'replace', 'remove'],
                            'type': 'str'
                        },
                        'pvc-vlan-tx-id': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                        'pvc-vlan-tx-op': {
                            'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']],
                            'choices': ['pass-through', 'replace', 'remove'],
                            'type': 'str'
                        },
                        'reachable-time': {'v_range': [['7.0.3', '']], 'type': 'int'},
                        'select-profile-30a-35b': {
                            'v_range': [['6.2.9', '6.2.13'], ['6.4.8', '6.4.15'], ['7.0.3', '']],
                            'choices': ['30A', '35B', '30a', '35b'],
                            'type': 'str'
                        },
                        'sfp-dsl': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sfp-dsl-adsl-fallback': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sfp-dsl-autodetect': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sfp-dsl-mac': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'str'},
                        'sw-algorithm': {'v_range': [['7.0.1', '']], 'choices': ['l2', 'l3', 'eh', 'default'], 'type': 'str'},
                        'system-id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'type': 'str'},
                        'system-id-type': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'choices': ['auto', 'user'], 'type': 'str'},
                        'vlan-id': {'v_range': [['6.2.9', '6.2.13'], ['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                        'vlan-op-mode': {
                            'v_range': [['6.2.9', '6.2.13'], ['6.4.8', '6.4.15'], ['7.0.3', '']],
                            'choices': ['tag', 'untag', 'passthrough'],
                            'type': 'str'
                        },
                        'generic-receive-offload': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'interconnect-profile': {
                            'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']],
                            'choices': ['default', 'profile1', 'profile2'],
                            'type': 'str'
                        },
                        'large-receive-offload': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'annex': {
                            'v_range': [['7.0.10', '7.0.14'], ['7.2.5', '7.2.11'], ['7.4.2', '']],
                            'choices': ['a', 'b', 'j', 'bjm', 'i', 'al', 'm', 'aijlm', 'bj'],
                            'type': 'str'
                        },
                        'aggregate-type': {'v_range': [['7.2.1', '']], 'choices': ['physical', 'vxlan'], 'type': 'str'},
                        'switch-controller-netflow-collect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'wifi-dns-server1': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'wifi-dns-server2': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'wifi-gateway': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'default-purdue-level': {
                            'v_range': [['7.4.0', '']],
                            'choices': ['1', '2', '3', '4', '5', '1.5', '2.5', '3.5', '5.5'],
                            'type': 'str'
                        },
                        'dhcp-broadcast-flag': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-smart-relay': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-controller-offloading': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-controller-offloading-gw': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-controller-offloading-ip': {'v_range': [['7.4.0', '']], 'type': 'str'},
                        'dhcp-relay-circuit-id': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'dhcp-relay-source-ip': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'switch-controller-offload': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-controller-offload-gw': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-controller-offload-ip': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'mirroring-direction': {'v_range': [['7.4.2', '']], 'choices': ['rx', 'tx', 'both'], 'type': 'str'},
                        'mirroring-port': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'port-mirroring': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'security-8021x-member-mode': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'switch'], 'type': 'str'},
                        'stp-edge': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-relay-allow-no-end-option': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'netflow-sample-rate': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'netflow-sampler-id': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'pppoe-egress-cos': {
                            'v_range': [['7.4.4', '']],
                            'choices': ['cos0', 'cos1', 'cos2', 'cos3', 'cos4', 'cos5', 'cos6', 'cos7'],
                            'type': 'str'
                        },
                        'security-ip-auth-bypass': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'virtual-mac': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'dhcp-relay-vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'exclude-signatures': {'v_range': [['7.6.2', '']], 'type': 'list', 'choices': ['iot', 'ot'], 'elements': 'str'},
                        'profiles': {
                            'v_range': [['7.0.14', '7.0.14'], ['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']],
                            'type': 'list',
                            'choices': ['8a', '8b', '8c', '8d', '12a', '12b', '17a', '30a', '35b'],
                            'elements': 'str'
                        },
                        'telemetry-discover': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan'),
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
