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
module: fmgr_fsp_vlan_dynamicmapping
short_description: Fsp vlan dynamic mapping
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
    vlan:
        description: The parameter (vlan) in requested url.
        type: str
        required: true
    fsp_vlan_dynamicmapping:
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
    - name: Fsp vlan dynamic mapping
      fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        vlan: <your own value>
        state: present # <value in [present, absent]>
        fsp_vlan_dynamicmapping:
          # _dhcp_status: <value in [disable, enable]>
          # _scope:
          #   - name: <string>
          #     vdom: <string>
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
          #   dhcp_relay_agent_option: <value in [disable, enable]>
          #   dhcp_relay_ip: <list or string>
          #   dhcp_relay_service: <value in [disable, enable]>
          #   dhcp_relay_type: <value in [regular, ipsec]>
          #   ip: <string>
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
          #   vlanid: <integer>
          #   dhcp_relay_interface_select_method: <value in [auto, sdwan, specify]>
          #   vrrp:
          #     - accept_mode: <value in [disable, enable]>
          #       adv_interval: <integer>
          #       ignore_default_route: <value in [disable, enable]>
          #       preempt: <value in [disable, enable]>
          #       priority: <integer>
          #       proxy_arp:
          #         - id: <integer>
          #           ip: <string>
          #       start_time: <integer>
          #       status: <value in [disable, enable]>
          #       version: <value in [2, 3]>
          #       vrdst: <list or string>
          #       vrdst_priority: <integer>
          #       vrgrp: <integer>
          #       vrid: <integer>
          #       vrip: <string>
          #   allowaccess:
          #     - "https"
          #     - "ping"
          #     - "ssh"
          #     - "snmp"
          #     - "http"
          #     - "telnet"
          #     - "fgfm"
          #     - "radius-acct"
          #     - "probe-response"
          #     - "dnp"
          #     - "ftm"
          #     - "fabric"
          #     - "speed-test"
          #     - "icond"
          #     - "scim"
          #   dhcp_relay_request_all_server: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping'
    ]
    url_params = ['adom', 'vlan']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fsp_vlan_dynamicmapping': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
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
                        'dhcp-relay-agent-option': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
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
                                    'options': {'id': {'v_range': [['7.4.0', '']], 'type': 'int'}, 'ip': {'v_range': [['7.4.0', '']], 'type': 'str'}},
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
                                'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'radius-acct', 'probe-response', 'dnp', 'ftm', 'fabric',
                                'speed-test', 'icond', 'scim'
                            ],
                            'elements': 'str'
                        },
                        'dhcp-relay-request-all-server': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping'),
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
