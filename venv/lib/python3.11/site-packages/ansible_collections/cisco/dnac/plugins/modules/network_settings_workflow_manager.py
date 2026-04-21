#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to perform operations on global pool, reserve pool and network in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["Muthu Rakesh, Madhan Sankaranarayanan, Megha Kandari"]
DOCUMENTATION = r"""
---
module: network_settings_workflow_manager
short_description: Resource module for IP Address pools
  and network functions
description:
  - Manage operations on Global Pool, Reserve Pool,
    Network resources.
  - API to create/update/delete global pool.
  - API to reserve/update/delete an ip subpool from
    the global pool.
  - API to update network settings for DHCP, Syslog,
    SNMP, NTP, Network AAA, Client and Endpoint AAA,
    and/or DNS center server settings.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Muthu Rakesh (@MUTHU-RAKESH-27) Madhan Sankaranarayanan
  (@madhansansel) Megha Kandari (@kandarimegha)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center
      after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description:
      - List of details of global pool, reserved pool,
        network being managed.
    type: list
    elements: dict
    required: true
    suboptions:
      global_pool_details:
        description: Manages IPv4 and IPv6 IP pools
          in the global level.
        type: dict
        suboptions:
          settings:
            description: Global Pool's settings.
            type: dict
            suboptions:
              ip_pool:
                description: Contains a list of global
                  IP pool configurations.
                elements: dict
                type: list
                suboptions:
                  name:
                    description:
                      - Specifies the name assigned
                        to the Global IP Pool.
                      - Required for the operations
                        in the Global IP Pool.
                      - Length should be less than or
                        equal to 100.
                      - Only letters, numbers and -_./
                        characters are allowed.
                    type: str
                  pool_type:
                    description: >
                      Includes both the Generic Ip Pool
                      and Tunnel Ip Pool. Generic -
                      Used for general purpose within
                      the network such as device management
                      or communication between the network
                      devices. Tunnel - Designated for
                      the tunnel interfaces to encapsulate
                      packets within the network protocol.
                      It is used in VPN connections,
                      GRE tunnels, or other types of
                      overlay networks.
                    default: Generic
                    choices: [Generic, Tunnel]
                    type: str
                  ip_address_space:
                    description: IP address space either
                      IPv4 or IPv6.
                    type: str
                  cidr:
                    description: >
                      Defines the IP pool's Classless
                      Inter-Domain Routing block, enabling
                      systematic IP address distribution
                      within a network.
                    type: str
                  gateway:
                    description: Serves as an entry
                      or exit point for data traffic
                      between networks.
                    type: str
                  dhcp_server_ips:
                    description: >
                      The DHCP server IPs responsible
                      for automatically assigning IP
                      addresses and network configuration
                      parameters to devices on a local
                      network.
                    elements: str
                    type: list
                  dns_server_ips:
                    description: Responsible for translating
                      domain names into corresponding
                      IP addresses.
                    elements: str
                    type: list
                  prev_name:
                    description: >
                      The former identifier for the
                      global pool. It should be used
                      exclusively when you need to update
                      the global pool's name.
                    type: str
                  force_delete:
                    description: >
                      Forcefully delete all IP pools
                      from the global level of the global
                      pool. The default value is false.
                    type: bool
                    required: false
                    default: false
      reserve_pool_details:
        description: Reserved IP subpool details from
          the global pool.
        type: list
        elements: dict
        suboptions:
          site_name:
            description: >
              The name of the site provided as a path
              parameter, used to specify where the IP
              sub-pool will be reserved.
            type: str
          name:
            description:
              - Name of the reserve IP subpool.
              - Required for the operations in the Reserve
                IP Pool.
              - Length should be less than or equal
                to 100.
              - Only letters, numbers and -_./ characters
                are allowed.
            type: str
          pool_type:
            description: Type of the reserve ip sub
              pool. Generic - Used for general purpose
              within the network such as device management
              or communication between the network devices.
              LAN - Used for the devices and the resources
              within the Local Area Network such as
              device connectivity, internal communication,
              or services. Management - Used for the
              management purposes such as device management
              interfaces, management access, or other
              administrative functions. Service - Used
              for the network services and application
              such as DNS (Domain Name System), DHCP
              (Dynamic Host Configuration Protocol),
              NTP (Network Time Protocol). WAN - Used
              for the devices and resources with the
              Wide Area Network such as remote sites
              interconnection with other network or
              services hosted within WAN.
            default: Generic
            choices: [Generic, LAN, Management, Service,
              WAN]
            type: str
          ipv6_address_space:
            description: >
              Determines whether both IPv6 and IPv4
              inputs are required. If set to false,
              only IPv4 inputs are required. If set
              to true, both IPv6 and IPv4 inputs are
              required.
            type: bool
          ipv4_global_pool:
            description:
              - Specifies the IPv4 global pool address in CIDR notation, for example, "175.175.0.0/16".
              - When both 'ipv4_global_pool' and 'ipv4_global_pool_name' are provided, the value of 'ipv4_global_pool' takes precedence in version 2.3.5.3.
              - However, in version 2.3.7.9, ipv4_global_pool_name takes precedence over ipv4_global_pool.
            type: str
          ipv4_global_pool_name:
            description:
              - Specifies the name to be associated
                with the IPv4 Global IP Pool.
              - If both 'ipv4_global_pool' and 'ipv4_global_pool_name'
                are provided, the 'ipv4_global_pool'
                will be given priority.
            type: str
            version_added: 6.14.0
          ipv4_subnet:
            description:
              - Indicates the IPv4 subnet address, for example, "175.175.0.0".
              - This parameter is required starting from Cisco Catalyst Center version 2.3.7.9 and later.
            type: str
          ipv4_prefix:
            description:
              - Indicates whether the IPv4 prefix length input is enabled.
              - If true, the IPv4 prefix length must be specified.
              - Alternatively, the IPv4 total host input can be enabled instead.
            type: bool
          ipv4_prefix_length:
            description:
              - Specifies the IPv4 prefix length.
              - For IPv4, it must be between 8 and 30, inclusive.
              - Required when 'ipv4_prefix' is true.
              - For example, a prefix length of 24 corresponds to a subnet mask of 255.255.255.0.
              - Mandatory starting from Cisco Catalyst Center version 2.3.7.9 if 'ipv4_total_host' is not provided.
            type: int
          ipv4_total_host:
            description:
              - Specifies the total number of IPv4 hosts.
              - Must be a positive integer within the subnet capacity.
              - For IPv4, the value must fit within a 32-bit address space.
              - Required when 'ipv4_prefix' is false.
              - Mandatory starting from Cisco Catalyst Center version 2.3.7.9 if 'ipv4_prefix_length' is not provided.
            type: int
          ipv4_gateway:
            description: Provides the gateway's IPv4
              address, for example, "175.175.0.1".
            type: str
            version_added: 4.0.0
          ipv4_dhcp_servers:
            description: Specifies the IPv4 addresses
              for DHCP servers, for example, "1.1.1.1".
            elements: str
            type: list
          ipv4_dns_servers:
            description: Specifies the IPv4 addresses
              for DNS servers, for example, "4.4.4.4".
            elements: str
            type: list
          ipv6_dhcp_servers:
            description: >
              Specifies the IPv6 addresses for DHCP
              servers in the format. For example, "2001:0db8:0123:4567:89ab:cdef:0001:0001".
            elements: str
            type: list
          ipv6_dns_servers:
            description: >
              Specifies the IPv6 addresses for DNS servers.
              For example, "2001:0db8:0123:4567:89ab:cdef:0002:0002".
            elements: str
            type: list
          ipv6_gateway:
            description: >
              Provides the gateway's IPv6 address. For
              example, "2001:0db8:0123:4567:89ab:cdef:0003:0003".
            type: str
          ipv6_global_pool:
            description:
              - The ipv6_global_pool is a required when
                the ipv6_address_space is set to true.
              - It specifies the global IPv6 address
                pool using CIDR notation, such as "2001:db8:85a3::/64".
              - In cases where both ipv6_global_pool
                and ipv6_global_pool_name are specified,
                ipv6_global_pool will take precedence.
            type: str
          ipv6_global_pool_name:
            description:
              - Specifies the name assigned to the Ip
                v6 Global IP Pool.
              - If both 'ipv6_global_pool' and 'ipv6_global_pool_name'
                are provided, the 'ipv6_global_pool'
                will be given priority.
            type: str
            version_added: 6.14.0
          ipv6_subnet:
            description:
              - IPv6 Subnet address, example 2001:db8:85a3:0:100.
              - This parameter is required starting from Cisco Catalyst Center version 2.3.7.9 and later.
            type: str
          ipv6_prefix:
            description:
              - Determines whether to enable the 'ipv6_prefix_length' or 'ipv6_total_host' input field.
              - If the IPv6 prefix value is true, the IPv6 prefix length input field is required.
              - If it is false, the ipv6_total_host input is required.
            type: bool
          ipv6_prefix_length:
            description:
              - Specifies the IPv6 prefix length.
              - The valid range is from 0 to 128.
              - Required when 'ipv6_prefix' is true.
              - Mandatory starting from Cisco Catalyst Center version 2.3.7.9 if 'ipv6_total_host' is not provided.
            type: int
          ipv6_total_host:
            description:
              - Specifies the total number of IPv6 hosts.
              - Must be an integer less than 256.
              - Required when 'ipv6_prefix' is false.
              - Mandatory starting from Cisco Catalyst Center version 2.3.7.9 if 'ipv6_prefix_length' is not provided.
            type: int
          prev_name:
            description: The former name associated
              with the reserved IP sub-pool.
            type: str
          slaac_support:
            description: >
              Allows devices on IPv6 networks to self-configure
              their IP addresses autonomously, eliminating
              the need for manual setup.
            type: bool
          ipv4_unassignable_addresses:
            description: >
              - Specifies the number of IPv4 addresses that cannot be assigned due to constraints or reservations.
              - These addresses are excluded from allocation pools.
            type: int
          ipv4_assigned_addresses:
            description: >
              - Specifies the number of IPv4 addresses that have already been allocated.
              - Reflects the count of addresses currently in use.
            type: int
          ipv4_default_assigned_addresses:
            description: >
              - Specifies the number of IPv4 addresses assigned by default during pool creation.
              - Represents the initial allocation count when the pool is created.
            type: int
          ipv6_unassignable_addresses:
            description: >
              - Specifies the number of IPv6 addresses that cannot be assigned due to constraints or reservations.
              - These addresses are excluded from allocation pools.
            type: int
          ipv6_assigned_addresses:
            description: >
              - Specifies the number of IPv6 addresses that have already been allocated.
              - Reflects the count of addresses currently in use.
            type: int
          ipv6_default_assigned_addresses:
            description: >
              - Specifies the number of IPv6 addresses assigned by default during pool creation.
              - Represents the initial allocation count when the pool is created.
            type: int
          force_delete:
            description: >
              Forcefully delete all IP pools from the
              reserve level of the IP sub-pool. The
              default value is false.
            type: bool
            required: false
            default: false
      network_management_details:
        description: Set default network settings for
          the site
        type: list
        elements: dict
        suboptions:
          site_name:
            description: >
              The name of the site provided as a path
              parameter, used to specify where the IP
              sub-pool will be reserved. (eg Global/Chennai/Trill)
            type: str
          settings:
            description: Network management details
              settings.
            type: dict
            suboptions:
              network_aaa:
                description: Manages AAA (Authentication
                  Authorization Accounting) for network
                  devices.
                suboptions:
                  server_type:
                    description: Server type for managing
                      AAA for network devices.
                    choices: [AAA, ISE]
                    type: str
                  protocol:
                    description: Protocol for AAA or
                      ISE server.
                    choices: [RADIUS, TACACS]
                    default: RADIUS
                    type: str
                  pan_address:
                    description:
                      - PAN IP address for the ISE server.
                      - For example, 1.1.1.1.
                    type: str
                    version_added: 6.14.0
                  primary_server_address:
                    description:
                      - Primary IP address for the ISE/AAA
                        server.
                      - For example, 1.1.1.2.
                    type: str
                    version_added: 6.14.0
                  secondary_server_address:
                    description:
                      - Secondary IP address for the
                        AAA server.
                      - For example, 1.1.1.3.
                    type: str
                    version_added: 6.14.0
                  shared_secret:
                    description:
                      - Shared secret for ISE Server.
                      - Length of the shared secret
                        should be atleast 4 characters.
                    type: str
                type: dict
              client_and_endpoint_aaa:
                description: Manages AAA (Authentication
                  Authorization Accounting) for clients
                  and endpoints.
                suboptions:
                  server_type:
                    description:
                      - Server type for managing AAA
                        for client and endpoints.
                    choices: [AAA, ISE]
                    type: str
                  protocol:
                    description: Protocol for AAA or
                      ISE server.
                    choices: [RADIUS, TACACS]
                    default: RADIUS
                    type: str
                  pan_address:
                    description:
                      - PAN IP address for the ISE server.
                      - For example, 1.1.1.1.
                    type: str
                    version_added: 6.14.0
                  primary_server_address:
                    description:
                      - Primary IP address for the ISE/AAA
                        server.
                      - For example, 1.1.1.2.
                    type: str
                    version_added: 6.14.0
                  secondary_server_address:
                    description:
                      - Secondary IP address for the
                        AAA server.
                      - For example, 1.1.1.3.
                    type: str
                    version_added: 6.14.0
                  shared_secret:
                    description:
                      - Shared secret for ISE Server.
                      - Length of the shared secret
                        should be atleast 4 characters.
                    type: str
                type: dict
              dhcp_server:
                description: DHCP Server IP address
                  (eg 1.1.1.4).
                elements: str
                type: list
              dns_server:
                description: DNS server details of the
                  network under a specific site.
                suboptions:
                  domain_name:
                    description: Domain Name of DHCP
                      (eg; cisco.com, cisco.net).
                    type: str
                  primary_ip_address:
                    description: Primary IP Address
                      for DHCP (eg 2.2.2.2).
                    type: str
                  secondary_ip_address:
                    description: Secondary IP Address
                      for DHCP (eg 3.3.3.3).
                    type: str
                type: dict
              ntp_server:
                description: IP address for NTP server
                  under a specific site (eg 1.1.1.2).
                elements: str
                type: list
              timezone:
                description: Time zone of a specific
                  site. (eg Africa/Abidjan/GMT).
                type: str
              message_of_the_day:
                description: Banner details under a
                  specific site.
                suboptions:
                  banner_message:
                    description: Message for the banner
                      (eg; Good day).
                    type: str
                  retain_existing_banner:
                    description: Retain existing banner
                      message.
                    type: bool
                type: dict
              wired_data_collection:
                description:
                  - Enables or disables the collection
                    of data from wired network devices
                    for telemetry and monitoring purposes.
                  - Applicable from Cisco Catalyst Center
                    version 2.3.7.6 onwards.
                suboptions:
                  enable_wired_data_collection:
                    description: Enable or disable wired
                      data collection.
                    type: bool
                type: dict
              wireless_telemetry:
                description:
                  - Enables or disables the collection
                    of telemetry data from wireless
                    network devices for performance
                    monitoring and analysis.
                  - Applicable from Cisco Catalyst Center
                    version 2.3.7.6 onwards.
                suboptions:
                  enable_wireless_telemetry:
                    description: Enable or disable wireless
                      telemetry.
                    type: bool
                type: dict
              netflow_collector:
                description: NetFlow collector configuration
                  for a specific site.
                suboptions:
                  collector_type:
                    description:
                      - Type of NetFlow collector.
                      - Supported values include 'Builtin'
                        and 'Telemetry_broker_or_UDP_director'.
                      - Applicable from Cisco Catalyst
                        Center version 2.3.7.6 onwards.
                    type: str
                    choices: [Builtin, Telemetry_broker_or_UDP_director]
                  ip_address:
                    description: IP Address for NetFlow
                      collector. For example, 3.3.3.1.
                    type: str
                  port:
                    description: Port number used by
                      the NetFlow collector. For example,
                      443.
                    type: int
                  enable_on_wired_access_devices:
                    description: Enable or disable wired
                      access device. Applicable from
                      Cisco Catalyst Center version
                      2.3.7.6 onwards..
                    type: bool
                type: dict
              snmp_server:
                description: Snmp Server details under
                  a specific site.
                suboptions:
                  configure_dnac_ip:
                    description: Configuration Cisco
                      Catalyst Center IP for SNMP Server
                      (eg true).
                    type: bool
                  ip_addresses:
                    description: IP Address for SNMP
                      Server (eg 4.4.4.1).
                    elements: str
                    type: list
                type: dict
              syslog_server:
                description: syslog Server details under
                  a specific site.
                suboptions:
                  configure_dnac_ip:
                    description: Configuration Cisco
                      Catalyst Center IP for syslog
                      server (eg true).
                    type: bool
                  ip_addresses:
                    description: IP Address for syslog
                      server (eg 4.4.4.4).
                    elements: str
                    type: list
                type: dict
      device_controllability_details:
        description:
            - Defines the default device controllability settings at the site level.
            - Controls whether Catalyst Center can apply telemetry and configuration policies to devices.
        type: dict
        suboptions:
          device_controllability:
            description:
                - Boolean flag to enable or disable device controllability at the site level.
                - This is a required setting.
                - When enabled, Catalyst Center manages telemetry and configuration policies on devices.
            type: bool
            required: true
          autocorrect_telemetry_config:
            description:
                - Boolean flag to automatically correct telemetry configuration on devices if it deviates from the expected state.
                - Optional setting; defaults to false.
            type: bool
            required: false
            default: false
requirements:
  - dnacentersdk >= 2.7.2
  - python >= 3.9
notes:
  - SDK Method used are
    network_settings.NetworkSettings.create_global_pool,
    network_settings.NetworkSettings.delete_global_ip_pool,
    network_settings.NetworkSettings.update_global_pool,
    network_settings.NetworkSettings.release_reserve_ip_subpool,
    network_settings.NetworkSettings.reserve_ip_subpool,
    network_settings.NetworkSettings.update_reserve_ip_subpool,
    network_settings.NetworkSettings.update_network_v2,
    network_settings.NetworkSettings.retrieves_global_ip_address_pools,
    network_settings.NetworkSettings.retrieves_ip_address_subpools,
    network_settings.NetworkSettings.create_a_global_ip_address_pool,
    network_settings.NetworkSettings.reserve_create_ip_address_subpools,
    network_settings.NetworkSettings.delete_a_global_ip_address_pool,
    network_settings.NetworkSettings.release_an_ip_address_subpool,
    network_settings.NetworkSettings.updates_a_global_ip_address_pool,
    network_settings.NetworkSettings.updates_an_ip_address_subpool,
    network_settings.NetworkSettings.get_device_controllability_settings,
    network_settings.NetworkSettings.update_device_controllability_settings

  - Paths used are
    post /dna/intent/api/v1/global-pool,
    delete /dna/intent/api/v1/global-pool/{id},
    put /dna/intent/api/v1/global-pool,
    post /dna/intent/api/v1/reserve-ip-subpool/{siteId},
    delete /dna/intent/api/v1/reserve-ip-subpool/{id},
    put /dna/intent/api/v1/reserve-ip-subpool/{siteId},
    put /dna/intent/api/v2/network/{siteId},
    GET /intent/api/v1/ipam/globalIpAddressPools
    GET /intent/api/v1/ipam/siteIpAddressPools
    POST /intent/api/v1/ipam/globalIpAddressPools
    POST /intent/api/v1/ipam/siteIpAddressPools
    PUT /intent/api/v1/ipam/globalIpAddressPools/{id}
    PUT /intent/api/v1/ipam/siteIpAddressPools/{id}
    DELETE  /intent/api/v1/ipam/globalIpAddressPools/{id}
    DELETE  /intent/api/v1/ipam/siteIpAddressPools/{id}
    GET /networkDevices/deviceControllability/settings
    PUT /dna/intent/api/v1/networkDevices/deviceControllability/settings
"""
EXAMPLES = r"""
---
- name: Create global pool
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - global_pool_details:
          settings:
            ip_pool:
              - name: string
                pool_type: Generic
                ip_address_space: string
                cidr: string
                gateway: string
                dhcp_server_ips: list
                dns_server_ips: list
- name: Create reserve an ip pool
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - reserve_pool_details:
          - site_name: string
            name: string
            pool_type: LAN
            ipv6_address_space: true
            ipv4_global_pool: string
            ipv4_prefix: true
            ipv4_prefix_length: 9
            ipv4_subnet: string
            ipv6_prefix: true
            ipv6_prefix_length: 64
            ipv6_global_pool: string
            ipv6_subnet: string
            slaac_support: true
- name: Create reserve an ip pool using global pool
    name
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - reserve_pool_details:
          - name: string
            site_name: string
            pool_type: LAN
            ipv6_address_space: true
            ipv4_global_pool_name: string
            ipv4_prefix: true
            ipv4_prefix_length: 9
            ipv4_subnet: string
            ipv6_prefix: true
            ipv6_prefix_length: 64
            ipv6_global_pool_name: string
            ipv6_subnet: string
            slaac_support: true
- name: Delete reserved pool
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: deleted
    config_verify: true
    config:
      - reserve_pool_details:
          - site_name: string
            name: string
- name: Delete Global Pool
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_version: "{{ dnac_version }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    state: deleted
    config_verify: true
    config:
      - global_pool_details:
          settings:
            ip_pool:
              - name: string
- name: Manage the network functions
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - network_management_details:
          - site_name: string
            settings:
              dhcp_server: list
              dns_server:
                domain_name: string
                primary_ip_address: string
                secondary_ip_address: string
              ntp_server: list
              timezone: string
              message_of_the_day:
                banner_message: string
                retain_existing_banner: bool
              netflow_collector:
                ip_address: string
                port: 443
              snmp_server:
                configure_dnac_ip: true
                ip_addresses: list
              syslog_server:
                configure_dnac_ip: true
                ip_addresses: list
- name: Adding the network_aaa and client_and_endpoint_aaa
    AAA server
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - network_management_details:
          - site_name: string
            settings:
              network_aaa:
                server_type: AAA
                primary_server_address: string
                secondary_server_address: string
                protocol: string
              client_and_endpoint_aaa:
                server_type: AAA
                primary_server_address: string
                secondary_server_address: string
                protocol: string
- name: Adding the network_aaa and client_and_endpoint_aaa
    ISE server
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - network_management_details:
          - site_name: string
            settings:
              network_aaa:
                server_type: ISE
                pan_address: string
                primary_server_address: string
                protocol: string
              client_and_endpoint_aaa:
                server_type: ISE
                pan_address: string
                primary_server_address: string
                protocol: string

- name: Adding device_controllability details
  cisco.dnac.network_settings_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - device_controllability_details:
          device_controllability: true
          autocorrect_telemetry_config: true
"""


RETURN = r"""
# Case_1: Successful creation/updation/deletion of global pool
response_1:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
# Case_2: Successful creation/updation/deletion of reserve pool
response_2:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
# Case_3: Successful creation/updation of network
response_3:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
import math
import copy
import re
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    dnac_compare_equality,
)


class NetworkSettings(DnacBase):
    """Class containing member attributes for network_settings_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.result["response"] = [
            {"globalPool": {"response": {}, "msg": {}}},
            {"reservePool": {"response": {}, "msg": {}}},
            {"network": {"response": {}, "msg": {}}},
            {"device_controllability": {"response": {}, "msg": {}}}
        ]
        self.global_pool_obj_params = self.get_obj_params("GlobalPool")
        self.reserve_pool_obj_params = self.get_obj_params("ReservePool")
        self.network_obj_params = self.get_obj_params("Network")
        self.device_controllability_obj_params = self.get_obj_params("device_controllability")
        self.all_reserved_pool_details = {}
        self.global_pool_response = {}
        self.reserve_pool_response = {}

    def validate_input(self):
        """
        Checks if the configuration parameters provided in the playbook
        meet the expected structure and data types,
        as defined in the 'temp_spec' dictionary.

        Parameters:
            None

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.

        """

        if not self.config:
            self.msg = "config not available in playbook for validation"
            self.status = "success"
            return self

        # temp_spec is the specification for the expected structure of configuration parameters
        temp_spec = {
            "global_pool_details": {
                "type": "dict",
                "settings": {
                    "type": "dict",
                    "ip_pool": {
                        "type": "list",
                        "elements": "dict",
                        "ip_address_space": {"type": "str"},
                        "dhcp_server_ips": {"type": "list"},
                        "dns_server_ips": {"type": "list"},
                        "gateway": {"type": "str"},
                        "cidr": {"type": "str"},
                        "name": {"type": "str"},
                        "prev_name": {"type": "str"},
                        "pool_type": {"type": "str", "choices": ["Generic", "Tunnel"]},
                        "force_delete": {
                            "type": "bool",
                            "required": False,
                            "default": False,
                        },
                    },
                },
            },
            "reserve_pool_details": {
                "type": "list",
                "elements": "dict",
                "name": {"type": "str"},
                "prev_name": {"type": "str"},
                "ipv6_address_space": {"type": "bool"},
                "ipv4_global_pool": {"type": "str"},
                "ipv4_prefix": {"type": "bool"},
                "ipv4_prefix_length": {"type": "str"},
                "ipv4_subnet": {"type": "str"},
                "ipv4_gateway": {"type": "str"},
                "ipv4_dhcp_servers": {"type": "list"},
                "ipv4_dns_servers": {"type": "list"},
                "ipv6_global_pool": {"type": "str"},
                "ipv6_prefix": {"type": "bool"},
                "ipv6_prefix_length": {"type": "int"},
                "ipv6_subnet": {"type": "str"},
                "ipv6_gateway": {"type": "str"},
                "ipv6_dhcp_servers": {"type": "list"},
                "ipv6_dns_servers": {"type": "list"},
                "ipv4_total_host": {"type": "int"},
                "ipv6_total_host": {"type": "int"},
                "slaac_support": {"type": "bool"},
                "site_name": {"type": "str"},
                "pool_type": {
                    "type": "str",
                    "choices": ["Generic", "LAN", "Management", "Service", "WAN"],
                },
                'force_delete': {'type': 'bool', 'required': False, 'default': False},
                "ipv4_unassignable_addresses": {'type': int, 'required': False},
                "ipv4_assigned_addresses": {'type': int, 'required': False},
                "ipv4_default_assigned_addresses": {'type': int, 'required': False},
                "ipv6_unassignable_addresses": {'type': int, 'required': False},
                "ipv6_assigned_addresses": {'type': int, 'required': False},
                "ipv6_default_assigned_addresses": {'type': int, 'required': False}
            },
            "network_management_details": {
                "type": "list",
                "elements": "dict",
                "settings": {
                    "type": "dict",
                    "dhcp_server": {"type": "list"},
                    "dns_server": {
                        "type": "dict",
                        "domain_name": {"type": "str"},
                        "primary_ip_address": {"type": "str"},
                        "secondary_ip_address": {"type": "str"},
                    },
                    "syslog_server": {
                        "type": "dict",
                        "ip_addresses": {"type": "list"},
                        "configure_dnac_ip": {"type": "bool"},
                    },
                    "snmp_server": {
                        "type": "dict",
                        "ip_addresses": {"type": "list"},
                        "configure_dnac_ip": {"type": "bool"},
                    },
                    "wired_data_collection": {
                        "type": "dict",
                        "enable_wired_data_collection": {"type": "bool"},
                    },
                    "wireless_telemetry": {
                        "type": "dict",
                        "enable_wireless_telemetry": {"type": "bool"},
                    },
                    "netflow_collector": {
                        "type": "dict",
                        "collector_type": {"type": "str"},
                        "ip_address": {"type": "str"},
                        "port": {"type": "int"},
                        "enable_on_wired_access_devices": {"type": "bool"},
                    },
                    "timezone": {"type": "str"},
                    "ntp_server": {"type": "list"},
                    "message_of_the_day": {
                        "type": "dict",
                        "banner_message": {"type": "str"},
                        "retain_existing_banner": {"type": "bool"},
                    },
                    "network_aaa": {
                        "type": "dict",
                        "server_type": {"type": "str", "choices": ["ISE", "AAA"]},
                        "pan_address": {"type": "str"},
                        "primary_server_address": {"type": "str"},
                        "secondary_server_address": {"type": "str"},
                        "protocol": {"type": "str", "choices": ["RADIUS", "TACACS"]},
                        "shared_secret": {"type": "str"},
                    },
                    "client_and_endpoint_aaa": {
                        "type": "dict",
                        "server_type": {"type": "str", "choices": ["ISE", "AAA"]},
                        "pan_address": {"type": "str"},
                        "primary_server_address": {"type": "str"},
                        "secondary_server_address": {"type": "str"},
                        "protocol": {"type": "str", "choices": ["RADIUS", "TACACS"]},
                        "shared_secret": {"type": "str"},
                    },
                },
                "site_name": {"type": 'str'},
            },
            "device_controllability_details": {
                "type": "dict",
                "options": {
                    "device_controllability": {"type": "bool", "required": True},
                    "autocorrect_telemetry_config": {"type": "bool", "required": False, "default": False}
                }
            }
        }

        invalid_params_type = []

        for config_item in self.config:
            ip_pool = (
                config_item.get("global_pool_details", {})
                .get("settings", {})
                .get("ip_pool", [])
            )

            for pool in ip_pool:
                # Check for 'dhcp_server_ips'
                dhcp_server_ips = pool.get("dhcp_server_ips")
                if dhcp_server_ips is not None and not isinstance(
                    dhcp_server_ips, list
                ):
                    invalid_params_type.append("'dhcp_server_ips' should be a list.")

                # Check for 'dns_server_ips'
                dns_server_ips = pool.get("dns_server_ips")
                if dns_server_ips is not None and not isinstance(dns_server_ips, list):
                    invalid_params_type.append("'dns_server_ips' should be a list.")

        if invalid_params_type:
            self.msg = "Invalid required parameter(s): {0}".format(
                ", ".join(invalid_params_type)
            )
            self.result["response"] = self.msg
            self.status = "failed"
            return self

        # Validate playbook params against the specification (temp_spec)
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.status = "failed"
            return self

        self.validated_config = valid_temp
        self.log(
            "Successfully validated playbook config params: {0}".format(valid_temp),
            "INFO",
        )
        self.msg = "Successfully validated input from the playbook"
        self.status = "success"
        return self

    def requires_update(self, have, want, obj_params):
        """
        Check if the template config given requires update by comparing
        current information wih the requested information.

        This method compares the current global pool, reserve pool,
        or network details from Cisco Catalyst Center with the user-provided details
        from the playbook, using a specified schema for comparison.

        Parameters:
            have (dict) - Current information from the Cisco Catalyst Center
                          (global pool, reserve pool, network details)
            want (dict) - Users provided information from the playbook
            obj_params (list of tuples) - A list of parameter mappings specifying which
                                          Cisco Catalyst Center parameters (dnac_param) correspond to
                                          the user-provided parameters (ansible_param).

        Returns:
            bool - True if any parameter specified in obj_params differs between
            current_obj and requested_obj, indicating that an update is required.
            False if all specified parameters are equal.

        """

        current_obj = have
        requested_obj = want
        self.log("Current State (have): {0}".format(current_obj), "DEBUG")
        self.log("Desired State (want): {0}".format(requested_obj), "DEBUG")

        return any(
            not dnac_compare_equality(
                current_obj.get(dnac_param), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param) in obj_params
        )

    def get_obj_params(self, get_object):
        """
        Get the required comparison obj_params value

        Parameters:
            get_object (str) - identifier for the required obj_params

        Returns:
            obj_params (list) - obj_params value for comparison.
        """

        try:
            if get_object == "GlobalPool":
                obj_params = [
                    ("ipPoolName", "ipPoolName"),
                    ("IpAddressSpace", "IpAddressSpace"),
                    ("dhcpServerIps", "dhcpServerIps"),
                    ("dnsServerIps", "dnsServerIps"),
                    ("name", "name"),
                    ("poolType", "poolType"),
                    ("addressSpace", "addressSpace")
                ]
            elif get_object == "ReservePool":
                obj_params = [
                    ("name", "name"),
                    ("type", "type"),
                    ("ipv6AddressSpace", "ipv6AddressSpace"),
                    ("ipv4GateWay", "ipv4GateWay"),
                    ("ipv4DhcpServers", "ipv4DhcpServers"),
                    ("ipv4DnsServers", "ipv4DnsServers"),
                    ("ipv6GateWay", "ipv6GateWay"),
                    ("ipv6DhcpServers", "ipv6DhcpServers"),
                    ("ipv6DnsServers", "ipv6DnsServers"),
                    ("ipv4TotalHost", "ipv4TotalHost"),
                    ("slaacSupport", "slaacSupport"),
                ]
            elif get_object == "Network":
                obj_params = [
                    ("settings", "settings"),
                    ("site_name", "site_name")
                ]
            elif get_object == "device_controllability":
                obj_params = [
                    ("deviceControllability", "device_controllability"),
                    ("autocorrectTelemetryConfig", "autocorrect_telemetry_config")
                ]
            else:
                raise ValueError(
                    "Received an unexpected value for 'get_object': {0}".format(
                        get_object
                    )
                )
        except Exception as msg:
            self.log("Received exception: {0}".format(msg), "CRITICAL")

        return obj_params

    def get_global_pool_params(self, pool_info):
        """
        Determine the correct version of the global pool parameter processor to use
        based on the Cisco Catalyst Center version.

        Parameters:
            pool_info (dict) - The input pool information.

        Returns:
            dict or None - Processed Global Pool data in a format suitable
            for Cisco Catalyst Center configuration.
        """
        current_version = self.get_ccc_version()
        self.log("Current Cisco Catalyst Center Version: {}".format(current_version), "DEBUG")

        if self.compare_dnac_versions(current_version, "2.3.7.9") < 0:
            self.log("Using get_global_pool_params_v1 based on version check", "DEBUG")
            return self.get_global_pool_params_v1(pool_info)

        self.log("Using get_global_pool_params_v2 based on version check", "DEBUG")
        return self.get_global_pool_params_v2(pool_info)

    def get_global_pool_params_v1(self, pool_info):
        """
        Process Global Pool parameters from playbook data for Global Pool configuration
        in Cisco Catalyst Center version < 2.3.7.9.

        Parameters:
            pool_info (dict) - Playbook data containing information about the global pool

        Returns:
            dict or None - Processed Global Pool data in a format suitable
            for Cisco Catalyst Center configuration, or None if pool_info is empty.
        """

        if not pool_info:
            self.log("Global Pool data is empty or missing.", "INFO")
            return None

        self.log("Global Pool Details: {0}".format(pool_info), "DEBUG")
        global_pool = {
            "dhcpServerIps": pool_info.get("dhcpServerIps"),
            "dnsServerIps": pool_info.get("dnsServerIps"),
            "ipPoolCidr": pool_info.get("ipPoolCidr"),
            "ipPoolName": pool_info.get("ipPoolName"),
            "type": pool_info.get("ipPoolType").capitalize(),
        }
        self.log("Formated global pool details: {0}".format(global_pool), "DEBUG")
        if pool_info.get("ipv6") is False:
            global_pool.update({"IpAddressSpace": "IPv4"})
        else:
            global_pool.update({"IpAddressSpace": "IPv6"})

        self.log(
            "ip_address_space: {0}".format(global_pool.get("IpAddressSpace")), "DEBUG"
        )
        if not pool_info["gateways"]:
            global_pool.update({"gateway": ""})
        else:
            global_pool.update({"gateway": pool_info.get("gateways")[0]})

        return global_pool

    def get_global_pool_params_v2(self, pool_info):
        """
        Process Global Pool parameters from playbook data for Global Pool configuration in
        Cisco Catalyst Center version <= 2.3.7.9.

        Parameters:
            pool_info (dict) - Playbook data containing information about the global pool

        Returns:
            dict or None - Processed Global Pool data in a format suitable
            for Cisco Catalyst Center configuration, or None if pool_info is empty.
        """

        if not pool_info:
            self.log("Global Pool data is empty or missing.", "INFO")
            return None

        self.log("Global Pool Details: {0}".format(self.pprint(pool_info)), "DEBUG")
        address_space = pool_info.get("addressSpace")
        if not address_space:
            self.log("Missing or invalid 'addressSpace' in Global Pool data.", "ERROR")
            return None
        global_pool = pool_info
        self.log("Formated global pool details: {0}".format(self.pprint(global_pool)), "DEBUG")

        return global_pool

    def get_reserve_pool_params(self, pool_info):
        """
        Process Reserved Pool parameters from playbook data
        for Reserved Pool configuration in Cisco Catalyst Center

        Parameters:
            pool_info (dict) - Playbook data containing information about the reserved pool

        Returns:
            reserve_pool (dict) - Processed Reserved pool data
            in the format suitable for the Cisco Catalyst Center config
        """

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
            self.log("Using new Reserved Pool format for version 2.3.7.9 and above", "INFO")
            return pool_info

        reserve_pool = {
            "name": pool_info.get("groupName"),
            "site_id": pool_info.get("siteId"),
        }
        pool_info_ippools = pool_info.get("ipPools")
        pool_info_length = len(pool_info_ippools)

        # If the reserved pool has only IPv4, pool_info_length will be 1.
        # If the reserved pool has both IPv4 and IPv6, pool_info_length will be 2.
        if pool_info_length == 1:
            reserve_pool.update(
                {
                    "ipv4DhcpServers": pool_info_ippools[0].get("dhcpServerIps"),
                    "ipv4DnsServers": pool_info_ippools[0].get("dnsServerIps"),
                    "ipv6AddressSpace": "False",
                }
            )
            if pool_info_ippools[0].get("gateways") != []:
                reserve_pool.update(
                    {"ipv4GateWay": pool_info_ippools[0].get("gateways")[0]}
                )
            else:
                reserve_pool.update({"ipv4GateWay": ""})
            reserve_pool.update({"ipv6AddressSpace": "False"})
        else:

            # If the ipv6 flag is set in the second element, ipv4_index will be 0 and ipv6_index will be 1.
            # If the ipv6 flag is set in the first element, ipv4_index will be 1 and ipv6_index will be 0.
            if not pool_info_ippools[0].get("ipv6"):
                ipv4_index = 0
                ipv6_index = 1
            else:
                ipv4_index = 1
                ipv6_index = 0

            reserve_pool.update(
                {
                    "ipv4DhcpServers": pool_info_ippools[ipv4_index].get(
                        "dhcpServerIps"
                    ),
                    "ipv4DnsServers": pool_info_ippools[ipv4_index].get("dnsServerIps"),
                    "ipv6AddressSpace": "True",
                    "ipv6Prefix": "True",
                    "ipv6DnsServers": pool_info_ippools[ipv6_index].get("dnsServerIps"),
                    "ipv6DhcpServers": pool_info_ippools[ipv6_index].get(
                        "dhcpServerIps"
                    ),
                }
            )
            if pool_info_ippools[ipv4_index].get("gateways") != []:
                reserve_pool.update(
                    {"ipv4GateWay": pool_info_ippools[ipv4_index].get("gateways")[0]}
                )
            else:
                reserve_pool.update({"ipv4GateWay": None})

            if pool_info_ippools[ipv6_index].get("gateways") != []:
                reserve_pool.update(
                    {"ipv6GateWay": pool_info_ippools[ipv6_index].get("gateways")[0]}
                )
            else:
                reserve_pool.update({"ipv6GateWay": ""})

            ippools_info = pool_info_ippools[ipv6_index].get("context")
            slaac_support_info = get_dict_result(
                ippools_info, "contextKey", "slaacSupport"
            )
            if (
                slaac_support_info is None
                or slaac_support_info.get("contextValue") == "false"
            ):
                reserve_pool.update({"slaacSupport": False})
            else:
                reserve_pool.update({"slaacSupport": True})

        self.log("Formatted reserve pool details: {0}".format(reserve_pool), "DEBUG")
        return reserve_pool

    def get_dhcp_settings_for_site(self, site_name, site_id):
        """
        Retrieve the DHCP settings for a specified site from Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to retrieve DHCP settings for.
            site_id (str) - The ID of the site to retrieve DHCP settings for.

        Returns:
            dhcp_details (dict) - DHCP settings details for the specified site.
        """
        self.log(
            "Attempting to retrieve DHCP settings for site '{0}' (ID: {1})".format(
                site_name, site_id
            ),
            "INFO",
        )

        try:
            dhcp_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_d_h_c_p_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id, "_inherited": True},
            )
            # Extract DHCP details
            dhcp_details = dhcp_response.get("response", {}).get("dhcp")

            if dhcp_response is None:
                self.log(
                    "No DHCP settings found for site '{0}' (ID: {1})".format(
                        site_name, site_id
                    ),
                    "WARNING",
                )
                return None

            self.log(
                "Successfully retrieved DNS settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, dhcp_response
                ),
                "DEBUG",
            )

            if dhcp_details.get("servers") is None:
                dhcp_details["servers"] = []

        except Exception as e:
            self.msg = "Exception occurred while getting DHCP settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return dhcp_details

    def get_dns_settings_for_site(self, site_name, site_id):
        """
        Retrieve the DNS settings for a specified site from Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to retrieve DNS settings for.
            site_id (str): The ID of the site to retrieve DNS settings for.

        Returns:
            dns_details (dict): DNS settings details for the specified site.
        """
        self.log(
            "Attempting to retrieve DNS settings for site '{0}' (ID: {1})".format(
                site_name, site_id
            ),
            "INFO",
        )

        try:
            dns_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_d_n_s_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id, "_inherited": True},
            )
            # Extract DNS details
            dns_details = dns_response.get("response", {}).get("dns")

            if not dns_details:
                self.log(
                    "No DNS settings found for site '{0}' (ID: {1})".format(
                        site_name, site_id
                    ),
                    "WARNING",
                )
                return None

            self.log(
                "Successfully retrieved DNS settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, dns_details
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while getting DNS settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return dns_details

    def get_telemetry_settings_for_site(self, site_name, site_id):
        """
        Retrieve the telemetry settings for a specified site from Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to retrieve telemetry settings for.
            site_id (str): The ID of the site to retrieve telemetry settings for.

        Returns:
            telemetry_details (dict): Telemetry settings details for the specified site.
        """
        self.log(
            "Attempting to retrieve telemetry settings for site ID: {0}".format(
                site_id
            ),
            "INFO",
        )

        try:
            telemetry_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_telemetry_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id, "_inherited": True},
            )

            # Extract telemetry details
            telemetry_details = telemetry_response.get("response", {})

            if not telemetry_details:
                self.log(
                    "No telemetry settings found for site '{0}' (ID: {1})".format(
                        site_name, site_id
                    ),
                    "WARNING",
                )
                return None

            self.log(
                "Successfully retrieved telemetry settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, telemetry_details
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while getting telemetry settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return telemetry_details

    def get_ntp_settings_for_site(self, site_name, site_id):
        """
        Retrieve the NTP server settings for a specified site from Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to retrieve NTP server settings for.
            site_id (str): The ID of the site to retrieve NTP server settings for.

        Returns:
            ntpserver_details (dict): NTP server settings details for the specified site.
        """
        self.log(
            "Attempting to retrieve NTP server settings for site '{0}' (ID: {1})".format(
                site_name, site_id
            ),
            "INFO",
        )

        try:
            ntpserver_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_n_t_p_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id, "_inherited": True},
            )
            # Extract NTP server details
            ntpserver_details = ntpserver_response.get("response", {}).get("ntp")

            if ntpserver_details is None:
                self.log(
                    "No NTP server settings found for site '{0}' (ID: {1})".format(
                        site_name, site_id
                    ),
                    "WARNING",
                )
                return None

            if ntpserver_details.get("servers") is None:
                ntpserver_details["servers"] = []

            self.log(
                "Successfully retrieved NTP server settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, ntpserver_details
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while getting NTP server settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return ntpserver_details

    def get_time_zone_settings_for_site(self, site_name, site_id):
        """
        Retrieve the time zone settings for a specified site from Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to retrieve time zone settings for.
            site_id (str): The ID of the site to retrieve time zone settings for.

        Returns:
            timezone_details (dict): Time zone settings details for the specified site.
        """
        self.log(
            "Attempting to retrieve time zone settings for site '{0}' (ID: {1})".format(
                site_name, site_id
            ),
            "INFO",
        )

        try:
            timezone_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_time_zone_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id, "_inherited": True},
            )
            # Extract time zone details
            timezone_details = timezone_response.get("response", {}).get("timeZone")

            if not timezone_details:
                self.log(
                    "No time zone settings found for site '{0}' (ID: {1})".format(
                        site_name, site_id
                    ),
                    "WARNING",
                )
                return None

            self.log(
                "Successfully retrieved time zone settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, timezone_details
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while getting time zone settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return timezone_details

    def get_banner_settings_for_site(self, site_name, site_id):
        """
        Retrieve the Message of the Day (banner) settings for a specified site from Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to retrieve banner settings for.
            site_id (str): The ID of the site to retrieve banner settings for.

        Returns:
            messageoftheday_details (dict): Banner (Message of the Day) settings details for the specified site.
        """
        self.log(
            "Attempting to retrieve banner (Message of the Day) settings for site '{0}' (ID: {1})".format(
                site_name, site_id
            ),
            "INFO",
        )

        try:
            banner_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_banner_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id, "_inherited": True},
            )
            # Extract banner (Message of the Day) details
            messageoftheday_details = banner_response.get("response", {}).get("banner")

            if not messageoftheday_details:
                self.log(
                    "No banner (Message of the Day) settings found for site '{0}' (ID: {1})".format(
                        site_name, site_id
                    ),
                    "WARNING",
                )
                return None

            self.log(
                "Successfully retrieved banner (Message of the Day) settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, messageoftheday_details
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while getting banner settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return messageoftheday_details

    def get_aaa_settings_for_site(self, site_name, site_id):
        """
        Retrieve the AAA (Authentication, Authorization, and Accounting) settings for a specified site from Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to retrieve AAA settings for.
            site_id (str): The ID of the site to retrieve AAA settings for.

        Returns:
            network_aaa (dict): AAA network settings details for the specified site.
            client_and_endpoint_aaa (dict): AAA client and endpoint settings details for the specified site.
        """
        self.log(
            "Attempting to retrieve AAA settings for site '{0}' (ID: {1})".format(
                site_name, site_id
            ),
            "INFO",
        )

        try:
            aaa_network_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_aaa_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id, "_inherited": True},
            )
            # Extract AAA network and client/endpoint settings
            response = aaa_network_response.get("response", {})
            network_aaa = response.get("aaaNetwork")
            client_and_endpoint_aaa = response.get("aaaClient")

            if not network_aaa or not client_and_endpoint_aaa:
                missing = []
                if not network_aaa:
                    missing.append("network_aaa")
                if not client_and_endpoint_aaa:
                    missing.append("client_and_endpoint_aaa")
                self.log(
                    "No {0} settings found for site '{1}' (ID: {2})".format(
                        " and ".join(missing), site_name, site_id
                    ),
                    "WARNING",
                )
                return network_aaa, client_and_endpoint_aaa

            self.log(
                "Successfully retrieved AAA Network settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, network_aaa
                ),
                "DEBUG",
            )
            self.log(
                "Successfully retrieved AAA Client and Endpoint settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, client_and_endpoint_aaa
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while getting AAA settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return network_aaa, client_and_endpoint_aaa

    def get_network_params(self, site_name, site_id):
        """
        Decides which network parameters function to call based on the Cisco Catalyst Center version.

        Parameters:
            site_name (str) - The Site name for which network parameters are requested
            site_id (str) - The Site ID for which network parameters are requested

        Returns:
            network_details: Processed Network data in a format suitable for configuration according to cisco catalyst center version.
        """
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") < 0:
            self.log(
                "Using get_network_params_v1 based on version check",
                "DEBUG",
            )
            return self.get_network_params_v1(site_name, site_id)

        return self.get_network_params_v2(site_name, site_id)

    def get_network_params_v1(self, site_name, site_id):
        """
        Process Network parameters for Cisco Catalyst Center version < 2.3.7.9.

        Parameters:
            site_name (str) - The Site name
            site_id (str) - The Site ID

        Returns:
            network_details: Processed Network data in a format suitable for configuration, or None on error.
        """
        self.log(
            "Attempting to retrieve network configuration details for site '{0}' (ID: {1})".format(
                site_name, site_id
            ),
            "INFO",
        )

        try:
            response = self.dnac._exec(
                family="network_settings",
                function="get_network_v2",
                op_modifies=True,
                params={"site_id": site_id},
            )
        except Exception as msg:
            self.msg = (
                "Exception occurred while getting the network settings details "
                "from Cisco Catalyst Center: {msg}".format(msg=msg)
            )
            self.log(str(msg), "ERROR")
            self.status = "failed"
            return self

        self.log(
            "Received API response from 'get_network_v2' for site '{0}' (ID: {1}): {2}".format(
                site_name,
                site_id,
                response,
            ),
            "DEBUG",
        )
        if not isinstance(response, dict):
            self.log(
                "Failed to retrieve the network details - "
                "Response is not a dictionary",
                "ERROR",
            )
            return None

        # Extract various network-related details from the response
        all_network_details = response.get("response")
        dhcp_details = get_dict_result(all_network_details, "key", "dhcp.server")
        dns_details = get_dict_result(all_network_details, "key", "dns.server")
        snmp_details = get_dict_result(all_network_details, "key", "snmp.trap.receiver")
        syslog_details = get_dict_result(all_network_details, "key", "syslog.server")
        netflow_details = get_dict_result(
            all_network_details, "key", "netflow.collector"
        )
        ntpserver_details = get_dict_result(all_network_details, "key", "ntp.server")
        timezone_details = get_dict_result(all_network_details, "key", "timezone.site")
        messageoftheday_details = get_dict_result(
            all_network_details, "key", "device.banner"
        )
        network_aaa = get_dict_result(
            all_network_details, "key", "aaa.network.server.1"
        )
        network_aaa2 = get_dict_result(
            all_network_details, "key", "aaa.network.server.2"
        )
        network_aaa_pan = get_dict_result(
            all_network_details, "key", "aaa.server.pan.network"
        )
        client_and_endpoint_aaa = get_dict_result(
            all_network_details, "key", "aaa.endpoint.server.1"
        )
        client_and_endpoint_aaa2 = get_dict_result(
            all_network_details, "key", "aaa.endpoint.server.2"
        )
        client_and_endpoint_aaa_pan = get_dict_result(
            all_network_details, "key", "aaa.server.pan.endpoint"
        )

        # Prepare the network details for Cisco Catalyst Center configuration
        network_details = {
            "settings": {
                "snmpServer": {
                    "configureDnacIP": snmp_details.get("value")[0].get(
                        "configureDnacIP"
                    ),
                    "ipAddresses": snmp_details.get("value")[0].get("ipAddresses"),
                },
                "syslogServer": {
                    "configureDnacIP": syslog_details.get("value")[0].get(
                        "configureDnacIP"
                    ),
                    "ipAddresses": syslog_details.get("value")[0].get("ipAddresses"),
                },
                "timezone": timezone_details.get("value")[0],
            }
        }
        network_settings = network_details.get("settings")
        if dhcp_details and dhcp_details.get("value") != []:
            network_settings.update({"dhcpServer": dhcp_details.get("value")})
        else:
            network_settings.update({"dhcpServer": [""]})

        if dns_details is not None:
            network_settings.update(
                {
                    "dnsServer": {
                        "domainName": dns_details.get("value")[0].get("domainName"),
                        "primaryIpAddress": dns_details.get("value")[0].get(
                            "primaryIpAddress"
                        ),
                        "secondaryIpAddress": dns_details.get("value")[0].get(
                            "secondaryIpAddress"
                        ),
                    }
                }
            )
        else:
            network_settings.update(
                {
                    "dnsServer": {
                        "domainName": "",
                        "primaryIpAddress": "",
                        "secondaryIpAddress": "",
                    }
                }
            )

        if ntpserver_details and ntpserver_details.get("value") != []:
            network_settings.update({"ntpServer": ntpserver_details.get("value")})
        else:
            network_settings.update({"ntpServer": [""]})

        netflow_collector_values = netflow_details.get("value")[0]
        ip_address = netflow_collector_values.get("ipAddress")
        port = netflow_collector_values.get("port")
        if port is None:
            port = "null"

        network_settings.update(
            {
                "netflowcollector": {
                    "ipAddress": ip_address,
                    "port": port,
                }
            }
        )

        if messageoftheday_details is not None:
            network_settings.update(
                {
                    "messageOfTheday": {
                        "bannerMessage": messageoftheday_details.get("value")[0].get(
                            "bannerMessage"
                        ),
                    }
                }
            )
            retain_existing_banner = messageoftheday_details.get("value")[0].get(
                "retainExistingBanner"
            )
            if retain_existing_banner is True:
                network_settings.get("messageOfTheday").update(
                    {"retainExistingBanner": "true"}
                )
            else:
                network_settings.get("messageOfTheday").update(
                    {"retainExistingBanner": "false"}
                )
        else:
            network_settings.update(
                {"messageOfTheday": {"bannerMessage": "", "retainExistingBanner": ""}}
            )

        if network_aaa and network_aaa_pan:
            if network_aaa_pan.get("value"):
                aaa_pan_value = network_aaa_pan.get("value")[0]
            else:
                aaa_pan_value = "None"

            if network_aaa.get("value"):
                aaa_value = network_aaa.get("value")[0]
            else:
                aaa_value = {}

            if aaa_pan_value == "None":
                network_settings.update(
                    {
                        "network_aaa": {
                            "network": aaa_value.get("ipAddress", ""),
                            "protocol": aaa_value.get("protocol", ""),
                            "servers": "AAA",
                        }
                    }
                )
                # Handle the second AAA server network_aaa2
                if network_aaa2 and network_aaa2.get("value"):
                    network_settings["network_aaa"].update(
                        {"ipAddress": network_aaa2.get("value")[0].get("ipAddress", "")}
                    )
                else:
                    network_settings["network_aaa"].update({"ipAddress": ""})
            else:
                network_settings.update(
                    {
                        "network_aaa": {
                            "network": aaa_pan_value,
                            "protocol": aaa_value.get("protocol", ""),
                            "ipAddress": aaa_value.get("ipAddress", ""),
                            "servers": "ISE",
                        }
                    }
                )
        else:
            network_settings.update(
                {
                    "network_aaa": {
                        "network": "",
                        "protocol": "",
                        "ipAddress": "",
                        "servers": "",
                    }
                }
            )

        if client_and_endpoint_aaa and client_and_endpoint_aaa_pan:
            if client_and_endpoint_aaa_pan.get("value"):
                aaa_pan_value = client_and_endpoint_aaa_pan.get("value")[0]
            else:
                aaa_pan_value = "None"

            if client_and_endpoint_aaa.get("value"):
                aaa_value = client_and_endpoint_aaa.get("value")[0]
            else:
                aaa_value = {}

            if aaa_pan_value == "None":
                network_settings.update(
                    {
                        "client_and_endpoint_aaa": {
                            "network": aaa_value.get("ipAddress", ""),
                            "protocol": aaa_value.get("protocol", ""),
                            "servers": "AAA",
                        }
                    }
                )
                # Handle the second client AAA server client_and_endpoint_aaa2
                if client_and_endpoint_aaa2 and client_and_endpoint_aaa2.get("value"):
                    network_settings["client_and_endpoint_aaa"].update(
                        {
                            "ipAddress": client_and_endpoint_aaa2.get("value")[0].get(
                                "ipAddress", ""
                            )
                        }
                    )
                else:
                    network_settings["client_and_endpoint_aaa"].update(
                        {"ipAddress": ""}
                    )
            else:
                network_settings.update(
                    {
                        "client_and_endpoint_aaa": {
                            "network": aaa_pan_value,
                            "protocol": aaa_value.get("protocol", ""),
                            "ipAddress": aaa_value.get("ipAddress", ""),
                            "servers": "ISE",
                        }
                    }
                )
        else:
            network_settings.update(
                {
                    "client_and_endpoint_aaa": {
                        "network": "",
                        "protocol": "",
                        "ipAddress": "",
                        "servers": "",
                    }
                }
            )

        network_settings_snmp = network_settings.get("snmpServer")
        if not network_settings_snmp.get("ipAddresses"):
            network_settings_snmp.update({"ipAddresses": []})

        network_settings_syslog = network_settings.get("syslogServer")
        if not network_settings_syslog.get("ipAddresses"):
            network_settings_syslog.update({"ipAddresses": []})

        self.log(
            "Formatted playbook network details: {0}".format(network_details), "DEBUG"
        )
        return network_details

    def get_network_params_v2(self, site_name, site_id):
        """
        Process Network parameters for Cisco Catalyst Center version >= 2.3.7.9.

        Parameters:
            site_name (str) - The Site name
            site_id (str) - The Site ID

        Returns:
            network_details: Processed Network data in a format suitable for configuration, or None on error.
        """

        dhcp_details = self.get_dhcp_settings_for_site(site_name, site_id)
        dns_details = self.get_dns_settings_for_site(site_name, site_id)
        telemetry_details = self.get_telemetry_settings_for_site(site_name, site_id)
        if telemetry_details.get("wiredDataCollection") is None:
            wired_data_collection = ""
        else:
            wired_data_collection = telemetry_details.get("wiredDataCollection")

        if telemetry_details.get("wirelessTelemetry") is None:
            wireless_telemetry = ""
        else:
            wireless_telemetry = telemetry_details.get("wirelessTelemetry")

        netflow_details = telemetry_details.get("applicationVisibility")
        snmp_details = telemetry_details.get("snmpTraps")
        syslog_details = telemetry_details.get("syslogs")
        ntpserver_details = self.get_ntp_settings_for_site(site_name, site_id)
        timezone_details = self.get_time_zone_settings_for_site(site_name, site_id)
        messageoftheday_details = self.get_banner_settings_for_site(site_name, site_id)
        network_aaa, client_and_endpoint_aaa = self.get_aaa_settings_for_site(
            site_name, site_id
        )

        # Prepare the network details for Cisco Catalyst Center configuration
        if not network_aaa:
            network_aaa = {
                "serverType": "",
                "primaryServerIp": "",
                "secondaryServerIp": "",
                "protocol": "",
            }
        if not client_and_endpoint_aaa:
            client_and_endpoint_aaa = {
                "serverType": "",
                "primaryServerIp": "",
                "secondaryServerIp": "",
                "protocol": "",
            }

        network_details = {
            "settings": {
                "network_aaa": network_aaa,
                "client_and_endpoint_aaa": client_and_endpoint_aaa,
                "wired_data_collection": wired_data_collection,
                "wireless_telemetry": wireless_telemetry,
            }
        }
        network_settings = network_details.get("settings")

        if snmp_details:
            network_settings.update({"snmpServer": snmp_details})
        else:
            network_settings.update({"snmpServer": [""]})

        if timezone_details is None:
            network_settings.update({"timezone": {"identifier": "GMT"}})
        else:
            network_settings.update({"timezone": timezone_details})

        if syslog_details:
            network_settings.update({"syslogServer": syslog_details})
        else:
            network_settings.update({"syslogServer": [""]})

        if dhcp_details:
            if "servers" not in dhcp_details:
                dhcp_details["servers"] = []
            network_settings.update({"dhcpServer": dhcp_details})
        else:
            network_settings.update({"dhcpServer": [""]})

        if dns_details is not None:
            domain_name = dns_details.get("domainName")
            if "dnsServer" not in network_settings:
                network_settings["dnsServer"] = {}
            if domain_name:
                network_settings.get("dnsServer").update(
                    {"domainName": dns_details.get("domainName")}
                )
            else:
                network_settings.get("dnsServer").update({"domainName": ""})
            dns_servers = dns_details.get("dnsServers", [])

            # If there are no DNS servers, provide an empty list or handle it accordingly.
            if len(dns_servers) == 0:
                network_settings.get("dnsServer").update(
                    {"primaryIpAddress": "", "secondaryIpAddress": ""}
                )
            else:
                if len(dns_servers) > 0:
                    network_settings.get("dnsServer").update(
                        {"primaryIpAddress": dns_details.get("dnsServers")[0]}
                    )

                    if len(dns_servers) > 1:
                        network_settings.get("dnsServer").update(
                            {"secondaryIpAddress": dns_details.get("dnsServers")[1]}
                        )
        else:
            network_settings.update(
                {
                    "dnsServer": {
                        "domainName": "",
                        "primaryIpAddress": "",
                        "secondaryIpAddress": "",
                    }
                }
            )

        if ntpserver_details is not None:
            network_settings.update({"ntpServer": ntpserver_details})
        else:
            network_settings.update({"ntpServer": [""]})

        if netflow_details is not None:
            ip_address = netflow_details.get("collector").get("address")
            if not ip_address:
                ip_address = ""
            port = netflow_details.get("collector").get("port")
            if not port:
                port = ""

            enable_on_wired_access_devices = netflow_details.get(
                "enableOnWiredAccessDevices"
            )
            collector_type = netflow_details.get("collector").get("collectorType")

            if collector_type:
                network_settings.update(
                    {
                        "netflowcollector": {
                            "collector": {
                                "collectorType": collector_type,
                                "address": ip_address,
                                "port": port,
                            },
                            "enableOnWiredAccessDevices": enable_on_wired_access_devices,
                        }
                    }
                )
        else:
            network_settings.update({"netflowcollector": {}})

        if messageoftheday_details is not None:
            network_settings.update({"messageOfTheday": messageoftheday_details})
        else:
            network_settings.update({"messageOfTheday": ""})

        self.log(
            "Formatted playbook network details: {0}".format(network_details), "DEBUG"
        )

        return network_details

    def get_reserved_ip_subpool(self, site_name, site_id):
        """
        Retrieve all the reserved IP subpool details from the Cisco Catalyst Center.

        Parameters:
            site_name (str): The name of the site for which reserved pool details are requested.
            site_id (str) - The Site ID for which reserved pool details are requested.
            self (object) - The current object details.

        Returns:
            self (object) - The current object with updated desired reserved subpool information.
        """

        offset = 1
        self.all_reserved_pool_details.update({site_id: []})
        start_time = time.time()
        while True:
            try:
                if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") < 0:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="get_reserve_ip_subpool",
                        op_modifies=True,
                        params={
                            "site_id": site_id,
                            "offset": offset
                        }
                    )
                else:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="retrieves_ip_address_subpools",
                        op_modifies=True,
                        params={
                            "id": site_id,
                            "offset": offset
                        }
                    )
            except Exception as msg:
                self.msg = "Exception occurred while fetching reserved pool details for site '{0}': {1}".format(
                    site_name, site_id
                )
                self.log(str(msg), "ERROR")
                self.status = "failed"
                return self
            if not isinstance(response, dict):
                self.msg = (
                    "Error in getting reserve pool - Response is not a dictionary"
                )
                self.log(self.msg, "CRITICAL")
                self.status = "exited"
                return self.check_return_status()

            reserve_pool_details = response.get("response")
            if not reserve_pool_details:
                self.log(
                    "No subpools are reserved in the site with ID - '{0}': '{1}'.".format(
                        site_id, site_name
                    ),
                    "DEBUG",
                )
                return self

            self.all_reserved_pool_details.get(site_id).extend(reserve_pool_details)

            if len(reserve_pool_details) < 25:
                self.log(
                    "Found {0} record(s), No more record available for the next offset".format(
                        str(len(reserve_pool_details))
                    ),
                    "INFO",
                )
                break

            offset += 25

            end_time = time.time()
            if (end_time - start_time) >= self.max_timeout:
                self.msg = "Max timeout of {0} sec has reached for the API 'get_reserved_ip_subpool' status.".format(
                    self.max_timeout
                )
                self.status = "failed"
                break

        return self

    def global_pool_exists(self, name):
        """
        Check if the Global Pool with the given name exists

        Parameters:
            name (str) - The name of the Global Pool to check for existence

        Returns:
            dict - A dictionary containing information about the Global Pool's existence:
            - 'exists' (bool): True if the Global Pool exists, False otherwise.
            - 'id' (str or None): The ID of the Global Pool if it exists, or None if it doesn't.
            - 'details' (dict or None): Details of the Global Pool if it exists, else None.
        """

        global_pool = {"exists": False, "details": None, "id": None}
        all_global_pool = []
        offset = 1
        global_pool_details = None
        response = None
        current_version = self.get_ccc_version()
        is_old_version = self.compare_dnac_versions(current_version, "2.3.7.9") < 0
        page_limit = 25 if is_old_version else 500
        while True:
            try:
                if is_old_version:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="get_global_pool",
                        params={"offset": offset}
                    )
                else:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="retrieves_global_ip_address_pools",
                        params={"offset": offset,
                                "limit": 500}
                    )
                self.log("Received response for list of global pool details existing in Catalyst Center: {}".format(self.pprint(response)), "DEBUG")
            except Exception as msg:
                self.msg = "Exception occurred while getting the global pool details with name '{name}': {msg}".format(
                    name=name, msg=msg
                )
                self.log(str(msg), "ERROR")
                self.fail_and_exit(self.msg)

            if not isinstance(response, dict):
                self.msg = "Failed to retrieve the global pool details - Response is not a dictionary"
                self.log(self.msg, "CRITICAL")
                self.fail_and_exit(self.msg)

            all_global_pool_details = response.get("response")
            if not all_global_pool_details:
                if name == "":
                    self.log(
                        "Global pool '{0}' does not exist".format(all_global_pool),
                        "INFO",
                    )
                    return all_global_pool
                self.log("Global pool '{0}' does not exist".format(name), "INFO")
                return global_pool

            if name == "":
                global_pool_details = all_global_pool_details
            else:
                if is_old_version:
                    global_pool_details = get_dict_result(all_global_pool_details, "ipPoolName", name)
                else:
                    global_pool_details = get_dict_result(all_global_pool_details, "name", name)

            if global_pool_details and isinstance(global_pool_details, dict):
                self.log(
                    "Global pool found with name '{0}': {1}".format(
                        name, global_pool_details
                    ),
                    "INFO",
                )
                global_pool.update({"exists": True})
                global_pool.update({"id": global_pool_details.get("id")})
                global_pool["details"] = self.get_global_pool_params(
                    global_pool_details
                )
                break

            if (
                global_pool_details
                and isinstance(global_pool_details, list)
                and name == ""
            ):
                self.log(
                    "Global pool found {0}".format(self.pprint(global_pool_details)),
                    "INFO",
                )

                for each_pool in global_pool_details:
                    global_del_pool = {
                        "exists": True,
                        "id": each_pool.get("id"),
                        "details": self.get_global_pool_params(each_pool),
                    }
                    all_global_pool.append(global_del_pool)

            if len(all_global_pool_details) < page_limit:
                self.log(
                    "Found {0} record(s), No more record available for the next offset".format(
                        str(len(all_global_pool_details))
                    ),
                    "INFO",
                )
                if self.payload.get("state") == "deleted" and name == "":
                    self.log(
                        "Formatted global pool details: {0}".format(
                            self.pprint(all_global_pool)
                        ),
                        "DEBUG",
                    )
                    return all_global_pool
                break

            offset += page_limit

        self.log("Formatted global pool details: {0}".format(global_pool), "DEBUG")
        return global_pool

    def reserve_pool_exists(self, name, site_name):
        """
        Check if the Reserved pool with the given name exists in a specific site
        Use check_return_status() to check for failure

        Parameters:
            name (str) - The name of the Reserved pool to check for existence.
            site_name (str) - The name of the site where the Reserved pool is located.

        Returns:
            dict - A dictionary containing information about the Reserved pool's existence:
            - 'exists' (bool): True if the Reserved pool exists in the specified site, else False.
            - 'id' (str or None): The ID of the Reserved pool if it exists, or None if it doesn't.
            - 'details' (dict or None): Details of the Reserved pool if it exists, or else None.
        """

        reserve_pool = {"exists": False, "details": None, "id": None, "success": True}
        site_exist, site_id = self.get_site_id(site_name)
        self.log(
            "Site ID for the site name {0}: {1}".format(site_name, site_id), "DEBUG"
        )
        if not site_id:
            reserve_pool.update({"success": False})
            self.msg = "Failed to get the site id from the site name {0}".format(
                site_name
            )
            self.status = "failed"
            return reserve_pool

        if not self.all_reserved_pool_details.get(site_id):
            self.get_reserved_ip_subpool(site_name, site_id)

        if not self.all_reserved_pool_details.get(site_id):
            self.log(
                "Reserved pool {0} does not exist in the site {1}".format(
                    name, site_name
                ),
                "DEBUG",
            )
            return reserve_pool

        reserve_pool_details = None
        if name == "":
            reserve_pool_details = self.all_reserved_pool_details.get(site_id)
        else:
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") < 0:
                reserve_pool_details = get_dict_result(
                    self.all_reserved_pool_details.get(site_id), "groupName", name)
            else:
                reserve_pool_details = get_dict_result(
                    self.all_reserved_pool_details.get(site_id), "name", name)

        if not reserve_pool_details:
            self.log(
                "Reserved pool {0} does not exist in the site {1}".format(
                    name, site_name
                ),
                "DEBUG",
            )
            return reserve_pool

        if isinstance(reserve_pool_details, dict):
            self.log(
                "Reserve pool found with name {0} in the site '{1}': {2}".format(
                    name, site_name, reserve_pool_details
                ),
                "INFO",
            )
            reserve_pool.update({"exists": True})
            reserve_pool.update({"id": reserve_pool_details.get("id")})
            reserve_pool.update(
                {"details": self.get_reserve_pool_params(reserve_pool_details)}
            )
            self.log(
                "Reserved pool details: {0}".format(reserve_pool.get("details")),
                "DEBUG",
            )
            self.log("Reserved pool id: {0}".format(reserve_pool.get("id")), "DEBUG")
            return reserve_pool

        if isinstance(reserve_pool_details, list):
            self.log(
                "Found reserve pools for site '{0}': {1}".format(
                    site_name, self.pprint(reserve_pool_details)
                ),
                "INFO",
            )
            all_reserve_pool = []
            for each_pool in reserve_pool_details:
                reserve_del_pool = {
                    "exists": True,
                    "id": each_pool.get("id"),
                    "details": self.get_reserve_pool_params(each_pool),
                    "success": True,
                }
                all_reserve_pool.append(reserve_del_pool)

            self.log(
                "Reserved pool list details: {0}".format(self.pprint(all_reserve_pool)),
                "DEBUG",
            )
            return all_reserve_pool

        return reserve_pool

    def get_have_global_pool(self, global_pool_details):
        """
        Get the current Global Pool information from
        Cisco Catalyst Center based on the provided playbook details.
        check this API using check_return_status.

        Parameters:
            global_pool_details (dict) - Playbook details containing Global Pool configuration.

        Returns:
            self - The current object with updated information.
        """

        global_pool_settings = global_pool_details.get("settings")
        if global_pool_settings is None:
            self.msg = "settings in global_pool_details is missing in the playbook"
            self.status = "failed"
            return self

        global_pool_ippool = global_pool_settings.get("ip_pool")
        if global_pool_ippool is None:
            self.msg = "ip_pool in global_pool_details is missing in the playbook"
            self.status = "failed"
            return self

        global_pool = []
        global_pool_index = 0
        errors = []  # To collect all error messages

        for pool_details in global_pool_ippool:
            delete_all = pool_details.get("force_delete")
            name = pool_details.get("name")
            if delete_all:
                name = ""
            else:
                if name is None:
                    errors.append(
                        "Missing required parameter 'name' in global_pool_details: {}".format(
                            pool_details
                        )
                    )
                    continue

                name_length = len(name)
                if name_length > 100:
                    errors.append(
                        "The length of the 'name' in global_pool_details should be less or equal to 100. Invalid_config: {}".format(
                            pool_details
                        )
                    )

                if " " in name:
                    errors.append(
                        "The 'name' in global_pool_details should not contain any spaces. Invalid_config: {}".format(
                            pool_details
                        )
                    )

                pattern = r"^[\w\-./]+$"
                if not re.match(pattern, name):
                    errors.append(
                        "The 'name' in global_pool_details should contain only letters, numbers, and -_./ characters. Invalid_config: {}".format(
                            pool_details
                        )
                    )

        if errors:
            # If there are errors, return a failure status with all messages
            self.msg = "Validation failed with the following errors:\n" + "\n".join(
                errors
            )
            self.status = "failed"
            return self

        if name == "":
            global_pool.append(self.global_pool_exists(name))
            self.log("Global pool details: {0}".format(global_pool), "DEBUG")
            self.have.update({"globalPool": global_pool})
            self.msg = (
                "Collected all global pool details from the Cisco Catalyst Center."
            )
            self.status = "success"
            return self

        for pool_details in global_pool_ippool:
            # If the Global Pool doesn't exist and a previous name is provided
            # Else try using the previous name
            name = pool_details.get("name")
            if pool_details.get("force_delete"):
                name = ""

            global_pool.append(self.global_pool_exists(name))
            self.log(
                "Global pool details of '{0}': {1}".format(
                    name, global_pool[global_pool_index]
                ),
                "DEBUG",
            )
            prev_name = pool_details.get("prev_name")
            if (
                global_pool[global_pool_index].get("exists") is False
                and prev_name is not None
            ):
                global_pool.pop()
                global_pool.append(self.global_pool_exists(prev_name))
                if global_pool[global_pool_index].get("exists") is False:
                    self.msg = (
                        "Prev name {0} doesn't exist in global_pool_details".format(
                            prev_name
                        )
                    )
                    self.status = "failed"
                    return self

                global_pool[global_pool_index].update({"prev_name": name})
            global_pool_index += 1

        self.log("Global pool details: {0}".format(global_pool), "DEBUG")
        self.have.update({"globalPool": global_pool})
        self.msg = "Collecting the global pool details from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_have_device_controllability(self, config_details):
        """
        Get the current Device Controllability information from Cisco Catalyst Center
        and store it directly in self.have.

        Parameters:
            config_details (list of dict) - Playbook details containing device controllability config.

        Returns:
            self - The current object with updated information.
        """

        self.log("Fetching device controllability details from Cisco Catalyst Center.", "INFO")

        try:
            # Call the Catalyst Center API using family/function
            response = self.dnac._exec(
                family="site_design",
                function="get_device_controllability_settings",
            )
            response = response.get("response")

            # Check if the API call was successful
            if not response:
                self.log("Device controllability response is empty or invalid.", "ERROR")
                return self.check_return_status()

            # Store response in 'have'
            self.have.update({"have_device_controllability": response})
            self.msg = "Collected device controllability details from Cisco Catalyst Center"
            self.status = "success"

        except Exception as e:
            # Handle any exceptions that occur during the API call
            self.log(f"Error occurred while fetching device controllability details: {str(e)}", "ERROR")
            self.status = "failed"
            self.msg = f"Exception during device controllability retrieval: {str(e)}"
            return self.check_return_status()

        return self

    def get_have_reserve_pool(self, reserve_pool_details):
        """
        Get the current Reserved Pool information from Cisco Catalyst Center
        based on the provided playbook details.
        Check this API using check_return_status

        Parameters:
            reserve_pool_details (list of dict) - Playbook details containing Reserved Pool configuration.

        Returns:
            self - The current object with updated information.
        """

        reserve_pool = []
        reserve_pool_index = 0
        for item in reserve_pool_details:
            delete_all = item.get("force_delete")
            name = item.get("name")
            site_name = item.get("site_name")
            if delete_all:
                name = ""
            else:
                if name is None:
                    self.msg = (
                        "Missing required parameter 'name' in reserve_pool_details."
                    )
                    self.status = "failed"
                    return self

                name_length = len(name)
                if name_length > 100:
                    self.msg = "The length of the 'name' in reserve_pool_details should be less or equal to 100."
                    self.status = "failed"
                    return self

                if " " in name:
                    self.msg = "The 'name' in reserve_pool_details should not contain any spaces."
                    self.status = "failed"
                    return self

                pattern = r"^[\w\-./]+$"
                if not re.match(pattern, name):
                    self.msg = "The 'name' in reserve_pool_details should contain only letters, numbers and -_./ characters."
                    self.status = "failed"
                    return self

            site_name = item.get("site_name")
            self.log("Site Name: {0}".format(site_name), "DEBUG")
            if site_name is None:
                self.msg = "Missing parameter 'site_name' in reserve_pool_details"
                self.status = "failed"
                return self

            # Check if the Reserved Pool exists in Cisco Catalyst Center
            # based on the provided name and site name
            if self.reserve_pool_exists(name, site_name):
                reserve_pool.append(self.reserve_pool_exists(name, site_name))
            else:
                self.have.update({"reservePool": reserve_pool})
                return self

            if name != "" and not reserve_pool[reserve_pool_index].get("success"):
                return self.check_return_status()
            elif name == "" and len(reserve_pool[reserve_pool_index]) < 1:
                return self.check_return_status()

            self.log(
                "Reserved pool details for {0}: {1}".format(
                    name, reserve_pool[reserve_pool_index]
                ),
                "DEBUG",
            )

            if name != "":
                # If the Reserved Pool doesn't exist and a previous name is provided
                # Else try using the previous name
                prev_name = item.get("prev_name")
                if (
                    reserve_pool[reserve_pool_index].get("exists") is False
                    and prev_name is not None
                ):
                    self.log(
                        "Current pool does not exist. Checking for previous name '{0}'.".format(
                            prev_name
                        ),
                        "DEBUG",
                    )
                    reserve_pool.pop()
                    reserve_pool.append(self.reserve_pool_exists(prev_name, site_name))
                    if not reserve_pool[reserve_pool_index].get("success"):
                        return self.check_return_status()

                    # If the previous name doesn't exist in Cisco Catalyst Center, return with error
                    if reserve_pool[reserve_pool_index].get("exists") is False:
                        self.msg = "Prev name {0} doesn't exist in reserve_pool_details".format(
                            prev_name
                        )
                        self.status = "failed"
                        return self

                self.log(
                    "Reserved pool exists: {0}".format(
                        reserve_pool[reserve_pool_index].get("exists")
                    ),
                    "DEBUG",
                )
                self.log(
                    "Reserved pool: {0}".format(
                        reserve_pool[reserve_pool_index].get("details")
                    ),
                    "DEBUG",
                )

                # If reserve pool exist, convert ipv6AddressSpace to the required format (boolean)
                if reserve_pool[reserve_pool_index].get("exists"):
                    reserve_pool_info = reserve_pool[reserve_pool_index].get("details")
                    if reserve_pool_info.get("ipv6AddressSpace") == "False":
                        reserve_pool_info.update({"ipv6AddressSpace": False})
                    else:
                        reserve_pool_info.update({"ipv6AddressSpace": True})

            reserve_pool_index += 1

        self.log("Reserved pool details: {0}".format(reserve_pool), "DEBUG")
        self.have.update({"reservePool": reserve_pool})
        self.msg = "Collected the reserve pool details from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_have_network(self, network_details):
        """
        Get the current Network details from Cisco Catalyst
        Center based on the provided playbook details.

        Parameters:
            network_details (dict) - Playbook details containing Network Management configuration.

        Returns:
            self - The current object with updated Network information.
        """
        all_network_management_details = []
        for item in network_details:
            network = {}
            site_name = item.get("site_name")
            if site_name is None:
                site_name = "Global"
                item.update({"site_name": site_name})

            site_exist, site_id = self.get_site_id(site_name)
            if site_id is None:
                self.msg = "The site with the name '{0}' is not available in the Catalyst Center".format(
                    site_name
                )
                self.status = "failed"
                return self

            network["site_name"] = site_name
            network["site_id"] = site_id
            network["net_details"] = self.get_network_params(site_name, site_id)
            self.log(
                "Network details from the Catalyst Center for site '{0}': {1}".format(
                    site_name, network
                ),
                "DEBUG",
            )
            all_network_management_details.append(network)

        self.have.update({"network": all_network_management_details})
        self.msg = "Collecting the network details from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_have(self, config):
        """
        Get the current Global Pool Reserved Pool and Network details from Cisco Catalyst Center

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self - The current object with updated Global Pool,
            Reserved Pool, and Network information.
        """

        global_pool_details = config.get("global_pool_details")
        if global_pool_details is not None:
            self.get_have_global_pool(global_pool_details).check_return_status()

        reserve_pool_details = config.get("reserve_pool_details")
        if reserve_pool_details is not None:
            self.get_have_reserve_pool(reserve_pool_details).check_return_status()

        network_details = config.get("network_management_details")
        if network_details is not None:
            self.get_have_network(network_details).check_return_status()

        # Retrieve device controllability details from the config
        device_controllability_details = config.get("device_controllability_details")

        if device_controllability_details:
            # Check if the CCC version is 2.3.7.9 or later
            current_version = self.get_ccc_version()
            if self.compare_dnac_versions(current_version, "2.3.7.9") >= 0:
                self.log(
                    f"Device controllability details found in config. Proceeding with version {current_version}.",
                    "DEBUG",
                )
                self.get_have_device_controllability(device_controllability_details).check_return_status()
            else:
                self.log(
                    f"Cisco Catalyst Center version {current_version} is lower than 2.3.7.9. Skipping device controllability retrieval.",
                    "INFO",
                )
        else:
            self.log("No device controllability details found in the provided config.", "DEBUG")

        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.msg = "Successfully retrieved the details from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_global_pool_cidr(self, global_pool_cidr, global_pool_name):
        """
        Retrieve the Global Pool CIDR or ID from Cisco Catalyst Center based on the pool name.

        This method returns the provided CIDR directly if available and compatible with the platform version.
        Otherwise, it queries the Catalyst Center for the matching global pool using the pool name.

        Parameters:
            global_pool_cidr (str): CIDR value of the global pool if already known. Used directly for older versions.
            global_pool_name (str): Name of the global pool to search for in Catalyst Center.

        Returns:
            str: The global pool CIDR (for versions < 2.3.7.9) or the global pool ID (for later versions).
                In case of error, the method sets internal status/message and returns from `check_return_status()`.
        """
        self.log(f"Starting retrieval of global pool. CIDR: {global_pool_cidr}, Name: {global_pool_name}", "INFO")
        current_version = self.get_ccc_version()
        is_old_version = self.compare_dnac_versions(current_version, "2.3.7.9") < 0
        page_limit = 25 if is_old_version else 500

        # Direct return for older versions when CIDR is provided
        if global_pool_cidr and is_old_version:
            self.log(f"Using provided CIDR '{global_pool_cidr}' directly for older platform versions.", "INFO")
            return global_pool_cidr

        if not global_pool_name and not global_pool_cidr:
            self.msg = "Missing parameter 'Global Pool CIDR' or 'Global Pool name' is required under reserve_pool_details."
            self.status = "failed"
            return self.check_return_status()

        offset = 1
        while True:
            self.log(f"Querying global pool details with offset {offset}.", "DEBUG")
            try:
                if is_old_version:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="get_global_pool",
                        params={"offset": offset}
                    )
                else:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="retrieves_global_ip_address_pools",
                        params={"offset": offset}
                    )
            except Exception as msg:
                self.msg = "Exception occurred while getting the global pool details with name '{name}': {msg}".format(
                    name=global_pool_name, msg=msg
                )
                self.log(str(msg), "ERROR")
                self.status = "failed"
                return self

            self.log(f"Global pool details retrieved successfully with offset {offset}.", "DEBUG")

            # Validate response type
            if not isinstance(response, dict):
                self.msg = "Failed to retrieve the global pool details - Response is not a dictionary"
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

            all_global_pool_details = response.get("response")
            if not all_global_pool_details:
                self.log(f"No global pool details returned for offset {offset}.", "WARNING")
                self.msg = f"No information found for the global pool named '{global_pool_name}'"
                self.status = "failed"
                return self.check_return_status()

            # Old Version (< 2.3.7.9)
            if is_old_version:
                self.log(f"Looking for global pool '{global_pool_name}' in older version format.", "DEBUG")
                global_pool_details = get_dict_result(all_global_pool_details, "ipPoolName", global_pool_name)
                if global_pool_details:
                    global_pool_cidr = global_pool_details.get("ipPoolCidr")
                    self.log(f"Global pool found with name '{global_pool_name}': {global_pool_details}", "INFO")
                    self.log(f"Global Pool '{global_pool_name}' CIDR: {global_pool_cidr}", "INFO")
                    return global_pool_cidr

                # Pagination end detection
                if len(all_global_pool_details) < page_limit:
                    self.log(
                        f"Reached last page with {len(all_global_pool_details)} record(s). "
                        f"Global pool '{global_pool_name}' not found.",
                        "ERROR",
                    )
                    self.msg = f"No information found for the global pool named '{global_pool_name}'"
                    self.status = "failed"
                    return self.check_return_status()

                offset += page_limit
                continue

            # Process results for newer platform versions
            self.log(f"Looking for global pool with name '{global_pool_name}' in newer versions.", "DEBUG")
            global_pool_details = None
            if global_pool_name:
                # Search by name
                self.log(f"Attempting to find global pool with name '{global_pool_name}' in the current batch.", "DEBUG")
                global_pool_details = get_dict_result(all_global_pool_details, "name", global_pool_name)
                if global_pool_details:
                    self.log(f"Global pool found with name '{global_pool_name}': {global_pool_details}", "INFO")
            else:
                # Search by CIDR
                self.log(f"Global pool name is not provided. Attempting to match by CIDR: {global_pool_cidr}", "DEBUG")
                try:
                    cidr = self.split_cidr(global_pool_cidr)
                    subnet = cidr.get("network_prefix")
                    self.log(f"Extracted subnet '{subnet}' from provided CIDR '{global_pool_cidr}'.", "DEBUG")

                except Exception as e:
                    self.log(f"Error while splitting CIDR '{global_pool_cidr}': {e}", "ERROR")
                    self.msg = "Invalid CIDR format provided."
                    self.status = "failed"
                    return self.check_return_status()

                # Search for the global pool by subnet in nested addressSpace
                for item in all_global_pool_details:
                    if not isinstance(item, dict):
                        self.log(f"Skipping non-dictionary item: {item}", "DEBUG")
                        continue

                    address_space = item.get("addressSpace")
                    if isinstance(address_space, dict):
                        match = get_dict_result([address_space], "subnet", subnet)
                        if match:
                            global_pool_details = item
                            self.log(f"Global pool matched by subnet '{subnet}': {global_pool_details}", "INFO")
                            break

            if global_pool_details:
                global_pool_id = global_pool_details.get("id")
                self.log(f"Global pool found: {global_pool_details}", "INFO")
                self.log(f"Global Pool ID: {global_pool_id}", "INFO")
                return global_pool_id

            # Pagination end detection for newer versions
            if len(all_global_pool_details) < page_limit:
                self.log(
                    f"Reached last page with {len(all_global_pool_details)} record(s). "
                    f"Global pool '{global_pool_name}' not found.",
                    "ERROR",
                )
                self.msg = f"No information found for the global pool named '{global_pool_name}'"
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            offset += page_limit

    def get_want_global_pool_v1(self, global_ippool):
        """
        Get all the Global Pool information from playbook for Catalyst Center version < 2.3.7.9.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            global_ippool (dict) - Playbook global pool details containing IpAddressSpace,
            DHCP server IPs, DNS server IPs, IP pool name, IP pool CIDR, gateway, and type.

        Returns:
            self - The current object with updated desired Global Pool information.
        """

        # Initialize the desired Global Pool configuration
        want_global = {"settings": {"ippool": []}}
        want_ippool = want_global.get("settings").get("ippool")
        global_pool_index = 0
        for pool_details in global_ippool:
            pool_values = {
                "dhcpServerIps": pool_details.get("dhcp_server_ips"),
                "dnsServerIps": pool_details.get("dns_server_ips"),
                "ipPoolName": pool_details.get("name"),
                "ipPoolCidr": pool_details.get("cidr"),
                "gateway": pool_details.get("gateway"),
                "type": pool_details.get("pool_type"),
            }
            ip_address_space = pool_details.get("ip_address_space", "").upper()
            if ip_address_space == "IPV4":
                ip_address_space = "IPv4"
            elif ip_address_space == "IPV6":
                ip_address_space = "IPv6"

            if not ip_address_space:
                self.msg = "Missing required parameter 'ip_address_space' under global_pool_details."
                self.status = "failed"
                return self

            ip_address_space_list = ["IPv4", "IPv6"]
            if ip_address_space not in ip_address_space_list:
                self.msg = "The 'ip_address_space' under global_pool_details should be in the list: {0}".format(
                    ip_address_space_list
                )
                self.status = "failed"
                return self

            pool_values.update({"IpAddressSpace": ip_address_space})

            # Converting to the required format based on the existing Global Pool
            have_global_pool = self.have.get("globalPool")[global_pool_index]
            if not have_global_pool.get("exists"):
                self.log(f"Pool {pool_details.get('name')} does not exist. Applying defaults.", "DEBUG")
                if pool_values.get("dhcpServerIps") is None:
                    pool_values.update({"dhcpServerIps": []})
                if pool_values.get("dnsServerIps") is None:
                    pool_values.update({"dnsServerIps": []})
                if pool_values.get("IpAddressSpace") is None:
                    pool_values.update({"IpAddressSpace": ""})
                if pool_values.get("gateway") is None:
                    pool_values.update({"gateway": ""})
                if pool_values.get("type") is None:
                    pool_values.update({"type": "Generic"})
            else:
                self.log(f"Updating pool {pool_details.get('name')} with existing configuration.", "DEBUG")
                have_ippool = have_global_pool.get("details", {})

                # Copy existing Global Pool information if the desired configuration is not provided
                pool_values.update(
                    {
                        "IpAddressSpace": have_ippool.get("IpAddressSpace"),
                        "type": have_ippool.get("type"),
                        "ipPoolCidr": have_ippool.get("ipPoolCidr"),
                        "id": self.have.get("globalPool")[global_pool_index].get("id"),
                    }
                )
                for key in ["dhcpServerIps", "dnsServerIps", "gateway"]:
                    if (
                        pool_values.get(key) is None
                        and have_ippool.get(key) is not None
                    ):
                        pool_values[key] = have_ippool[key]
            want_ippool.append(pool_values)
            global_pool_index += 1

        self.log("Global pool playbook details: {0}".format(want_global), "DEBUG")
        self.want.update({"wantGlobal": want_global})
        self.msg = "Collecting the global pool details from the playbook"
        self.status = "success"
        return self

    def get_want_global_pool_v2(self, global_ippool):
        """
        Get all the Global Pool information from playbook for Catalyst Center version >= 2.3.7.9.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            global_ippool (dict) - Playbook global pool details containing IpAddressSpace,
            DHCP server IPs, DNS server IPs, IP pool name, IP pool CIDR, gateway, and type.

        Returns:
            self - The current object with updated desired Global Pool information.
        """
        self.log("Starting to process global pool details from the playbook.", "INFO")
        # Initialize the desired Global Pool cwant_global = {
        want_global = {
            "settings": {
                "ippool": []
            }
        }
        want_ippool = want_global.get("settings").get("ippool")
        global_pool_index = 0

        # Valid pool types enforced by API
        VALID_POOL_TYPES = ["Tunnel", "Generic"]

        # Process each pool in the global_ippool
        for pool_details in global_ippool:
            cidr_value = pool_details.get("cidr")
            if not cidr_value:
                self.log("Missing CIDR value in pool details. Skipping this pool.", "WARNING")
                continue
            cidr = self.split_cidr(cidr_value)
            if not cidr:
                self.log(f"Invalid CIDR value '{cidr_value}'. Skipping this pool.", "WARNING")
                continue
            subnet = cidr.get("network_prefix")
            prefix_len = cidr.get("prefix_length")

            # Normalize pool_type: first letter capitalized, rest lowercase
            user_pool_type = pool_details.get("pool_type", "")
            normalized_pool_type = (
                user_pool_type.capitalize() if isinstance(user_pool_type, str) else ""
            )

            if normalized_pool_type not in VALID_POOL_TYPES:
                self.log(
                    f"Invalid or missing pool_type '{user_pool_type}'. "
                    f"Valid options are {VALID_POOL_TYPES}.",
                    "ERROR"
                )
                self.msg = f"Invalid or missing pool_type '{user_pool_type}'. Valid options are {VALID_POOL_TYPES}."
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            pool_values = {
                "addressSpace": {
                    "subnet": subnet,
                    "prefixLength": prefix_len,
                    "gatewayIpAddress": pool_details.get("gateway"),
                    "dhcpServers":
                        pool_details.get("dhcp_server_ips"),
                    "dnsServers":
                        pool_details.get("dns_server_ips")
                },
                "name": pool_details.get("name"),
                "poolType": normalized_pool_type
            }
            self.log(f"Initial pool values: {pool_values}", "DEBUG")

            # Converting to the required format based on the existing Global Pool
            address_space = pool_values.get("addressSpace")
            if not self.have.get("globalPool")[global_pool_index].get("exists"):
                if address_space.get("dhcpServers") is None:
                    address_space.update({"dhcpServers": []})
                if address_space.get("dnsServers") is None:
                    address_space.update({"dnsServers": []})
                if address_space.get("gatewayIpAddress") is None:
                    address_space.pop("gatewayIpAddress")
                if pool_values.get("poolType") is None:
                    pool_values.update({"poolType": "Generic"})
            else:
                have_ippool = self.have.get("globalPool")[global_pool_index].get("details")
                if pool_details.get("prev_name"):
                    pool_values["prev_name"] = pool_details.get("prev_name")

                # Copy existing Global Pool information if the desired configuration is not provided
                pool_values["poolType"] = have_ippool.get("poolType")
                pool_values["id"] = self.have.get("globalPool")[global_pool_index].get("id")
                address_space.update({
                    "subnet": have_ippool.get("addressSpace").get("subnet"),
                    "prefixLength": have_ippool.get("addressSpace").get("prefixLength"),
                })
                for key in ["dhcpServers", "dnsServers", "gatewayIpAddress"]:
                    if address_space.get(key) is None and have_ippool.get("addressSpace").get(key) is not None:
                        address_space[key] = have_ippool.get("addressSpace").get(key)

            want_ippool.append(pool_values)
            self.log(f"Processed pool values: {pool_values}", "DEBUG")
            global_pool_index += 1

        self.log("Final desired global pool configuration: {}".format(self.pprint(want_global)), "DEBUG")
        self.want.update({"wantGlobal": want_global})
        self.msg = "Successfully collected global pool details from the playbook."
        self.status = "success"
        return self

    def get_want_reserve_pool_v1(self, reserve_pool):
        """
        Get all the Reserved Pool information from playbook for Catalyst Center version < 2.3.7.9.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            reserve_pool (dict) - Playbook reserved pool
            details containing various properties.

        Returns:
            self - The current object with updated desired Reserved Pool information.
        """

        want_reserve = []
        reserve_pool_index = 0
        for item in reserve_pool:
            pool_values = {
                "name": item.get("name"),
                "type": item.get("pool_type"),
                "ipv6AddressSpace": item.get("ipv6_address_space"),
                "ipv4GlobalPool": self.get_global_pool_cidr(
                    item.get("ipv4_global_pool"), item.get("ipv4_global_pool_name")
                ),
                "ipv4Prefix": item.get("ipv4_prefix"),
                "ipv4PrefixLength": item.get("ipv4_prefix_length"),
                "ipv4GateWay": item.get("ipv4_gateway"),
                "ipv4DhcpServers": item.get("ipv4_dhcp_servers"),
                "ipv4DnsServers": item.get("ipv4_dns_servers"),
                "ipv4Subnet": item.get("ipv4_subnet"),
                "ipv6Prefix": item.get("ipv6_prefix"),
                "ipv6PrefixLength": item.get("ipv6_prefix_length"),
                "ipv6GateWay": item.get("ipv6_gateway"),
                "ipv6DhcpServers": item.get("ipv6_dhcp_servers"),
                "ipv6Subnet": item.get("ipv6_subnet"),
                "ipv6DnsServers": item.get("ipv6_dns_servers"),
                "ipv4TotalHost": item.get("ipv4_total_host"),
                "ipv6TotalHost": item.get("ipv6_total_host"),
                "slaacSupport": item.get("slaac_support"),
            }
            # Check for missing required parameters in the playbook
            if pool_values.get("ipv6AddressSpace") is True:
                pool_values.update(
                    {
                        "ipv6GlobalPool": self.get_global_pool_cidr(
                            item.get("ipv6_global_pool"),
                            item.get("ipv6_global_pool_name"),
                        )
                    }
                )

            if not pool_values.get("name"):
                self.msg = "Missing required parameter 'name' in reserve_pool_details '{0}' element".format(
                    reserve_pool_index + 1
                )
                self.status = "failed"
                return self

            if pool_values.get("ipv4Prefix") is True:
                if (
                    pool_values.get("ipv4Subnet") is None
                    and pool_values.get("ipv4TotalHost") is None
                ):
                    self.msg = (
                        "Failed to add IPv4 in reserve_pool_details '{0}'. ".format(
                            reserve_pool_index + 1
                        )
                        + "Required parameters 'ipv4_subnet' or 'ipv4_total_host' are missing."
                    )
                    self.status = "failed"
                    return self

            if pool_values.get("ipv6Prefix") is True:
                if (
                    pool_values.get("ipv6Subnet") is None
                    and pool_values.get("ipv6TotalHost") is None
                ):
                    self.msg = (
                        "Failed to add IPv6 in reserve_pool_details '{0}'. ".format(
                            reserve_pool_index + 1
                        )
                        + "Required parameters 'ipv6_subnet' or 'ipv6_total_host' are missing."
                    )
                    self.status = "failed"
                    return self

            self.log(
                "Reserved IP pool playbook details: {0}".format(pool_values), "DEBUG"
            )

            # If there are no existing Reserved Pool details, validate and set defaults
            if not self.have.get("reservePool")[reserve_pool_index].get("details"):
                self.log(f"No existing details found for reserved pool at index {reserve_pool_index + 1}. Applying defaults.", "DEBUG")
                if not pool_values.get("ipv4GlobalPool"):
                    self.msg = "missing parameter 'ipv4GlobalPool' in reserve_pool_details '{0}' element".format(
                        reserve_pool_index + 1
                    )
                    self.status = "failed"
                    return self

                if pool_values.get("ipv4Prefix") and not pool_values.get(
                    "ipv4PrefixLength"
                ):
                    self.msg = "missing parameter 'ipv4_prefix_length' in reserve_pool_details '{0}' element".format(
                        reserve_pool_index + 1
                    )
                    self.status = "failed"
                    return self

                if pool_values.get("type") is None:
                    pool_values.update({"type": "Generic"})
                if pool_values.get("ipv4DhcpServers") is None:
                    pool_values.update({"ipv4DhcpServers": []})
                if pool_values.get("ipv4DnsServers") is None:
                    pool_values.update({"ipv4DnsServers": []})
                if pool_values.get("ipv6AddressSpace") is None:
                    pool_values.update({"ipv6AddressSpace": False})
                if pool_values.get("ipv4TotalHost") is None:
                    del pool_values["ipv4TotalHost"]
                if pool_values.get("ipv6AddressSpace") is True:
                    pool_values.update({"ipv6AddressSpace": True})
                else:
                    del pool_values["ipv6Prefix"]

            else:
                keys_to_delete = [
                    "type",
                    "ipv4GlobalPool",
                    "ipv4Prefix",
                    "ipv4PrefixLength",
                    "ipv4TotalHost",
                    "ipv4Subnet",
                    "slaacSupport",
                ]
                for key in keys_to_delete:
                    if key in pool_values:
                        del pool_values[key]

                copy_pool_values = copy.deepcopy(pool_values)
                for item in copy_pool_values:
                    if pool_values.get(item) is None:
                        del pool_values[item]

            if not pool_values.get("ipv6AddressSpace"):
                keys_to_check = [
                    "ipv6PrefixLength",
                    "ipv6GateWay",
                    "ipv6DhcpServers",
                    "ipv6DnsServers",
                    "ipv6TotalHost",
                    "ipv6Subnet",
                ]
                for key in keys_to_check:
                    if key in pool_values:
                        del pool_values[key]

            want_reserve.append(pool_values)
            reserve_pool_index += 1

        self.want.update({"wantReserve": want_reserve})
        self.log("Reserved Pool details: {0}".format(want_reserve), "INFO")
        self.msg = "Collected the reserved pool details from the playbook"
        self.status = "success"
        return self

    def get_prefix_length_from_total_hosts(self, total_hosts, ip_version="IPv4"):
        """
        Calculates the IP prefix length from the total number of addresses in the pool
        for both IPv4 and IPv6. Updates status and message on failure.

        Args:
            self: The object containing `msg` and `status`.
            total_hosts (int or str): Total number of addresses in the pool.
            ip_version (str): Either 'IPv4' or 'IPv6'. Default is 'IPv4'.

        Returns:
            int or self: Prefix length on success, or self on failure.
        """
        self.log(f"Calculating prefix length for total_hosts={total_hosts}, ip_version={ip_version}.", "INFO")

        try:
            total_hosts = int(total_hosts)
            self.log(f"Parsed total_hosts as integer: {total_hosts}.", "DEBUG")
        except (ValueError, TypeError):
            self.msg = f"Invalid total_hosts '{total_hosts}' for {ip_version}. Total hosts must be a number."
            self.log(self.msg, "WARNING")
            self.set_operation_result("failed", False, self.msg,
                                      "ERROR", self.global_pool_response).check_return_status()

        max_bits = 32 if ip_version == "IPv4" else 128
        max_addresses = 2 ** max_bits
        self.log(f"Max addresses for {ip_version}: {max_addresses}.", "DEBUG")

        # Validate total_hosts
        if total_hosts <= 0 or total_hosts > (max_addresses - 2 if ip_version == "IPv4" else max_addresses):
            self.msg = (
                f"Invalid total_hosts '{total_hosts}' for {ip_version}. "
                f"Total hosts must be greater than 0 and not exceed {max_addresses}."
            )
            self.log(self.msg, "WARNING")
            self.set_operation_result("failed", False, self.msg,
                                      "ERROR", self.global_pool_response).check_return_status()

        # Calculate host bits (add 2 for network + broadcast in IPv4)
        adjustment = 2 if ip_version == "IPv4" else 0
        host_bits = math.ceil(math.log2(total_hosts))
        prefix_length = max_bits - host_bits

        self.log(
            f"Calculated prefix length for total_hosts={total_hosts}, ip_version={ip_version}: {prefix_length}.",
            "INFO",
        )
        return prefix_length

    def get_want_reserve_pool_v2(self, reserve_pool):
        """
        Get all the Reserved Pool information from playbook for Catalyst Center version >= 2.3.7.9.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            reserve_pool (dict) - Playbook reserved pool
            details containing various properties.

        Returns:
            self - The current object with updated desired Reserved Pool information.
        """
        self.log("Starting to process reserved pool details from the playbook.", "INFO")

        want_reserve = []
        reserve_pool_index = 0

        # Process each reserved pool
        for item in reserve_pool:
            self.log(f"Processing reserved pool index {reserve_pool_index + 1}: {item}", "DEBUG")

            # Prepare the IPv4 address space dictionary
            ipv4_dhcp_servers = item.get("ipv4_dhcp_servers")
            ipv4_global_pool_id = self.get_global_pool_cidr(item.get("ipv4_global_pool"),
                                                            item.get("ipv4_global_pool_name"))
            ipv4_prefix_length = item.get("ipv4_prefix_length")
            ipv4_total_addresses = item.get("ipv4_total_host")
            ipv4_gateway = item.get("ipv4_gateway")
            ipv4_dhcp_servers = item.get("ipv4_dhcp_servers")
            ipv4_dns_servers = item.get("ipv4_dns_servers")
            ipv4_subnet = item.get("ipv4_subnet")
            slaac_support = item.get("slaac_support")
            if ipv4_prefix_length is None and not ipv4_total_addresses:
                self.msg = "Failed to add IPv4 in reserve_pool_details '{0}'. ".format(reserve_pool_index + 1) + \
                           "At least one of 'ipv4_prefix_length' or 'ipv4_total_host' must be provided."
                self.status = "failed"
                return self

            if ipv4_prefix_length is None and ipv4_total_addresses:
                self.log(f"Calculating prefix length for IPv4 total addresses: {ipv4_total_addresses}.", "DEBUG")
                ipv4_prefix_length = self.get_prefix_length_from_total_hosts(ipv4_total_addresses, "IPv4")
            ipv4_address_space = {
                "subnet": ipv4_subnet,
                "prefixLength": ipv4_prefix_length,
                "globalPoolId": ipv4_global_pool_id
            }

            missing_params = []
            if not ipv4_subnet:
                missing_params.append("ipv4_subnet")
            if not ipv4_global_pool_id:
                missing_params.append("ipv4_global_pool_id")
            if not ipv4_prefix_length:
                missing_params.append("ipv4_prefix_length")

            if missing_params:
                self.msg = (
                    "Failed to add IPv4 in reserve_pool_details '{0}'. "
                    "Missing or invalid required parameter(s): {1}. "
                    "These parameters are mandatory for version {2} and above."
                ).format(reserve_pool_index + 1, ", ".join(missing_params), self.dnac_version)
                self.status = "failed"
                return self

            # Conditionally add gateway and slaac_support
            if ipv4_gateway is not None:
                ipv4_address_space["gatewayIpAddress"] = ipv4_gateway

            if slaac_support:
                ipv4_address_space["slaacSupport"] = slaac_support

            # Conditionally add DHCP  and dns servers
            if ipv4_dhcp_servers:
                ipv4_address_space["dhcpServers"] = ipv4_dhcp_servers

            if ipv4_dhcp_servers:
                ipv4_address_space["dnsServers"] = ipv4_dns_servers

            # Conditionally add address statistics
            ipv4_total_addresses = item.get("ipv4_total_addresses")
            if ipv4_total_addresses is not None:
                ipv4_address_space["totalAddresses"] = ipv4_total_addresses

            ipv4_unassignable_addresses = item.get("ipv4_unassignable_addresses")
            if ipv4_unassignable_addresses is not None:
                ipv4_address_space["unassignableAddresses"] = ipv4_unassignable_addresses

            ipv4_assigned_addresses = item.get("ipv4_assigned_addresses")
            if ipv4_assigned_addresses is not None:
                ipv4_address_space["assignedAddresses"] = ipv4_assigned_addresses

            ipv4_default_assigned_addresses = item.get("ipv4_default_assigned_addresses")
            if ipv4_default_assigned_addresses is not None:
                ipv4_address_space["defaultAssignedAddresses"] = ipv4_default_assigned_addresses

            pool_values = {
                "ipV4AddressSpace": ipv4_address_space,
                "name": item.get("name"),
                "poolType": item.get("pool_type"),
                "siteName": item.get("site_name")
            }
            self.log(f"Processed IPv4 address space: {ipv4_address_space}", "DEBUG")

            # Process IPv6 details if enabled
            ipv6_address = item.get("ipv6_address_space")
            if ipv6_address is not None and not isinstance(ipv6_address, bool):
                self.msg = "Invalid value for 'ipv6_address_space' parameter: '{0}'. Expected boolean value (True or False), but received {1}.".format(
                    ipv6_address, type(ipv6_address).__name__)
                self.log("IPv6 address space validation failed: {0}".format(self.msg), "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            # Check for missing required parameters in the playbook
            if ipv6_address is True:
                self.log(f"Processing IPv6 details for reserve pool index {reserve_pool_index + 1}.", "DEBUG")
                ipv6_subnet = item.get("ipv6_subnet")
                ipv6_prefix_length = item.get("ipv6_prefix_length")
                ipv6_gateway = item.get("ipv6_gateway")
                ipv6_dhcp_servers = item.get("ipv6_dhcp_servers")
                ipv6_dns_servers = item.get("ipv6_dns_servers")
                ipv6_total_addresses = item.get("ipv6_total_host")
                ipv6_unassignable_addresses = item.get("ipv6_unassignable_addresses")
                ipv6_assigned_addresses = item.get("ipv6_assigned_addresses")
                ipv6_default_assigned_addresses = item.get("ipv6_default_assigned_addresses")
                ipv6_global_pool_id = self.get_global_pool_cidr(item.get("ipv6_global_pool"),
                                                                item.get("ipv6_global_pool_name"))
                if ipv6_prefix_length is None and not ipv6_total_addresses:
                    self.msg = (
                        "Failed to add IPv6 in reserve_pool_details '{0}'. ".format(reserve_pool_index + 1) +
                        "At least one of 'ipv6_prefix_length' or 'ipv6_total_host' must be provided."
                    )
                    self.status = "failed"
                    return self

                if ipv6_prefix_length is None and ipv6_total_addresses:
                    self.log(f"Calculating prefix length for IPv6 total addresses: {ipv6_total_addresses}.", "DEBUG")
                    ipv6_prefix_length = self.get_prefix_length_from_total_hosts(ipv6_total_addresses, "IPv6")

                ipv6_address_space = {
                    "subnet": ipv6_subnet,
                    "prefixLength": ipv6_prefix_length,
                    "globalPoolId": ipv6_global_pool_id
                }

                if not (ipv6_prefix_length and ipv6_subnet and ipv6_global_pool_id):
                    self.msg = "Failed to add IPv6 in reserve_pool_details '{0}'. ".format(reserve_pool_index + 1) + \
                               "Required parameters 'ipv6_subnet' or 'ipv6_global_pool_id' or 'ipv6_prefix_length' are missing."
                    self.status = "failed"
                    return self

                if ipv6_gateway:
                    ipv6_address_space["gatewayIpAddress"] = ipv6_gateway

                if ipv6_dhcp_servers:
                    ipv6_address_space["dhcpServers"] = ipv6_dhcp_servers

                if ipv6_dns_servers:
                    ipv6_address_space["dnsServers"] = ipv6_dns_servers

                if ipv6_total_addresses:
                    ipv6_address_space["totalAddresses"] = ipv6_total_addresses

                if ipv6_unassignable_addresses:
                    ipv6_address_space["unassignableAddresses"] = ipv6_unassignable_addresses

                if ipv6_assigned_addresses:
                    ipv6_address_space["assignedAddresses"] = ipv6_assigned_addresses

                if ipv6_default_assigned_addresses:
                    ipv6_address_space["defaultAssignedAddresses"] = ipv6_default_assigned_addresses

                if slaac_support and ipv6_prefix_length == 64:
                    ipv6_address_space["slaacSupport"] = slaac_support

                if ipv6_address_space:
                    pool_values["ipV6AddressSpace"] = ipv6_address_space

            if not pool_values.get("name"):
                self.msg = "Missing required parameter 'name' in reserve_pool_details '{0}' element" \
                           .format(reserve_pool_index + 1)
                self.status = "failed"
                return self

            self.log("Reserved IP pool playbook details: {0}".format(self.pprint(pool_values)), "DEBUG")

            # If there are no existing Reserved Pool details, validate and set defaults
            if not self.have.get("reservePool")[reserve_pool_index].get("details"):
                if pool_values.get("poolType") is None:
                    self.log(f"Setting default 'poolType' to 'Generic' for reserved pool at index {reserve_pool_index + 1}.", "DEBUG")
                    pool_values.update({"poolType": "Generic"})
            else:
                self.log(f"Existing details found for reserved pool at index {reserve_pool_index + 1}. Removing unnecessary fields.", "DEBUG")
                keys_to_delete = [
                    "totalAddresses",
                    "unassignableAddresses",
                    "assignedAddresses",
                    "defaultAssignedAddresses"
                ]

                for ip_version in ["ipV4AddressSpace", "ipV6AddressSpace"]:
                    if ip_version in pool_values:
                        for key in keys_to_delete:
                            if key in pool_values[ip_version]:
                                self.log(f"Removing key '{key}' from {ip_version} for reserved pool at index {reserve_pool_index + 1}.", "DEBUG")
                                del pool_values[ip_version][key]

                copy_pool_values = copy.deepcopy(pool_values)
                for item in copy_pool_values:
                    if pool_values.get(item) is None:
                        self.log(f"Removing empty key '{item}' from reserved pool at index {reserve_pool_index + 1}.", "DEBUG")
                        del pool_values[item]

            self.log(f"Final processed pool values for index {reserve_pool_index + 1}: {pool_values}", "DEBUG")
            want_reserve.append(pool_values)
            reserve_pool_index += 1

        self.want.update({"wantReserve": want_reserve})
        self.log(f"Final Reserved Pool details: {self.pprint(want_reserve)}", "INFO")
        self.msg = "Successfully collected reserved pool details from the playbook."
        self.status = "success"
        return self

    def get_want_network(self, network_management_details):
        """
        Get all the Network related information from playbook
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            network_management_details (dict) - Playbook network
            details containing various network settings.

        Returns:
            self - The current object with updated desired Network-related information.
        """
        all_network_management_details = []
        network_management_index = 0
        for item in network_management_details:
            item = item.get("settings")
            want_network = {
                "settings": {
                    "dhcpServer": {},
                    "dnsServer": {},
                    "snmpServer": {},
                    "syslogServer": {},
                    "netflowcollector": {},
                    "ntpServer": {},
                    "timezone": "",
                    "messageOfTheday": {},
                    "network_aaa": {},
                    "client_and_endpoint_aaa": {}
                }
            }
            want_network_settings = want_network.get("settings")
            self.log("Current state (have): {0}".format(self.have), "DEBUG")
            have_network_details = self.have.get("network")[network_management_index].get("net_details").get("settings")
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") < 0:
                if item.get("dhcp_server") is not None:
                    want_network_settings.update({
                        "dhcpServer": item.get("dhcp_server")
                    })
                else:
                    del want_network_settings["dhcpServer"]

                if item.get("ntp_server") is not None:
                    want_network_settings.update({"ntpServer": item.get("ntp_server")})
                else:
                    del want_network_settings["ntpServer"]

                have_timezone = (
                    self.have.get("network")[network_management_index]
                    .get("net_details")
                    .get("settings")
                    .get("timezone")
                )
                if item.get("timezone") is not None:
                    want_network_settings["timezone"] = item.get("timezone")
                elif have_timezone is not None:
                    want_network_settings["timezone"] = have_timezone
                else:
                    want_network_settings["timezone"] = "GMT"

                dns_server = item.get("dns_server")
                if dns_server is not None:
                    if dns_server.get("domain_name") is not None:
                        want_network_settings.get("dnsServer").update(
                            {"domainName": dns_server.get("domain_name")}
                        )

                    if dns_server.get("primary_ip_address") is not None:
                        want_network_settings.get("dnsServer").update(
                            {"primaryIpAddress": dns_server.get("primary_ip_address")}
                        )

                    if dns_server.get("secondary_ip_address") is not None:
                        want_network_settings.get("dnsServer").update(
                            {
                                "secondaryIpAddress": dns_server.get(
                                    "secondary_ip_address"
                                )
                            }
                        )
                else:
                    del want_network_settings["dnsServer"]

                snmp_server = item.get("snmp_server")
                if snmp_server is not None:
                    if snmp_server.get("configure_dnac_ip") is not None:
                        want_network_settings.get("snmpServer").update(
                            {"configureDnacIP": snmp_server.get("configure_dnac_ip")}
                        )
                    if snmp_server.get("ip_addresses") is not None:
                        want_network_settings.get("snmpServer").update(
                            {"ipAddresses": snmp_server.get("ip_addresses")}
                        )
                else:
                    del want_network_settings["snmpServer"]

                syslog_server = item.get("syslog_server")
                if syslog_server is not None:
                    if syslog_server.get("configure_dnac_ip") is not None:
                        want_network_settings.get("syslogServer").update(
                            {"configureDnacIP": syslog_server.get("configure_dnac_ip")}
                        )
                    if syslog_server.get("ip_addresses") is not None:
                        want_network_settings.get("syslogServer").update(
                            {"ipAddresses": syslog_server.get("ip_addresses")}
                        )
                else:
                    del want_network_settings["syslogServer"]

                netflow_collector = item.get("netflow_collector")
                if netflow_collector is not None:
                    if netflow_collector.get("ip_address") is not None:
                        want_network_settings.get("netflowcollector").update(
                            {"ipAddress": netflow_collector.get("ip_address")}
                        )
                    if netflow_collector.get("port") is not None:
                        want_network_settings.get("netflowcollector").update(
                            {"port": netflow_collector.get("port")}
                        )
                else:
                    del want_network_settings["netflowcollector"]

                message_of_the_day = item.get("message_of_the_day")
                if message_of_the_day is not None:
                    retain_existing_banner = message_of_the_day.get(
                        "retain_existing_banner"
                    )
                    if retain_existing_banner is not None:
                        if retain_existing_banner is True:
                            want_network_settings.get("messageOfTheday").update(
                                {"retainExistingBanner": "true"}
                            )
                        else:
                            want_network_settings.get("messageOfTheday").update(
                                {"retainExistingBanner": "false"}
                            )
                    if message_of_the_day.get("banner_message") is not None:
                        want_network_settings.get("messageOfTheday").update(
                            {"bannerMessage": message_of_the_day.get("banner_message")}
                        )
                else:
                    del want_network_settings["messageOfTheday"]

                server_types = ["AAA", "ISE"]
                protocol_types = ["RADIUS", "TACACS"]
                network_aaa = item.get("network_aaa")
                if network_aaa:
                    server_type = network_aaa.get("server_type")
                    if server_type:
                        want_network_settings.get("network_aaa").update(
                            {"servers": server_type}
                        )
                    else:
                        self.msg = "The 'server_type' is required under network_aaa."
                        self.status = "failed"
                        return self

                    if server_type not in server_types:
                        self.msg = "The 'server_type' in the network_aaa should be in {0}".format(
                            server_types
                        )
                        self.status = "failed"
                        return self

                    primary_server_address = network_aaa.get("primary_server_address")
                    if primary_server_address:
                        want_network_settings.get("network_aaa").update(
                            {"network": primary_server_address}
                        )
                    else:
                        self.msg = "Missing required parameter 'primary_server_address' in network_aaa."
                        self.status = "failed"
                        return self

                    if server_type == "ISE":
                        pan_address = network_aaa.get("pan_address")
                        if pan_address:
                            want_network_settings.get("network_aaa").update(
                                {"ipAddress": pan_address}
                            )
                        else:
                            self.msg = "Missing required parameter 'pan_address' for ISE server in network_aaa."
                            self.status = "failed"
                            return self
                    else:
                        secondary_server_address = network_aaa.get(
                            "secondary_server_address"
                        )
                        if secondary_server_address:
                            want_network_settings.get("network_aaa").update(
                                {"ipAddress": secondary_server_address}
                            )

                    protocol = network_aaa.get("protocol")
                    if protocol:
                        want_network_settings.get("network_aaa").update(
                            {"protocol": protocol}
                        )
                    else:
                        want_network_settings.get("network_aaa").update(
                            {"protocol": "RADIUS"}
                        )

                    if protocol not in protocol_types:
                        self.msg = (
                            "The 'protocol' in the network_aaa should be in {0}".format(
                                protocol_types
                            )
                        )
                        self.status = "failed"
                        return self

                    shared_secret = network_aaa.get("shared_secret")
                    if shared_secret is not None:
                        if len(shared_secret) < 4:
                            self.msg = "The 'shared_secret' length in 'network_aaa' should be greater than or equal to 4."
                            self.status = "failed"
                            return self

                        want_network_settings.get("network_aaa").update(
                            {"sharedSecret": shared_secret}
                        )
                else:
                    del want_network_settings["network_aaa"]

                client_and_endpoint_aaa = item.get("client_and_endpoint_aaa")
                if client_and_endpoint_aaa:
                    server_type = client_and_endpoint_aaa.get("server_type")
                    if server_type:
                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"servers": server_type}
                        )
                    else:
                        self.msg = "The 'server_type' is required under client_and_endpoint_aaa."
                        self.status = "failed"
                        return self

                    if server_type not in server_types:
                        self.msg = "The 'server_type' in the client_and_endpoint_aaa should be in {0}".format(
                            server_types
                        )
                        self.status = "failed"
                        return self

                    primary_server_address = client_and_endpoint_aaa.get(
                        "primary_server_address"
                    )
                    if primary_server_address:
                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"network": primary_server_address}
                        )
                    else:
                        self.msg = "Missing required parameter 'primary_server_address' in client_and_endpoint_aaa."
                        self.status = "failed"
                        return self

                    if server_type == "ISE":
                        pan_address = client_and_endpoint_aaa.get("pan_address")
                        if pan_address:
                            want_network_settings.get("client_and_endpoint_aaa").update(
                                {"ipAddress": pan_address}
                            )
                        else:
                            self.msg = "Missing required parameter 'pan_address' for ISE server in client_and_endpoint_aaa."
                            self.status = "failed"
                            return self
                    else:
                        secondary_server_address = client_and_endpoint_aaa.get(
                            "secondary_server_address"
                        )
                        if secondary_server_address:
                            want_network_settings.get("client_and_endpoint_aaa").update(
                                {"ipAddress": secondary_server_address}
                            )

                    protocol = client_and_endpoint_aaa.get("protocol")
                    if protocol:
                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"protocol": protocol}
                        )
                    else:
                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"protocol": "RADIUS"}
                        )

                    if protocol not in protocol_types:
                        self.msg = "The 'protocol' in the client_and_endpoint_aaa should be in {0}".format(
                            protocol_types
                        )
                        self.status = "failed"
                        return self

                    shared_secret = client_and_endpoint_aaa.get("shared_secret")
                    if shared_secret is not None:
                        if len(shared_secret) < 4:
                            self.msg = "The 'shared_secret' length in 'client_and_endpoint_aaa' should be greater than or equal to 4."
                            self.status = "failed"
                            return self

                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"sharedSecret": shared_secret}
                        )
                else:
                    del want_network_settings["client_and_endpoint_aaa"]

                network_aaa = want_network_settings.get("network_aaa")
                client_and_endpoint_aaa = want_network_settings.get(
                    "client_and_endpoint_aaa"
                )
                if (
                    network_aaa
                    and client_and_endpoint_aaa
                    and network_aaa.get("sharedSecret")
                    and client_and_endpoint_aaa.get("sharedSecret")
                    and network_aaa.get("sharedSecret")
                    != client_and_endpoint_aaa.get("sharedSecret")
                ):
                    self.msg = "The 'shared_secret' of 'network_aaa' and 'client_and_endpoint_aaa' should be same."
                    self.status = "failed"
                    return self

                all_network_management_details.append(want_network)
                network_management_index += 1
            else:
                if item.get("dhcp_server") == {}:
                    self.want.update({"settings": {"dhcpServer": {}}})
                elif item.get("dhcp_server") is not None:
                    want_network_settings.update(
                        {"dhcpServer": {"servers": item.get("dhcp_server")}}
                    )
                else:
                    del want_network_settings["dhcpServer"]

                ntp_servers = item.get("ntp_server")

                if ntp_servers:
                    self.log(
                        "Validating 'ntp_server' input: {0}".format(ntp_servers),
                        "DEBUG",
                    )

                    if isinstance(ntp_servers, list) and any(
                        ntp_servers
                    ):  # Ensure it's a list with at least one non-empty value
                        want_network_settings["ntpServer"] = {"servers": ntp_servers}
                        self.log(
                            "Updated 'want_network_settings' with NTP servers: {0}".format(
                                ntp_servers
                            ),
                            "INFO",
                        )
                    else:
                        self.msg = (
                            "'ntp_servers' attribute must be a list containing at least one valid IPv4 or IPv6 address. "
                            "Provided value: '{0}'.".format(ntp_servers)
                        )
                        self.log(self.msg, "CRITICAL")
                        self.status = "failed"
                        return self.check_return_status()
                elif ntp_servers == {}:
                    want_network_settings["ntpServer"] = {}
                else:
                    self.log(
                        "'ntp_server' not provided. Removing 'ntpServer' from 'want_network_settings'.",
                        "DEBUG",
                    )
                    want_network_settings.pop(
                        "ntpServer", None
                    )  # Use pop to avoid KeyError if key doesn't exist

                if item.get("timezone") == {}:
                    want_network_settings["timezone"] = {}
                elif item.get("timezone") is not None:
                    want_network_settings.update(
                        {"timezone": {"identifier": item.get("timezone")}}
                    )
                else:
                    del want_network_settings["timezone"]

                dns_server = item.get("dns_server")
                if dns_server is not None:
                    if dns_server.get("domain_name") is not None:
                        want_network_settings.get("dnsServer").update(
                            {"domainName": dns_server.get("domain_name")}
                        )

                    if dns_server.get("primary_ip_address") is not None:
                        want_network_settings.get("dnsServer").update(
                            {"primaryIpAddress": dns_server.get("primary_ip_address")}
                        )

                    if dns_server.get("secondary_ip_address") is not None:
                        want_network_settings.get("dnsServer").update(
                            {
                                "secondaryIpAddress": dns_server.get(
                                    "secondary_ip_address"
                                )
                            }
                        )
                else:
                    del want_network_settings["dnsServer"]

                if item.get("dns_server") == {}:
                    self.want.update({"settings": {"dnsServer": {}}})

                snmp_server = item.get("snmp_server")
                if snmp_server is not None:
                    self.log("Processing SNMP server configuration...", "DEBUG")

                    # Check and update configure_dnac_ip
                    configure_dnac_ip = snmp_server.get("configure_dnac_ip")
                    if configure_dnac_ip is not None:
                        self.log(
                            "Updating 'useBuiltinTrapServer' with provided configure_dnac_ip: {0}".format(
                                configure_dnac_ip
                            ),
                            "INFO",
                        )
                        want_network_settings.get("snmpServer").update(
                            {"useBuiltinTrapServer": configure_dnac_ip}
                        )
                    else:
                        have_configure_dnac_ip = have_network_details.get(
                            "snmpServer", {}
                        ).get("useBuiltinTrapServer")
                        if have_configure_dnac_ip is not None:
                            self.log(
                                "Retaining existing 'useBuiltinTrapServer' from current network details: {0}".format(
                                    have_configure_dnac_ip
                                ),
                                "INFO",
                            )
                            want_network_settings.get("snmpServer").update(
                                {"useBuiltinTrapServer": have_configure_dnac_ip}
                            )
                        else:
                            self.log(
                                "'useBuiltinTrapServer' not found in provided or existing configurations",
                                "DEBUG",
                            )

                    # Check and update ip_addresses
                    ip_addresses = snmp_server.get("ip_addresses")
                    if ip_addresses is not None:
                        self.log(
                            "Updating 'externalTrapServers' with provided IP addresses: {0}".format(
                                ip_addresses
                            ),
                            "INFO",
                        )
                        want_network_settings.get("snmpServer").update(
                            {"externalTrapServers": ip_addresses}
                        )
                    else:
                        have_ip_addresses = have_network_details.get(
                            "snmpServer", {}
                        ).get("externalTrapServers")
                        if have_ip_addresses is not None:
                            self.log(
                                "Retaining existing 'externalTrapServers' from current network details: {0}".format(
                                    have_ip_addresses
                                ),
                                "INFO",
                            )
                            want_network_settings.get("snmpServer").update(
                                {"externalTrapServers": have_ip_addresses}
                            )
                        else:
                            self.log(
                                "'externalTrapServers' not found in provided or existing configurations",
                                "DEBUG",
                            )
                elif have_network_details.get("snmpServer") != [""]:
                    self.log(
                        "No SNMP server provided; using existing SNMP server configuration",
                        "INFO",
                    )

                    # If snmpServer is not defined in item, use have_network_details
                    want_network_settings["snmpServer"] = have_network_details.get(
                        "snmpServer"
                    )
                else:
                    self.log(
                        "No SNMP server provided and no existing SNMP configuration found; setting to None",
                        "INFO",
                    )
                    want_network_settings["snmpServer"] = None

                syslog_server = item.get("syslog_server")
                if syslog_server is not None:
                    self.log("Processing Syslog server configuration...", "DEBUG")

                    # Retrieve existing syslog details
                    have_syslog_server = have_network_details.get("syslogServer", {})
                    have_configure_dnac_ip = have_syslog_server.get(
                        "useBuiltinSyslogServer"
                    )
                    have_ip_addresses = have_syslog_server.get("externalSyslogServers")

                    # Update configure_dnac_ip if provided, else fallback to existing value
                    configure_dnac_ip = syslog_server.get("configure_dnac_ip")
                    if configure_dnac_ip is not None:
                        self.log(
                            "Updating 'useBuiltinSyslogServer' with provided configure_dnac_ip: {0}".format(
                                configure_dnac_ip
                            ),
                            "INFO",
                        )
                        want_network_settings.get("syslogServer").update(
                            {"useBuiltinSyslogServer": configure_dnac_ip}
                        )
                    elif have_configure_dnac_ip is not None:
                        self.log(
                            "Retaining existing 'useBuiltinSyslogServer': {0}".format(
                                have_configure_dnac_ip
                            ),
                            "INFO",
                        )
                        want_network_settings.get("syslogServer").update(
                            {"useBuiltinSyslogServer": have_configure_dnac_ip}
                        )
                    else:
                        self.log(
                            "'useBuiltinSyslogServer' not found in provided or existing configurations",
                            "DEBUG",
                        )

                    # Update ip_addresses if provided, else fallback to existing value
                    ip_addresses = syslog_server.get("ip_addresses")
                    if ip_addresses is not None:
                        self.log(
                            "Updating 'externalSyslogServers' with provided IP addresses: {0}".format(
                                ip_addresses
                            ),
                            "INFO",
                        )
                        want_network_settings.get("syslogServer").update(
                            {"externalSyslogServers": ip_addresses}
                        )
                    elif have_ip_addresses is not None:
                        self.log(
                            "Retaining existing 'externalSyslogServers': {0}".format(
                                have_ip_addresses
                            ),
                            "INFO",
                        )
                        want_network_settings.get("syslogServer").update(
                            {"externalSyslogServers": have_ip_addresses}
                        )
                    else:
                        self.log(
                            "'externalSyslogServers' not found in provided or existing configurations",
                            "DEBUG",
                        )
                elif have_network_details.get("syslogServer") != [""]:
                    self.log(
                        "No Syslog server provided; using existing Syslog server configuration",
                        "INFO",
                    )

                    # Use have value if syslogServer is not defined in the item
                    want_network_settings["syslogServer"] = have_network_details.get(
                        "syslogServer"
                    )
                else:
                    self.log(
                        "No Syslog server provided and no existing configuration found; setting to None",
                        "INFO",
                    )

                    # Set to None if no value exists in item or have
                    want_network_settings["syslogServer"] = None

                netflow_collector_data = item.get("netflow_collector")
                if netflow_collector_data is not None:
                    have_netflowcollector = have_network_details.get(
                        "netflowcollector", {}
                    ).get("collector", {})
                    netflow_collector = want_network_settings.get("netflowcollector")
                    netflow_collector["collector"] = {}

                    # Handle collectorType
                    collector_type = netflow_collector_data.get("collector_type")

                    # Check if collector_type is None and assign from 'have' if so
                    if collector_type is None:
                        collector_type = have_netflowcollector.get("collectorType")
                        if collector_type != "":
                            netflow_collector["collector"][
                                "collectorType"
                            ] = collector_type
                        else:
                            netflow_collector["collector"]["collectorType"] = None
                        self.log(
                            "Assigned collectorType from 'have': {}".format(
                                collector_type
                            ),
                            "INFO",
                        )

                    if (
                        collector_type == "TelemetryBrokerOrUDPDirector"
                        or collector_type == "Telemetry_broker_or_UDP_director"
                    ):
                        netflow_collector["collector"][
                            "collectorType"
                        ] = "TelemetryBrokerOrUDPDirector"

                        # Ensure mandatory fields for TelemetryBrokerOrUDPDirector
                        ip_address = netflow_collector_data.get("ip_address")
                        port = netflow_collector_data.get("port")

                        if port:
                            port = str(port)

                        if not ip_address or not port:

                            # Attempt to retrieve values from `have`

                            if (
                                not ip_address
                                and have_netflowcollector.get("ip_address") != ""
                            ):
                                ip_address = have_netflowcollector.get("ip_address")

                            if not port and have_netflowcollector.get("port") != "":
                                port = have_netflowcollector.get("port")

                            # Log the values after attempting to assign from `have`
                            self.log(
                                "Assigned missing 'ip_address' and 'port' from 'have': ip_address={0}, port={1}".format(
                                    ip_address, port
                                ),
                                "DEBUG",
                            )

                            # If still missing, log failure and set status
                            if not ip_address or not port:
                                self.msg = (
                                    "The 'ip_address' and 'port' are mandatory when 'collector_type' is "
                                    "'Telemetry_broker_or_UDP_director', and values could not be fetched from 'have'."
                                )
                                self.status = "failed"
                                return self

                        if port:
                            if not (1 <= int(port) <= 65535):
                                self.msg = "The 'port' value must be between 1 and 65535 for 'Telemetry_broker_or_UDP_director'."
                                self.status = "failed"
                                return self

                        # Add address and port
                        netflow_collector["collector"]["address"] = ip_address
                        self.log(
                            "Successfully added {0} and {1} to the netflow collector config.".format(
                                ip_address, port
                            ),
                            "INFO",
                        )
                        netflow_collector["collector"]["port"] = port

                    elif collector_type == "Builtin":
                        netflow_collector["collector"]["collectorType"] = "Builtin"
                    else:

                        # Invalid collector_type
                        self.msg = (
                            "Invalid 'collector_type': {}. Expected values are 'Builtin' or "
                            "'Telemetry_broker_or_UDP_director'.".format(collector_type)
                        )
                        self.log(self.msg, "ERROR")
                        self.status = "failed"
                        return self

                    # Handle enableOnWiredAccessDevices (optional boolean field)
                    enable_on_wired_access_devices = netflow_collector_data.get(
                        "enable_on_wired_access_devices"
                    )
                    if enable_on_wired_access_devices is not None:
                        netflow_collector["enableOnWiredAccessDevices"] = (
                            enable_on_wired_access_devices
                        )
                        self.log(
                            "Added enableOnWiredAccessDevices field to the netflow collector config.",
                            "INFO",
                        )
                    elif (
                        have_network_details.get("netflowcollector", {}).get(
                            "enableOnWiredAccessDevices"
                        )
                        != ""
                    ):
                        netflow_collector["enableOnWiredAccessDevices"] = (
                            have_network_details.get("netflowcollector", {}).get(
                                "enableOnWiredAccessDevices"
                            )
                        )
                elif have_network_details.get("netflowcollector") != {}:
                    want_network_settings["netflowcollector"] = (
                        have_network_details.get("netflowcollector")
                    )
                else:
                    want_network_settings["netflowcollector"] = None
                    self.log(
                        "netflow_collector is not provided, setting netflowcollector as None in network settings.",
                        "INFO",
                    )

                wired_data_collection = item.get("wired_data_collection")
                if wired_data_collection is not None:
                    enable_wired_data_collection = wired_data_collection.get(
                        "enable_wired_data_collection"
                    )
                    if enable_wired_data_collection is not None:
                        want_network_settings["wired_data_collection"] = {
                            "enableWiredDataCollection": enable_wired_data_collection
                        }
                elif have_network_details.get("wired_data_collection") != "":
                    want_network_settings["wired_data_collection"] = (
                        have_network_details.get("wired_data_collection")
                    )
                else:
                    want_network_settings["wired_data_collection"] = None

                wireless_telemetry = item.get("wireless_telemetry")
                if wireless_telemetry is not None:
                    enable_wireless_telemetry = wireless_telemetry.get(
                        "enable_wireless_telemetry"
                    )
                    if enable_wireless_telemetry is not None:
                        want_network_settings["wireless_telemetry"] = {
                            "enableWirelessTelemetry": enable_wireless_telemetry
                        }
                elif have_network_details.get("wireless_telemetry") != "":
                    want_network_settings["wireless_telemetry"] = (
                        have_network_details.get("wireless_telemetry")
                    )
                else:
                    want_network_settings["wireless_telemetry"] = None

                message_of_the_day = item.get("message_of_the_day")
                if message_of_the_day is not None:
                    retain_existing_banner = message_of_the_day.get(
                        "retain_existing_banner"
                    )
                    if retain_existing_banner is not None:
                        if retain_existing_banner is True:
                            want_network_settings.get("messageOfTheday").update(
                                {"type": "Builtin"}
                            )
                        else:
                            want_network_settings.get("messageOfTheday").update(
                                {"type": "Custom"}
                            )
                            if message_of_the_day.get("banner_message") is not None:
                                want_network_settings.get("messageOfTheday").update(
                                    {
                                        "message": message_of_the_day.get(
                                            "banner_message"
                                        )
                                    }
                                )
                else:
                    del want_network_settings["messageOfTheday"]

                if message_of_the_day == {}:
                    self.want.update({"settings": {"messageOfTheday": {}}})

                server_types = ["AAA", "ISE"]
                protocol_types = ["RADIUS", "TACACS"]
                network_aaa = item.get("network_aaa")

                if network_aaa:
                    server_type = network_aaa.get("server_type")
                    if server_type:
                        want_network_settings.get("network_aaa").update(
                            {"serverType": server_type}
                        )
                    else:
                        self.msg = "The 'serverType' is required under network_aaa."
                        self.status = "failed"
                        return self

                    if server_type not in server_types:
                        self.msg = "The 'server_type' in the network_aaa should be in {0}".format(
                            server_types
                        )
                        self.status = "failed"
                        return self

                    primary_server_address = network_aaa.get("primary_server_address")
                    if primary_server_address:
                        want_network_settings.get("network_aaa").update(
                            {"primaryServerIp": primary_server_address}
                        )
                    else:
                        self.msg = "Missing required parameter 'primary_server_address' in network_aaa."
                        self.status = "failed"
                        return self

                    if server_type == "ISE":
                        pan_address = network_aaa.get("pan_address")
                        if pan_address:
                            want_network_settings.get("network_aaa").update(
                                {"pan": pan_address}
                            )
                        else:
                            self.msg = "Missing required parameter 'pan' for ISE server in network_aaa."
                            self.status = "failed"
                            return self
                    else:
                        secondary_server_address = network_aaa.get(
                            "secondary_server_address"
                        )
                        if secondary_server_address:
                            want_network_settings.get("network_aaa").update(
                                {"secondaryServerIp": secondary_server_address}
                            )

                    protocol = network_aaa.get("protocol")
                    if protocol:
                        want_network_settings.get("network_aaa").update(
                            {"protocol": protocol}
                        )
                    else:
                        want_network_settings.get("network_aaa").update(
                            {"protocol": "RADIUS"}
                        )

                    if protocol not in protocol_types:
                        self.msg = (
                            "The 'protocol' in the network_aaa should be in {0}".format(
                                protocol_types
                            )
                        )
                        self.status = "failed"
                        return self

                    shared_secret = network_aaa.get("shared_secret")
                    if shared_secret is not None:
                        if len(shared_secret) < 4:
                            self.msg = "The 'shared_secret' length in 'network_aaa' should be greater than or equal to 4."
                            self.status = "failed"
                            return self

                        want_network_settings.get("network_aaa").update(
                            {"sharedSecret": shared_secret}
                        )
                else:
                    del want_network_settings["network_aaa"]

                if network_aaa == {}:
                    want_network_settings["network_aaa"] = network_aaa

                client_and_endpoint_aaa = item.get("client_and_endpoint_aaa")
                if client_and_endpoint_aaa:
                    server_type = client_and_endpoint_aaa.get("server_type")
                    if server_type:
                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"serverType": server_type}
                        )
                    else:
                        self.msg = "The 'server_type' is required under client_and_endpoint_aaa."
                        self.status = "failed"
                        return self

                    if server_type not in server_types:
                        self.msg = "The 'server_type' in the client_and_endpoint_aaa should be in {0}".format(
                            server_types
                        )
                        self.status = "failed"
                        return self

                    primary_server_address = client_and_endpoint_aaa.get(
                        "primary_server_address"
                    )
                    if primary_server_address:
                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"primaryServerIp": primary_server_address}
                        )
                    else:
                        self.msg = "Missing required parameter 'primary_server_address' in client_and_endpoint_aaa."
                        self.status = "failed"
                        return self

                    if server_type == "ISE":
                        pan_address = client_and_endpoint_aaa.get("pan_address")
                        if pan_address:
                            want_network_settings.get("client_and_endpoint_aaa").update(
                                {"pan": pan_address}
                            )
                        else:
                            self.msg = "Missing required parameter 'pan_address' for ISE server in client_and_endpoint_aaa."
                            self.status = "failed"
                            return self
                    else:
                        secondary_server_address = client_and_endpoint_aaa.get(
                            "secondary_server_address"
                        )
                        if secondary_server_address:
                            want_network_settings.get("client_and_endpoint_aaa").update(
                                {"secondaryServerIp": secondary_server_address}
                            )

                    protocol = client_and_endpoint_aaa.get("protocol")
                    if protocol:
                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"protocol": protocol}
                        )
                    else:
                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"protocol": "RADIUS"}
                        )

                    if protocol not in protocol_types:
                        self.msg = "The 'protocol' in the client_and_endpoint_aaa should be in {0}".format(
                            protocol_types
                        )
                        self.status = "failed"
                        return self

                    shared_secret = client_and_endpoint_aaa.get("shared_secret")
                    if shared_secret is not None:
                        if len(shared_secret) < 4:
                            self.msg = "The 'shared_secret' length in 'client_and_endpoint_aaa' should be greater than or equal to 4."
                            self.status = "failed"
                            return self

                        want_network_settings.get("client_and_endpoint_aaa").update(
                            {"sharedSecret": shared_secret}
                        )
                else:
                    del want_network_settings["client_and_endpoint_aaa"]

                if client_and_endpoint_aaa == {}:
                    want_network_settings["client_and_endpoint_aaa"] = client_and_endpoint_aaa

                network_aaa = want_network_settings.get("network_aaa")
                client_and_endpoint_aaa = want_network_settings.get(
                    "client_and_endpoint_aaa"
                )
                if (
                    network_aaa
                    and client_and_endpoint_aaa
                    and network_aaa.get("sharedSecret")
                    and client_and_endpoint_aaa.get("sharedSecret")
                    and network_aaa.get("sharedSecret")
                    != client_and_endpoint_aaa.get("sharedSecret")
                ):
                    self.msg = "The 'shared_secret' of 'network_aaa' and 'client_and_endpoint_aaa' should be same."
                    self.status = "failed"
                    return self

                all_network_management_details.append(want_network)
                network_management_index += 1

        self.log(
            "Network playbook details: {0}".format(self.pprint(all_network_management_details)),
            "DEBUG",
        )
        self.want.update({"wantNetwork": all_network_management_details})
        self.msg = "Collected the network details from the playbook"
        self.status = "success"
        return self

    def get_want_device_controllability(self, device_controllability_details):
        """
        Extract and validate device controllability configuration from playbook.
        Set appropriate status and message based on validation.

        Parameters:
            device_controllability_details (dict): Playbook configuration containing device_controllability details.

        Returns:
            self - The current object with updated device controllability information.
        """
        self.log("Starting to process device controllability details from the playbook.", "INFO")

        try:
            device_controllability = device_controllability_details.get("device_controllability")
            autocorrect_telemetry = device_controllability_details.get("autocorrect_telemetry_config")
            self.log(f"Extracted 'device_controllability': {device_controllability}", "DEBUG")
            self.log(f"Extracted 'autocorrect_telemetry_config': {autocorrect_telemetry}", "DEBUG")

            # Basic validation
            if device_controllability is None:
                self.msg = "'device_controllability' must be defined in 'device_controllability_details'"
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            if autocorrect_telemetry and not device_controllability:
                self.msg = "'autocorrect_telemetry_config' can only be enabled if 'device_controllability' is True"
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            # Build desired configuration dictionary
            want_device_config = {
                "device_controllability": device_controllability,
                "autocorrect_telemetry_config": autocorrect_telemetry,
            }

            self.want.update({"want_device_controllability": want_device_config})
            self.msg = "Successfully collected the device controllability details from the playbook."
            self.log(f"Device Controllability details: {self.pprint(want_device_config)}", "INFO")
            self.status = "success"

        except Exception as e:
            self.msg = "Error processing device controllability details: {0}".format(str(e))
            self.status = "failed"

        return self

    def get_want(self, config):
        """
        Get all the Global Pool, Reserved Pool, and Network-related information from the playbook.

        Parameters:
            config (dict): Playbook details containing global_pool_details, reserve_pool_details, network_management_details,
                   and device_controllability_details.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers and Device Controllability information.
        """
        self.log("Starting to process the desired state (want) from the playbook.", "INFO")
        ccc_version = self.get_ccc_version()

        if config.get("global_pool_details"):
            self.log("Processing global pool details from the playbook.", "INFO")
            global_ippool = config.get("global_pool_details", {}).get("settings", {}).get("ip_pool")
            if global_ippool:
                if self.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
                    self.log("Using Global Pool handling method: V1 (legacy) for Catalyst Center version < 2.3.7.9.", "DEBUG")
                    self.get_want_global_pool_v1(global_ippool).check_return_status()
                else:
                    self.log("Using Global Pool handling method: V2 (latest) for Catalyst Center version >= 2.3.7.9.", "DEBUG")
                    self.get_want_global_pool_v2(global_ippool).check_return_status()
            else:
                self.log("No valid global pool details found in the playbook.", "WARNING")

        if config.get("reserve_pool_details"):
            self.log("Processing reserve pool details from the playbook.", "INFO")
            reserve_pool = config.get("reserve_pool_details")
            if self.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
                self.log("Detected Catalyst Center version < 2.3.7.9: {}".format(ccc_version), "DEBUG")
                self.log("Using Reserve Pool handling method: V1 (legacy)", "DEBUG")
                self.get_want_reserve_pool_v1(reserve_pool).check_return_status()
            else:
                self.log("Detected Catalyst Center version >= 2.3.7.9: {}".format(ccc_version), "DEBUG")
                self.log("Using Reserve Pool handling method: V2 (latest)", "DEBUG")
                self.get_want_reserve_pool_v2(reserve_pool).check_return_status()
        else:
            self.log("No reserve pool details provided in the playbook.", "INFO")

        if config.get("network_management_details"):
            self.log("Processing network management details from the playbook.", "INFO")
            network_management_details = config.get("network_management_details")
            self.get_want_network(network_management_details).check_return_status()
        else:
            self.log("No network management details provided in the playbook.", "INFO")

        # Process Device Controllability details (only for Catalyst Center version >= 2.3.7.9)
        if config.get("device_controllability_details"):
            self.log("Processing device controllability details from the playbook.", "INFO")
            device_controllability_details = config.get("device_controllability_details")
            if self.compare_dnac_versions(ccc_version, "2.3.7.9") >= 0:
                self.log("Using Device Controllability handling method for Catalyst Center version >= 2.3.7.9.", "DEBUG")
                self.get_want_device_controllability(device_controllability_details).check_return_status()
            else:
                self.log("Device Controllability is not supported for Catalyst Center versions < 2.3.7.9.", "WARNING")

        self.log("Desired State (want): {0}".format(self.want), "INFO")
        self.msg = "Successfully retrieved details from the playbook"
        self.status = "success"
        return self

    def update_global_pool(self, global_pool):
        """
        Dispatcher for updating/creating global pools based on the version.

        Parameters:
            global_pool (list of dict): Global Pool playbook details
            version (int): Version of the update logic to use (1 or 2)

        Returns:
            self
        """
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
            return self.update_global_pool_v2(global_pool)

        return self.update_global_pool_v1(global_pool)

    def update_global_pool_v1(self, global_pool):
        """
        Update/Create Global Pool in Cisco Catalyst Center with fields provided in playbook for Catalyst Center version < 2.3.7.9.

        Parameters:
            global_pool (list of dict) - Global Pool playbook details

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """

        create_global_pool = []
        update_global_pool = []
        global_pool_index = 0
        result_global_pool = self.result.get("response")[0].get("globalPool")
        want_global_pool = self.want.get("wantGlobal").get("settings").get("ippool")
        self.log("Global pool playbook details: {0}".format(self.pprint(global_pool)), "DEBUG")

        for item in self.have.get("globalPool"):
            result_global_pool.get("msg").update(
                {want_global_pool[global_pool_index].get("ipPoolName"): {}}
            )
            if item.get("exists") is True:
                update_global_pool.append(want_global_pool[global_pool_index])
            else:
                create_global_pool.append(want_global_pool[global_pool_index])

            global_pool_index += 1

        # Check create_global_pool; if yes, create the global pool in batches
        if create_global_pool:
            self.log(
                "Global pool(s) details to be created: {0}".format(create_global_pool),
                "INFO",
            )

            batch_size = 25  # Define batch size
            for i in range(0, len(create_global_pool), batch_size):
                batch = create_global_pool[i : i + batch_size]
                pool_params = {"settings": {"ippool": copy.deepcopy(batch)}}
                self.log("Creating global pool batch: {0}".format(batch), "INFO")
                try:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="create_global_pool",
                        op_modifies=True,
                        params=pool_params,
                    )
                except Exception as msg:
                    self.msg = "Exception occurred while creating the global pools: {msg}".format(
                        msg=msg
                    )
                    self.log(str(msg), "ERROR")
                    self.status = "failed"
                    return self

                self.check_execution_response_status(
                    response, "create_global_pool"
                ).check_return_status()
                self.log(
                    "Successfully created the following global pool batch: {0}".format(
                        batch
                    ),
                    "INFO",
                )

                for pool in pool_params.get("settings").get("ippool"):
                    pool_name = pool.get("ipPoolName")
                    self.log(
                        "Global pool '{0}' created successfully.".format(pool_name),
                        "INFO",
                    )
                    result_global_pool.get("response").update({"created": pool_params})
                    result_global_pool.get("msg").update(
                        {pool_name: "Global Pool Created Successfully"}
                    )

        # Check update_global_pool; if yes, update the global pool in batches
        if update_global_pool:
            pools_to_update = []

            for item in update_global_pool:
                pool_name = item.get("ipPoolName")
                self.log(
                    "Checking global pool '{0}' for updates...".format(pool_name),
                    "DEBUG",
                )
                for pool in self.have.get("globalPool", []):
                    if not pool.get("exists"):
                        self.log(
                            "Skipping global pool '{0}' as it does not exist".format(
                                pool_name
                            ),
                            "DEBUG",
                        )
                        continue

                    pool_details = pool.get("details", {})
                    prev_name = pool.get("prev_name")

                    if (
                        pool_details.get("ipPoolName") == pool_name
                        or prev_name == pool_name
                    ):
                        if not self.requires_update(
                            pool_details, item, self.global_pool_obj_params
                        ):
                            self.log(
                                "Global pool '{0}' doesn't require an update".format(
                                    pool_name
                                ),
                                "INFO",
                            )
                            result_global_pool["msg"][
                                pool_name
                            ] = "Global pool doesn't require an update"
                        else:
                            self.log(
                                "Global pool '{0}' requires an update. Adding to update list.".format(
                                    pool_name
                                ),
                                "INFO",
                            )
                            pools_to_update.append(item)

            if pools_to_update:
                self.log(
                    "Total global pools requiring updates: {0}".format(
                        len(pools_to_update)
                    ),
                    "INFO",
                )

                batch_size = 25  # Define batch size
                for i in range(0, len(pools_to_update), batch_size):
                    batch = pools_to_update[i : i + batch_size]
                    batch_number = i // batch_size + 1
                    total_batches = (len(pools_to_update) // batch_size) + 1
                    self.log(
                        "Processing batch {0} of {1}".format(
                            batch_number, total_batches
                        ),
                        "INFO",
                    )
                    pool_params = {"settings": {"ippool": copy.deepcopy(batch)}}

                    self.log(
                        "Desired State for global pool (want): {0}".format(pool_params),
                        "DEBUG",
                    )

                    # Remove unnecessary keys
                    keys_to_remove = {"IpAddressSpace", "ipPoolCidr", "type"}
                    for pool in pool_params["settings"]["ippool"]:
                        for key in keys_to_remove:
                            pool.pop(key, None)

                    self.log(
                        "Final global pool update details: {0}".format(pool_params),
                        "DEBUG",
                    )
                    try:
                        self.log("Executing API call to update global pools...", "INFO")
                        response = self.dnac._exec(
                            family="network_settings",
                            function="update_global_pool",
                            op_modifies=True,
                            params=pool_params,
                        )
                        self.log("Received API response: {0}".format(response), "DEBUG")
                    except Exception as msg:
                        self.msg = "Exception occurred while updating the global pools: {msg}".format(
                            msg=msg
                        )
                        self.log(str(msg), "ERROR")
                        self.status = "failed"
                        return self

                    self.check_execution_response_status(
                        response, "update_global_pool"
                    ).check_return_status()
                    for pool in pool_params.get("settings").get("ippool"):
                        pool_name = pool.get("ipPoolName")
                        self.log(
                            "Global pool '{0}' Updated successfully.".format(pool_name),
                            "INFO",
                        )
                        result_global_pool.get("response").update(
                            {"globalPool Details": pool_params}
                        )
                        result_global_pool.get("msg").update(
                            {pool_name: "Global Pool Updated Successfully"}
                        )

        self.log("Global pool configuration operations completed successfully.", "INFO")
        return self

    def update_global_pool_v2(self, global_pool):
        """
        Update/Create Global Pool in Cisco Catalyst Center with fields provided in playbook for Catalyst Center version >= 2.3.7.9.

        Parameters:
            global_pool (list of dict) - Global Pool playbook details

        Returns:
            self: The current object after completing the global pool operations.
        """
        self.log("Starting global pool update/create process for Catalyst Center version >= 2.3.7.9.", "INFO")

        create_global_pool = []
        update_global_pool = []
        global_pool_index = 0
        result_global_pool = self.result.get("response")[0].get("globalPool")
        want_global_pool = self.want.get("wantGlobal").get("settings").get("ippool")
        self.log("Global pool playbook details: {0}".format(global_pool), "DEBUG")

        # Classify global pools into create and update lists
        for item in self.have.get("globalPool", []):
            if global_pool_index >= len(want_global_pool):
                self.log(
                    f"Skipping further processing as global_pool_index ({global_pool_index})\
                        exceeds the number of items in want_global_pool ({len(want_global_pool)}).",
                    "WARNING",
                )
                break  # Avoid index errors if `want_global_pool` has fewer items

            pool_name = want_global_pool[global_pool_index].get("name")
            result_global_pool.setdefault("msg", {}).update({pool_name: {}})

            if item.get("exists"):
                self.log(f"Global pool '{pool_name}' exists. Adding to update list.", "DEBUG")
                update_global_pool.append(want_global_pool[global_pool_index])
            else:
                self.log(f"Global pool '{pool_name}' does not exist. Adding to create list.", "DEBUG")
                create_global_pool.append(want_global_pool[global_pool_index])

            global_pool_index += 1

        # Check create_global_pool; if yes, create the global pool
        if create_global_pool:
            self.log(f"Global pool(s) to be created: {self.pprint(create_global_pool)}", "INFO")
            pool_params = {
                "settings": {
                    "ippool": copy.deepcopy(create_global_pool)
                }
            }
            creation_list = pool_params.get("settings").get("ippool")
            for param in creation_list:
                self.log("Global pool details to be created: {0}".format(self.pprint(param)), "INFO")
                try:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="create_a_global_ip_address_pool",
                        op_modifies=True,
                        params=param,
                    )
                    self.log("Received API response: {0}".format(response), "DEBUG")
                except Exception as msg:
                    self.msg = (
                        "Exception occurred while creating the global pools: {msg}"
                        .format(msg=msg)
                    )
                    self.log(str(msg), "ERROR")
                    self.status = "failed"
                    return self

                self.check_tasks_response_status(response, "create_a_global_ip_address_pool").check_return_status()
                name = param.get("name")
                self.log("Global pool '{0}' created successfully.".format(name), "INFO")
                result_global_pool.get("response").update({"created": creation_list})
                result_global_pool.get("msg").update({name: "Global Pool Created Successfully"})

        if update_global_pool:
            self.log("Checking for updates required for existing global pools.", "INFO")
            final_update_global_pool = []
            # Pool exists, check update is required
            for item in update_global_pool:
                name = item.get("name")
                prev_name = item.get("prev_name")
                self.log(f"Checking if global pool '{name}' (or previous name '{prev_name}') requires an update.", "DEBUG")
                for pool_value in self.have.get("globalPool", []):
                    if not pool_value.get("exists"):
                        self.log(
                            "Skipping global pool '{0}' as it does not exist".format(
                                pool_name
                            ),
                            "DEBUG",
                        )
                        continue

                    pool_exists = pool_value.get("exists")
                    pool_name = pool_value.get("details", {}).get("name")
                    self.log(f"Evaluating existing global pool: {pool_name}, exists: {pool_exists}", "DEBUG")

                    # Check if the pool exists and matches the current or previous name
                    if pool_exists and (pool_name in [name, prev_name]):
                        if not self.requires_update(pool_value.get("details"), item, self.global_pool_obj_params):
                            self.log(f"Global pool '{name}' does not require an update.", "INFO")
                            result_global_pool["msg"].update({name: "Global Pool Does Not Require Update"})
                        elif item not in final_update_global_pool:
                            self.log(f"Global pool '{name}' requires an update. Adding to the update list.", "DEBUG")
                            final_update_global_pool.append(item)

            if final_update_global_pool:
                self.log(f"Global pools requiring updates: {self.pprint(final_update_global_pool)}", "INFO")

                updation_list = copy.deepcopy(final_update_global_pool)
                for item in updation_list:
                    if item.get("prev_name"):
                        item.pop("prev_name")

                self.log("Desired global pool details (want): {0}".format(self.pprint(updation_list)), "DEBUG")
                for param in updation_list:
                    self.log("Global pool details to be updated: {0}".format(self.pprint(param)), "INFO")
                    try:
                        response = self.dnac._exec(
                            family="network_settings",
                            function="updates_a_global_ip_address_pool",
                            op_modifies=True,
                            params=param,
                        )
                        self.log("Received API response: {0}".format(response), "DEBUG")
                        self.check_tasks_response_status(response, "updates_a_global_ip_address_pool").check_return_status()
                        self.log("Successfully updated global pool successfully.", "INFO")
                    except Exception as msg:
                        self.msg = (
                            "Exception occurred while updating the global pools: {msg}"
                            .format(msg=msg)
                        )
                        self.log(str(msg), "ERROR")
                        self.status = "failed"
                        return self

                for item in updation_list:
                    name = item.get("name")
                    self.log("Global pool '{0}' Updated successfully.".format(name), "INFO")
                    result_global_pool.get("response").update({"globalPool Details": updation_list})
                    result_global_pool.get("msg").update({name: "Global Pool Updated Successfully"})

        self.log("Global pool configuration operations completed successfully.", "INFO")
        return self

    def update_reserve_pool(self, reserve_pool):
        """
        Dispatcher function that routes to the appropriate reserve pool update method
        based on Catalyst Center version (v1 or v2).
        """
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") < 0:
            return self.update_reserve_pool_v1(reserve_pool)
        else:
            return self.update_reserve_pool_v2(reserve_pool)

    def update_reserve_pool_v1(self, reserve_pool):
        """
        Update or Create a Reserve Pool in Cisco Catalyst Center based on the provided configuration for Catalyst Center version < 2.3.7.9.
        This method checks if a reserve pool with the specified name exists in Cisco Catalyst Center.
        If it exists and requires an update, it updates the pool. If not, it creates a new pool.

        Parameters:
            reserve_pool (list of dict) - Playbook details containing Reserve Pool information.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """

        reserve_pool_index = -1
        for item in reserve_pool:
            reserve_pool_index += 1
            name = item.get("name")
            result_reserve_pool = self.result.get("response")[1].get("reservePool")
            self.log(
                "Current reserved pool '{0}' details in Catalyst Center: {1}".format(
                    name,
                    self.have.get("reservePool")[reserve_pool_index].get("details"),
                ),
                "DEBUG",
            )
            self.log(
                "Desired reserved pool '{0}' details in Catalyst Center: {1}".format(
                    name, self.want.get("wantReserve")[reserve_pool_index]
                ),
                "DEBUG",
            )

            # Check pool exist, if not create and return
            self.log(
                "IPv4 reserved pool '{0}': {1}".format(
                    name,
                    self.want.get("wantReserve")[reserve_pool_index].get(
                        "ipv4GlobalPool"
                    ),
                ),
                "DEBUG",
            )
            site_name = item.get("site_name")
            reserve_params = self.want.get("wantReserve")[reserve_pool_index]
            site_exist, site_id = self.get_site_id(site_name)
            reserve_params.update({"site_id": site_id})
            if not self.have.get("reservePool")[reserve_pool_index].get("exists"):
                self.log(
                    "Desired reserved pool '{0}' details (want): {1}".format(
                        name, reserve_params
                    ),
                    "DEBUG",
                )
                try:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="reserve_ip_subpool",
                        op_modifies=True,
                        params=reserve_params,
                    )
                except Exception as msg:
                    self.msg = (
                        "Exception occurred while reserving the ip pool with the name '{name}' "
                        "in site '{site}: {msg}".format(
                            name=name, site=site_name, msg=msg
                        )
                    )
                    self.log(str(msg), "ERROR")
                    self.status = "failed"
                    return self

                self.check_execution_response_status(
                    response, "reserve_ip_subpool"
                ).check_return_status()
                self.log(
                    "Successfully created IP subpool reservation '{0}'.".format(name),
                    "INFO",
                )
                result_reserve_pool.get("response").update(
                    {name: self.want.get("wantReserve")[reserve_pool_index]}
                )
                result_reserve_pool.get("msg").update(
                    {name: "Ip Subpool Reservation Created Successfully"}
                )
                continue

            # Check update is required
            if not self.requires_update(
                self.have.get("reservePool")[reserve_pool_index].get("details"),
                self.want.get("wantReserve")[reserve_pool_index],
                self.reserve_pool_obj_params,
            ):
                self.log(
                    "Reserved ip subpool '{0}' doesn't require an update".format(name),
                    "INFO",
                )
                result_reserve_pool.get("msg").update(
                    {name: "Reserved ip subpool doesn't require an update"}
                )
                continue

            self.log("Reserved ip pool '{0}' requires an update".format(name), "DEBUG")

            # Pool Exists
            self.log(
                "Current reserved ip pool '{0}' details in Catalyst Center: {1}".format(
                    name, self.have.get("reservePool")
                ),
                "DEBUG",
            )
            self.log(
                "Desired reserved ip pool '{0}' details: {1}".format(
                    name, self.want.get("wantReserve")
                ),
                "DEBUG",
            )
            reserve_params.update(
                {"id": self.have.get("reservePool")[reserve_pool_index].get("id")}
            )
            try:
                response = self.dnac._exec(
                    family="network_settings",
                    function="update_reserve_ip_subpool",
                    op_modifies=True,
                    params=reserve_params,
                )
            except Exception as msg:
                self.msg = "Exception occurred while updating the global pool with name '{name}': {msg}".format(
                    name=name, msg=msg
                )
                self.log(str(msg), "ERROR")
                self.status = "failed"
                return self

            self.check_execution_response_status(
                response, "update_reserve_ip_subpool"
            ).check_return_status()
            self.log(
                "Reserved ip subpool '{0}' updated successfully.".format(name), "INFO"
            )
            result_reserve_pool.get("response").update({name: reserve_params})
            result_reserve_pool.get("response").get(name).update(
                {"Id": self.have.get("reservePool")[reserve_pool_index].get("id")}
            )
            result_reserve_pool.get("msg").update(
                {name: "Reserved Ip Subpool updated successfully."}
            )

        self.log("Completed reserved pool update/create operations successfully.", "INFO")
        return self

    def update_reserve_pool_v2(self, reserve_pool):
        """
        Update or Create a Reserve Pool in Cisco Catalyst Center based on the provided configuration for Catalyst Center version >= 2.3.7.9.
        This method checks if a reserve pool with the specified name exists in Cisco Catalyst Center.
        If it exists and requires an update, it updates the pool. If not, it creates a new pool.

        Parameters:
            reserve_pool (list of dict) - Playbook details containing Reserve Pool information.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """
        self.log("Starting the reserved pool update/create process for Catalyst Center version >= 2.3.7.9.", "INFO")

        reserve_pool_index = -1
        for item in reserve_pool:
            reserve_pool_index += 1
            name = item.get("name")
            result_reserve_pool = self.result.get("response")[1].get("reservePool")
            self.log(f"Processing reserved pool '{name}' at index {reserve_pool_index}.", "INFO")
            self.log("Current reserved pool '{0}' details in Catalyst Center: {1}"
                     .format(name, self.have.get("reservePool")[reserve_pool_index].get("details")), "DEBUG")
            self.log("Desired reserved pool '{0}' details in Catalyst Center: {1}"
                     .format(name, self.want.get("wantReserve")[reserve_pool_index]), "DEBUG")

            # Check pool exist, if not create and return
            self.log("IPv4 reserved pool '{0}': {1}"
                     .format(name, self.want.get("wantReserve")[reserve_pool_index].get("ipv4GlobalPool")), "DEBUG")
            site_name = item.get("site_name")
            reserve_params = self.want.get("wantReserve")[reserve_pool_index]
            site_exist, site_id = self.get_site_id(site_name)
            reserve_params.update({"siteId": site_id})
            if not self.have.get("reservePool")[reserve_pool_index].get("exists"):
                self.log(f"Reserved pool '{name}' does not exist. Creating a new subpool reservation.", "INFO")
                self.log(f"Details for new reserved pool '{name}': {self.pprint(reserve_params)}", "DEBUG")
                try:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="reservecreate_ip_address_subpools",
                        op_modifies=True,
                        params=reserve_params,
                    )
                    self.log(f"Received API response for creating reserved pool '{name}': {self.pprint(response)}", "DEBUG")
                except Exception as msg:
                    self.msg = (
                        "Exception occurred while reserving the global pool with the name '{name}' "
                        "in site '{site}: {msg}".format(name=name, site=site_name, msg=msg)
                    )
                    self.log(str(msg), "ERROR")
                    self.status = "failed"
                    return self

                self.check_tasks_response_status(response, "reservecreate_ip_address_subpools").check_return_status()
                self.log("Successfully created IP subpool reservation '{0}'.".format(name), "INFO")
                result_reserve_pool.get("response") \
                    .update({name: self.want.get("wantReserve")[reserve_pool_index]})
                result_reserve_pool.get("msg") \
                    .update({name: "Ip Subpool Reservation Created Successfully"})
                continue

            # Check update is required
            if not self.requires_update(self.have.get("reservePool")[reserve_pool_index].get("details"),
                                        self.want.get("wantReserve")[reserve_pool_index],
                                        self.reserve_pool_obj_params):
                self.log("Reserved ip subpool '{0}' doesn't require an update".format(name), "INFO")
                result_reserve_pool.get("msg") \
                    .update({name: "Reserved ip subpool doesn't require an update"})
                continue

            self.log("Reserved ip pool '{0}' requires an update".format(name), "DEBUG")

            # Pool Exists
            self.log("Current reserved ip pool '{0}' details in Catalyst Center: {1}"
                     .format(name, self.have.get("reservePool")), "DEBUG")
            self.log("Desired reserved ip pool '{0}' details: {1}"
                     .format(name, self.want.get("wantReserve")), "DEBUG")
            reserve_params.update({"id": self.have.get("reservePool")[reserve_pool_index].get("id")})
            try:
                response = self.dnac._exec(
                    family="network_settings",
                    function="updates_an_ip_address_subpool",
                    op_modifies=True,
                    params=reserve_params,
                )
                self.log(f"Received API response for updating reserved pool '{name}': {self.pprint(response)}", "DEBUG")
            except Exception as msg:
                self.msg = (
                    "Exception occurred while updating the reserved pool with name '{name}': {msg}"
                    .format(name=name, msg=msg)
                )
                self.log(str(msg), "ERROR")
                self.status = "failed"
                return self

            self.check_tasks_response_status(response, "updates_an_ip_address_subpool").check_return_status()
            self.log("Reserved ip subpool '{0}' updated successfully.".format(name), "INFO")
            result_reserve_pool.get("response") \
                .update({name: reserve_params})
            result_reserve_pool.get("response").get(name) \
                .update({"Id": self.have.get("reservePool")[reserve_pool_index].get("id")})
            result_reserve_pool.get("msg") \
                .update({name: "Reserved Ip Subpool updated successfully."})

        self.log("Updated reserved IP subpool successfully", "INFO")
        return self

    def update_dhcp_settings_for_site(self, site_name, site_id, dhcp_settings):
        """
        Update the DHCP settings for a specified site in Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_id (str) - The ID of the site to update the DHCP settings.
            dhcp_settings (dict) - The DHCP settings to be applied.

        Returns:
            Response (dict) - The response after updating the DHCP settings.
        """
        self.log(
            "Attempting to update DHCP settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, dhcp_settings
            ),
            "INFO",
        )

        try:
            response = self.dnac._exec(
                family="network_settings",
                function="set_dhcp_settings_for_a_site",
                op_modifies=True,
                params={"id": site_id, "dhcp": dhcp_settings},
            )
            self.log(
                "DHCP settings updated for for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, dhcp_settings
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while updating DHCP settings for site {0}: {1}".format(
                site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return response

    def update_ntp_settings_for_site(self, site_name, site_id, ntp_settings):
        """
        Update the NTP server settings for a specified site in Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to update the NTP settings.
            site_id (str): The ID of the site to update the NTP settings.
            ntp_settings (dict): The NTP server settings to be applied.

        Returns:
            Response (dict): The response after updating the NTP settings.
        """
        self.log(
            "Attempting to update NTP settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, ntp_settings
            ),
            "INFO",
        )

        try:
            response = self.dnac._exec(
                family="network_settings",
                function="set_n_t_p_settings_for_a_site",
                op_modifies=True,
                params={"id": site_id, "ntp": ntp_settings},
            )
            self.log(
                "NTP settings updated for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, ntp_settings
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while updating NTP settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return response

    def update_time_zone_settings_for_site(
        self, site_name, site_id, time_zone_settings
    ):
        """
        Update the time zone settings for a specified site in Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to update the time zone settings.
            site_id (str): The ID of the site to update the time zone settings.
            time_zone_settings (dict): The time zone settings to be applied.

        Returns:
            Response (dict): The response after updating the time zone settings.
        """
        self.log(
            "Attempting to update time zone settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, time_zone_settings
            ),
            "INFO",
        )

        param = {"id": site_id, "timeZone": time_zone_settings}
        if time_zone_settings == {}:
            payload = {"settings": {"timeZone": {}}}
            param = {"id": site_id, "payload": payload}

        try:
            response = self.dnac._exec(
                family="network_settings",
                function="set_time_zone_for_a_site",
                op_modifies=True,
                params=param,
            )
            self.log(
                "Time zone settings updated for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, time_zone_settings
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while updating time zone settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return response

    def update_dns_settings_for_site(self, site_name, site_id, dns_settings):
        """
        Update the DNS settings for a specified site in Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to update the DNS settings.
            site_id (str): The ID of the site to update the DNS settings.
            dns_settings (dict): The DNS settings to be applied.

        Returns:
            Response (dict): The response after updating the DNS settings.
        """
        self.log(
            "Attempting to update DNS settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, dns_settings
            ),
            "INFO",
        )

        dns_params = {}
        if dns_settings.get("domainName"):
            dns_params["domainName"] = dns_settings.get("domainName")

        if "primaryIpAddress" in dns_settings or "secondaryIpAddress" in dns_settings:
            dns_params["dnsServers"] = []
        primary_ip = dns_settings.get("primaryIpAddress")
        secondary_ip = dns_settings.get("secondaryIpAddress")

        if primary_ip:
            dns_params["dnsServers"].append(primary_ip)
        if secondary_ip:
            dns_params["dnsServers"].append(secondary_ip)

        try:
            response = self.dnac._exec(
                family="network_settings",
                function="set_d_n_s_settings_for_a_site",
                op_modifies=True,
                params={"id": site_id, "dns": dns_params},
            )
            self.log(
                "DNS settings updated for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, dns_settings
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while updating DNS settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return response

    def update_telemetry_settings_for_site(
        self, site_name, site_id, telemetry_settings
    ):
        """
        Update the telemetry settings for a specified site in Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to update the telemetry settings.
            site_id (str): The ID of the site to update the telemetry settings.
            telemetry_settings (dict): The telemetry settings to be applied.

        Returns:
            Response (dict): The response after updating the telemetry settings.
        """
        self.log(
            "Attempting to update telemetry settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, telemetry_settings
            ),
            "INFO",
        )

        try:
            response = self.dnac._exec(
                family="network_settings",
                function="set_telemetry_settings_for_a_site",
                op_modifies=True,
                params={
                    "id": site_id,
                    "wiredDataCollection": telemetry_settings.get(
                        "wired_data_collection"
                    ),
                    "wirelessTelemetry": telemetry_settings.get("wireless_telemetry"),
                    "snmpTraps": telemetry_settings.get("snmp_server"),
                    "syslogs": telemetry_settings.get("syslog_server"),
                    "applicationVisibility": telemetry_settings.get("netflowcollector"),
                },
            )
            self.log(
                "Telemetry settings updated for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, telemetry_settings
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while updating telemetry settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return response

    def update_banner_settings_for_site(self, site_name, site_id, banner_settings):
        """
        Update the banner (Message of the Day) settings for a specified site in Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to update the banner settings.
            site_id (str): The ID of the site to update the banner settings.
            banner_settings (dict): The banner settings to be applied.

        Returns:
            Response (dict): The response after updating the banner settings.
        """
        self.log(
            "Attempting to update banner settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, banner_settings
            ),
            "INFO",
        )

        param = {"id": site_id, "banner": banner_settings}
        if banner_settings == {}:
            payload = {"settings": {"messageOfTheday": {}}}
            param = {"id": site_id, "payload": payload}
        try:
            response = self.dnac._exec(
                family="network_settings",
                function="set_banner_settings_for_a_site",
                op_modifies=True,
                params=param,
            )
            self.log(
                "Banner settings updated for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, banner_settings
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while updating banner settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return response

    def update_aaa_settings_for_site(
        self, site_name, site_id, network_aaa, client_and_endpoint_aaa
    ):
        """
        Update the AAA (Authentication, Authorization, and Accounting) settings for a specified site in Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            site_name (str): The name of the site to update the AAA settings.
            site_id (str): The ID of the site to update the AAA settings.
            network_aaa (dict): The AAA network settings to be applied.
            client_and_endpoint_aaa (dict): The AAA client and endpoint settings to be applied.

        Returns:
            Response (dict): The response after updating the AAA settings.
        """
        self.log(
            "Attempting to update AAA settings for site '{0}' (ID: {1})".format(
                site_name, site_id
            ),
            "INFO",
        )
        self.log(
            {
                "id": site_id,
                "aaaNetwork": network_aaa,
                "aaaClient": client_and_endpoint_aaa,
            },
            "DEBUG",
        )
        if network_aaa and client_and_endpoint_aaa:
            param = {
                "id": site_id,
                "aaaNetwork": network_aaa,
                "aaaClient": client_and_endpoint_aaa,
            }
        elif network_aaa is not None:
            param = {"id": site_id, "aaaNetwork": network_aaa}
        elif client_and_endpoint_aaa is not None:
            param = {"id": site_id, "aaaClient": client_and_endpoint_aaa}

        if network_aaa == {} and client_and_endpoint_aaa == {}:
            payload = {"aaaNetwork": {}, "aaaClient": {}}
            param = {"id": site_id, "payload": payload}

        try:
            response = self.dnac._exec(
                family="network_settings",
                function="set_aaa_settings_for_a_site",
                op_modifies=True,
                params=param,
            )
            self.log(
                "AAA settings updated for site '{0}' (ID: {1}): Network AAA: {2}, Client and Endpoint AAA: {3}".format(
                    site_name, site_id, network_aaa, client_and_endpoint_aaa
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while updating AAA settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return response

    def update_network(self, network_management):
        """
        Update or create a network configuration in Cisco Catalyst
        Center based on the provided playbook details.

        Parameters:
            network_management (list of dict) - Playbook details containing Network Management information.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """
        network_management_index = 0
        for item in network_management:
            site_name = item.get("site_name")
            result_network = self.result.get("response")[2].get("network")
            result_network.get("response").update({site_name: {}})
            have_network_details = self.have.get("network")[
                network_management_index
            ].get("net_details")
            want_network_details = self.want.get("wantNetwork")[
                network_management_index
            ]
            network_aaa = want_network_details.get("settings").get("network_aaa")
            client_and_endpoint_aaa = want_network_details.get("settings").get(
                "client_and_endpoint_aaa"
            )

            # Check update is required or not
            skip_update = False

            # Only apply extra checks for versions > 2.3.7.9
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
                empty_settings = [
                    network_aaa,
                    client_and_endpoint_aaa,
                    want_network_details.get("settings", {}).get("ntpServer"),
                    want_network_details.get("settings", {}).get("timezone"),
                    want_network_details.get("settings", {}).get("dnsServer"),
                    want_network_details.get("settings", {}).get("dhcpServer"),
                    want_network_details.get("settings", {}).get("messageOfTheday"),
                ]
                if any(setting == {} for setting in empty_settings):
                    skip_update = True

            # Check update is required or not
            if not (
                (network_aaa and network_aaa.get("sharedSecret"))
                or (
                    client_and_endpoint_aaa
                    and client_and_endpoint_aaa.get("sharedSecret")
                )
                or self.requires_update(
                    have_network_details, want_network_details, self.network_obj_params
                )
            ) and not skip_update:

                self.log(
                    "Network in site '{0}' doesn't require an update.".format(
                        site_name
                    ),
                    "INFO",
                )
                result_network.get("response").get(site_name).update(
                    {
                        "Cisco Catalyst Center params": self.have.get("network")[
                            network_management_index
                        ]
                        .get("net_details")
                        .get("settings")
                    }
                )
                result_network.get("msg").update(
                    {site_name: "Network doesn't require an update"}
                )
                continue

            self.log("Network in site '{0}' requires update.".format(site_name), "INFO")
            self.log(
                "Current State of network in Catalyst Center: {0}".format(
                    self.have.get("network")
                ),
                "DEBUG",
            )
            self.log(
                "Desired State of network: {0}".format(self.want.get("wantNetwork")),
                "DEBUG",
            )

            net_params = copy.deepcopy(
                self.want.get("wantNetwork")[network_management_index]
            )
            net_params.update(
                {
                    "site_id": self.have.get("network")[network_management_index].get(
                        "site_id"
                    )
                }
            )
            self.log(
                "Network parameters for 'update_network_v2': {0}".format(net_params),
                "DEBUG",
            )
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") < 0:
                if "client_and_endpoint_aaa" in net_params["settings"]:
                    net_params["settings"]["clientAndEndpoint_aaa"] = net_params[
                        "settings"
                    ].pop("client_and_endpoint_aaa")

                try:
                    response = self.dnac._exec(
                        family="network_settings",
                        function="update_network_v2",
                        op_modifies=True,
                        params=net_params,
                    )
                    self.log(
                        "Received API response of 'update_network_v2': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    validation_string = "desired common settings operation successful"
                    self.check_task_response_status(
                        response, validation_string, "update_network_v2"
                    ).check_return_status()
                except Exception as msg:
                    self.msg = "Exception occurred while updating the network settings of '{site_name}': {msg}".format(
                        site_name=site_name, msg=msg
                    )
                    self.log(str(msg), "ERROR")
                    self.status = "failed"
                    return self
            else:
                site_id = net_params.get("site_id")
                site_name = self.have.get("network")[network_management_index].get(
                    "site_name"
                )

                dhcp_settings = net_params.get("settings").get("dhcpServer")
                if dhcp_settings is not None:
                    response = self.update_dhcp_settings_for_site(
                        site_name, site_id, dhcp_settings
                    )
                    self.log(
                        "Received API response of 'set_dhcp_settings_for_a_site': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, "set_dhcp_settings_for_a_site"
                    ).check_return_status()

                ntp_settings = net_params.get("settings").get("ntpServer")
                if ntp_settings is not None:
                    response = self.update_ntp_settings_for_site(
                        site_name, site_id, ntp_settings
                    )
                    self.log(
                        "Received API response of 'set_n_t_p_settings_for_a_site': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, "set_n_t_p_settings_for_a_site"
                    ).check_return_status()

                time_zone_settings = net_params.get("settings").get("timezone")
                if time_zone_settings is not None:
                    response = self.update_time_zone_settings_for_site(
                        site_name, site_id, time_zone_settings
                    )
                    self.log(
                        "Received API response of 'set_time_zone_for_a_site': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, "set_time_zone_for_a_site"
                    ).check_return_status()

                dns_settings = net_params.get("settings").get("dnsServer")
                if dns_settings is not None:
                    response = self.update_dns_settings_for_site(
                        site_name, site_id, dns_settings
                    )
                    self.log(
                        "Received API response of 'set_d_n_s_settings_for_a_site': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, "set_d_n_s_settings_for_a_site"
                    ).check_return_status()

                banner_settings = net_params.get("settings").get("messageOfTheday")
                if banner_settings is not None:
                    response = self.update_banner_settings_for_site(
                        site_name, site_id, banner_settings
                    )
                    self.log(
                        "Received API response of 'set_banner_settings_for_a_site': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, "set_banner_settings_for_a_site"
                    ).check_return_status()

                if any(
                    [
                        net_params.get("settings", {}).get("snmpServer"),
                        net_params.get("settings", {}).get("syslogServer"),
                        net_params.get("settings", {}).get("netflowcollector"),
                        net_params.get("settings", {}).get("wired_data_collection"),
                        net_params.get("settings", {}).get("wireless_telemetry"),
                    ]
                ):
                    telemetry_settings = {
                        "snmp_server": net_params.get("settings").get("snmpServer"),
                        "syslog_server": net_params.get("settings").get("syslogServer"),
                        "netflowcollector": net_params.get("settings").get(
                            "netflowcollector"
                        ),
                        "wired_data_collection": net_params.get("settings").get(
                            "wired_data_collection"
                        ),
                        "wireless_telemetry": net_params.get("settings").get(
                            "wireless_telemetry"
                        ),
                    }
                    response = self.update_telemetry_settings_for_site(
                        site_name, site_id, telemetry_settings
                    )
                    self.log(
                        "Received API response of 'set_telemetry_settings_for_a_site': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, "set_telemetry_settings_for_a_site"
                    ).check_return_status()

                network_aaa = net_params.get("settings").get("network_aaa")
                client_and_endpoint_aaa = net_params.get("settings").get(
                    "client_and_endpoint_aaa"
                )
                if network_aaa is not None or client_and_endpoint_aaa is not None:
                    response = self.update_aaa_settings_for_site(
                        site_name, site_id, network_aaa, client_and_endpoint_aaa
                    )
                    self.log(
                        "Received API response of 'set_aaa_settings_for_a_site': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, "set_aaa_settings_for_a_site"
                    ).check_return_status()

            self.log(
                "Network under the site '{0}' has been changed successfully".format(
                    site_name
                ),
                "INFO",
            )
            result_network.get("msg").update(
                {site_name: "Network Updated successfully"}
            )
            result_network.get("response").get(site_name).update(
                {
                    "Network Details": self.want.get("wantNetwork")[
                        network_management_index
                    ].get("settings")
                }
            )
            network_management_index += 1

        return self

    def update_device_controllability(self, device_controllability_details):
        """
        Update the Device Controllability settings for a specified site in Cisco Catalyst Center.

        Parameters:
            self - The current object details.
            device_controllability_details (dict): The device controllability settings to be applied. It should contain:
                - device_controllability (bool): Whether device controllability is enabled.
                - autocorrect_telemetry_config (bool): Whether autocorrect telemetry configuration is enabled.

        Returns:
            self: The current object after attempting to update device controllability settings.
        """
        self.log("Starting Device Controllability update process.", "INFO")
        result_device_ctrl = self.result.get("response")[3].get("device_controllability")
        want = self.want.get("want_device_controllability")
        have = self.have.get("have_device_controllability", {})

        self.log("Desired State for device controllability (want): {0}".format(want), "DEBUG")
        self.log("Current State for device controllability (have): {0}".format(have), "DEBUG")

        if not self.requires_update(have, want, self.device_controllability_obj_params):
            self.msg = "Device Controllability configuration does not require an update."
            result_device_ctrl.setdefault("msg", {}).update({"message": self.msg})
            return self

        device_controllability = device_controllability_details.get("device_controllability")
        autocorrect_telemetry_config = device_controllability_details.get("autocorrect_telemetry_config")

        if device_controllability is None:
            self.msg = "'device_controllability' is required in the device_controllability_details."
            self.status = "failed"
            return self.check_return_status()

        self.log("Attempting to update Device Controllability settings: autocorrectTelemetryConfig={0}, deviceControllability={1}".format(
            autocorrect_telemetry_config, device_controllability), "INFO")

        payload = {
            'autocorrectTelemetryConfig': autocorrect_telemetry_config,
            'deviceControllability': device_controllability,
        }

        try:
            response = self.dnac._exec(
                family="site_design",
                function='update_device_controllability_settings',
                op_modifies=True,
                params=payload,
            )
            self.log("Received API response of 'update_device_controllability_settings': {0}".format(response), "DEBUG")
            self.check_tasks_response_status(response, "update_device_controllability_settings").check_return_status()

            # Update the 'msg' field
            self.log("Device Controllability settings updated successfully.", "INFO")
            result_device_ctrl["msg"].update({"message": "Device controllability updated successfully"})

            # Update the 'response' field with your payload
            result_device_ctrl["response"].update({"Device Controllability Details": payload})

        except Exception as e:
            self.msg = (
                "Exception occurred while updating Device Controllability settings: {0}".format(str(e))
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"

        return self

    def get_diff_merged(self, config):
        """
        Update or create Global Pool, Reserve Pool, and
        Network configurations in Cisco Catalyst Center based on the playbook details

        Parameters:
            config (list of dict) - Playbook details containing
            Global Pool, Reserve Pool, and Network Management information.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """

        global_pool = config.get("global_pool_details")
        if global_pool is not None:
            self.update_global_pool(global_pool).check_return_status()

        reserve_pool = config.get("reserve_pool_details")
        if reserve_pool is not None:
            self.update_reserve_pool(reserve_pool).check_return_status()

        network_management = config.get("network_management_details")
        if network_management is not None:
            self.update_network(network_management).check_return_status()

        device_controllability_detail = config.get("device_controllability_details")
        if not device_controllability_detail:
            self.log("No device controllability details provided in the playbook.", "INFO")
            return self
        if device_controllability_detail:
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
                self.update_device_controllability(device_controllability_detail).check_return_status()
            else:
                self.log("Device controlability feature is available for only for version 2.3.7.9 onwards")
                self.msg = "Device controlability feature is available for only for version 2.3.7.9 onwards"
                self.set_operation_result("failed", False, self.msg, "ERROR")
        return self

    def delete_ip_pool(self, name, pool_id, function_name, pool_type):
        """
        Delete single reserve/global pool from based on the pool ID and return
        execution id and status message.

        Parameters:
            name (str) - name contains ip pool name for release ip pool
            pool_id (str) - ID contails IP pool id from get ip pool
            function_name (str) - contains execution of sdk function name either
                                release_reserve_ip_subpool or delete_global_ip_pool
            pool_type (str) - contains string message for log either Reserve or Global

        Returns:
            execution_details (dict) - contains response for the delete execution
            contains name, execution id and status message.
        """
        self.log(
            "{0} IP pool scheduled for deletion: {1}".format(pool_type, name), "INFO"
        )
        self.log("{0} pool '{1}' id: {2}".format(pool_type, name, pool_id), "DEBUG")
        try:
            response = self.dnac._exec(
                family="network_settings",
                function=function_name,
                op_modifies=True,
                params={"id": pool_id},
            )
            execution_id = None
            task_id = None
            if pool_type == "Global":
                success_msg = "Global pool deleted successfully."
                failed_msg = "Unable to delete global pool reservation. "
            else:
                success_msg = "Ip subpool reservation released successfully."
                failed_msg = "Unable to release subpool reservation. "
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
                self.check_tasks_response_status(response, function_name)
                task_id = response["response"]["taskId"]
            else:
                self.check_execution_response_status(response, function_name)
                execution_id = response.get("executionId")
            self.log("Response received from delete {0} pool API: {1}".
                     format(pool_type, self.pprint(response)), "DEBUG")

            if (execution_id or task_id) and self.status == "success":
                return {
                    "name": name,
                    "msg": success_msg,
                    "status": "success",
                }
            self.log("No execution ID received for '{name}'".format(name=name), "ERROR")
            return {
                "name": name,
                "msg": failed_msg + self.msg,
                "status": "failed",
            }

        except Exception as e:
            error_msg = "Exception occurred while deleting the {type} pool with the name '{name}': {error}".format(
                name=name, error=str(e), type=pool_type
            )
            self.log(error_msg, "ERROR")
            return {
                "name": name,
                "execution_id": None,
                "msg": error_msg,
                "status": "failed",
            }

    def delete_reserve_pool(self, reserve_pool_details):
        """
        Delete a Reserve Pool by name in Cisco Catalyst Center

        Parameters:
            reserve_pool_details (list of dict) - Reserverd pool playbook details.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """
        reserve_pool_index = -1
        for item in reserve_pool_details:
            reserve_pool_index += 1
            delete_all = item.get("force_delete")
            site_name = item.get("site_name")
            result_reserve_pool = self.result.get("response")[1].get("reservePool")
            if delete_all:
                self.log(
                    "Delete all reserved pools operation initiated for site '{0}'".format(
                        site_name
                    ),
                    "INFO",
                )
                have_reserve_pool = reserve_pool = self.have.get("reservePool")[
                    reserve_pool_index
                ]
                result_reserve_pool.get("response").update({site_name: []})
                if have_reserve_pool:
                    if isinstance(have_reserve_pool, dict):
                        self.log(
                            "Found reserved pools for site '{0}': {1}".format(
                                site_name, self.pprint(have_reserve_pool)
                            ),
                            "DEBUG",
                        )
                        reserve_pool = have_reserve_pool.get("exists")
                        if not reserve_pool:
                            result_reserve_pool.get("msg").update(
                                {site_name: "Reserve Pool not found"}
                            )
                            self.log(
                                "Reserved IP Subpool '{0}' not found".format(site_name),
                                "INFO",
                            )
                            continue

                    for each_pool in have_reserve_pool:
                        if not each_pool.get("exists"):
                            result_reserve_pool["msg"].update(
                                {site_name: "Reserve Pool not found"}
                            )
                            self.log(
                                "Reserved IP Subpool '{0}' not found for deletion".format(
                                    site_name
                                ),
                                "INFO",
                            )
                            continue

                        pool_name = each_pool.get("details", {}).get("name")
                        pool_id = each_pool.get("id")
                        self.log("Processing deletion for reserved pool '{0}' with ID '{1}'"
                                 .format(pool_name, pool_id), "INFO")
                        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
                            execution_details = self.delete_ip_pool(pool_name, pool_id,
                                                                    "release_an_ip_address_subpool",
                                                                    "Reserve")
                        else:
                            execution_details = self.delete_ip_pool(pool_name, pool_id,
                                                                    "release_reserve_ip_subpool",
                                                                    "Reserve")
                        result_reserve_pool["response"][site_name].append(execution_details)
                        self.log("Deletion completed for reserved pool '{0}' with ID '{1}'"
                                 .format(pool_name, pool_id), "DEBUG")
                    self.reserve_pool_response = result_reserve_pool["response"]
                    if execution_details["status"] == "failed":
                        self.set_operation_result("failed", False, self.msg,
                                                  "ERROR", self.reserve_pool_response).check_return_status()
                else:
                    result_reserve_pool["msg"].update(
                        {site_name: "No Reserve Pools available"}
                    )
                    self.log(
                        "No Reserved IP Subpools found for site '{0}'. Skipping deletion.".format(
                            site_name
                        ),
                        "INFO",
                    )
            else:
                pool_name = item.get("name")
                pool_id = self.have.get("reservePool")[reserve_pool_index].get("id")
                self.log(
                    "Delete operation initiated for specific reserved pool '{0}'".format(
                        pool_name
                    ),
                    "INFO",
                )

                reserve_pool = None
                if self.have.get("reservePool"):
                    reserve_pool = self.have.get("reservePool")[reserve_pool_index].get(
                        "exists"
                    )

                if not reserve_pool:
                    result_reserve_pool.get("msg").update(
                        {pool_name: "Reserve Pool not found"}
                    )
                    self.log(
                        "Reserved IP Subpool '{0}' not found. Skipping deletion.".format(
                            pool_name
                        ),
                        "INFO",
                    )
                    continue

                self.log("Reserved IP pool '{0}' scheduled for deletion".format(pool_name), "INFO")
                self.log("Reserved pool '{0}' ID: {1}".format(pool_name, pool_id), "DEBUG")
                if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
                    execution_details = self.delete_ip_pool(pool_name, pool_id,
                                                            "release_an_ip_address_subpool",
                                                            "Reserve"
                                                            )
                else:
                    execution_details = self.delete_ip_pool(
                        pool_name, pool_id, "release_reserve_ip_subpool", "Reserve"
                    )
                self.log("Deletion completed for reserved pool '{0}' with ID '{1}'".format(pool_name, pool_id), "DEBUG")
                result_reserve_pool["response"].update({pool_name: execution_details})
                self.reserve_pool_response = result_reserve_pool["response"]
                if execution_details["status"] == "failed":
                    self.set_operation_result("failed", False, self.msg,
                                              "ERROR", self.reserve_pool_response).check_return_status()

        self.msg = "Reserved pool(s) released successfully"
        self.status = "success"
        return self

    def delete_global_pool(self, global_pool_details):
        """
        Delete a Global Pool by name in Cisco Catalyst Center

        Parameters:
            global_pool_details (dict) - Global pool details of the playbook

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """

        result_global_pool = self.result.get("response")[0].get("globalPool")
        global_pool_index = 0
        for item in self.have.get("globalPool"):
            if isinstance(item, list):
                self.log("Processing global pool deletion for a list of items", "INFO")
                for each_item in item:
                    global_pool_exists = each_item.get("exists")
                    pool_name = each_item.get("details", {}).get("ipPoolName")
                    global_pool_index += 1

                    if not global_pool_exists:
                        result_global_pool.get("msg").update(
                            {pool_name: "Global Pool not found"}
                        )
                        self.log(
                            "Global pool '{0}' not found".format(pool_name), "INFO"
                        )
                        continue

                    execution_details = {}
                    pool_id = each_item.get("id")
                    if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
                        execution_details = self.delete_ip_pool(pool_name, pool_id,
                                                                "delete_a_global_ip_address_pool",
                                                                "Global")
                    else:
                        execution_details = self.delete_ip_pool(pool_name, pool_id,
                                                                "delete_global_ip_pool",
                                                                "Global")
                    self.log("Deletion completed for global pool '{0}' execution details: '{1}'".
                             format(pool_name, self.pprint(execution_details)), "DEBUG")
                    result_global_pool["response"][pool_name] = execution_details

                self.log(
                    "Deletion completed for global pool all:'{0}'".format(
                        self.pprint(result_global_pool["response"])
                    ),
                    "DEBUG",
                )
                self.global_pool_response = result_global_pool["response"]
                if execution_details["status"] == "failed":
                    self.set_operation_result("failed", False, self.msg,
                                              "ERROR", self.global_pool_response).check_return_status()
            else:
                self.log("Processing global pool deletion for a single item", "INFO")
                global_pool_exists = item.get("exists")
                pool_name = (
                    global_pool_details.get("settings")
                    .get("ip_pool")[global_pool_index]
                    .get("name")
                )
                global_pool_index += 1
                if not global_pool_exists:
                    result_global_pool.get("msg").update(
                        {pool_name: "Global Pool not found"}
                    )
                    self.log(
                        "Global pool '{0}' not found. Skipping deletion.".format(
                            pool_name
                        ),
                        "INFO",
                    )
                    continue

                self.log(
                    "Global pool '{0}' exists. Proceeding with deletion.".format(
                        pool_name
                    ),
                    "INFO",
                )
                id = item.get("id")
                if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0:
                    execution_details = self.delete_ip_pool(pool_name, id,
                                                            "delete_a_global_ip_address_pool",
                                                            "Global")
                else:
                    execution_details = self.delete_ip_pool(pool_name, id,
                                                            "delete_global_ip_pool",
                                                            "Global")
                result_global_pool.get("response").update({pool_name: execution_details})
                self.global_pool_response = result_global_pool.get("response")
                if execution_details["status"] == "failed":
                    self.set_operation_result("failed", False, self.msg,
                                              "ERROR", self.global_pool_response).check_return_status()

        self.msg = "Global pools deleted successfully"
        self.status = "success"
        return self

    def get_diff_deleted(self, config):
        """
        Delete Reserve Pool and Global Pool in Cisco Catalyst Center based on playbook details.

        Parameters:
            config (list of dict) - Playbook details

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """

        reserve_pool_details = config.get("reserve_pool_details")
        if reserve_pool_details is not None:
            self.delete_reserve_pool(reserve_pool_details).check_return_status()

        global_pool_details = config.get("global_pool_details")
        if global_pool_details is not None:
            self.delete_global_pool(global_pool_details).check_return_status()

        return self

    def verify_diff_merged(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """

        self.all_reserved_pool_details = {}
        self.get_have(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Requested State (want): {0}".format(self.want), "INFO")
        if config.get("global_pool_details") is not None:
            global_pool_index = 0
            self.log(
                "Desired State of global pool (want): {0}".format(
                    self.want.get("wantGlobal")
                ),
                "DEBUG",
            )
            self.log(
                "Current State of global pool (have): {0}".format(
                    self.have.get("globalPool")
                ),
                "DEBUG",
            )
            for item in self.want.get("wantGlobal").get("settings").get("ippool"):
                global_pool_details = self.have.get("globalPool")[
                    global_pool_index
                ].get("details")
                if not global_pool_details:
                    self.msg = (
                        "The global pool is not created with the config: {0}".format(
                            item
                        )
                    )
                    self.status = "failed"
                    return self

                if self.requires_update(
                    global_pool_details, item, self.global_pool_obj_params
                ):
                    self.msg = (
                        "Global Pool Config is not applied to the Cisco Catalyst Center"
                    )
                    self.status = "failed"
                    return self

                global_pool_index += 1

            self.log("Successfully validated global pool(s).", "INFO")
            self.result.get("response")[0].get("globalPool").update(
                {"Validation": "Success"}
            )

        if config.get("reserve_pool_details") is not None:
            reserve_pool_index = 0
            self.log(
                "Desired State for reserve pool (want): {0}".format(
                    self.want.get("wantReserve")
                ),
                "DEBUG",
            )
            self.log(
                "Current State for reserve pool (have): {0}".format(
                    self.have.get("reservePool")
                ),
                "DEBUG",
            )
            for item in self.want.get("wantReserve"):
                reserve_pool_details = self.have.get("reservePool")[
                    reserve_pool_index
                ].get("details")
                if not reserve_pool_details:
                    self.msg = (
                        "The reserve pool is not created with the config: {0}".format(
                            item
                        )
                    )
                    self.status = "failed"
                    return self

                if self.requires_update(
                    reserve_pool_details, item, self.reserve_pool_obj_params
                ):
                    self.msg = "Reserved Pool Config is not applied to the Cisco Catalyst Center"
                    self.status = "failed"
                    return self

                reserve_pool_index += 1

            self.log("Successfully validated the reserved pool(s)", "INFO")
            self.result.get("response")[1].get("reservePool").update(
                {"Validation": "Success"}
            )

        network_management_details = config.get("network_management_details")
        if network_management_details is not None:
            network_management_index = 0
            for item in network_management_details:
                if self.requires_update(
                    self.have.get("network")[network_management_index].get(
                        "net_details"
                    ),
                    self.want.get("wantNetwork")[network_management_index],
                    self.network_obj_params,
                ):
                    self.msg = "Network Functions Config is not applied to the Cisco Catalyst Center"
                    self.status = "failed"
                    return self

                want_network_aaa = self.want.get("wantNetwork")[network_management_index].get("settings", {}).get("network_aaa", {})
                have_net_details = self.have.get("network")[network_management_index].get("net_details")
                have_aaa_primary_ip = have_net_details.get("settings", {}).get("network_aaa", {}).get("primaryServerIp", "")

                # RESET CASE (both empty)
                if want_network_aaa == {} and have_aaa_primary_ip not in ("", None):
                    self.msg = "Network AAA Primary IP update not applied on Cisco Catalyst Center"
                    self.status = "failed"
                    return self

                self.log(
                    "Successfully validated the network functions '{0}'.".format(
                        item.get("site_name")
                    ),
                    "INFO",
                )
                network_management_index += 1

            self.result.get("response")[2].get("network").update(
                {"Validation": "Success"}
            )

        device_ctrl_config = config.get("device_controllability_details")
        if device_ctrl_config:
            want = self.want.get("want_device_controllability")
            have = self.have.get("have_device_controllability", {})

            self.log("Desired State for device controllability (want): {0}".format(want), "DEBUG")
            self.log("Current State for device controllability (have): {0}".format(have), "DEBUG")

            if self.requires_update(have, want, self.device_controllability_obj_params):
                self.msg = "Device Controllability Config is not applied to the Cisco Catalyst Center"
                self.status = "failed"
                return self

            self.log("Successfully validated the device controllability config", "INFO")
            self.result["response"][3]["device_controllability"]["Validation"] = "Success"

        self.msg = "Successfully validated the Global Pool, Reserve Pool, Network Functions and the Device Controlability."
        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is deleted (delete).

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """

        self.all_reserved_pool_details = {}
        self.get_have(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Desired State (want): {0}".format(self.want), "INFO")
        delete_all = []
        if config.get("global_pool_details") is not None:
            self.log("Starting validation for Global Pool absence.", "INFO")
            global_pool_index = 0
            global_pool_details = self.have.get("globalPool")
            for item in global_pool_details:
                if isinstance(item, dict):
                    global_pool_exists = item.get("exists")
                    name = (
                        config.get("global_pool_details")
                        .get("settings")
                        .get("ip_pool")[global_pool_index]
                        .get("name")
                    )
                    if global_pool_exists:
                        self.msg = "Global Pool Config '{0}' is not applied to the Cisco Catalyst Center".format(
                            name
                        )
                        self.status = "failed"
                        return self

                    self.log(
                        "Successfully validated absence of Global Pool '{0}'.".format(
                            name
                        ),
                        "INFO",
                    )
                else:
                    if len(item) > 0:
                        for each_ip_pool in item:
                            each_pool_validation = {}
                            global_pool_exists = each_ip_pool.get("exists")
                            name = each_ip_pool.get("details", {}).get("ipPoolName")
                            if global_pool_exists:
                                each_pool_validation = {
                                    "name": name,
                                    "msg": "Global Pool Config is not applied to the Catalyst Center.",
                                    "validation": "failed",
                                }
                            delete_all.append(each_pool_validation)

                global_pool_index += 1

            if delete_all:
                self.msg = "Global Pool Config is not applied to the Catalyst Center"
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR", self.global_pool_response
                ).check_return_status()
                return self

            if not delete_all and not self.global_pool_response:
                self.msg = "Global Pool Config does not exist or already deleted from the Catalyst Center"
                self.set_operation_result(
                    "success", False, self.msg, "ERROR"
                ).check_return_status()
                return self

            self.result.get("response")[0].get("globalPool").update(
                {"Validation": "Success"}
            )
            self.msg = "Successfully validated the absence of Global Pool."
            self.log(self.msg, "INFO")
            self.log(
                "Last Check {0}".format(
                    self.result.get("response")[0].get("globalPool")
                ),
                "INFO",
            )
            del_response = (
                self.result.get("response")[0].get("globalPool").get("response")
            )
            delete_all.append(del_response)
            self.set_operation_result(
                "success", True, self.msg, "INFO", self.global_pool_response
            ).check_return_status()

        if config.get("reserve_pool_details") is not None:
            self.log("Starting validation for Reserve Pool absence.", "INFO")
            reserve_pool_index = 0
            reserve_pool_details = self.have.get("reservePool")

            for item in reserve_pool_details:
                site_name = config.get("reserve_pool_details")[reserve_pool_index].get(
                    "site_name"
                )
                if isinstance(item, dict):
                    reserve_pool_exists = item.get("exists")
                    name = config.get("reserve_pool_details")[reserve_pool_index].get(
                        "name"
                    )

                    if reserve_pool_exists:
                        self.msg = "Reserved Pool Config '{0}' is not applied to the Catalyst Center".format(
                            name
                        )
                        self.fail_and_exit(self.msg)
                        return self

                    self.log(
                        "Successfully validated the absence of Reserve Pool '{0}'.".format(
                            name
                        ),
                        "INFO",
                    )
                    reserve_pool_index += 1

                    if self.result.get("response"):
                        self.result.get("response")[1].get("reservePool").update(
                            {"Validation": "Success"}
                        )

                else:
                    if len(item) > 0:
                        for each_ip_pool in item:
                            each_pool_validation = {}
                            reserve_pool_exists = each_ip_pool.get("exists")
                            if reserve_pool_exists:
                                self.log(
                                    "Reserve Pool '{0}' found. Marking as failed validation.".format(
                                        name
                                    ),
                                    "ERROR",
                                )
                                each_pool_validation = {
                                    "site_name": site_name,
                                    "name": each_ip_pool.get("details", {}).get("name"),
                                    "msg": "Reserved Pool Config is not applied to the Catalyst Center",
                                    "validation": "failed",
                                }
                            delete_all.append(each_pool_validation)

                    reserve_pool_index += 1

            if delete_all:
                self.msg = "Reserved Pool Config is not applied to the Catalyst Center"
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR", delete_all
                ).check_return_status()

            if not delete_all and not self.reserve_pool_response:
                self.msg = "Reserve Pool Config does not exist or already deleted from the Catalyst Center"
                self.set_operation_result(
                    "success", False, self.msg, "ERROR"
                ).check_return_status()
                return self

            self.msg = "Successfully validated the absence of Reserve Pool."
            self.log(self.msg, "INFO")
            del_response = (
                self.result.get("response")[1].get("reservePool").get("response")
            )
            delete_all.append(del_response)
            self.set_operation_result(
                "success", True, self.msg, "INFO", self.reserve_pool_response
            ).check_return_status()

        self.msg = "Successfully validated the absence of Global Pool/Reserve Pool"
        self.status = "success"
        return self

    def reset_values(self):
        """
        Reset all neccessary attributes to default values

        Parameters:
            None

        Returns:
            None
        """

        self.have.clear()
        self.want.clear()
        return


def main():
    """main entry point for module execution"""

    # Define the specification for module arguments
    element_spec = {
        "dnac_host": {"type": "str", "required": True},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_network = NetworkSettings(module)
    state = ccc_network.params.get("state")

    if ccc_network.compare_dnac_versions(ccc_network.get_ccc_version(), "2.3.5.3") < 0:
        ccc_network.msg = """The specified version '{0}' does not support the Network_settings_workflow features.
        Supported versions start from '2.3.5.3' onwards. """.format(
            ccc_network.get_ccc_version()
        )
        ccc_network.status = "failed"
        ccc_network.check_return_status()

    config_verify = ccc_network.params.get("config_verify")
    if state not in ccc_network.supported_states:
        ccc_network.status = "invalid"
        ccc_network.msg = "State {0} is invalid".format(state)
        ccc_network.check_return_status()

    ccc_network.validate_input().check_return_status()

    for config in ccc_network.config:
        ccc_network.reset_values()
        ccc_network.get_have(config).check_return_status()
        if state != "deleted":
            ccc_network.get_want(config).check_return_status()
        ccc_network.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_network.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_network.result)


if __name__ == "__main__":
    main()
