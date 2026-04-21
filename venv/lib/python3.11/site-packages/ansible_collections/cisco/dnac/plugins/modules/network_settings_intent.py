#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2023, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to perform operations on global pool, reserve pool and network in DNAC."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["Muthu Rakesh, Madhan Sankaranarayanan"]
DOCUMENTATION = r"""
---
module: network_settings_intent
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
  - cisco.dnac.intent_params
author: Muthu Rakesh (@MUTHU-RAKESH-27) Madhan Sankaranarayanan
  (@madhansansel)
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
                  gateway:
                    description: Serves as an entry
                      or exit point for data traffic
                      between networks.
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
                  prev_name:
                    description: >
                      The former identifier for the
                      global pool. It should be used
                      exclusively when you need to update
                      the global pool's name.
                    type: str
                  name:
                    description: Specifies the name
                      assigned to the Global IP Pool.
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
      reserve_pool_details:
        description: Reserved IP subpool details from
          the global pool.
        type: dict
        suboptions:
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
          ipv4_gateway:
            description: Provides the gateway's IPv4
              address, for example, "175.175.0.1".
            type: str
            version_added: 4.0.0
          ipv4_global_pool:
            description: IP v4 Global pool address with
              cidr, example 175.175.0.0/16.
            type: str
          ipv4_prefix:
            description: ip4 prefix length is enabled
              or ipv4 total Host input is enabled
            type: bool
          ipv4_prefix_length:
            description: The ipv4 prefix length is required
              when ipv4_prefix value is true.
            type: int
          ipv4_subnet:
            description: Indicates the IPv4 subnet address,
              for example, "175.175.0.0".
            type: str
          ipv4_total_host:
            description: The total number of hosts for
              IPv4, required when the 'ipv4_prefix'
              is set to false.
            type: int
          ipv6_address_space:
            description: >
              Determines whether both IPv6 and IPv4
              inputs are required. If set to false,
              only IPv4 inputs are required. If set
              to true, both IPv6 and IPv4 inputs are
              required.
            type: bool
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
            description: >
              IPv6 Global pool address with cidr this
              is required when ipv6_address_space value
              is true, example 2001 db8 85a3 /64.
            type: str
          ipv6_prefix:
            description: >
              Ipv6 prefix value is true, the ip6 prefix
              length input field is enabled, if it is
              false ipv6 total Host input is enable.
            type: bool
          ipv6_prefix_length:
            description: IPv6 prefix length is required
              when the ipv6_prefix value is true.
            type: int
          ipv6_subnet:
            description: IPv6 Subnet address, example
              2001 db8 85a3 0 100.
            type: str
          ipv6_total_host:
            description: The total number of hosts for
              IPv6 is required if the 'ipv6_prefix'
              is set to false.
            type: int
          name:
            description: Name of the reserve IP subpool.
            type: str
          prev_name:
            description: The former name associated
              with the reserved IP sub-pool.
            type: str
          site_name:
            description: >
              The name of the site provided as a path
              parameter, used to specify where the IP
              sub-pool will be reserved.
            type: str
          slaac_support:
            description: >
              Allows devices on IPv6 networks to self-configure
              their IP addresses autonomously, eliminating
              the need for manual setup.
            type: bool
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
      network_management_details:
        description: Set default network settings for
          the site
        type: dict
        suboptions:
          settings:
            description: Network management details
              settings.
            type: dict
            suboptions:
              client_and_endpoint_aaa:
                description: Network V2's clientAndEndpoint_aaa.
                suboptions:
                  ip_address:
                    description: IP address for ISE
                      serve (eg 1.1.1.4).
                    type: str
                  network:
                    description: IP address for AAA
                      or ISE server (eg 2.2.2.1).
                    type: str
                  protocol:
                    description: Protocol for AAA or
                      ISE serve (eg RADIUS).
                    type: str
                  servers:
                    description: Server type AAA or
                      ISE server (eg AAA).
                    type: str
                  shared_secret:
                    description: Shared secret for ISE
                      server.
                    type: str
                type: dict
              dhcp_server:
                description: DHCP Server IP (eg 1.1.1.1).
                elements: str
                type: list
              dns_server:
                description: Network V2's dnsServer.
                suboptions:
                  domain_name:
                    description: Domain Name of DHCP
                      (eg; cisco).
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
              message_of_the_day:
                description: Network V2's messageOfTheday.
                suboptions:
                  banner_message:
                    description: Massage for Banner
                      message (eg; Good day).
                    type: str
                  retain_existing_banner:
                    description: Retain existing Banner
                      Message (eg "true" or "false").
                    type: str
                type: dict
              netflow_collector:
                description: Network V2's netflowcollector.
                suboptions:
                  ip_address:
                    description: IP Address for NetFlow
                      collector (eg 3.3.3.1).
                    type: str
                  port:
                    description: Port for NetFlow Collector
                      (eg; 443).
                    type: int
                type: dict
              network_aaa:
                description: Network V2's network_aaa.
                suboptions:
                  ip_address:
                    description: IP address for AAA
                      and ISE server (eg 1.1.1.1).
                    type: str
                  network:
                    description: IP Address for AAA
                      or ISE server (eg 2.2.2.2).
                    type: str
                  protocol:
                    description: Protocol for AAA or
                      ISE serve (eg RADIUS).
                    type: str
                  servers:
                    description: Server type for AAA
                      Network (eg AAA).
                    type: str
                  shared_secret:
                    description: Shared secret for ISE
                      Server.
                    type: str
                type: dict
              ntp_server:
                description: IP address for NTP server
                  (eg 1.1.1.2).
                elements: str
                type: list
              snmp_server:
                description: Network V2's snmpServer.
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
                description: Network V2's syslogServer.
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
              timezone:
                description: Input for time zone (eg
                  Africa/Abidjan).
                type: str
          site_name:
            description: >
              The name of the site provided as a path
              parameter, used to specify where the IP
              sub-pool will be reserved.
            type: str
requirements:
  - dnacentersdk == 2.4.5
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
  - Paths used are
    post /dna/intent/api/v1/global-pool,
    delete /dna/intent/api/v1/global-pool/{id},
    put
    /dna/intent/api/v1/global-pool,
    post /dna/intent/api/v1/reserve-ip-subpool/{siteId},
    delete /dna/intent/api/v1/reserve-ip-subpool/{id},
    put /dna/intent/api/v1/reserve-ip-subpool/{siteId},
    put /dna/intent/api/v2/network/{siteId},
"""
EXAMPLES = r"""
---
- name: Create global pool, reserve an ip pool and network
  cisco.dnac.network_settings_intent:
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
                gateway: string
                ip_address_space: string
                cidr: string
                pool_type: Generic
                dhcp_server_ips: list
                dns_server_ips: list
        reserve_pool_details:
          ipv6_address_space: true
          ipv4_global_pool: string
          ipv4_prefix: true
          ipv4_prefix_length: 9
          ipv4_subnet: string
          name: string
          ipv6_prefix: true
          ipv6_prefix_length: 64
          ipv6_global_pool: string
          ipv6_subnet: string
          site_name: string
          slaac_support: true
          pool_type: LAN
        network_management_details:
          settings:
            dhcp_server: list
            dns_server:
              domain_name: string
              primary_ip_address: string
              secondary_ip_address: string
            client_and_endpoint_aaa:
              network: string
              protocol: string
              servers: string
            message_of_the_day:
              banner_message: string
              retain_existing_banner: string
            netflow_collector:
              ip_address: string
              port: 443
            network_aaa:
              network: string
              protocol: string
              servers: string
            ntp_server: list
            snmp_server:
              configure_dnac_ip: true
              ip_addresses: list
            syslog_server:
              configure_dnac_ip: true
              ip_addresses: list
          site_name: string
"""
RETURN = r"""
# Case_1: Successful creation/updation/deletion of global pool
response_1:
  description: A dictionary or list with the response returned by the Cisco DNA Center Python SDK
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
  description: A dictionary or list with the response returned by the Cisco DNA Center Python SDK
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
  description: A dictionary or list with the response returned by the Cisco DNA Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    dnac_compare_equality,
)


class NetworkSettings(DnacBase):
    """Class containing member attributes for network intent module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = [
            {"globalPool": {"response": {}, "msg": {}}},
            {"reservePool": {"response": {}, "msg": {}}},
            {"network": {"response": {}, "msg": {}}},
        ]
        self.global_pool_obj_params = self.get_obj_params("GlobalPool")
        self.reserve_pool_obj_params = self.get_obj_params("ReservePool")
        self.network_obj_params = self.get_obj_params("Network")

    def validate_input(self):
        """
        Checks if the configuration parameters provided in the playbook
        meet the expected structure and data types,
        as defined in the 'temp_spec' dictionary.

        Parameters:
            None

        Returns:
            self

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
                        "ip_address_space": {"type": "string"},
                        "dhcp_server_ips": {"type": "list"},
                        "dns_server_ips": {"type": "list"},
                        "gateway": {"type": "string"},
                        "cidr": {"type": "string"},
                        "name": {"type": "string"},
                        "prevName": {"type": "string"},
                        "pool_type": {
                            "type": "string",
                            "choices": [
                                "Generic",
                                "LAN",
                                "Management",
                                "Service",
                                "WAN",
                            ],
                        },
                    },
                },
            },
            "reserve_pool_details": {
                "type": "dict",
                "name": {"type": "string"},
                "prevName": {"type": "string"},
                "ipv6_address_space": {"type": "bool"},
                "ipv4_global_pool": {"type": "string"},
                "ipv4_prefix": {"type": "bool"},
                "ipv4_prefix_length": {"type": "string"},
                "ipv4_subnet": {"type": "string"},
                "ipv4GateWay": {"type": "string"},
                "ipv4DhcpServers": {"type": "list"},
                "ipv4_dns_servers": {"type": "list"},
                "ipv6_global_pool": {"type": "string"},
                "ipv6_prefix": {"type": "bool"},
                "ipv6_prefix_length": {"type": "integer"},
                "ipv6_subnet": {"type": "string"},
                "ipv6GateWay": {"type": "string"},
                "ipv6DhcpServers": {"type": "list"},
                "ipv6DnsServers": {"type": "list"},
                "ipv4TotalHost": {"type": "integer"},
                "ipv6TotalHost": {"type": "integer"},
                "slaac_support": {"type": "bool"},
                "site_name": {"type": "string"},
                "pool_type": {
                    "type": "string",
                    "choices": ["Generic", "LAN", "Management", "Service", "WAN"],
                },
            },
            "network_management_details": {
                "type": "dict",
                "settings": {
                    "type": "dict",
                    "dhcp_server": {"type": "list"},
                    "dns_server": {
                        "type": "dict",
                        "domain_name": {"type": "string"},
                        "primary_ip_address": {"type": "string"},
                        "secondary_ip_address": {"type": "string"},
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
                    "netflow_collector": {
                        "type": "dict",
                        "ip_address": {"type": "string"},
                        "port": {"type": "integer"},
                    },
                    "timezone": {"type": "string"},
                    "ntp_server": {"type": "list"},
                    "message_of_the_day": {
                        "type": "dict",
                        "banner_message": {"type": "string"},
                        "retain_existing_banner": {"type": "bool"},
                    },
                    "network_aaa": {
                        "type": "dict",
                        "servers": {"type": "string", "choices": ["ISE", "AAA"]},
                        "ip_address": {"type": "string"},
                        "network": {"type": "string"},
                        "protocol": {"type": "string", "choices": ["RADIUS", "TACACS"]},
                        "shared_secret": {"type": "string"},
                    },
                    "client_and_endpoint_aaa": {
                        "type": "dict",
                        "servers": {"type": "string", "choices": ["ISE", "AAA"]},
                        "ip_address": {"type": "string"},
                        "network": {"type": "string"},
                        "protocol": {"type": "string", "choices": ["RADIUS", "TACACS"]},
                        "shared_secret": {"type": "string"},
                    },
                },
                "site_name": {"type": "string"},
            },
        }

        # Validate playbook params against the specification (temp_spec)
        self.config = self.camel_to_snake_case(self.config)
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
        or network details from Cisco DNA Center with the user-provided details
        from the playbook, using a specified schema for comparison.

        Parameters:
            have (dict) - Current information from the Cisco DNA Center
                          (global pool, reserve pool, network details)
            want (dict) - Users provided information from the playbook
            obj_params (list of tuples) - A list of parameter mappings specifying which
                                          Cisco DNA Center parameters (dnac_param) correspond to
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
                    ("settings", "settings"),
                ]
            elif get_object == "ReservePool":
                obj_params = [
                    ("name", "name"),
                    ("type", "type"),
                    ("ipv6AddressSpace", "ipv6AddressSpace"),
                    ("ipv4GlobalPool", "ipv4GlobalPool"),
                    ("ipv4Prefix", "ipv4Prefix"),
                    ("ipv4PrefixLength", "ipv4PrefixLength"),
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
                obj_params = [("settings", "settings"), ("site_name", "site_name")]
            else:
                raise ValueError(
                    "Received an unexpected value for 'get_object': {0}".format(
                        get_object
                    )
                )
        except Exception as msg:
            self.log("Received exception: {0}".format(msg), "CRITICAL")

        return obj_params

    def get_site_id(self, site_name):
        """
        Get the site id from the site name.
        Use check_return_status() to check for failure

        Parameters:
            site_name (str) - Site name

        Returns:
            str or None - The Site Id if found, or None if not found or error
        """

        try:
            response = self.dnac._exec(
                family="sites",
                function="get_site",
                op_modifies=True,
                params={"name": site_name},
            )
            self.log(
                "Received API response from 'get_site': {0}".format(response), "DEBUG"
            )
            if not response:
                self.log(
                    "Failed to retrieve the site ID for the site name: {0}".format(
                        site_name
                    ),
                    "ERROR",
                )
                return None

            _id = response.get("response")[0].get("id")
            self.log("Site ID for site name '{0}': {1}".format(site_name, _id), "DEBUG")
        except Exception as msg:
            self.log(
                "Exception occurred while retrieving site_id from the site_name: {0}".format(
                    msg
                ),
                "CRITICAL",
            )
            return None

        return _id

    def get_global_pool_params(self, pool_info):
        """
        Process Global Pool params from playbook data for Global Pool config in Cisco DNA Center

        Parameters:
            pool_info (dict) - Playbook data containing information about the global pool

        Returns:
            dict or None - Processed Global Pool data in a format suitable
            for Cisco DNA Center configuration, or None if pool_info is empty.
        """

        if not pool_info:
            self.log("Global Pool is empty", "INFO")
            return None

        self.log("Global Pool Details: {0}".format(pool_info), "DEBUG")
        global_pool = {
            "settings": {
                "ippool": [
                    {
                        "dhcpServerIps": pool_info.get("dhcpServerIps"),
                        "dnsServerIps": pool_info.get("dnsServerIps"),
                        "ipPoolCidr": pool_info.get("ipPoolCidr"),
                        "ipPoolName": pool_info.get("ipPoolName"),
                        "type": pool_info.get("ipPoolType").capitalize(),
                    }
                ]
            }
        }
        self.log("Formated global pool details: {0}".format(global_pool), "DEBUG")
        global_ippool = global_pool.get("settings").get("ippool")[0]
        if pool_info.get("ipv6") is False:
            global_ippool.update({"IpAddressSpace": "IPv4"})
        else:
            global_ippool.update({"IpAddressSpace": "IPv6"})

        self.log(
            "ip_address_space: {0}".format(global_ippool.get("IpAddressSpace")), "DEBUG"
        )
        if not pool_info["gateways"]:
            global_ippool.update({"gateway": ""})
        else:
            global_ippool.update({"gateway": pool_info.get("gateways")[0]})

        return global_pool

    def get_reserve_pool_params(self, pool_info):
        """
        Process Reserved Pool parameters from playbook data
        for Reserved Pool configuration in Cisco DNA Center

        Parameters:
            pool_info (dict) - Playbook data containing information about the reserved pool

        Returns:
            reserve_pool (dict) - Processed Reserved pool data
            in the format suitable for the Cisco DNA Center config
        """

        reserve_pool = {
            "name": pool_info.get("groupName"),
            "site_id": pool_info.get("siteId"),
        }
        if len(pool_info.get("ipPools")) == 1:
            reserve_pool.update(
                {
                    "ipv4DhcpServers": pool_info.get("ipPools")[0].get("dhcpServerIps"),
                    "ipv4DnsServers": pool_info.get("ipPools")[0].get("dnsServerIps"),
                    "ipv6AddressSpace": "False",
                }
            )
            if pool_info.get("ipPools")[0].get("gateways") != []:
                reserve_pool.update(
                    {"ipv4GateWay": pool_info.get("ipPools")[0].get("gateways")[0]}
                )
            else:
                reserve_pool.update({"ipv4GateWay": ""})
            reserve_pool.update({"ipv6AddressSpace": "False"})
        elif len(pool_info.get("ipPools")) == 2:
            if not pool_info.get("ipPools")[0].get("ipv6"):
                reserve_pool.update(
                    {
                        "ipv4DhcpServers": pool_info.get("ipPools")[0].get(
                            "dhcpServerIps"
                        ),
                        "ipv4DnsServers": pool_info.get("ipPools")[0].get(
                            "dnsServerIps"
                        ),
                        "ipv6AddressSpace": "True",
                        "ipv6DhcpServers": pool_info.get("ipPools")[1].get(
                            "dhcpServerIps"
                        ),
                        "ipv6DnsServers": pool_info.get("ipPools")[1].get(
                            "dnsServerIps"
                        ),
                    }
                )

                if pool_info.get("ipPools")[0].get("gateways") != []:
                    reserve_pool.update(
                        {"ipv4GateWay": pool_info.get("ipPools")[0].get("gateways")[0]}
                    )
                else:
                    reserve_pool.update({"ipv4GateWay": ""})

                if pool_info.get("ipPools")[1].get("gateways") != []:
                    reserve_pool.update(
                        {"ipv6GateWay": pool_info.get("ipPools")[1].get("gateways")[0]}
                    )
                else:
                    reserve_pool.update({"ipv6GateWay": ""})

            elif not pool_info.get("ipPools")[1].get("ipv6"):
                reserve_pool.update(
                    {
                        "ipv4DhcpServers": pool_info.get("ipPools")[1].get(
                            "dhcpServerIps"
                        ),
                        "ipv4DnsServers": pool_info.get("ipPools")[1].get(
                            "dnsServerIps"
                        ),
                        "ipv6AddressSpace": "True",
                        "ipv6DnsServers": pool_info.get("ipPools")[0].get(
                            "dnsServerIps"
                        ),
                        "ipv6DhcpServers": pool_info.get("ipPools")[0].get(
                            "dhcpServerIps"
                        ),
                    }
                )
                if pool_info.get("ipPools")[1].get("gateways") != []:
                    reserve_pool.update(
                        {"ipv4GateWay": pool_info.get("ipPools")[1].get("gateways")[0]}
                    )
                else:
                    reserve_pool.update({"ipv4GateWay": ""})

                if pool_info.get("ipPools")[0].get("gateways") != []:
                    reserve_pool.update(
                        {"ipv6GateWay": pool_info.get("ipPools")[0].get("gateways")[0]}
                    )
                else:
                    reserve_pool.update({"ipv6GateWay": ""})
        reserve_pool.update({"slaacSupport": True})
        self.log("Formatted reserve pool details: {0}".format(reserve_pool), "DEBUG")
        return reserve_pool

    def get_network_params(self, site_id):
        """
        Process the Network parameters from the playbook
        for Network configuration in Cisco DNA Center

        Parameters:
            site_id (str) - The Site ID for which network parameters are requested

        Returns:
            dict or None: Processed Network data in a format
            suitable for Cisco DNA Center configuration, or None
            if the response is not a dictionary or there was an error.
        """

        response = self.dnac._exec(
            family="network_settings",
            function="get_network_v2",
            op_modifies=True,
            params={"site_id": site_id},
        )
        self.log(
            "Received API response from 'get_network_v2': {0}".format(response), "DEBUG"
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
        clientAndEndpoint_aaa = get_dict_result(
            all_network_details, "key", "aaa.endpoint.server.1"
        )
        clientAndEndpoint_aaa2 = get_dict_result(
            all_network_details, "key", "aaa.endpoint.server.2"
        )
        clientAndEndpoint_aaa_pan = get_dict_result(
            all_network_details, "key", "aaa.server.pan.endpoint"
        )

        # Prepare the network details for Cisco DNA Center configuration
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
                "netflowcollector": {
                    "ipAddress": netflow_details.get("value")[0].get("ipAddress"),
                    "port": netflow_details.get("value")[0].get("port"),
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

        if ntpserver_details and ntpserver_details.get("value") != []:
            network_settings.update({"ntpServer": ntpserver_details.get("value")})
        else:
            network_settings.update({"ntpServer": [""]})

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

        if network_aaa and network_aaa_pan:
            aaa_pan_value = network_aaa_pan.get("value")[0]
            aaa_value = network_aaa.get("value")[0]
            if aaa_pan_value == "None":
                network_settings.update(
                    {
                        "network_aaa": {
                            "network": aaa_value.get("ipAddress"),
                            "protocol": aaa_value.get("protocol"),
                            "ipAddress": network_aaa2.get("value")[0].get("ipAddress"),
                            "servers": "AAA",
                        }
                    }
                )
            else:
                network_settings.update(
                    {
                        "network_aaa": {
                            "network": aaa_value.get("ipAddress"),
                            "protocol": aaa_value.get("protocol"),
                            "ipAddress": aaa_pan_value,
                            "servers": "ISE",
                        }
                    }
                )

        if clientAndEndpoint_aaa and clientAndEndpoint_aaa_pan:
            aaa_pan_value = clientAndEndpoint_aaa_pan.get("value")[0]
            aaa_value = clientAndEndpoint_aaa.get("value")[0]
            if aaa_pan_value == "None":
                network_settings.update(
                    {
                        "clientAndEndpoint_aaa": {
                            "network": aaa_value.get("ipAddress"),
                            "protocol": aaa_value.get("protocol"),
                            "ipAddress": clientAndEndpoint_aaa2.get("value")[0].get(
                                "ipAddress"
                            ),
                            "servers": "AAA",
                        }
                    }
                )
            else:
                network_settings.update(
                    {
                        "clientAndEndpoint_aaa": {
                            "network": aaa_value.get("ipAddress"),
                            "protocol": aaa_value.get("protocol"),
                            "ipAddress": aaa_pan_value,
                            "servers": "ISE",
                        }
                    }
                )

        self.log(
            "Formatted playbook network details: {0}".format(network_details), "DEBUG"
        )
        return network_details

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
        response = self.dnac._exec(
            family="network_settings",
            function="get_global_pool",
        )
        if not isinstance(response, dict):
            self.log(
                "Failed to retrieve the global pool details - "
                "Response is not a dictionary",
                "CRITICAL",
            )
            return global_pool

        all_global_pool_details = response.get("response")
        global_pool_details = get_dict_result(
            all_global_pool_details, "ipPoolName", name
        )
        self.log("Global ip pool name: {0}".format(name), "DEBUG")
        self.log("Global pool details: {0}".format(global_pool_details), "DEBUG")
        if not global_pool_details:
            self.log("Global pool {0} does not exist".format(name), "INFO")
            return global_pool
        global_pool.update({"exists": True})
        global_pool.update({"id": global_pool_details.get("id")})
        global_pool["details"] = self.get_global_pool_params(global_pool_details)

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
        site_id = self.get_site_id(site_name)
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

        response = self.dnac._exec(
            family="network_settings",
            function="get_reserve_ip_subpool",
            op_modifies=True,
            params={"siteId": site_id},
        )
        if not isinstance(response, dict):
            reserve_pool.update({"success": False})
            self.msg = "Error in getting reserve pool - Response is not a dictionary"
            self.status = "exited"
            return reserve_pool

        all_reserve_pool_details = response.get("response")
        reserve_pool_details = get_dict_result(
            all_reserve_pool_details, "groupName", name
        )
        if not reserve_pool_details:
            self.log(
                "Reserved pool {0} does not exist in the site {1}".format(
                    name, site_name
                ),
                "DEBUG",
            )
            return reserve_pool

        reserve_pool.update({"exists": True})
        reserve_pool.update({"id": reserve_pool_details.get("id")})
        reserve_pool.update(
            {"details": self.get_reserve_pool_params(reserve_pool_details)}
        )

        self.log(
            "Reserved pool details: {0}".format(reserve_pool.get("details")), "DEBUG"
        )
        self.log("Reserved pool id: {0}".format(reserve_pool.get("id")), "DEBUG")
        return reserve_pool

    def get_have_global_pool(self, config):
        """
        Get the current Global Pool information from
        Cisco DNA Center based on the provided playbook details.
        check this API using check_return_status.

        Parameters:
            config (dict) - Playbook details containing Global Pool configuration.

        Returns:
            self - The current object with updated information.
        """

        global_pool = {"exists": False, "details": None, "id": None}
        global_pool_settings = config.get("global_pool_details").get("settings")
        if global_pool_settings is None:
            self.msg = "settings in global_pool_details is missing in the playbook"
            self.status = "failed"
            return self

        global_pool_ippool = global_pool_settings.get("ip_pool")
        if global_pool_ippool is None:
            self.msg = "ip_pool in global_pool_details is missing in the playbook"
            self.status = "failed"
            return self

        name = global_pool_ippool[0].get("name")
        if name is None:
            self.msg = "Mandatory Parameter name required"
            self.status = "failed"
            return self

        # If the Global Pool doesn't exist and a previous name is provided
        # Else try using the previous name
        global_pool = self.global_pool_exists(name)
        self.log("Global pool details: {0}".format(global_pool), "DEBUG")
        prev_name = global_pool_ippool[0].get("prev_name")
        if global_pool.get("exists") is False and prev_name is not None:
            global_pool = self.global_pool_exists(prev_name)
            if global_pool.get("exists") is False:
                self.msg = "Prev name {0} doesn't exist in global_pool_details".format(
                    prev_name
                )
                self.status = "failed"
                return self

        self.log("Global pool exists: {0}".format(global_pool.get("exists")), "DEBUG")
        self.log("Current Site: {0}".format(global_pool.get("details")), "DEBUG")
        self.have.update({"globalPool": global_pool})
        self.msg = "Collecting the global pool details from the Cisco DNA Center"
        self.status = "success"
        return self

    def get_have_reserve_pool(self, config):
        """
        Get the current Reserved Pool information from Cisco DNA Center
        based on the provided playbook details.
        Check this API using check_return_status

        Parameters:
            config (list of dict) - Playbook details containing Reserved Pool configuration.

        Returns:
            self - The current object with updated information.
        """

        reserve_pool = {"exists": False, "details": None, "id": None}
        reserve_pool_details = config.get("reserve_pool_details")
        name = reserve_pool_details.get("name")
        if name is None:
            self.msg = "Mandatory Parameter name required in reserve_pool_details\n"
            self.status = "failed"
            return self

        site_name = reserve_pool_details.get("site_name")
        self.log("Site Name: {0}".format(site_name), "DEBUG")
        if site_name is None:
            self.msg = "Missing parameter 'site_name' in reserve_pool_details"
            self.status = "failed"
            return self

        # Check if the Reserved Pool exists in Cisco DNA Center
        # based on the provided name and site name
        reserve_pool = self.reserve_pool_exists(name, site_name)
        if not reserve_pool.get("success"):
            return self.check_return_status()
        self.log("Reserved pool details: {0}".format(reserve_pool), "DEBUG")

        # If the Reserved Pool doesn't exist and a previous name is provided
        # Else try using the previous name
        prev_name = reserve_pool_details.get("prev_name")
        if reserve_pool.get("exists") is False and prev_name is not None:
            reserve_pool = self.reserve_pool_exists(prev_name, site_name)
            if not reserve_pool.get("success"):
                return self.check_return_status()

            # If the previous name doesn't exist in Cisco DNA Center, return with error
            if reserve_pool.get("exists") is False:
                self.msg = "Prev name {0} doesn't exist in reserve_pool_details".format(
                    prev_name
                )
                self.status = "failed"
                return self

        self.log(
            "Reserved pool exists: {0}".format(reserve_pool.get("exists")), "DEBUG"
        )
        self.log("Reserved pool: {0}".format(reserve_pool.get("details")), "DEBUG")

        # If reserve pool exist, convert ipv6AddressSpace to the required format (boolean)
        if reserve_pool.get("exists"):
            reserve_pool_details = reserve_pool.get("details")
            if reserve_pool_details.get("ipv6AddressSpace") == "False":
                reserve_pool_details.update({"ipv6AddressSpace": False})
            else:
                reserve_pool_details.update({"ipv6AddressSpace": True})

        self.log("Reserved pool details: {0}".format(reserve_pool), "DEBUG")
        self.have.update({"reservePool": reserve_pool})
        self.msg = "Collecting the reserve pool details from the Cisco DNA Center"
        self.status = "success"
        return self

    def get_have_network(self, config):
        """
        Get the current Network details from Cisco DNA
        Center based on the provided playbook details.

        Parameters:
            config (dict) - Playbook details containing Network Management configuration.

        Returns:
            self - The current object with updated Network information.
        """
        network = {}
        site_name = config.get("network_management_details").get("site_name")
        if site_name is None:
            self.msg = "Mandatory Parameter 'site_name' missing"
            self.status = "failed"
            return self

        site_id = self.get_site_id(site_name)
        if site_id is None:
            self.msg = "Failed to get site id from {0}".format(site_name)
            self.status = "failed"
            return self

        network["site_id"] = site_id
        network["net_details"] = self.get_network_params(site_id)
        self.log(
            "Network details from the Catalyst Center: {0}".format(network), "DEBUG"
        )
        self.have.update({"network": network})
        self.msg = "Collecting the network details from the Cisco DNA Center"
        self.status = "success"
        return self

    def get_have(self, config):
        """
        Get the current Global Pool Reserved Pool and Network details from Cisco DNA Center

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self - The current object with updated Global Pool,
            Reserved Pool, and Network information.
        """

        if config.get("global_pool_details") is not None:
            self.get_have_global_pool(config).check_return_status()

        if config.get("reserve_pool_details") is not None:
            self.get_have_reserve_pool(config).check_return_status()

        if config.get("network_management_details") is not None:
            self.get_have_network(config).check_return_status()

        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.msg = "Successfully retrieved the details from the Cisco DNA Center"
        self.status = "success"
        return self

    def get_want_global_pool(self, global_ippool):
        """
        Get all the Global Pool information from playbook
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            global_ippool (dict) - Playbook global pool details containing IpAddressSpace,
            DHCP server IPs, DNS server IPs, IP pool name, IP pool CIDR, gateway, and type.

        Returns:
            self - The current object with updated desired Global Pool information.
        """

        # Initialize the desired Global Pool configuration
        want_global = {
            "settings": {
                "ippool": [
                    {
                        "IpAddressSpace": global_ippool.get("ip_address_space"),
                        "dhcpServerIps": global_ippool.get("dhcp_server_ips"),
                        "dnsServerIps": global_ippool.get("dns_server_ips"),
                        "ipPoolName": global_ippool.get("name"),
                        "ipPoolCidr": global_ippool.get("cidr"),
                        "gateway": global_ippool.get("gateway"),
                        "type": global_ippool.get("pool_type"),
                    }
                ]
            }
        }
        want_ippool = want_global.get("settings").get("ippool")[0]

        # Converting to the required format based on the existing Global Pool
        if not self.have.get("globalPool").get("exists"):
            if want_ippool.get("dhcpServerIps") is None:
                want_ippool.update({"dhcpServerIps": []})
            if want_ippool.get("dnsServerIps") is None:
                want_ippool.update({"dnsServerIps": []})
            if want_ippool.get("IpAddressSpace") is None:
                want_ippool.update({"IpAddressSpace": ""})
            if want_ippool.get("gateway") is None:
                want_ippool.update({"gateway": ""})
            if want_ippool.get("type") is None:
                global_ippool_type = global_ippool.get("type")
                if not global_ippool_type:
                    want_ippool.update({"type": "Generic"})
                else:
                    want_ippool.update({"type": global_ippool_type})
                    self.log("'type' is deprecated and use 'pool_type'", "WARNING")

        else:
            have_ippool = (
                self.have.get("globalPool")
                .get("details")
                .get("settings")
                .get("ippool")[0]
            )

            # Copy existing Global Pool information if the desired configuration is not provided
            want_ippool.update(
                {
                    "IpAddressSpace": have_ippool.get("IpAddressSpace"),
                    "type": have_ippool.get("type"),
                    "ipPoolCidr": have_ippool.get("ipPoolCidr"),
                }
            )
            want_ippool.update({})
            want_ippool.update({})

            for key in ["dhcpServerIps", "dnsServerIps", "gateway"]:
                if want_ippool.get(key) is None and have_ippool.get(key) is not None:
                    want_ippool[key] = have_ippool[key]

        self.log("Global pool playbook details: {0}".format(want_global), "DEBUG")
        self.want.update({"wantGlobal": want_global})
        self.msg = "Collecting the global pool details from the playbook"
        self.status = "success"
        return self

    def get_want_reserve_pool(self, reserve_pool):
        """
        Get all the Reserved Pool information from playbook
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            reserve_pool (dict) - Playbook reserved pool
            details containing various properties.

        Returns:
            self - The current object with updated desired Reserved Pool information.
        """

        want_reserve = {
            "name": reserve_pool.get("name"),
            "type": reserve_pool.get("pool_type"),
            "ipv6AddressSpace": reserve_pool.get("ipv6_address_space"),
            "ipv4GlobalPool": reserve_pool.get("ipv4_global_pool"),
            "ipv4Prefix": reserve_pool.get("ipv4_prefix"),
            "ipv4PrefixLength": reserve_pool.get("ipv4_prefix_length"),
            "ipv4GateWay": reserve_pool.get("ipv4_gateway"),
            "ipv4DhcpServers": reserve_pool.get("ipv4_dhcp_servers"),
            "ipv4DnsServers": reserve_pool.get("ipv4_dns_servers"),
            "ipv4Subnet": reserve_pool.get("ipv4_subnet"),
            "ipv6GlobalPool": reserve_pool.get("ipv6_global_pool"),
            "ipv6Prefix": reserve_pool.get("ipv6_prefix"),
            "ipv6PrefixLength": reserve_pool.get("ipv6_prefix_length"),
            "ipv6GateWay": reserve_pool.get("ipv6_gateway"),
            "ipv6DhcpServers": reserve_pool.get("ipv6_dhcp_servers"),
            "ipv6Subnet": reserve_pool.get("ipv6_subnet"),
            "ipv6DnsServers": reserve_pool.get("ipv6_dns_servers"),
            "ipv4TotalHost": reserve_pool.get("ipv4_total_host"),
            "ipv6TotalHost": reserve_pool.get("ipv6_total_host"),
        }

        # Check for missing mandatory parameters in the playbook
        if not want_reserve.get("name"):
            self.msg = "Missing mandatory parameter 'name' in reserve_pool_details"
            self.status = "failed"
            return self

        if want_reserve.get("ipv4Prefix") is True:
            if (
                want_reserve.get("ipv4Subnet") is None
                and want_reserve.get("ipv4TotalHost") is None
            ):
                self.msg = "missing parameter 'ipv4_subnet' or 'ipv4TotalHost' \
                    while adding the ipv4 in reserve_pool_details"
                self.status = "failed"
                return self

        if want_reserve.get("ipv6Prefix") is True:
            if (
                want_reserve.get("ipv6Subnet") is None
                and want_reserve.get("ipv6TotalHost") is None
            ):
                self.msg = "missing parameter 'ipv6_subnet' or 'ipv6TotalHost' \
                    while adding the ipv6 in reserve_pool_details"
                self.status = "failed"
                return self

        self.log("Reserved IP pool playbook details: {0}".format(want_reserve), "DEBUG")

        # If there are no existing Reserved Pool details, validate and set defaults
        if not self.have.get("reservePool").get("details"):
            if not want_reserve.get("ipv4GlobalPool"):
                self.msg = "missing parameter 'ipv4GlobalPool' in reserve_pool_details"
                self.status = "failed"
                return self

            if not want_reserve.get("ipv4PrefixLength"):
                self.msg = (
                    "missing parameter 'ipv4_prefix_length' in reserve_pool_details"
                )
                self.status = "failed"
                return self

            if want_reserve.get("type") is None:
                reserve_pool_type = reserve_pool.get("type")
                if not reserve_pool_type:
                    want_reserve.update({"type": "Generic"})
                else:
                    want_reserve.update({"type": reserve_pool_type})
                    self.log("'type' is deprecated and use 'pool_type'", "WARNING")
            if want_reserve.get("ipv4GateWay") is None:
                want_reserve.update({"ipv4GateWay": ""})
            if want_reserve.get("ipv4DhcpServers") is None:
                want_reserve.update({"ipv4DhcpServers": []})
            if want_reserve.get("ipv4DnsServers") is None:
                want_reserve.update({"ipv4DnsServers": []})
            if want_reserve.get("ipv6AddressSpace") is None:
                want_reserve.update({"ipv6AddressSpace": False})
            if want_reserve.get("slaacSupport") is None:
                want_reserve.update({"slaacSupport": True})
            if want_reserve.get("ipv4TotalHost") is None:
                del want_reserve["ipv4TotalHost"]
            if want_reserve.get("ipv6AddressSpace") is True:
                want_reserve.update({"ipv6Prefix": True})
            else:
                del want_reserve["ipv6Prefix"]

            if not want_reserve.get("ipv6AddressSpace"):
                keys_to_check = [
                    "ipv6GlobalPool",
                    "ipv6PrefixLength",
                    "ipv6GateWay",
                    "ipv6DhcpServers",
                    "ipv6DnsServers",
                    "ipv6TotalHost",
                ]
                for key in keys_to_check:
                    if want_reserve.get(key) is None:
                        del want_reserve[key]
        else:
            keys_to_delete = [
                "type",
                "ipv4GlobalPool",
                "ipv4Prefix",
                "ipv4PrefixLength",
                "ipv4TotalHost",
                "ipv4Subnet",
            ]
            for key in keys_to_delete:
                if key in want_reserve:
                    del want_reserve[key]

        self.want.update({"wantReserve": want_reserve})
        self.log("Desired State (want): {0}".format(self.want), "INFO")
        self.msg = "Collecting the reserve pool details from the playbook"
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
                "clientAndEndpoint_aaa": {},
            }
        }
        want_network_settings = want_network.get("settings")
        self.log("Current state (have): {0}".format(self.have), "DEBUG")
        if network_management_details.get("dhcp_server") is not None:
            want_network_settings.update(
                {"dhcpServer": network_management_details.get("dhcp_server")}
            )
        else:
            del want_network_settings["dhcpServer"]

        if network_management_details.get("ntp_server") is not None:
            want_network_settings.update(
                {"ntpServer": network_management_details.get("ntp_server")}
            )
        else:
            del want_network_settings["ntpServer"]

        if network_management_details.get("timezone") is not None:
            want_network_settings["timezone"] = network_management_details.get(
                "timezone"
            )
        else:
            self.msg = "missing parameter timezone in network"
            self.status = "failed"
            return self

        dnsServer = network_management_details.get("dns_server")
        if dnsServer is not None:
            if dnsServer.get("domain_name") is not None:
                want_network_settings.get("dnsServer").update(
                    {"domainName": dnsServer.get("domain_name")}
                )

            if dnsServer.get("primary_ip_address") is not None:
                want_network_settings.get("dnsServer").update(
                    {"primaryIpAddress": dnsServer.get("primary_ip_address")}
                )

            if dnsServer.get("secondary_ip_address") is not None:
                want_network_settings.get("dnsServer").update(
                    {"secondaryIpAddress": dnsServer.get("secondary_ip_address")}
                )
        else:
            del want_network_settings["dnsServer"]

        snmpServer = network_management_details.get("snmp_server")
        if snmpServer is not None:
            if snmpServer.get("configure_dnac_ip") is not None:
                want_network_settings.get("snmpServer").update(
                    {"configureDnacIP": snmpServer.get("configure_dnac_ip")}
                )
            if snmpServer.get("ip_addresses") is not None:
                want_network_settings.get("snmpServer").update(
                    {"ipAddresses": snmpServer.get("ip_addresses")}
                )
        else:
            del want_network_settings["snmpServer"]

        syslogServer = network_management_details.get("syslog_server")
        if syslogServer is not None:
            if syslogServer.get("configure_dnac_ip") is not None:
                want_network_settings.get("syslogServer").update(
                    {"configureDnacIP": syslogServer.get("configure_dnac_ip")}
                )
            if syslogServer.get("ip_addresses") is not None:
                want_network_settings.get("syslogServer").update(
                    {"ipAddresses": syslogServer.get("ip_addresses")}
                )
        else:
            del want_network_settings["syslogServer"]

        netflowcollector = network_management_details.get("netflow_collector")
        if netflowcollector is not None:
            if netflowcollector.get("ip_address") is not None:
                want_network_settings.get("netflowcollector").update(
                    {"ipAddress": netflowcollector.get("ip_address")}
                )
            if netflowcollector.get("port") is not None:
                want_network_settings.get("netflowcollector").update(
                    {"port": netflowcollector.get("port")}
                )
        else:
            del want_network_settings["netflowcollector"]

        messageOfTheday = network_management_details.get("message_of_the_day")
        if messageOfTheday is not None:
            if messageOfTheday.get("banner_message") is not None:
                want_network_settings.get("messageOfTheday").update(
                    {"bannerMessage": messageOfTheday.get("banner_message")}
                )
            if messageOfTheday.get("retain_existing_banner") is not None:
                want_network_settings.get("messageOfTheday").update(
                    {
                        "retainExistingBanner": messageOfTheday.get(
                            "retain_existing_banner"
                        )
                    }
                )
        else:
            del want_network_settings["messageOfTheday"]

        network_aaa = network_management_details.get("network_aaa")
        if network_aaa:
            if network_aaa.get("ip_address"):
                want_network_settings.get("network_aaa").update(
                    {"ipAddress": network_aaa.get("ip_address")}
                )
            else:
                if network_aaa.get("servers") == "ISE":
                    self.msg = (
                        "missing parameter ip_address in network_aaa, server ISE is set"
                    )
                    self.status = "failed"
                    return self

            if network_aaa.get("network"):
                want_network_settings.get("network_aaa").update(
                    {"network": network_aaa.get("network")}
                )
            else:
                self.msg = "missing parameter network in network_aaa"
                self.status = "failed"
                return self

            if network_aaa.get("protocol"):
                want_network_settings.get("network_aaa").update(
                    {"protocol": network_aaa.get("protocol")}
                )
            else:
                self.msg = "missing parameter protocol in network_aaa"
                self.status = "failed"
                return self

            if network_aaa.get("servers"):
                want_network_settings.get("network_aaa").update(
                    {"servers": network_aaa.get("servers")}
                )
            else:
                self.msg = "missing parameter servers in network_aaa"
                self.status = "failed"
                return self

            if network_aaa.get("shared_secret"):
                want_network_settings.get("network_aaa").update(
                    {"sharedSecret": network_aaa.get("shared_secret")}
                )
        else:
            del want_network_settings["network_aaa"]

        clientAndEndpoint_aaa = network_management_details.get(
            "client_and_endpoint_aaa"
        )
        if clientAndEndpoint_aaa:
            if clientAndEndpoint_aaa.get("ip_address"):
                want_network_settings.get("clientAndEndpoint_aaa").update(
                    {"ipAddress": clientAndEndpoint_aaa.get("ip_address")}
                )
            else:
                if clientAndEndpoint_aaa.get("servers") == "ISE":
                    self.msg = "missing parameter ip_address in clientAndEndpoint_aaa, \
                        server ISE is set"
                    self.status = "failed"
                    return self

            if clientAndEndpoint_aaa.get("network"):
                want_network_settings.get("clientAndEndpoint_aaa").update(
                    {"network": clientAndEndpoint_aaa.get("network")}
                )
            else:
                self.msg = "missing parameter network in clientAndEndpoint_aaa"
                self.status = "failed"
                return self

            if clientAndEndpoint_aaa.get("protocol"):
                want_network_settings.get("clientAndEndpoint_aaa").update(
                    {"protocol": clientAndEndpoint_aaa.get("protocol")}
                )
            else:
                self.msg = "missing parameter protocol in clientAndEndpoint_aaa"
                self.status = "failed"
                return self

            if clientAndEndpoint_aaa.get("servers"):
                want_network_settings.get("clientAndEndpoint_aaa").update(
                    {"servers": clientAndEndpoint_aaa.get("servers")}
                )
            else:
                self.msg = "missing parameter servers in clientAndEndpoint_aaa"
                self.status = "failed"
                return self

            if clientAndEndpoint_aaa.get("shared_secret"):
                want_network_settings.get("clientAndEndpoint_aaa").update(
                    {"sharedSecret": clientAndEndpoint_aaa.get("shared_secret")}
                )
        else:
            del want_network_settings["clientAndEndpoint_aaa"]

        self.log("Network playbook details: {0}".format(want_network), "DEBUG")
        self.want.update({"wantNetwork": want_network})
        self.msg = "Collecting the network details from the playbook"
        self.status = "success"
        return self

    def get_want(self, config):
        """
        Get all the Global Pool Reserved Pool and Network related information from playbook

        Parameters:
            config (list of dict) - Playbook details

        Returns:
            None
        """

        if config.get("global_pool_details"):
            global_ippool = (
                config.get("global_pool_details").get("settings").get("ip_pool")[0]
            )
            self.get_want_global_pool(global_ippool).check_return_status()

        if config.get("reserve_pool_details"):
            reserve_pool = config.get("reserve_pool_details")
            self.get_want_reserve_pool(reserve_pool).check_return_status()

        if config.get("network_management_details"):
            network_management_details = config.get("network_management_details").get(
                "settings"
            )
            self.get_want_network(network_management_details).check_return_status()

        self.log("Desired State (want): {0}".format(self.want), "INFO")
        self.msg = "Successfully retrieved details from the playbook"
        self.status = "success"
        return self

    def update_global_pool(self, config):
        """
        Update/Create Global Pool in Cisco DNA Center with fields provided in playbook

        Parameters:
            config (list of dict) - Playbook details

        Returns:
            None
        """

        name = (
            config.get("global_pool_details")
            .get("settings")
            .get("ip_pool")[0]
            .get("name")
        )
        result_global_pool = self.result.get("response")[0].get("globalPool")
        result_global_pool.get("response").update({name: {}})

        # Check pool exist, if not create and return
        if not self.have.get("globalPool").get("exists"):
            pool_params = self.want.get("wantGlobal")
            self.log(
                "Desired State for global pool (want): {0}".format(pool_params), "DEBUG"
            )
            response = self.dnac._exec(
                family="network_settings",
                function="create_global_pool",
                op_modifies=True,
                params=pool_params,
            )
            self.check_execution_response_status(response).check_return_status()
            self.log("Successfully created global pool '{0}'.".format(name), "INFO")
            result_global_pool.get("response").get(name).update(
                {"globalPool Details": self.want.get("wantGlobal")}
            )
            result_global_pool.get("msg").update(
                {name: "Global Pool Created Successfully"}
            )
            return

        # Pool exists, check update is required
        if not self.requires_update(
            self.have.get("globalPool").get("details"),
            self.want.get("wantGlobal"),
            self.global_pool_obj_params,
        ):
            self.log("Global pool '{0}' doesn't require an update".format(name), "INFO")
            result_global_pool.get("response").get(name).update(
                {
                    "Cisco DNA Center params": self.have.get("globalPool")
                    .get("details")
                    .get("settings")
                    .get("ippool")[0]
                }
            )
            result_global_pool.get("response").get(name).update(
                {"Id": self.have.get("globalPool").get("id")}
            )
            result_global_pool.get("msg").update(
                {name: "Global pool doesn't require an update"}
            )
            return

        self.log("Global pool requires update", "DEBUG")
        # Pool Exists
        pool_params = copy.deepcopy(self.want.get("wantGlobal"))
        pool_params_ippool = pool_params.get("settings").get("ippool")[0]
        pool_params_ippool.update({"id": self.have.get("globalPool").get("id")})
        self.log(
            "Desired State for global pool (want): {0}".format(pool_params), "DEBUG"
        )
        keys_to_remove = ["IpAddressSpace", "ipPoolCidr", "type"]
        for key in keys_to_remove:
            del pool_params["settings"]["ippool"][0][key]

        have_ippool = (
            self.have.get("globalPool").get("details").get("settings").get("ippool")[0]
        )
        keys_to_update = ["dhcpServerIps", "dnsServerIps", "gateway"]
        for key in keys_to_update:
            if pool_params_ippool.get(key) is None:
                pool_params_ippool[key] = have_ippool.get(key)

        self.log("Desired global pool details (want): {0}".format(pool_params), "DEBUG")
        response = self.dnac._exec(
            family="network_settings",
            function="update_global_pool",
            op_modifies=True,
            params=pool_params,
        )

        self.check_execution_response_status(response).check_return_status()
        self.log("Global pool '{0}' updated successfully".format(name), "INFO")
        result_global_pool.get("response").get(name).update(
            {"Id": self.have.get("globalPool").get("details").get("id")}
        )
        result_global_pool.get("msg").update({name: "Global Pool Updated Successfully"})
        return

    def update_reserve_pool(self, config):
        """
        Update or Create a Reserve Pool in Cisco DNA Center based on the provided configuration.
        This method checks if a reserve pool with the specified name exists in Cisco DNA Center.
        If it exists and requires an update, it updates the pool. If not, it creates a new pool.

        Parameters:
            config (list of dict) - Playbook details containing Reserve Pool information.

        Returns:
            None
        """

        name = config.get("reserve_pool_details").get("name")
        result_reserve_pool = self.result.get("response")[1].get("reservePool")
        result_reserve_pool.get("response").update({name: {}})
        self.log(
            "Current reserved pool details in Catalyst Center: {0}".format(
                self.have.get("reservePool").get("details")
            ),
            "DEBUG",
        )
        self.log(
            "Desired reserved pool details in Catalyst Center: {0}".format(
                self.want.get("wantReserve")
            ),
            "DEBUG",
        )

        # Check pool exist, if not create and return
        self.log(
            "IPv4 global pool: {0}".format(
                self.want.get("wantReserve").get("ipv4GlobalPool")
            ),
            "DEBUG",
        )
        site_name = config.get("reserve_pool_details").get("site_name")
        reserve_params = self.want.get("wantReserve")
        site_id = self.get_site_id(site_name)
        reserve_params.update({"site_id": site_id})
        if not self.have.get("reservePool").get("exists"):
            self.log(
                "Desired reserved pool details (want): {0}".format(reserve_params),
                "DEBUG",
            )
            response = self.dnac._exec(
                family="network_settings",
                function="reserve_ip_subpool",
                op_modifies=True,
                params=reserve_params,
            )
            self.check_execution_response_status(response).check_return_status()
            self.log(
                "Successfully created IP subpool reservation '{0}'.".format(name),
                "INFO",
            )
            result_reserve_pool.get("response").get(name).update(
                {"reservePool Details": self.want.get("wantReserve")}
            )
            result_reserve_pool.get("msg").update(
                {name: "Ip Subpool Reservation Created Successfully"}
            )
            return

        # Check update is required
        if not self.requires_update(
            self.have.get("reservePool").get("details"),
            self.want.get("wantReserve"),
            self.reserve_pool_obj_params,
        ):
            self.log(
                "Reserved ip subpool '{0}' doesn't require an update".format(name),
                "INFO",
            )
            result_reserve_pool.get("response").get(name).update(
                {"Cisco DNA Center params": self.have.get("reservePool").get("details")}
            )
            result_reserve_pool.get("response").get(name).update(
                {"Id": self.have.get("reservePool").get("id")}
            )
            result_reserve_pool.get("msg").update(
                {name: "Reserve ip subpool doesn't require an update"}
            )
            return

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
        reserve_params.update({"id": self.have.get("reservePool").get("id")})
        response = self.dnac._exec(
            family="network_settings",
            function="update_reserve_ip_subpool",
            op_modifies=True,
            params=reserve_params,
        )
        self.check_execution_response_status(response).check_return_status()
        self.log("Reserved ip subpool '{0}' updated successfully.".format(name), "INFO")
        result_reserve_pool["msg"] = "Reserved Ip Subpool Updated Successfully"
        result_reserve_pool.get("response").get(name).update(
            {"Reservation details": self.have.get("reservePool").get("details")}
        )
        return

    def update_network(self, config):
        """
        Update or create a network configuration in Cisco DNA
        Center based on the provided playbook details.

        Parameters:
            config (list of dict) - Playbook details containing Network Management information.

        Returns:
            None
        """

        site_name = config.get("network_management_details").get("site_name")
        result_network = self.result.get("response")[2].get("network")
        result_network.get("response").update({site_name: {}})

        # Check update is required or not
        if not self.requires_update(
            self.have.get("network").get("net_details"),
            self.want.get("wantNetwork"),
            self.network_obj_params,
        ):

            self.log(
                "Network in site '{0}' doesn't require an update.".format(site_name),
                "INFO",
            )
            result_network.get("response").get(site_name).update(
                {
                    "Cisco DNA Center params": self.have.get("network")
                    .get("net_details")
                    .get("settings")
                }
            )
            result_network.get("msg").update(
                {site_name: "Network doesn't require an update"}
            )
            return

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

        net_params = copy.deepcopy(self.want.get("wantNetwork"))
        net_params.update({"site_id": self.have.get("network").get("site_id")})
        response = self.dnac._exec(
            family="network_settings",
            function="update_network_v2",
            op_modifies=True,
            params=net_params,
        )
        self.log(
            "Received API response of 'update_network_v2': {0}".format(response),
            "DEBUG",
        )
        validation_string = "desired common settings operation successful"
        self.check_task_response_status(
            response, validation_string
        ).check_return_status()
        self.log("Network has been changed successfully", "INFO")
        result_network.get("msg").update({site_name: "Network Updated successfully"})
        result_network.get("response").get(site_name).update(
            {"Network Details": self.want.get("wantNetwork").get("settings")}
        )
        return

    def get_diff_merged(self, config):
        """
        Update or create Global Pool, Reserve Pool, and
        Network configurations in Cisco DNA Center based on the playbook details

        Parameters:
            config (list of dict) - Playbook details containing
            Global Pool, Reserve Pool, and Network Management information.

        Returns:
            self
        """

        if config.get("global_pool_details") is not None:
            self.update_global_pool(config)

        if config.get("reserve_pool_details") is not None:
            self.update_reserve_pool(config)

        if config.get("network_management_details") is not None:
            self.update_network(config)

        return self

    def delete_reserve_pool(self, name):
        """
        Delete a Reserve Pool by name in Cisco DNA Center

        Parameters:
            name (str) - The name of the Reserve Pool to be deleted.

        Returns:
            self
        """

        reserve_pool_exists = self.have.get("reservePool").get("exists")
        result_reserve_pool = self.result.get("response")[1].get("reservePool")

        if not reserve_pool_exists:
            result_reserve_pool.get("response").update({name: "Reserve Pool not found"})
            self.msg = "Reserved Ip Subpool Not Found"
            self.status = "success"
            return self

        self.log(
            "Reserved IP pool scheduled for deletion: {0}".format(
                self.have.get("reservePool").get("name")
            ),
            "INFO",
        )
        _id = self.have.get("reservePool").get("id")
        self.log("Reserved pool {0} id: {1}".format(name, _id), "DEBUG")
        response = self.dnac._exec(
            family="network_settings",
            function="release_reserve_ip_subpool",
            op_modifies=True,
            params={"id": _id},
        )
        self.check_execution_response_status(response).check_return_status()
        executionid = response.get("executionId")
        result_reserve_pool = self.result.get("response")[1].get("reservePool")
        result_reserve_pool.get("response").update({name: {}})
        result_reserve_pool.get("response").get(name).update(
            {"Execution Id": executionid}
        )
        result_reserve_pool.get("msg").update(
            {name: "Ip subpool reservation released successfully"}
        )
        self.msg = "Reserved pool - {0} released successfully".format(name)
        self.status = "success"
        return self

    def delete_global_pool(self, name):
        """
        Delete a Global Pool by name in Cisco DNA Center

        Parameters:
            name (str) - The name of the Global Pool to be deleted.

        Returns:
            self
        """

        global_pool_exists = self.have.get("globalPool").get("exists")
        result_global_pool = self.result.get("response")[0].get("globalPool")
        if not global_pool_exists:
            result_global_pool.get("response").update({name: "Global Pool not found"})
            self.msg = "Global pool Not Found"
            self.status = "success"
            return self

        response = self.dnac._exec(
            family="network_settings",
            function="delete_global_ip_pool",
            op_modifies=True,
            params={"id": self.have.get("globalPool").get("id")},
        )

        # Check the execution status
        self.check_execution_response_status(response).check_return_status()
        executionid = response.get("executionId")

        # Update result information
        result_global_pool = self.result.get("response")[0].get("globalPool")
        result_global_pool.get("response").update({name: {}})
        result_global_pool.get("response").get(name).update(
            {"Execution Id": executionid}
        )
        result_global_pool.get("msg").update({name: "Pool deleted successfully"})
        self.msg = "Global pool - {0} deleted successfully".format(name)
        self.status = "success"
        return self

    def get_diff_deleted(self, config):
        """
        Delete Reserve Pool and Global Pool in Cisco DNA Center based on playbook details.

        Parameters:
            config (list of dict) - Playbook details

        Returns:
            self
        """

        if config.get("reserve_pool_details") is not None:
            name = config.get("reserve_pool_details").get("name")
            self.delete_reserve_pool(name).check_return_status()

        if config.get("global_pool_details") is not None:
            name = (
                config.get("global_pool_details")
                .get("settings")
                .get("ip_pool")[0]
                .get("name")
            )
            self.delete_global_pool(name).check_return_status()

        return self

    def verify_diff_merged(self, config):
        """
        Validating the DNAC configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Requested State (want): {0}".format(self.want), "INFO")
        if config.get("global_pool_details") is not None:
            self.log(
                "Desired State of global pool (want): {0}".format(
                    self.want.get("wantGlobal")
                ),
                "DEBUG",
            )
            self.log(
                "Current State of global pool (have): {0}".format(
                    self.have.get("globalPool").get("details")
                ),
                "DEBUG",
            )
            if self.requires_update(
                self.have.get("globalPool").get("details"),
                self.want.get("wantGlobal"),
                self.global_pool_obj_params,
            ):
                self.msg = "Global Pool Config is not applied to the DNAC"
                self.status = "failed"
                return self

            self.log(
                "Successfully validated global pool '{0}'.".format(
                    self.want.get("wantGlobal")
                    .get("settings")
                    .get("ippool")[0]
                    .get("ipPoolName")
                ),
                "INFO",
            )
            self.result.get("response")[0].get("globalPool").update(
                {"Validation": "Success"}
            )

        if config.get("reserve_pool_details") is not None:
            if self.requires_update(
                self.have.get("reservePool").get("details"),
                self.want.get("wantReserve"),
                self.reserve_pool_obj_params,
            ):
                self.log(
                    "Desired State for reserve pool (want): {0}".format(
                        self.want.get("wantReserve")
                    ),
                    "DEBUG",
                )
                self.log(
                    "Current State for reserve pool (have): {0}".format(
                        self.have.get("reservePool").get("details")
                    ),
                    "DEBUG",
                )
                self.msg = "Reserved Pool Config is not applied to the DNAC"
                self.status = "failed"
                return self

            self.log(
                "Successfully validated the reserved pool '{0}'.".format(
                    self.want.get("wantReserve").get("name")
                ),
                "INFO",
            )
            self.result.get("response")[1].get("reservePool").update(
                {"Validation": "Success"}
            )

        if config.get("network_management_details") is not None:
            if self.requires_update(
                self.have.get("network").get("net_details"),
                self.want.get("wantNetwork"),
                self.network_obj_params,
            ):
                self.msg = "Network Functions Config is not applied to the DNAC"
                self.status = "failed"
                return self

            self.log(
                "Successfully validated the network functions '{0}'.".format(
                    config.get("network_management_details").get("site_name")
                ),
                "INFO",
            )
            self.result.get("response")[2].get("network").update(
                {"Validation": "Success"}
            )

        self.msg = "Successfully validated the Global Pool, Reserve Pool \
                    and the Network Functions."
        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Validating the DNAC configuration with the playbook details
        when state is deleted (delete).

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Desired State (want): {0}".format(self.want), "INFO")
        if config.get("global_pool_details") is not None:
            global_pool_exists = self.have.get("globalPool").get("exists")
            if global_pool_exists:
                self.msg = "Global Pool Config is not applied to the DNAC"
                self.status = "failed"
                return self

            self.log(
                "Successfully validated absence of Global Pool '{0}'.".format(
                    config.get("global_pool_details")
                    .get("settings")
                    .get("ip_pool")[0]
                    .get("name")
                ),
                "INFO",
            )
            self.result.get("response")[0].get("globalPool").update(
                {"Validation": "Success"}
            )

        if config.get("reserve_pool_details") is not None:
            reserve_pool_exists = self.have.get("reservePool").get("exists")
            if reserve_pool_exists:
                self.msg = "Reserved Pool Config is not applied to the Catalyst Center"
                self.status = "failed"
                return self

            self.log(
                "Successfully validated the absence of Reserve Pool '{0}'.".format(
                    config.get("reserve_pool_details").get("name")
                ),
                "INFO",
            )
            self.result.get("response")[1].get("reservePool").update(
                {"Validation": "Success"}
            )

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
    dnac_network = NetworkSettings(module)
    state = dnac_network.params.get("state")
    config_verify = dnac_network.params.get("config_verify")
    if state not in dnac_network.supported_states:
        dnac_network.status = "invalid"
        dnac_network.msg = "State {0} is invalid".format(state)
        dnac_network.check_return_status()

    dnac_network.validate_input().check_return_status()

    for config in dnac_network.config:
        dnac_network.reset_values()
        dnac_network.get_have(config).check_return_status()
        if state != "deleted":
            dnac_network.get_want(config).check_return_status()
        dnac_network.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            dnac_network.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**dnac_network.result)


if __name__ == "__main__":
    main()
