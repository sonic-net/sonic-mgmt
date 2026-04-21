#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_simple_cluster
short_description: Manages simple-cluster objects on Checkpoint over Web Services API
description:
  - Manages simple-cluster objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R80.40 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  ip_address:
    description:
      - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
    type: str
  ipv4_address:
    description:
      - IPv4 address.
    type: str
  ipv6_address:
    description:
      - IPv6 address.
    type: str
  anti_bot:
    description:
      - Anti-Bot blade enabled.
    type: bool
  anti_virus:
    description:
      - Anti-Virus blade enabled.
    type: bool
  application_control:
    description:
      - Application Control blade enabled.
    type: bool
  cluster_mode:
    description:
      - Cluster mode.
    type: str
    choices: ['cluster-xl-ha', 'cluster-ls-multicast', 'cluster-ls-unicast', 'opsec-ha', 'opsec-ls']
  content_awareness:
    description:
      - Content Awareness blade enabled.
    type: bool
  firewall:
    description:
      - Firewall blade enabled.
    type: bool
  firewall_settings:
    description:
      - N/A
    type: dict
    suboptions:
      auto_calculate_connections_hash_table_size_and_memory_pool:
        description:
          - N/A
        type: bool
      auto_maximum_limit_for_concurrent_connections:
        description:
          - N/A
        type: bool
      connections_hash_size:
        description:
          - N/A
        type: int
      maximum_limit_for_concurrent_connections:
        description:
          - N/A
        type: int
      maximum_memory_pool_size:
        description:
          - N/A
        type: int
      memory_pool_size:
        description:
          - N/A
        type: int
  hardware:
    description:
      - Cluster platform hardware.
    type: str
  interfaces:
    description:
      - N/A
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Object name.
        type: str
      interface_type:
        description:
          - Cluster interface type.
        type: str
        choices: ['cluster', 'sync', 'cluster + sync', 'private']
      ip_address:
        description:
          - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
        type: str
      ipv4_address:
        description:
          - IPv4 address.
        type: str
      ipv6_address:
        description:
          - IPv6 address.
        type: str
      network_mask:
        description:
          - IPv4 or IPv6 network mask. If both masks are required use ipv4-network-mask and ipv6-network-mask fields explicitly. Instead of
            providing mask itself it is possible to specify IPv4 or IPv6 mask length in mask-length field. If both masks length are required use
            ipv4-mask-length and  ipv6-mask-length fields explicitly.
        type: str
      ipv4_network_mask:
        description:
          - IPv4 network address.
        type: str
      ipv6_network_mask:
        description:
          - IPv6 network address.
        type: str
      mask_length:
        description:
          - IPv4 or IPv6 network mask length.
        type: str
      ipv4_mask_length:
        description:
          - IPv4 network mask length.
        type: str
      ipv6_mask_length:
        description:
          - IPv6 network mask length.
        type: str
      anti_spoofing:
        description:
          - N/A
        type: bool
      anti_spoofing_settings:
        description:
          - N/A
        type: dict
        suboptions:
          action:
            description:
              - If packets will be rejected (the Prevent option) or whether the packets will be monitored (the Detect option).
            type: str
            choices: ['prevent', 'detect']
          exclude_packets:
            description:
              - Don't check packets from excluded network.
              - Available from R81.10 management version.
            type: bool
          excluded_network_name:
            description:
              - Excluded network name.
              - Available from R81.10 management version.
            type: str
          excluded_network_uid:
            description:
              - Excluded network UID.
              - Available from R81.10 management version.
            type: str
          spoof_tracking:
            description:
              - Spoof tracking.
              - Available from R81.10 management version.
            type: str
            choices: ['none', 'log', 'alert']
      multicast_address:
        description:
          - Multicast IP Address.
        type: str
      multicast_address_type:
        description:
          - Multicast Address Type.
        type: str
        choices: ['manual', 'default']
      security_zone:
        description:
          - N/A
        type: bool
      security_zone_settings:
        description:
          - N/A
        type: dict
        suboptions:
          auto_calculated:
            description:
              - Security Zone is calculated according to where the interface leads to.
            type: bool
          specific_zone:
            description:
              - Security Zone specified manually.
            type: str
      tags:
        description:
          - Collection of tag identifiers.
        type: list
        elements: str
      topology:
        description:
          - N/A
        type: str
        choices: ['automatic', 'external', 'internal']
      topology_settings:
        description:
          - N/A
        type: dict
        suboptions:
          interface_leads_to_dmz:
            description:
              - Whether this interface leads to demilitarized zone (perimeter network).
            type: bool
          ip_address_behind_this_interface:
            description:
              - Network settings behind this interface.
            type: str
            choices: ['not defined', 'network defined by the interface ip and net mask', 'network defined by routing', 'specific']
          specific_network:
            description:
              - Network behind this interface.
            type: str
      color:
        description:
          - Color of the object. Should be one of existing colors.
        type: str
        choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange',
                 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray',
                 'light green', 'lemon chiffon', 'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive',
                 'orange', 'red', 'sienna', 'yellow']
      comments:
        description:
          - Comments string.
        type: str
      details_level:
        description:
          - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
            representation of the object.
        type: str
        choices: ['uid', 'standard', 'full']
      ignore_warnings:
        description:
          - Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description:
          - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
  ips:
    description:
      - Intrusion Prevention System blade enabled.
    type: bool
  ips_settings:
    description:
      - Cluster IPS settings.
      - Available from R82 JHF management version.
    type: dict
    version_added: "6.5.0"
    suboptions:
      bypass_all_under_load:
        description:
          - Disable/enable all IPS protections until CPU and memory levels are back to normal.
        type: bool
      bypass_track_method:
        description:
          - Track options when all IPS protections are disabled until CPU/memory levels are back to normal.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      activation_mode:
        description:
          - Defines whether the IPS blade operates in Detect Only mode or enforces the configured IPS Policy.
        type: str
        choices: ['according-to-policy', 'detect-only']
      cpu_usage_low_threshold:
        description:
          - CPU usage low threshold percentage (1-99).
        type: int
      cpu_usage_high_threshold:
        description:
          - CPU usage high threshold percentage (1-99).
        type: int
      memory_usage_low_threshold:
        description:
          - Memory usage low threshold percentage (1-99).
        type: int
      memory_usage_high_threshold:
        description:
          - Memory usage high threshold percentage (1-99).
        type: int
      send_threat_cloud_info:
        description:
          - Help improve Check Point Threat Prevention product by sending anonymous information.
        type: bool
      reject_on_cluster_fail_over:
        description:
          - Define the IPS connections during fail over reject packets or accept packets.
        type: bool
  members:
    description:
      - Cluster members list. Only new cluster member can be added. Adding existing gateway is not supported.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Object name.
        type: str
      interfaces:
        description:
          - Cluster Member network interfaces.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Object name.
            type: str
          anti_spoofing:
            description:
              - N/A
            type: bool
          anti_spoofing_settings:
            description:
              - N/A
            type: dict
            suboptions:
              action:
                description:
                  - If packets will be rejected (the Prevent option) or whether the packets will be monitored (the Detect option).
                type: str
                choices: ['prevent', 'detect']
              exclude_packets:
                description:
                  - Don't check packets from excluded network.
                  - Available from R81.10 management version.
                type: bool
              excluded_network_name:
                description:
                  - Excluded network name.
                  - Available from R81.10 management version.
                type: str
              excluded_network_uid:
                description:
                  - Excluded network UID.
                  - Available from R81.10 management version.
                type: str
              spoof_tracking:
                description:
                  - Spoof tracking.
                  - Available from R81.10 management version.
                type: str
                choices: ['none', 'log', 'alert']
          ip_address:
            description:
              - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
            type: str
          ipv4_address:
            description:
              - IPv4 address.
            type: str
          ipv6_address:
            description:
              - IPv6 address.
            type: str
          network_mask:
            description:
              - IPv4 or IPv6 network mask. If both masks are required use ipv4-network-mask and ipv6-network-mask fields explicitly. Instead
                of providing mask itself it is possible to specify IPv4 or IPv6 mask length in mask-length field. If both masks length are required use
                ipv4-mask-length and  ipv6-mask-length fields explicitly.
            type: str
          ipv4_network_mask:
            description:
              - IPv4 network address.
            type: str
          ipv6_network_mask:
            description:
              - IPv6 network address.
            type: str
          mask_length:
            description:
              - IPv4 or IPv6 network mask length.
            type: str
          ipv4_mask_length:
            description:
              - IPv4 network mask length.
            type: str
          ipv6_mask_length:
            description:
              - IPv6 network mask length.
            type: str
          security_zone:
            description:
              - N/A
            type: bool
          security_zone_settings:
            description:
              - N/A
            type: dict
            suboptions:
              auto_calculated:
                description:
                  - Security Zone is calculated according to where the interface leads to.
                type: bool
              specific_zone:
                description:
                  - Security Zone specified manually.
                type: str
          tags:
            description:
              - Collection of tag identifiers.
            type: list
            elements: str
          topology:
            description:
              - N/A
            type: str
            choices: ['automatic', 'external', 'internal']
          topology_settings:
            description:
              - N/A
            type: dict
            suboptions:
              interface_leads_to_dmz:
                description:
                  - Whether this interface leads to demilitarized zone (perimeter network).
                type: bool
              ip_address_behind_this_interface:
                description:
                  - Network settings behind this interface.
                type: str
                choices: ['not defined', 'network defined by the interface ip and net mask', 'network defined by routing', 'specific']
              specific_network:
                description:
                  - Network behind this interface.
                type: str
          color:
            description:
              - Color of the object. Should be one of existing colors.
            type: str
            choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange',
                     'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray',
                     'light green', 'lemon chiffon', 'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive',
                     'orange', 'red', 'sienna', 'yellow']
          comments:
            description:
              - Comments string.
            type: str
          details_level:
            description:
              - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully
                detailed representation of the object.
            type: str
            choices: ['uid', 'standard', 'full']
          ignore_warnings:
            description:
              - Apply changes ignoring warnings.
            type: bool
          ignore_errors:
            description:
              - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings
                will also be ignored.
            type: bool
      ip_address:
        description:
          - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
        type: str
      ipv4_address:
        description:
          - IPv4 address.
        type: str
      ipv6_address:
        description:
          - IPv6 address.
        type: str
      one_time_password:
        description:
          - N/A
        type: str
      tags:
        description:
          - Collection of tag identifiers.
        type: list
        elements: str
      color:
        description:
          - Color of the object. Should be one of existing colors.
        type: str
        choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange',
                 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray',
                 'light green', 'lemon chiffon', 'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive',
                 'orange', 'red', 'sienna', 'yellow']
      comments:
        description:
          - Comments string.
        type: str
      details_level:
        description:
          - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
            representation of the object.
        type: str
        choices: ['uid', 'standard', 'full']
      ignore_warnings:
        description:
          - Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description:
          - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
  os_name:
    description:
      - Cluster platform operating system.
    type: str
  platform_portal_settings:
    description:
      - Platform portal settings.
      - Available from R81 JHF management version.
    type: dict
    suboptions:
      portal_web_settings:
        description:
          - Configuration of the portal web settings.
        type: dict
        suboptions:
          aliases:
            description:
              - List of URL aliases that are redirected to the main portal URL.
            type: list
            elements: str
          ip_address:
            description:
              - Optional, IP address for the web portal to use, if your DNS server fails to resolve the main portal URL.
                Note, If your DNS server resolves the main portal URL, this IP address is ignored.
            type: str
          main_url:
            description:
              - The main URL for the web portal.
            type: str
      certificate_settings:
        description:
          - Configuration of the portal certificate settings.
        type: dict
        suboptions:
          base64_certificate:
            description:
              - The certificate file encoded in Base64 with padding. This file must be in the *.p12 format.
            type: str
          base64_password:
            description:
              - Password (encoded in Base64 with padding) for the certificate file.
            type: str
      accessibility:
        description:
          - Configuration of the portal access settings.
        type: dict
        suboptions:
          allow_access_from:
            description:
              - Allowed access to the web portal (based on interfaces, or security policy).
            type: str
            choices: ['rule_base', 'internal_interfaces', 'all_interfaces']
          internal_access_settings:
            description:
              - Configuration of the additional portal access settings for internal interfaces only.
            type: dict
            suboptions:
              undefined:
                description:
                  - Controls portal access settings for internal interfaces, whose topology is set to 'Undefined'.
                type: bool
              dmz:
                description:
                  - Controls portal access settings for internal interfaces, whose topology is set to 'DMZ'.
                type: bool
              vpn:
                description:
                  - Controls portal access settings for interfaces that are part of a VPN Encryption Domain.
                type: bool
  send_alerts_to_server:
    description:
      - Server(s) to send alerts to.
    type: list
    elements: str
  send_logs_to_backup_server:
    description:
      - Backup server(s) to send logs to.
    type: list
    elements: str
  send_logs_to_server:
    description:
      - Server(s) to send logs to.
    type: list
    elements: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  threat_emulation:
    description:
      - Threat Emulation blade enabled.
    type: bool
  threat_extraction:
    description:
      - Threat Extraction blade enabled.
      - Available from R81.10 management version.
    type: bool
  threat_prevention_mode:
    description:
      - The mode of Threat Prevention to use. When using Autonomous Threat Prevention, disabling the Threat Prevention blades is not allowed.
      - Available from R81.10 management version.
    type: str
    choices: ['autonomous', 'custom']
  url_filtering:
    description:
      - URL Filtering blade enabled.
    type: bool
  usercheck_portal_settings:
    description:
      - UserCheck portal settings.
      - Available from R81 JHF management version.
    type: dict
    suboptions:
      enabled:
        description:
          - State of the web portal (enabled or disabled). The supported blades are, {'Application Control', 'URL Filtering', 'Data Loss
            Prevention', 'Anti Virus', 'Anti Bot', 'Threat Emulation', 'Threat Extraction', 'Data Awareness'}.
        type: bool
      portal_web_settings:
        description:
          - Configuration of the portal web settings.
        type: dict
        suboptions:
          aliases:
            description:
              - List of URL aliases that are redirected to the main portal URL.
            type: list
            elements: str
          ip_address:
            description:
              - Optional, IP address for the web portal to use, if your DNS server fails to resolve the main portal URL.
                Note, If your DNS server resolves the main portal URL, this IP address is ignored.
            type: str
          main_url:
            description:
              - The main URL for the web portal.
            type: str
      certificate_settings:
        description:
          - Configuration of the portal certificate settings.
        type: dict
        suboptions:
          base64_certificate:
            description:
              - The certificate file encoded in Base64 with padding. This file must be in the *.p12 format.
            type: str
          base64_password:
            description:
              - Password (encoded in Base64 with padding) for the certificate file.
            type: str
      accessibility:
        description:
          - Configuration of the portal access settings.
        type: dict
        suboptions:
          allow_access_from:
            description:
              - Allowed access to the web portal (based on interfaces, or security policy).
            type: str
            choices: ['rule_base', 'internal_interfaces', 'all_interfaces']
          internal_access_settings:
            description:
              - Configuration of the additional portal access settings for internal interfaces only.
            type: dict
            suboptions:
              undefined:
                description:
                  - Controls portal access settings for internal interfaces, whose topology is set to 'Undefined'.
                type: bool
              dmz:
                description:
                  - Controls portal access settings for internal interfaces, whose topology is set to 'DMZ'.
                type: bool
              vpn:
                description:
                  - Controls portal access settings for interfaces that are part of a VPN Encryption Domain.
                type: bool
  cluster_version:
    description:
      - Cluster platform version.
    type: str
  vpn:
    description:
      - VPN blade enabled.
    type: bool
  vpn_settings:
    description:
      - Gateway VPN settings.
    type: dict
    suboptions:
      authentication:
        description:
          - Authentication.
          - Available from R81 management version.
        type: dict
        suboptions:
          authentication_clients:
            description:
              - Collection of VPN Authentication clients identified by the name or UID.
            type: list
            elements: str
      link_selection:
        description:
          - Link Selection.
          - Available from R81 management version.
        type: dict
        suboptions:
          ip_selection:
            description:
              - N/A
            type: str
            choices: ['use-main-address', 'use-selected-address-from-topology', 'use-statically-nated-ip',
                     'calculated-ip-based-on-topology', 'dns-resolving-from-hostname', 'dns-resolving-from-gateway-and-domain-name',
                     'use-probing-with-high-availability', 'use-probing-with-load-sharing', 'use-one-time-probing']
          dns_resolving_hostname:
            description:
              - DNS Resolving Hostname. Must be set when "ip-selection" was selected to be "dns-resolving-from-hostname".
            type: str
          ip_address:
            description:
              - IP Address. Must be set when "ip-selection" was selected to be "use-selected-address-from-topology" or "use-statically-nated-ip".
            type: str
      maximum_concurrent_ike_negotiations:
        description:
          - N/A
        type: int
      maximum_concurrent_tunnels:
        description:
          - N/A
        type: int
      office_mode:
        description:
          - Office Mode. Notation Wide Impact - Office Mode apply IPSec VPN Software Blade clients and to the Mobile Access Software Blade clients.
          - Available from R81 management version.
        type: dict
        suboptions:
          mode:
            description:
              - Office Mode Permissions.When selected to be "off", all the other definitions are irrelevant.
            type: str
            choices: ['off', 'specific-group', 'all-users']
          group:
            description:
              - Group. Identified by name or UID. Must be set when "office-mode-permissions" was selected to be "group".
            type: str
          allocate_ip_address_from:
            description:
              - Allocate IP address Method.
                Allocate IP address by sequentially trying the given methods until success.
            type: dict
            suboptions:
              radius_server:
                description:
                  - Radius server used to authenticate the user.
                type: bool
              use_allocate_method:
                description:
                  - Use Allocate Method.
                type: bool
              allocate_method:
                description:
                  - Using either Manual (IP Pool) or Automatic (DHCP).
                    Must be set when "use-allocate-method" is true.
                type: str
                choices: ['manual', 'automatic']
              manual_network:
                description:
                  - Manual Network. Identified by name or UID.
                    Must be set when "allocate-method" was selected to be "manual".
                type: str
              dhcp_server:
                description:
                  - DHCP Server. Identified by name or UID.
                    Must be set when "allocate-method" was selected to be "automatic".
                type: str
              virtual_ip_address:
                description:
                  - Virtual IPV4 address for DHCP server replies.
                    Must be set when "allocate-method" was selected to be "automatic".
                type: str
              dhcp_mac_address:
                description:
                  - Calculated MAC address for DHCP allocation.
                    Must be set when "allocate-method" was selected to be "automatic".
                type: str
                choices: ['per-machine', 'per-user']
              optional_parameters:
                description:
                  - This configuration applies to all Office Mode methods except Automatic (using DHCP) and ipassignment.conf entries which contain this data.
                type: dict
                suboptions:
                  use_primary_dns_server:
                    description:
                      - Use Primary DNS Server.
                    type: bool
                  primary_dns_server:
                    description:
                      - Primary DNS Server. Identified by name or UID.
                        Must be set when "use-primary-dns-server" is true and can not be set when "use-primary-dns-server" is false.
                    type: str
                  use_first_backup_dns_server:
                    description:
                      - Use First Backup DNS Server.
                    type: bool
                  first_backup_dns_server:
                    description:
                      - First Backup DNS Server. Identified by name or UID.
                        Must be set when "use-first-backup-dns-server" is true and can not be set when "use-first-backup-dns-server" is false.
                    type: str
                  use_second_backup_dns_server:
                    description:
                      - Use Second Backup DNS Server.
                    type: bool
                  second_backup_dns_server:
                    description:
                      - Second Backup DNS Server. Identified by name or UID.
                        Must be set when "use-second-backup-dns-server" is true and can not be set when "use-second-backup-dns-server" is false.
                    type: str
                  dns_suffixes:
                    description:
                      - DNS Suffixes.
                    type: str
                  use_primary_wins_server:
                    description:
                      - Use Primary WINS Server.
                    type: bool
                  primary_wins_server:
                    description:
                      - Primary WINS Server. Identified by name or UID.
                        Must be set when "use-primary-wins-server" is true and can not be set when "use-primary-wins-server" is false.
                    type: str
                  use_first_backup_wins_server:
                    description:
                      - Use First Backup WINS Server.
                    type: bool
                  first_backup_wins_server:
                    description:
                      - First Backup WINS Server. Identified by name or UID.
                        Must be set when "use-first-backup-wins-server" is true and can not be set when "use-first-backup-wins-server" is false.
                    type: str
                  use_second_backup_wins_server:
                    description:
                      - Use Second Backup WINS Server.
                    type: bool
                  second_backup_wins_server:
                    description:
                      - Second Backup WINS Server. Identified by name or UID.
                        Must be set when "use-second-backup-wins-server" is true and can not be set when "use-second-backup-wins-server" is false.
                    type: str
                  ip_lease_duration:
                    description:
                      - IP Lease Duration in Minutes. The value must be in the range 2-32767.
                    type: int
          support_multiple_interfaces:
            description:
              - Support connectivity enhancement for gateways with multiple external interfaces.
            type: bool
          perform_anti_spoofing:
            description:
              - Perform Anti-Spoofing on Office Mode addresses.
            type: bool
          anti_spoofing_additional_addresses:
            description:
              - Additional IP Addresses for Anti-Spoofing. Identified by name or UID.
                Must be set when "perform-anti-spoofings" is true.
            type: str
      remote_access:
        description:
          - Remote Access.
          - Available from R81 management version.
        type: dict
        suboptions:
          support_l2tp:
            description:
              - Support L2TP (relevant only when office mode is active).
            type: bool
          l2tp_auth_method:
            description:
              - L2TP Authentication Method.
                Must be set when "support-l2tp" is true.
            type: str
            choices: ['certificate', 'md5']
          l2tp_certificate:
            description:
              - L2TP Certificate.
                Must be set when "l2tp-auth-method" was selected to be "certificate".
                Insert "defaultCert" when you want to use the default certificate.
            type: str
          allow_vpn_clients_to_route_traffic:
            description:
              - Allow VPN clients to route traffic.
            type: bool
          support_nat_traversal_mechanism:
            description:
              - Support NAT traversal mechanism (UDP encapsulation).
            type: bool
          nat_traversal_service:
            description:
              - Allocated NAT traversal UDP service. Identified by name or UID.
                Must be set when "support-nat-traversal-mechanism" is true.
            type: str
          support_visitor_mode:
            description:
              - Support Visitor Mode.
            type: bool
          visitor_mode_service:
            description:
              - TCP Service for Visitor Mode. Identified by name or UID.
                Must be set when "support-visitor-mode" is true.
            type: str
          visitor_mode_interface:
            description:
              - Interface for Visitor Mode.
                Must be set when "support-visitor-mode" is true.
                Insert IPV4 Address of existing interface or "All IPs" when you want all interfaces.
            type: str
      vpn_domain:
        description:
          - Gateway VPN domain identified by the name or UID.
        type: str
      vpn_domain_type:
        description:
          - Gateway VPN domain type.
        type: str
        choices: ['manual', 'addresses_behind_gw']
  show_portals_certificate:
    description:
      - Indicates whether to show the portals certificate value in the reply.
      - Available from R81 JHF management version.
    type: bool
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  groups:
    description:
      - Collection of group identifiers.
    type: list
    elements: str
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-simple-cluster
  cp_mgmt_simple_cluster:
    cluster_mode: cluster-xl-ha
    color: yellow
    firewall: true
    interfaces:
      - anti_spoofing: true
        interface_type: cluster
        ip_address: 17.23.5.1
        name: eth0
        network_mask: 255.255.255.0
        topology: EXTERNAL
      - interface_type: sync
        name: eth1
        topology: INTERNAL
        topology_settings:
          interface_leads_to_dmz: false
          ip_address_behind_this_interface: network defined by the interface ip and net mask
      - anti_spoofing: true
        interface_type: cluster
        ip_address: 192.168.1.1
        name: eth2
        network_mask: 255.255.255.0
        topology: INTERNAL
        topology_settings:
          interface_leads_to_dmz: false
          ip_address_behind_this_interface: network defined by the interface ip and net mask
    ip_address: 17.23.5.1
    members:
      - interfaces:
          - ip_address: 17.23.5.2
            name: eth0
            network_mask: 255.255.255.0
          - ip_address: 1.1.2.4
            name: eth1
            network_mask: 255.255.255.0
          - ip_address: 192.168.1.2
            name: eth2
            network_mask: 255.255.255.0
        ip_address: 17.23.5.2
        name: member1
        one_time_password: abcd
      - interfaces:
          - ip_address: 17.23.5.3
            name: eth0
            network_mask: 255.255.255.0
          - ip_address: 1.1.2.5
            name: eth1
            network_mask: 255.255.255.0
          - ip_address: 192.168.1.3
            name: eth2
            network_mask: 255.255.255.0
        ip_address: 17.23.5.3
        name: member2
        one_time_password: abcd
    name: cluster1
    os_name: Gaia
    state: present
    cluster_version: R80.30

- name: set-simple-cluster
  cp_mgmt_simple_cluster:
    name: cluster1
    state: present

- name: delete-simple-cluster
  cp_mgmt_simple_cluster:
    name: cluster1
    state: absent
"""

RETURN = """
cp_mgmt_simple_cluster:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_objects,
    api_call,
)


def main():
    argument_spec = dict(
        name=dict(type="str", required=True),
        ip_address=dict(type="str"),
        ipv4_address=dict(type="str"),
        ipv6_address=dict(type="str"),
        anti_bot=dict(type="bool"),
        anti_virus=dict(type="bool"),
        application_control=dict(type="bool"),
        cluster_mode=dict(
            type="str",
            choices=[
                "cluster-xl-ha",
                "cluster-ls-multicast",
                "cluster-ls-unicast",
                "opsec-ha",
                "opsec-ls",
            ],
        ),
        content_awareness=dict(type="bool"),
        firewall=dict(type="bool"),
        firewall_settings=dict(
            type="dict",
            options=dict(
                auto_calculate_connections_hash_table_size_and_memory_pool=dict(
                    type="bool"
                ),
                auto_maximum_limit_for_concurrent_connections=dict(
                    type="bool"
                ),
                connections_hash_size=dict(type="int"),
                maximum_limit_for_concurrent_connections=dict(type="int"),
                maximum_memory_pool_size=dict(type="int"),
                memory_pool_size=dict(type="int"),
            ),
        ),
        hardware=dict(type="str"),
        interfaces=dict(
            type="list",
            elements="dict",
            options=dict(
                name=dict(type="str"),
                interface_type=dict(
                    type="str",
                    choices=["cluster", "sync", "cluster + sync", "private"],
                ),
                ip_address=dict(type="str"),
                ipv4_address=dict(type="str"),
                ipv6_address=dict(type="str"),
                network_mask=dict(type="str"),
                ipv4_network_mask=dict(type="str"),
                ipv6_network_mask=dict(type="str"),
                mask_length=dict(type="str"),
                ipv4_mask_length=dict(type="str"),
                ipv6_mask_length=dict(type="str"),
                anti_spoofing=dict(type="bool"),
                anti_spoofing_settings=dict(
                    type="dict",
                    options=dict(
                        action=dict(type="str", choices=["prevent", "detect"]),
                        exclude_packets=dict(type="bool"),
                        excluded_network_name=dict(type="str"),
                        excluded_network_uid=dict(type="str"),
                        spoof_tracking=dict(
                            type="str", choices=["none", "log", "alert"]
                        ),
                    ),
                ),
                multicast_address=dict(type="str"),
                multicast_address_type=dict(
                    type="str", choices=["manual", "default"]
                ),
                security_zone=dict(type="bool"),
                security_zone_settings=dict(
                    type="dict",
                    options=dict(
                        auto_calculated=dict(type="bool"),
                        specific_zone=dict(type="str"),
                    ),
                ),
                tags=dict(type="list", elements="str"),
                topology=dict(
                    type="str", choices=["automatic", "external", "internal"]
                ),
                topology_settings=dict(
                    type="dict",
                    options=dict(
                        interface_leads_to_dmz=dict(type="bool"),
                        ip_address_behind_this_interface=dict(
                            type="str",
                            choices=[
                                "not defined",
                                "network defined by the interface ip and net mask",
                                "network defined by routing",
                                "specific",
                            ],
                        ),
                        specific_network=dict(type="str"),
                    ),
                ),
                color=dict(
                    type="str",
                    choices=[
                        "aquamarine",
                        "black",
                        "blue",
                        "crete blue",
                        "burlywood",
                        "cyan",
                        "dark green",
                        "khaki",
                        "orchid",
                        "dark orange",
                        "dark sea green",
                        "pink",
                        "turquoise",
                        "dark blue",
                        "firebrick",
                        "brown",
                        "forest green",
                        "gold",
                        "dark gold",
                        "gray",
                        "dark gray",
                        "light green",
                        "lemon chiffon",
                        "coral",
                        "sea green",
                        "sky blue",
                        "magenta",
                        "purple",
                        "slate blue",
                        "violet red",
                        "navy blue",
                        "olive",
                        "orange",
                        "red",
                        "sienna",
                        "yellow",
                    ],
                ),
                comments=dict(type="str"),
                details_level=dict(
                    type="str", choices=["uid", "standard", "full"]
                ),
                ignore_warnings=dict(type="bool"),
                ignore_errors=dict(type="bool"),
            ),
        ),
        ips=dict(type="bool"),
        ips_settings=dict(
            type="dict",
            options=dict(
                bypass_all_under_load=dict(type="bool"),
                bypass_track_method=dict(
                    type="str",
                    choices=[
                        "none",
                        "log",
                        "popup alert",
                        "mail alert",
                        "snmp trap alert",
                        "user defined alert no.1",
                        "user defined alert no.2",
                        "user defined alert no.3",
                    ],
                ),
                activation_mode=dict(
                    type="str",
                    choices=["according-to-policy", "detect-only"],
                ),
                cpu_usage_low_threshold=dict(type="int"),
                cpu_usage_high_threshold=dict(type="int"),
                memory_usage_low_threshold=dict(type="int"),
                memory_usage_high_threshold=dict(type="int"),
                send_threat_cloud_info=dict(type="bool"),
                reject_on_cluster_fail_over=dict(type="bool"),
            ),
        ),
        members=dict(
            type="list",
            elements="dict",
            options=dict(
                name=dict(type="str"),
                interfaces=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        name=dict(type="str"),
                        anti_spoofing=dict(type="bool"),
                        anti_spoofing_settings=dict(
                            type="dict",
                            options=dict(
                                action=dict(
                                    type="str", choices=["prevent", "detect"]
                                ),
                                exclude_packets=dict(type="bool"),
                                excluded_network_name=dict(type="str"),
                                excluded_network_uid=dict(type="str"),
                                spoof_tracking=dict(
                                    type="str",
                                    choices=["none", "log", "alert"],
                                ),
                            ),
                        ),
                        ip_address=dict(type="str"),
                        ipv4_address=dict(type="str"),
                        ipv6_address=dict(type="str"),
                        network_mask=dict(type="str"),
                        ipv4_network_mask=dict(type="str"),
                        ipv6_network_mask=dict(type="str"),
                        mask_length=dict(type="str"),
                        ipv4_mask_length=dict(type="str"),
                        ipv6_mask_length=dict(type="str"),
                        security_zone=dict(type="bool"),
                        security_zone_settings=dict(
                            type="dict",
                            options=dict(
                                auto_calculated=dict(type="bool"),
                                specific_zone=dict(type="str"),
                            ),
                        ),
                        tags=dict(type="list", elements="str"),
                        topology=dict(
                            type="str",
                            choices=["automatic", "external", "internal"],
                        ),
                        topology_settings=dict(
                            type="dict",
                            options=dict(
                                interface_leads_to_dmz=dict(type="bool"),
                                ip_address_behind_this_interface=dict(
                                    type="str",
                                    choices=[
                                        "not defined",
                                        "network defined by the interface ip and net mask",
                                        "network defined by routing",
                                        "specific",
                                    ],
                                ),
                                specific_network=dict(type="str"),
                            ),
                        ),
                        color=dict(
                            type="str",
                            choices=[
                                "aquamarine",
                                "black",
                                "blue",
                                "crete blue",
                                "burlywood",
                                "cyan",
                                "dark green",
                                "khaki",
                                "orchid",
                                "dark orange",
                                "dark sea green",
                                "pink",
                                "turquoise",
                                "dark blue",
                                "firebrick",
                                "brown",
                                "forest green",
                                "gold",
                                "dark gold",
                                "gray",
                                "dark gray",
                                "light green",
                                "lemon chiffon",
                                "coral",
                                "sea green",
                                "sky blue",
                                "magenta",
                                "purple",
                                "slate blue",
                                "violet red",
                                "navy blue",
                                "olive",
                                "orange",
                                "red",
                                "sienna",
                                "yellow",
                            ],
                        ),
                        comments=dict(type="str"),
                        details_level=dict(
                            type="str", choices=["uid", "standard", "full"]
                        ),
                        ignore_warnings=dict(type="bool"),
                        ignore_errors=dict(type="bool"),
                    ),
                ),
                ip_address=dict(type="str"),
                ipv4_address=dict(type="str"),
                ipv6_address=dict(type="str"),
                one_time_password=dict(type="str", no_log=True),
                tags=dict(type="list", elements="str"),
                color=dict(
                    type="str",
                    choices=[
                        "aquamarine",
                        "black",
                        "blue",
                        "crete blue",
                        "burlywood",
                        "cyan",
                        "dark green",
                        "khaki",
                        "orchid",
                        "dark orange",
                        "dark sea green",
                        "pink",
                        "turquoise",
                        "dark blue",
                        "firebrick",
                        "brown",
                        "forest green",
                        "gold",
                        "dark gold",
                        "gray",
                        "dark gray",
                        "light green",
                        "lemon chiffon",
                        "coral",
                        "sea green",
                        "sky blue",
                        "magenta",
                        "purple",
                        "slate blue",
                        "violet red",
                        "navy blue",
                        "olive",
                        "orange",
                        "red",
                        "sienna",
                        "yellow",
                    ],
                ),
                comments=dict(type="str"),
                details_level=dict(
                    type="str", choices=["uid", "standard", "full"]
                ),
                ignore_warnings=dict(type="bool"),
                ignore_errors=dict(type="bool"),
            ),
        ),
        os_name=dict(type="str"),
        platform_portal_settings=dict(
            type="dict",
            options=dict(
                portal_web_settings=dict(
                    type="dict",
                    options=dict(
                        aliases=dict(type="list", elements="str"),
                        ip_address=dict(type="str"),
                        main_url=dict(type="str"),
                    ),
                ),
                certificate_settings=dict(
                    type="dict",
                    options=dict(
                        base64_certificate=dict(type="str"),
                        base64_password=dict(type="str", no_log=True),
                    ),
                ),
                accessibility=dict(
                    type="dict",
                    options=dict(
                        allow_access_from=dict(
                            type="str",
                            choices=[
                                "rule_base",
                                "internal_interfaces",
                                "all_interfaces",
                            ],
                        ),
                        internal_access_settings=dict(
                            type="dict",
                            options=dict(
                                undefined=dict(type="bool"),
                                dmz=dict(type="bool"),
                                vpn=dict(type="bool"),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        send_alerts_to_server=dict(type="list", elements="str"),
        send_logs_to_backup_server=dict(type="list", elements="str"),
        send_logs_to_server=dict(type="list", elements="str"),
        tags=dict(type="list", elements="str"),
        threat_emulation=dict(type="bool"),
        threat_extraction=dict(type="bool"),
        threat_prevention_mode=dict(
            type="str", choices=["autonomous", "custom"]
        ),
        url_filtering=dict(type="bool"),
        usercheck_portal_settings=dict(
            type="dict",
            options=dict(
                enabled=dict(type="bool"),
                portal_web_settings=dict(
                    type="dict",
                    options=dict(
                        aliases=dict(type="list", elements="str"),
                        ip_address=dict(type="str"),
                        main_url=dict(type="str"),
                    ),
                ),
                certificate_settings=dict(
                    type="dict",
                    options=dict(
                        base64_certificate=dict(type="str"),
                        base64_password=dict(type="str", no_log=True),
                    ),
                ),
                accessibility=dict(
                    type="dict",
                    options=dict(
                        allow_access_from=dict(
                            type="str",
                            choices=[
                                "rule_base",
                                "internal_interfaces",
                                "all_interfaces",
                            ],
                        ),
                        internal_access_settings=dict(
                            type="dict",
                            options=dict(
                                undefined=dict(type="bool"),
                                dmz=dict(type="bool"),
                                vpn=dict(type="bool"),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        cluster_version=dict(type="str"),
        vpn=dict(type="bool"),
        vpn_settings=dict(
            type="dict",
            options=dict(
                authentication=dict(
                    type="dict",
                    options=dict(
                        authentication_clients=dict(
                            type="list", elements="str"
                        )
                    ),
                ),
                link_selection=dict(
                    type="dict",
                    options=dict(
                        ip_selection=dict(
                            type="str",
                            choices=[
                                "use-main-address",
                                "use-selected-address-from-topology",
                                "use-statically-nated-ip",
                                "calculated-ip-based-on-topology",
                                "dns-resolving-from-hostname",
                                "dns-resolving-from-gateway-and-domain-name",
                                "use-probing-with-high-availability",
                                "use-probing-with-load-sharing",
                                "use-one-time-probing",
                            ],
                        ),
                        dns_resolving_hostname=dict(type="str"),
                        ip_address=dict(type="str"),
                    ),
                ),
                maximum_concurrent_ike_negotiations=dict(type="int"),
                maximum_concurrent_tunnels=dict(type="int"),
                office_mode=dict(
                    type="dict",
                    options=dict(
                        mode=dict(
                            type="str",
                            choices=["off", "specific-group", "all-users"],
                        ),
                        group=dict(type="str"),
                        allocate_ip_address_from=dict(
                            type="dict",
                            options=dict(
                                radius_server=dict(type="bool"),
                                use_allocate_method=dict(type="bool"),
                                allocate_method=dict(
                                    type="str", choices=["manual", "automatic"]
                                ),
                                manual_network=dict(type="str"),
                                dhcp_server=dict(type="str"),
                                virtual_ip_address=dict(type="str"),
                                dhcp_mac_address=dict(
                                    type="str",
                                    choices=["per-machine", "per-user"],
                                ),
                                optional_parameters=dict(
                                    type="dict",
                                    options=dict(
                                        use_primary_dns_server=dict(
                                            type="bool"
                                        ),
                                        primary_dns_server=dict(type="str"),
                                        use_first_backup_dns_server=dict(
                                            type="bool"
                                        ),
                                        first_backup_dns_server=dict(
                                            type="str"
                                        ),
                                        use_second_backup_dns_server=dict(
                                            type="bool"
                                        ),
                                        second_backup_dns_server=dict(
                                            type="str"
                                        ),
                                        dns_suffixes=dict(type="str"),
                                        use_primary_wins_server=dict(
                                            type="bool"
                                        ),
                                        primary_wins_server=dict(type="str"),
                                        use_first_backup_wins_server=dict(
                                            type="bool"
                                        ),
                                        first_backup_wins_server=dict(
                                            type="str"
                                        ),
                                        use_second_backup_wins_server=dict(
                                            type="bool"
                                        ),
                                        second_backup_wins_server=dict(
                                            type="str"
                                        ),
                                        ip_lease_duration=dict(type="int"),
                                    ),
                                ),
                            ),
                        ),
                        support_multiple_interfaces=dict(type="bool"),
                        perform_anti_spoofing=dict(type="bool"),
                        anti_spoofing_additional_addresses=dict(type="str"),
                    ),
                ),
                remote_access=dict(
                    type="dict",
                    options=dict(
                        support_l2tp=dict(type="bool"),
                        l2tp_auth_method=dict(
                            type="str", choices=["certificate", "md5"]
                        ),
                        l2tp_certificate=dict(type="str"),
                        allow_vpn_clients_to_route_traffic=dict(type="bool"),
                        support_nat_traversal_mechanism=dict(type="bool"),
                        nat_traversal_service=dict(type="str"),
                        support_visitor_mode=dict(type="bool"),
                        visitor_mode_service=dict(type="str"),
                        visitor_mode_interface=dict(type="str"),
                    ),
                ),
                vpn_domain=dict(type="str"),
                vpn_domain_type=dict(
                    type="str", choices=["manual", "addresses_behind_gw"]
                ),
            ),
        ),
        show_portals_certificate=dict(type="bool"),
        color=dict(
            type="str",
            choices=[
                "aquamarine",
                "black",
                "blue",
                "crete blue",
                "burlywood",
                "cyan",
                "dark green",
                "khaki",
                "orchid",
                "dark orange",
                "dark sea green",
                "pink",
                "turquoise",
                "dark blue",
                "firebrick",
                "brown",
                "forest green",
                "gold",
                "dark gold",
                "gray",
                "dark gray",
                "light green",
                "lemon chiffon",
                "coral",
                "sea green",
                "sky blue",
                "magenta",
                "purple",
                "slate blue",
                "violet red",
                "navy blue",
                "olive",
                "orange",
                "red",
                "sienna",
                "yellow",
            ],
        ),
        comments=dict(type="str"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        groups=dict(type="list", elements="str"),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "simple-cluster"

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
