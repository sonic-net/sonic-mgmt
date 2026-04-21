#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_vrf_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_vrf_global
short_description: Resource module to configure VRF definitions.
description: This module provides declarative management of VRF definitions on Cisco NXOS.
version_added: 8.1.0
author: Vinay Mulugund (@roverflow)
notes:
  - Tested against NX-OS 9.3.6.
  - This module works with connection C(network_cli) and C(httpapi).
    See U(https://docs.ansible.com/ansible/latest/network/user_guide/platform_nxos.html)
options:
  config:
    description: A list containing device configurations for VRF.
    type: dict
    suboptions:
      vrfs:
        description: List of VRF definitions.
        type: list
        elements: dict
        suboptions:
          name:
            description: Name of the VRF..
            required: true
            type: str
          description:
            description: Description of the VRF.
            type: str
          rd:
            description: VPN Route Distinguisher
            type: str
          ip:
            description: Configure IP features for the specified vrf.
            type: dict
            suboptions:
              auto_discard:
                description: Auto 0.0.0.0/0 discard route.
                type: bool
              domain_list:
                description: Add list domain names.
                type: list
                elements: str
              domain_name:
                description: Specify default domain name.
                type: str
              icmp_err:
                description: Enable ICMP error message.
                type: dict
                suboptions:
                  source_interface:
                    description: Configure source-address for applications.
                    type: dict
                    suboptions:
                      interface:
                        description: Source interface for ICMP error messages.
                        type: str
                        choices:
                          - loopback
                          - ethernet
                          - port-channel
                      interface_value:
                        description: Source interface value for ICMP error messages.
                        type: str
              igmp:
                description: IGMP global configuration commands
                type: dict
                suboptions:
                  ssm_translate:
                    description: Translate IGMPv1/v2 reports to (S,G) route entries.
                    type: list
                    elements: dict
                    suboptions:
                      group:
                        description: Source address.
                        type: str
                      source:
                        description: Group address.
                        type: str
              mroutes:
                description: Configure multicast routes.
                type: list
                elements: dict
                suboptions:
                  group:
                    description: Multicast group address.
                    type: str
                  source:
                    description: Source address.
                    type: str
                  preference:
                    description: Preference value.
                    type: int
                  vrf:
                    description: VRF name.
                    type: str
              multicast:
                description: Configure IP multicast global parameters.
                type: dict
                suboptions:
                  group_range_prefix_list:
                    description: Group range prefix-list policy for multicast boundary.
                    type: str
                  multipath:
                    description: Configure ECMP multicast load splitting.
                    type: dict
                    suboptions:
                      resilient:
                        description: Configure resilient RPF interface.
                        type: bool
                      splitting_type:
                        description: Configure multicast load splitting type.
                        type: dict
                        suboptions:
                          none:
                            description: Disable multicast load splitting.
                            type: bool
                          legacy:
                            description: Configure hash based on source and group.
                            type: bool
                          nbm:
                            description: Configure NBM controlled RPF interface.
                            type: bool
                          sg_hash:
                            description: Configure hash based on source and group address.
                            type: bool
                          sg_hash_next_hop:
                            description: Configure hash based on source and group address and next-hop.
                            type: bool
                  rpf:
                    description: Configure RPF check.
                    type: list
                    elements: dict
                    suboptions:
                      vrf_name:
                        description: VRF for RPF lookup.
                        type: str
                      group_list_range:
                        description: Group range for RPF select.
                        type: str
              name_server:
                description: Specify nameserver address.
                type: dict
                suboptions:
                  address_list:
                    description: Configure multicast name server address.
                    type: list
                    elements: str
                  use_vrf:
                    description: Display per-VRF information.
                    type: dict
                    suboptions:
                      vrf:
                        description: VRF name.
                        type: str
                      source_address:
                        description: source address for configuring name server.
                        type: str
              route:
                description: Configure static routes.
                type: list
                elements: dict
                suboptions:
                  source:
                    description: Destination prefix.
                    type: str
                  destination:
                    description: Next-hop address.
                    type: str
                  tags:
                    description: Route tag.
                    type: dict
                    suboptions:
                      tag_value:
                        description: Route tag value.
                        type: int
                      route_pref:
                        description: Route preference.
                        type: int
                  vrf:
                    description: add vrf to the route.
                    type: str
                  track:
                    description: Configure track object.
                    type: str
          vni:
            description: Virtual Network Identifier.
            type: dict
            suboptions:
              vni_number:
                description: VNI number.
                type: int
              layer_3:
                description: Configure Layer 3 VNI.
                type: bool
          multicast:
            description: Configure IP multicast options.
            type: dict
            suboptions:
              service_reflect:
                description: Configure service reflect option.
                type: list
                elements: dict
                suboptions:
                  service_interface:
                    description: configure service interface.
                    type: str
                  map_to:
                    description: Map to interface.
                    type: str
          ipv6:
            description: Configure IPv6 features for the specified vrf.
            type: dict
            suboptions:
              mld_ssm_translate:
                description: Translate MLDv1/v2 reports to (S,G) route entries.
                type: list
                elements: dict
                suboptions:
                  icmp:
                    description: Configure ICMP parameters with mld.
                    type: bool
                  group:
                    description: Source address.
                    type: str
                  source:
                    description: Group address.
                    type: str
              multicast:
                description: Configure IP multicast global parameters for ipv6.
                type: dict
                suboptions:
                  group_range_prefix_list:
                    description: Group range prefix-list policy for multicast boundary.
                    type: str
                  multipath:
                    description: Configure ECMP multicast load splitting.
                    type: dict
                    suboptions:
                      resilient:
                        description: Configure resilient RPF interface.
                        type: bool
                      splitting_type:
                        description: Configure multicast load splitting type.
                        type: dict
                        suboptions:
                          none:
                            description: Disable multicast load splitting.
                            type: bool
                          sg_hash:
                            description: Configure hash based on source and group address.
                            type: bool
                          sg_hash_next_hop:
                            description: Configure hash based on source and group address and next-hop.
                            type: bool
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the NX-OS device
        by executing the command B(show running-config | section ^vrf).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    choices:
      [
        parsed,
        gathered,
        deleted,
        merged,
        replaced,
        rendered,
        overridden,
        purged,
      ]
    default: merged
    description:
      - The state the configuration should be left in
      - The states I(rendered), I(gathered) and I(parsed) does not perform any change
        on the device.
      - The state I(rendered) will transform the configuration in C(config) option to
        platform specific CLI commands which will be returned in the I(rendered) key
        within the result. For state I(rendered) active connection to remote host is
        not required.
      - The state I(gathered) will fetch the running configuration from device and transform
        it into structured data in the format as per the resource module argspec and
        the value is returned in the I(gathered) key within the result.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into JSON format as per the resource module parameters and the
        value is returned in the I(parsed) key within the result. The value of C(running_config)
        option should be the same format as the output of command I(show running-config | section ^vrf).
        connection to remote host is not required.
    type: str
"""

EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf

- name: Merge provided VRF configuration
  cisco.nxos.vrf_global:
    config:
      vrfs:
        - name: testvrf
          description: this is description
          ip:
            auto_discard: true
            domain_list:
              - example.net
              - example.com
            domain_name: test.com
            icmp_err:
              source_interface:
                interface: port-channel
                interface_value: '1'
            igmp:
              ssm_translate:
                - group: 232.0.0.0/8
                  source: 10.1.1.1
                - group: 239.1.2.3/24
                  source: 192.168.1.1
            mroutes:
              - group: 192.168.1.0/24
                source: 192.168.1.1
              - group: 192.168.1.0/24
                preference: 2
                source: 192.168.1.2
                vrf: temp1
            multicast:
              multipath:
                resilient: true
                splitting_type:
                  legacy: true
              rpf:
                - group_list_range: 238.1.0.0/24
                  vrf_name: temp1
                - group_list_range: 239.1.0.0/24
                  vrf_name: temp1
            name_server:
              address_list:
                - 192.168.0.1
                - 192.168.0.2
                - 192.168.1.1
                - 192.169.1.3
              use_vrf:
                source_address: 192.168.0.1
                vrf: temp1
            route:
              - destination: 192.0.2.22
                source: 192.0.0.0/24
              - destination: 192.0.2.22
                source: 192.0.0.0/24
                vrf: temp1
              - destination: 192.0.2.22
                source: 192.0.2.0/24
                tags:
                  route_pref: 4
                  tag_value: 2
          ipv6:
            mld_ssm_translate:
              - group: 'ff28::/16'
                source: '2001:db8:0:abcd::2'
              - group: 'ff30::/16'
                source: '2001:db8:0:abcd::5'
            multicast:
              group_range_prefix_list: temp2
              multipath:
                resilient: true
                splitting_type:
                  none: true
          multicast:
            service_reflect:
              - map_to: Ethernet2/2
                service_interface: Ethernet1/1
              - map_to: Ethernet4/2
                service_interface: Ethernet2/1
          vni:
            vni_number: 5
    state: merged

# Task Output:
# ------------

# before: {}
# commands:
#   - vrf context test1
#   - description this is description
#   - ip auto-discard
#   - ip domain-name test.net
#   - ip name-server 192.168.0.1 192.168.0.2 192.168.1.1 192.169.1.3
#   - ip icmp-errors source-interface port-channel 1
#   - ip multicast multipath resilient
#   - ip multicast multipath legacy
#   - ip name-server 192.168.0.1 use-vrf temp1
#   - vni 5
#   - ipv6 multicast group-range prefix-list temp2
#   - ipv6 multicast multipath resilient
#   - ipv6 multicast multipath none
#   - ip domain-list test.org
#   - ip domain-list example.com
#   - ip domain-list example.net
#   - ip igmp ssm-translate 232.0.0.0/8 10.1.1.1
#   - ip igmp ssm-translate 239.1.2.3/24 192.168.1.1
#   - ip mroute 192.168.1.0/24 192.168.1.1
#   - ip mroute 192.168.1.0/24 192.168.1.2 2 vrf temp1
#   - ip multicast rpf select vrf temp1 group-list 238.1.0.0/24
#   - ip multicast rpf select vrf temp1 group-list 239.1.0.0/24
#   - ip route 192.0.0.0/24 192.0.2.22
#   - ip route 192.0.0.0/24 192.0.2.22 vrf temp1
#   - ip route 192.0.2.0/24 192.0.2.22 tag 2 4
#   - multicast service-reflect interface Ethernet1/1 map interface Ethernet2/2
#   - multicast service-reflect interface Ethernet2/1 map interface Ethernet4/2
#   - ipv6 mld ssm-translate ff28::/16 2001:db8:0:abcd::2
#   - ipv6 mld ssm-translate ff30::/16 2001:db8:0:abcd::5

# after:
# 	vrfs:
# 	 - name: testvrf
# 	   description: this is description
# 	   ip:
# 	     auto_discard: true
# 	     domain_list:
# 	     - example.net
# 	     - example.com
# 	     domain_name: test.com
# 	     icmp_err:
# 	       source_interface:
# 	         interface: port-channel
# 	         interface_value: '1'
# 	     igmp:
# 	       ssm_translate:
# 	       - group: 232.0.0.0/8
# 	         source: 10.1.1.1
# 	       - group: 239.1.2.3/24
# 	         source: 192.168.1.1
# 	     mroutes:
# 	     - group: 192.168.1.0/24
# 	       source: 192.168.1.1
# 	     - group: 192.168.1.0/24
# 	       preference: 2
# 	       source: 192.168.1.2
# 	       vrf: temp1
# 	     multicast:
# 	       multipath:
# 	         resilient: true
# 	         splitting_type:
# 	           legacy: true
# 	       rpf:
# 	       - group_list_range: 238.1.0.0/24
# 	         vrf_name: temp1
# 	       - group_list_range: 239.1.0.0/24
# 	         vrf_name: temp1
# 	     name_server:
# 	       address_list:
# 	       - 192.168.0.1
# 	       - 192.168.0.2
# 	       - 192.168.1.1
# 	       - 192.169.1.3
# 	       use_vrf:
# 	         source_address: 192.168.0.1
# 	         vrf: temp1
# 	     route:
# 	     - destination: 192.0.2.22
# 	       source: 192.0.0.0/24
# 	     - destination: 192.0.2.22
# 	       source: 192.0.0.0/24
# 	        vrf: temp1
# 	     - destination: 192.0.2.22
# 	       source: 192.0.2.0/24
# 	       tags:
# 	         route_pref: 4
# 	         tag_value: 2
# 	   ipv6:
# 	     mld_ssm_translate:
# 	     - group: ff28::/16
# 	       source: 2001:db8:0:abcd::2
# 	     - group: ff30::/16
# 	       source: 2001:db8:0:abcd::5
# 	     multicast:
# 	       group_range_prefix_list: temp2
# 	       multipath:
# 	         resilient: true
# 	         splitting_type:
# 	           none: true
# 	   multicast:
# 	     service_reflect:
# 	      - map_to: Ethernet2/2
# 	        service_interface: Ethernet1/1
# 	      - map_to: Ethernet4/2
# 	        service_interface: Ethernet2/1
# 	   vni:
# 	     vni_number: 5

# After state:
# ------------
#
# nxos#show running-config | section ^vrf
# vrf context testvrf
#   description this is description
#   ip auto-discard
#   ip domain-name test.net
#   ip name-server 192.168.0.1 192.168.0.2 192.168.1.1 192.169.1.3
#   ip icmp-errors source-interface port-channel 1
#   ip multicast multipath resilient
#   ip multicast multipath legacy
#   ip name-server 192.168.0.1 use-vrf temp1
#   vni 5
#   ipv6 multicast group-range prefix-list temp2
#   ipv6 multicast multipath resilient
#   ipv6 multicast multipath none
#   ip domain-list test.org
#   ip domain-list example.com
#   ip domain-list example.net
#   ip igmp ssm-translate 232.0.0.0/8 10.1.1.1
#   ip igmp ssm-translate 239.1.2.3/24 192.168.1.1
#   ip mroute 192.168.1.0/24 192.168.1.1
#   ip mroute 192.168.1.0/24 192.168.1.2 2 vrf temp1
#   ip multicast rpf select vrf temp1 group-list 238.1.0.0/24
#   ip multicast rpf select vrf temp1 group-list 239.1.0.0/24
#   ip route 192.0.0.0/24 192.0.2.22
#   ip route 192.0.0.0/24 192.0.2.22 vrf temp1
#   ip route 192.0.2.0/24 192.0.2.22 tag 2 4
#   multicast service-reflect interface Ethernet1/1 map interface Ethernet2/2
#   multicast service-reflect interface Ethernet2/1 map interface Ethernet4/2
#   ipv6 mld ssm-translate ff28::/16 2001:db8:0:abcd::2
#   ipv6 mld ssm-translate ff30::/16 2001:db8:0:abcd::5

# Using deleted

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf
# vrf context management
#  ip name-server 192.168.255.1
#  ip route 0.0.0.0/0 192.168.255.1
# vrf context test1
#  description this is description
#  ip domain-name test.net
#  ip domain-list example.net
#  ip domain-list example.com
#  ip domain-list test.org
#  vni 5
#  ip auto-discard
#  ip route 192.0.0.0/24 192.0.2.22
#  ip route 192.0.0.0/24 192.0.2.22 vrf temp1
#  ip route 192.0.2.0/24 192.0.2.22 tag 2 4
#  ip mroute 192.168.1.0/24 192.168.1.1
#  ip mroute 192.168.1.0/24 192.168.1.2 2 vrf temp1
#  ip icmp-errors source-interface po1
#  ip igmp ssm-translate 232.0.0.0/8 10.1.1.1
#  ip igmp ssm-translate 239.1.2.3/24 192.168.1.1
#  ip multicast multipath legacy
#  ip multicast multipath resilient
#  ip multicast rpf select vrf temp1 group-list 238.1.0.0/24
#  ip multicast rpf select vrf temp1 group-list 239.1.0.0/24
#  ip multicast group-range prefix-list temp2

- name: Delete VRF configuration
  cisco.nxos.vrf_global:
    config:
      vrfs:
        - name: test1
    state: deleted

# Task Output:
# ------------
#
# before:
# 	vrfs:
# 	 - name: management
# 	   ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - source: 0.0.0.0/0
# 	       destination: 192.168.255.1
# 	 - name: test1
# 	   description: this is description
# 	   ip:
# 	     domain_name: test.net
# 	     domain_list:
# 	     - test.org
# 	     - example.net
# 	     - example.com
# 	     auto_discard: true
# 	     route:
# 	     - source: 192.0.0.0/24
# 	       destination: 192.0.2.22
# 	     - source: 192.0.0.0/24
# 	       destination: 192.0.2.22
# 	       vrf: temp1
# 	     - source: 192.0.2.0/24
# 	       destination: 192.0.2.22
# 	       tags:
# 	         tag_value: 2
# 	         route_pref: 4
# 	     mroutes:
# 	     - group: 192.168.1.0/24
# 	       source: 192.168.1.1
# 	     - group: 192.168.1.0/24
# 	       source: 192.168.1.2
# 	       preference: 2
# 	       vrf: temp1
# 	     icmp_err:
# 	       source_interface:
# 	         interface: port-channel
# 	         interface_value: '1'
# 	     igmp:
# 	       ssm_translate:
# 	       - group: 232.0.0.0/8
# 	         source: 10.1.1.1
# 	       - group: 239.1.2.3/24
# 	         source: 192.168.1.1
# 	     multicast:
# 	       multipath:
# 	         splitting_type:
# 	           legacy: true
# 	         resilient: true
# 	       rpf:
# 	       - vrf_name: temp1
# 	         group_list_range: 238.1.0.0/24
# 	       - vrf_name: temp1
# 	         group_list_range: 239.1.0.0/24
# 	   vni:
# 	     vni_number: 5

# commands:
#   - vrf context test1
#   - no description this is description
#   - no ip auto-discard
#   - no ip domain-name test.net
#   - no ip icmp-errors source-interface port-channel 1
#   - no ip multicast multipath resilient
#   - no ip multicast multipath legacy
#   - no vni 5
#   - no ip domain-list example.net
#   - no ip domain-list test.org
#   - no ip domain-list example.com
#   - no ip igmp ssm-translate 232.0.0.0/8 10.1.1.1
#   - no ip igmp ssm-translate 239.1.2.3/24 192.168.1.1
#   - no ip mroute 192.168.1.0/24 192.168.1.1
#   - no ip mroute 192.168.1.0/24 192.168.1.2 2 vrf temp1
#   - no ip multicast rpf select vrf temp1 group-list 238.1.0.0/24
#   - no ip multicast rpf select vrf temp1 group-list 239.1.0.0/24
#   - no ip route 192.0.0.0/24 192.0.2.22
#   - no ip route 192.0.0.0/24 192.0.2.22 vrf temp1
#   - no ip route 192.0.2.0/24 192.0.2.22 tag 2 4
#
# after:
# 	vrfs:
# 	 - name: management
# 	   ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - source: 0.0.0.0/0
# 	       destination: 192.168.255.1
# 	 - name: test1

# Using deleted with empty config

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf
# vrf context management
#  ip name-server 192.168.255.1
#  ip route 0.0.0.0/0 192.168.255.1
# vrf context test1
#  description this is description
#  ip domain-name test.net
#  ip domain-list example.net
#  ip domain-list example.com
#  ip domain-list test.org
#  vni 5

- name: Delete VRF configuration
  cisco.nxos.vrf_global:
    config:
      vrfs:
        - name: test1
    state: deleted

# Task Output:
# ------------
#
# before:
# 	vrfs:
# 	 - name: management
# 	   ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - source: 0.0.0.0/0
# 	       destination: 192.168.255.1
# 	 - name: test1
# 	   description: this is description
# 	   ip:
# 	     domain_name: test.net
# 	     domain_list:
# 	     - test.org
# 	     - example.net
# 	     - example.com
# 	   vni:
# 	     vni_number: 5

# commands:
#   - vrf context management
#   - no ip name-server 192.168.255.1
#   - no ip route 0.0.0.0/0 192.168.255.1
#   - vrf context test1
#   - no description this is description
#   - no ip domain-name test.net
#   - no vni 5
#   - no ip domain-list example.net
#   - no ip domain-list test.org
#   - no ip domain-list example.com

# after:
# 	vrfs:
# 	  - name: management
# 	  - name: test1

# Using purged

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf
# vrf context management
#   ip name-server 192.168.255.1
#   ip route 0.0.0.0/0 192.168.255.1
# vrf context test1
#   description this is description
#   ip domain-name example.com
#   ip domain-list example.net
#   ip domain-list example.org
#   vni 5
#   ip auto-discard
#   ip route 192.0.0.0/24 192.0.2.22
#   ip route 192.0.0.0/24 192.0.2.22 vrf temp1
#   ip route 192.0.2.0/24 192.0.2.22 tag 2 4
# vrf context test2
#   description test description
#   ip auto-discard
#   ip domain-name test.com

- name: Override VRF configuration
  cisco.nxos.vrf_global:
    config:
      vrfs:
        - name: test1
        - name: test2
    state: purged

# Task Output:
# ------------
#
# before:
# 	vrfs:
# 	 - name: management
# 	   ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - source: 0.0.0.0/0
# 	       destination: 192.168.255.1
# 	 - name: test1
# 	   description: this is description
# 	   ip:
# 	     domain_name: example.com
# 	     domain_list:
# 	     - example.net
# 	     - example.org
# 	     auto_discard: true
# 	     route:
# 	     - source: 192.0.0.0/24
# 	       destination: 192.0.2.22
# 	     - source: 192.0.0.0/24
# 	       destination: 192.0.2.22
# 	       vrf: temp1
# 	     - source: 192.0.2.0/24
# 	       destination: 192.0.2.22
# 	       tags:
# 	         tag_value: 2
# 	         route_pref: 4
# 	  vni:
# 	    vni_number: 5
# 	 - name: test2
# 	   description: test description
# 	   ip:
# 	     auto_discard: true
# 	     domain_name: test.com
#
# commands:
# - no vrf context test1
# - no vrf context test2
#
# after:
# 	vrfs:
# 	 - name: management
# 	   ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - source: 0.0.0.0/0
# 	       destination: 192.168.255.1

# Using overridden

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf
# vrf context management
#   ip name-server 192.168.255.1
#   ip route 0.0.0.0/0 192.168.255.1
# vrf context test1
#   description this is description
#   ip domain-name example.com
#   ip domain-list example.net
#   ip domain-list example.org
#   vni 5
#   ip auto-discard
#   ip route 192.0.0.0/24 192.0.2.22
#   ip route 192.0.0.0/24 192.0.2.22 vrf temp1
#   ip route 192.0.2.0/24 192.0.2.22 tag 2 4
# vrf context test2
#   description test description
#   ip auto-discard
#   ip domain-name test.com

- name: Override VRF configuration
  cisco.nxos.vrf_global:
    config:
      vrfs:
        - name: management
          ip:
            name_server:
              address_list:
                - 192.168.255.1
            route:
              - source: 0.0.0.0/0
                destination: 192.168.255.1
        - name: test1
          ip:
            auto_discard: false
            name_server:
              address_list:
                - 192.168.255.1
            route:
              - source: 192.0.0.0/24
                destination: 192.0.2.22
    state: overridden

# Task Output:
# ------------
#
# before:
# 	vrfs:
# 	 - name: management
# 	   ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - source: 0.0.0.0/0
# 	       destination: 192.168.255.1
# 	 - name: test1
# 	   description: this is description
# 	   ip:
# 	     domain_name: example.com
# 	     domain_list:
# 	     - example.net
# 	     - example.org
# 	     auto_discard: true
# 	     route:
# 	     - source: 192.0.0.0/24
# 	       destination: 192.0.2.22
# 	     - source: 192.0.0.0/24
# 	       destination: 192.0.2.22
# 	       vrf: temp1
# 	     - source: 192.0.2.0/24
# 	       destination: 192.0.2.22
# 	       tags:
# 	         tag_value: 2
# 	         route_pref: 4
# 	   vni:
# 	     vni_number: 5
# 	 - name: test2
# 	   description: test description
# 	   ip:
# 	     auto_discard: true
# 	     domain_name: test.com
#
# commands:
# - vrf context test1
# - no description this is description
# - no ip domain-name example.com
# - no ip domain-list example.net
# - no ip domain-list example.org
# - ip name-server 192.168.255.1
# - no ip auto-discard
# - no vni 5
# - no ip route 192.0.0.0/24 192.0.2.22 vrf temp1
# - no ip route 192.0.2.0/24 192.0.2.22 tag 2 4
# - vrf context test2
# - no description test description
# - no ip auto-discard
# - no ip domain-name test.com
#
# after:
# 	vrfs:
# 	 - name: management
# 	   ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - source: 0.0.0.0/0
# 	       destination: 192.168.255.1
# 	 - name: test1
# 	   ip:
# 	     auto_discard: false
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - source: 192.0.0.0/24
# 	       destination: 192.0.2.22

# Using replaced

# Before state:
# -------------
#
# nxos# show running-config | section ^vrf
# vrf context management
#   ip name-server 192.168.255.1
#   ip route 0.0.0.0/0 192.168.255.1
# vrf context temp
#   ip domain-name test.org
#   ip domain-list example.net
#   ip domain-list example.com
#   ip domain-list test.org
#   ip name-server 192.168.0.1 192.169.1.3
#   ip name-server 192.168.0.1 use-vrf temp1
#   multicast service-reflect interface Ethernet1/1 map interface Ethernet2/2
#   multicast service-reflect interface Ethernet2/1 map interface Ethernet4/2
#   description this is descrition
#   vni 5
#   ip auto-discard
#   ip route 192.0.0.0/24 192.0.2.22
#   ip route 192.0.0.0/24 192.0.2.22 vrf temp1
#   ip route 192.0.2.0/24 192.0.2.22 tag 2 4
#   ip mroute 192.168.1.0/24 192.168.1.1
#   ip mroute 192.168.1.0/24 192.168.1.2 2 vrf temp1
#   ip icmp-errors source-interface po1
#   ip igmp ssm-translate 232.0.0.0/8 10.1.1.1
#   ip igmp ssm-translate 239.1.2.3/24 192.168.1.1
#   ip multicast multipath legacy
#   ip multicast multipath resilient
#   ip multicast rpf select vrf temp1 group-list 238.1.0.0/24
#   ip multicast rpf select vrf temp1 group-list 239.1.0.0/24
#   ip multicast group-range prefix-list temp2
#   ipv6 multicast multipath none
#   ipv6 multicast multipath resilient
#   ipv6 multicast group-range prefix-list temp2
#   ipv6 mld ssm-translate ff28::/16 2001:db8:0:abcd::2
#   ipv6 mld ssm-translate ff30::/16 2001:db8:0:abcd::1
#   ipv6 mld ssm-translate ff32::/16 2001:db8:0:abcd::2
#   ipv6 mld ssm-translate ff32::/16 2001:db8:0:abcd::3

- name: Replaced state for VRF configuration
  cisco.nxos.nxos_vrf_global:
    config:
      vrfs:
        - ip:
            name_server:
              address_list:
                - 192.168.255.1
            route:
              - destination: 192.168.255.1
                source: 0.0.0.0/0
          name: management
        - name: temp
          description: Test
          ip:
            auto_discard: true
            domain_list:
              - invalid.com
              - example.com
            domain_name: test.org
    state: replaced

# Task Output:
# ------------
#
# before:
# 	vrfs:
# 	 - ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - destination: 192.168.255.1
# 	       source: 0.0.0.0/0
# 	   name: management
# 	 - description: this is descrition
# 	   ip:
# 	     auto_discard: true
# 	     domain_list:
# 	     - example.net
# 	     - test.org
# 	     - example.com
# 	     domain_name: test.org
# 	     icmp_err:
# 	       source_interface:
# 	         interface: port-channel
# 	         interface_value: '1'
# 	     igmp:
# 	       ssm_translate:
# 	       - group: 232.0.0.0/8
# 	         source: 10.1.1.1
# 	       - group: 239.1.2.3/24
# 	         source: 192.168.1.1
# 	     mroutes:
# 	     - group: 192.168.1.0/24
# 	       source: 192.168.1.1
# 	     - group: 192.168.1.0/24
# 	       preference: 2
# 	       source: 192.168.1.2
# 	       vrf: temp1
# 	     multicast:
# 	       multipath:
# 	         resilient: true
# 	         splitting_type:
# 	           legacy: true
# 	       rpf:
# 	       - group_list_range: 238.1.0.0/24
# 	         vrf_name: temp1
# 	       - group_list_range: 239.1.0.0/24
# 	         vrf_name: temp1
# 	     name_server:
# 	       address_list:
# 	       - 192.168.0.1
# 	       - 192.169.1.3
# 	       use_vrf:
# 	         source_address: 192.168.0.1
# 	         vrf: temp1
# 	     route:
# 	     - destination: 192.0.2.22
# 	       source: 192.0.0.0/24
# 	     - destination: 192.0.2.22
# 	       source: 192.0.0.0/24
# 	       vrf: temp1
# 	     - destination: 192.0.2.22
# 	       source: 192.0.2.0/24
# 	       tags:
# 	         route_pref: 4
# 	         tag_value: 2
# 	   ipv6:
# 	     mld_ssm_translate:
# 	     - group: ff28::/16
# 	       source: 2001:db8:0:abcd::2
# 	     - group: ff30::/16
# 	       source: 2001:db8:0:abcd::1
# 	     - group: ff32::/16
# 	       source: 2001:db8:0:abcd::2
# 	     - group: ff32::/16
# 	       source: 2001:db8:0:abcd::3
# 	     multicast:
# 	       group_range_prefix_list: temp2
# 	       multipath:
# 	         resilient: true
# 	         splitting_type:
# 	           none: true
# 	   multicast:
# 	     service_reflect:
# 	     - map_to: Ethernet2/2
# 	       service_interface: Ethernet1/1
# 	     - map_to: Ethernet4/2
# 	       service_interface: Ethernet2/1
# 	   name: temp
# 	   vni:
# 	     vni_number: 5
#
# commands:
#   - vrf context temp
#   - description Test
#   - no ip name-server 192.168.0.1 192.169.1.3
#   - no ip icmp-errors source-interface port-channel 1
#   - no ip multicast multipath resilient
#   - no ip multicast multipath legacy
#   - no ip name-server 192.168.0.1 use-vrf temp1
#   - no vni 5
#   - no ipv6 multicast group-range prefix-list temp2
#   - no ipv6 multicast multipath resilient
#   - no ipv6 multicast multipath none
#   - ip domain-list invalid.com
#   - no ip domain-list example.net
#   - no ip domain-list test.org
#   - no ip igmp ssm-translate 232.0.0.0/8 10.1.1.1
#   - no ip igmp ssm-translate 239.1.2.3/24 192.168.1.1
#   - no ip mroute 192.168.1.0/24 192.168.1.1
#   - no ip mroute 192.168.1.0/24 192.168.1.2 2 vrf temp1
#   - no ip multicast rpf select vrf temp1 group-list 238.1.0.0/24
#   - no ip multicast rpf select vrf temp1 group-list 239.1.0.0/24
#   - no ip route 192.0.0.0/24 192.0.2.22
#   - no ip route 192.0.0.0/24 192.0.2.22 vrf temp1
#   - no ip route 192.0.2.0/24 192.0.2.22 tag 2 4
#   - no multicast service-reflect interface Ethernet1/1 map interface Ethernet2/2
#   - no multicast service-reflect interface Ethernet2/1 map interface Ethernet4/2
#   - no ipv6 mld ssm-translate ff28::/16 2001:db8:0:abcd::2
#   - no ipv6 mld ssm-translate ff30::/16 2001:db8:0:abcd::1
#   - no ipv6 mld ssm-translate ff32::/16 2001:db8:0:abcd::2
#   - no ipv6 mld ssm-translate ff32::/16 2001:db8:0:abcd::3
#
# after:
# 	vrfs:
# 	 - ip:
# 	     name_server:
# 	       address_list:
# 	       - 192.168.255.1
# 	     route:
# 	     - destination: 192.168.255.1
# 	       source: 0.0.0.0/0
# 	   name: management
# 	 - description: Test
# 	   ip:
# 	     auto_discard: true
# 	     domain_list:
# 	     - invalid.com
# 	     - example.com
# 	     domain_name: test.org
# 	     multicast:
# 	       rpf:
# 	       - group_list_range: 238.1.0.0/24
# 	         vrf_name: temp1
# 	       - group_list_range: 239.1.0.0/24
# 	         vrf_name: temp1
#
# After state:
# ------------
# router-ios#show running-config | section ^vrf
# vrf context management
#   ip name-server 192.168.255.1
#   ip route 0.0.0.0/0 192.168.255.1
# vrf context temp
#   ip domain-name test.org
#   ip domain-list example.com
#   ip domain-list invalid.com
#   description Test
#   ip auto-discard
#   ip multicast rpf select vrf temp1 group-list 238.1.0.0/24
#   ip multicast rpf select vrf temp1 group-list 239.1.0.0/24
#   ip multicast group-range prefix-list temp2
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
commands:
  description: The set of commands pushed to the remote device.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample:
    - vrf context management
    - description this is management vrf
    - ip domain-name example.com
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - vrf context test1
    - description This is a test VRF
    - ip route 192.0.0.0/24 192.0.2.22
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when I(state) is C(gathered)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when I(state) is C(parsed)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.vrf_global.vrf_global import (
    Vrf_globalArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.vrf_global.vrf_global import (
    Vrf_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Vrf_globalArgs.argument_spec,
        mutually_exclusive=[["config", "running_config"]],
        required_if=[
            ["state", "merged", ["config"]],
            ["state", "replaced", ["config"]],
            ["state", "overridden", ["config"]],
            ["state", "rendered", ["config"]],
            ["state", "parsed", ["running_config"]],
        ],
        supports_check_mode=True,
    )

    result = Vrf_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
