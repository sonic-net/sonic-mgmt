#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_l3_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_l3_interfaces
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Configure the IPv4 and IPv6 parameters on Interfaces such as, Eth, LAG, VLAN, and loopback
description:
  - Configures Layer 3 interface settings on devices running Enterprise SONiC
    Distribution by Dell Technologies. This module provides configuration management
    of IPv4 and IPv6 parameters on Ethernet interfaces of devices running Enterprise SONiC.
author: Kumaraguru Narayanan (@nkumaraguru)
options:
  config:
    description:
      - A list of l3_interfaces configurations.
    type: list
    elements: dict
    suboptions:
      name:
        required: true
        type: str
        description:
          - Full name of the interface, for example, Eth1/3.
      ipv4:
        description:
          - ipv4 configurations to be set for the Layer 3 interface mentioned in name option.
        type: dict
        suboptions:
          addresses:
            description:
              - List of IPv4 addresses to be set.
            type: list
            elements: dict
            suboptions:
              address:
                description:
                  - IPv4 address to be set in the format <ipv4 address>/<mask>
                    for example, 192.0.2.1/24.
                type: str
              secondary:
                description:
                  - secondary flag of the ip address.
                  - Functional default is 'false'
                type: bool
          anycast_addresses:
            description:
              - List of IPv4 addresses to be set for anycast.
            type: list
            elements: str
          proxy_arp:
            description:
              - Configurations parameters for ipv4 proxy ARP
            version_added: 3.1.0
            type: dict
            suboptions:
              mode:
                description:
                  - Modes for proxy_arp
                type: str
                choices:
                  - DISABLE
                  - REMOTE_ONLY
                  - ALL
      ipv6:
        description:
          - ipv6 configurations to be set for the Layer 3 interface mentioned in name option.
        type: dict
        suboptions:
          addresses:
            description:
              - List of IPv6 addresses to be set.
            type: list
            elements: dict
            suboptions:
              address:
                description:
                  - IPv6 address to be set in the address format is <ipv6 address>/<mask>
                    for example, 2001:db8:2201:1::1/64.
                type: str
              eui64:
                description:
                  - Flag to indicate whether it is eui64 address
                version_added: 2.5.0
                type: bool
          anycast_addresses:
            description:
              - List of IPv6 anycast addresses.
            version_added: 3.1.0
            type: list
            elements: str
          enabled:
            description:
              - enabled flag of the ipv6.
            type: bool
          autoconf:
            description:
              - autoconfiguration flag
            version_added: 2.5.0
            type: bool
          dad:
            description:
              - IPv6 nd dad related configs.
            version_added: 2.5.0
            type: str
            choices:
              - ENABLE
              - DISABLE
              - DISABLE_IPV6_ON_FAILURE
          nd_proxy:
            description:
              - Configurations parameters for ipv6 ND-proxy
            version_added: 3.1.0
            type: dict
            suboptions:
              mode:
                description:
                  - Modes for nd_proxy
                type: str
                choices:
                  - DISABLE
                  - REMOTE_ONLY
                  - ALL
              nd_proxy_rules:
                description:
                  - List of ipv6 prefixes (subnets) for which this interface is
                    to serve as an nd proxy
                type: list
                elements: str
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 83.1.1.1/16
#  ip address 84.1.1.1/16 secondary
#  ipv6 address 83::1/16
#  ipv6 address 84::1/16
#  ipv6 address 85::/64 eui-64
#  ipv6 enable
#  ipv6 address autoconfig
#  ipv6 nd dad enable
#  ip proxy-arp enable remote-only
#  ipv6 nd-proxy enable all
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ip address 92.1.1.1/16 secondary
#  ipv6 address 90::1/16
#  ipv6 address 91::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
# !
# interface Vlan501
#  ip anycast-address 11.12.13.14/12
#  ip anycast-address 1.2.3.4/22
#  ipv6 anycast-address 101::101/64
#  ipv6 anycast-address 102::102/64
# !

- name: delete l3 interface attributes
  dellemc.enterprise_sonic.sonic_l3_interfaces:
    config:
      - name: Ethernet20
        ipv4:
          proxy_arp:
            mode: REMOTE_ONLY
          addresses:
            - address: 83.1.1.1/16
            - address: 84.1.1.1/16
        ipv6:
          addresses:
            - address: 85::/64
      - name: Ethernet24
        ipv6:
          enabled: true
          addresses:
            - address: 91::1/16
      - name: Vlan501
        ipv4:
          anycast_addresses:
            - 11.12.13.14/12
        ipv6:
          anycast_addresses:
            - 101::101/64
    state: deleted

#
# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
#  ipv6 address 83::1/16
#  ipv6 address 84::1/16
#  ipv6 enable
#  ipv6 address autoconfig
#  ipv6 nd dad enable
#  ipv6 nd-proxy enable all
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ip address 92.1.1.1/16 secondary
#  ipv6 address 90::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
# !
# interface Vlan501
#  ip anycast-address 1.2.3.4/22
#  ipv6 anycast-address 102::102/64
# !

# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 83.1.1.1/16
#  ip address 84.1.1.1/16 secondary
#  ipv6 address 83::1/16
#  ipv6 address 84::1/16
#  ipv6 address 85::/64 eui-64
#  ipv6 enable
#  ipv6 address autoconfig
#  ipv6 nd dad enable
#  ip proxy-arp enable remote-only
#  ipv6 nd-proxy enable all
#  ipv6 nd-proxy rule prefix 5001::/24
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ipv6 address 90::1/16
#  ipv6 address 91::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
#  ip proxy-arp enable all
#  ipv6 nd-proxy enable remote-only
#  ipv6 nd-proxy rule prefix 6001::/24
# !
# interface Vlan501
#  ip anycast-address 11.12.13.14/12
#  ip anycast-address 1.2.3.4/22
#  ipv6 anycast-address 101::101/64
#  ipv6 anycast-address 102::102/64
# !

- name: delete all l3 interface
  dellemc.enterprise_sonic.sonic_l3_interfaces:
    config:
    state: deleted

#
# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
# !
# interface Vlan501
# !

# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
# !
# interface Vlan501
#  ip anycast-address 1.2.3.4/22
#  ipv6 anycast-address 101::101/64
# !

- name: Add l3 interface configurations
  dellemc.enterprise_sonic.sonic_l3_interfaces:
    config:
      - name: Ethernet20
        ipv4:
          addresses:
            - address: 83.1.1.1/16
            - address: 84.1.1.1/16
              secondary: true
          proxy_arp:
            mode: REMOTE_ONLY
        ipv6:
          enabled: true
          dad: ENABLE
          autoconf: true
          addresses:
            - address: 83::1/16
            - address: 84::1/16
            - address: 85::/64
              eui64: true
      - name: Ethernet24
        ipv4:
          addresses:
            - address: 91.1.1.1/16
        ipv6:
          addresses:
            - address: 90::1/16
            - address: 91::1/16
            - address: 92::1/16
            - address: 93::1/16
          nd_proxy:
            mode: REMOTE_ONLY
            nd_proxy_rules:
              - 6001::/24
      - name: Vlan501
        ipv4:
          anycast_addresses:
            - 11.12.13.14/12
        ipv6:
          anycast_addresses:
            - 102::102/64
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 83.1.1.1/16
#  ip address 84.1.1.1/16 secondary
#  ip proxy-arp enable remote-only
#  ipv6 address 83::1/16
#  ipv6 address 84::1/16
#  ipv6 address 85::/64 eui-64
#  ipv6 enable
#  ipv6 address autoconfig
#  ipv6 nd dad enable
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ipv6 address 90::1/16
#  ipv6 address 91::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
#  ipv6 nd-proxy enable remote-only
#  ipv6 nd-proxy rule prefix 6001::/24
# !
# interface Vlan501
#  ip anycast-address 1.2.3.4/22
#  ip anycast-address 11.12.13.14/12
#  ipv6 anycast-address 101::101/64
#  ipv6 anycast-address 102::102/64
# !

# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 83.1.1.1/16
#  ip address 84.1.1.1/16 secondary
#  ipv6 address 83::1/16
#  ipv6 address 84::1/16
#  ipv6 enable
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ipv6 address 90::1/16
#  ipv6 address 91::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
# !

- name: Replace l3 interface
  dellemc.enterprise_sonic.sonic_l3_interfaces:
    config:
      - name: Ethernet20
        ipv4:
          - address: 81.1.1.1/16
        proxy_arp:
          mode: ALL
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 81.1.1.1/16
#  ip proxy-arp enable all
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ipv6 address 90::1/16
#  ipv6 address 91::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
# !

# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 83.1.1.1/16
#  ip address 84.1.1.1/16 secondary
#  ip proxy-arp enable all
#  ipv6 address 83::1/16
#  ipv6 address 84::1/16
#  ipv6 enable
#  ipv6 nd-proxy enable remote-only
#  ipv6 nd-proxy rule prefix 6001::/24
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ipv6 address 90::1/16
#  ipv6 address 91::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
# !

- name: Replace l3 interface
  dellemc.enterprise_sonic.sonic_l3_interfaces:
    config:
      - name: Ethernet20
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ipv6 address 90::1/16
#  ipv6 address 91::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
# !

# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 83.1.1.1/16
#  ip address 84.1.1.1/16 secondary
#  ipv6 address 83::1/16
#  ipv6 address 84::1/16
#  ipv6 address 85::/64 eui-64
#  ipv6 enable
#  ipv6 address autoconfig
#  ipv6 nd dad enable
#  ipv6 nd-proxy enable remote-only
#  ipv6 nd-proxy rule prefix 6001::/24
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 91.1.1.1/16
#  ipv6 address 90::1/16
#  ipv6 address 91::1/16
#  ipv6 address 92::1/16
#  ipv6 address 93::1/16
# !

- name: Override l3 interface
  dellemc.enterprise_sonic.sonic_l3_interfaces:
    config:
      - name: Ethernet24
        ipv4:
          - address: 81.1.1.1/16
        proxy_arp:
          mode: ALL
      - name: Vlan100
        ipv4:
          anycast_addresses:
            - 83.1.1.1/24
            - 85.1.1.12/24
        ipv6:
          anycast_addresses:
            - 83::1/24
            - 85::1/24
          nd_proxy:
            mode: REMOTE_ONLY
            nd_proxy_rules:
              - 6001::/24
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Ethernet20
#  mtu 9100
#  speed 100000
#  shutdown
# !
# interface Ethernet24
#  mtu 9100
#  speed 100000
#  shutdown
#  ip address 81.1.1.1/16
#  ip proxy-arp enable all
# !
# interface Vlan100
#  ip anycast-address 83.1.1.1/24
#  ip anycast-address 85.1.1.12/24
#  ipv6 anycast-address 83::1/24
#  ipv6 anycast-address 85::1/24
#  ipv6 nd-proxy enable remote-only
#  ipv6 nd-proxy rule prefix 6001::/24

# !
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after(generated):
  description: The generated configuration module invocation.
  returned: when C(check_mode)
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l3_interfaces.l3_interfaces import L3_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.l3_interfaces.l3_interfaces import L3_interfaces


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=L3_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = L3_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
