#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ipv6_router_advertisement
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ipv6_router_advertisement
version_added: '3.1.0'
short_description: Manage interface-specific IPv6 Router Advertisement configurations on SONiC
description:
  - This module provides configuration management of interface-specific
    IPv6 Router Advertisement parameters for devices running SONiC.
  - This functionality is referred to as 'ipv6 nd' in Enterprise SONiC CLI.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran)'
options:
  config:
    description:
      - Specifies interface-specific IPv6 Router Advertisement configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the interface.
        type: str
        required: true
      adv_interval_option:
        description:
          - Include Advertisement Interval option in Router Advertisement.
        type: bool
      home_agent_config:
        description:
          - Set 'Home Agent' flag in Router Advertisement.
        type: bool
      home_agent_lifetime:
        description:
          - Specifies the Home Agent lifetime in seconds when I(home_agent_config=True).
          - The range is from 0 to 65520.
        type: int
      home_agent_preference:
        description:
          - Specifies the Home Agent preference when I(home_agent_config=True).
          - The range is from 0 to 65535.
        type: int
      managed_config:
        description:
          - Set 'Managed Address Configuration' flag in Router Advertisement.
        type: bool
      mtu:
        description:
          - Specifies the MTU (in bytes) to be advertised.
          - The range is from 0 to 65535.
        type: int
      other_config:
        description:
          - Set 'Other Configuration' flag in Router Advertisement.
        type: bool
      ra_fast_retrans:
        description:
          - Enable faster transmissions of RA packets.
        type: bool
      ra_hop_limit:
        description:
          - Specifies the Hop limit to be advertised.
          - The range is from 0 to 255.
        type: int
      ra_interval:
        description:
          - Specifies the maximum Router Advertisement interval in seconds.
          - The range is from 1 to 1800.
        type: int
      ra_interval_msec:
        description:
          - Specifies the maximum Router Advertisement interval in milliseconds.
          - The range is from 70 to 1800000.
        type: int
      min_ra_interval:
        description:
          - Specifies the minimum Router Advertisement interval in seconds.
          - The range is from 1 to 1350.
        type: int
      min_ra_interval_msec:
        description:
          - Specifies the minimum Router Advertisement interval in milliseconds.
          - The range is from 30 to 1350000.
        type: int
      ra_lifetime:
        description:
          - Specifies the Router Lifetime in seconds.
          - The range is from 0 to 9000.
        type: int
      ra_retrans_interval:
        description:
          - Specifies the Retransmission Interval in milliseconds.
          - The range is from 0 to 4294967295.
        type: int
      reachable_time:
        description:
          - Specifies the Reachable Time in milliseconds.
          - The range is from 0 to 3600000.
        type: int
      router_preference:
        description:
          - Specifies the default router preference.
        type: str
        choices:
          - low
          - medium
          - high
      suppress:
        description:
          - Enable suppression of Router Advertisement.
        type: bool
      dnssl:
        description:
          - Specifies the DNS search list to advertise.
          - If I(state=deleted), options other than I(dnssl_name) are not considered.
        type: list
        elements: dict
        suboptions:
          dnssl_name:
            description:
              - Domain Name suffix to be advertised.
            type: str
            required: true
          valid_lifetime:
            description:
              - Specifies the valid lifetime in seconds.
              - The range if from 0 to 4294967295.
              - Value of 4294967295 represents infinite valid lifetime.
            type: int
      ra_prefixes:
        description:
          - Specifies the IPv6 prefixes to be included in Router Advertisement.
          - If I(state=deleted), options other than I(prefix) are not considered.
        type: list
        elements: dict
        suboptions:
          prefix:
            description:
              - IPv6 prefix to be advertised.
            type: str
            required: true
          valid_lifetime:
            description:
              - Specifies the valid lifetime in seconds.
              - The range if from 0 to 4294967295.
              - Value of 4294967295 represents infinite valid lifetime.
            type: int
          preferred_lifetime:
            description:
              - Specifies the preferred lifetime in seconds.
              - The range if from 0 to 4294967295.
              - Value of 4294967295 represents infinite preferred lifetime.
            type: int
          no_autoconfig:
            description:
              - Indicate the prefix cannot be used for IPv6 autoconfiguration.
            type: bool
          off_link:
            description:
              - Indicate the prefix cannot be used for on-link determination.
            type: bool
          router_address:
            description:
              - Set 'Router Address' flag.
            type: bool
      rdnss:
        description:
          - Specifies the Recursive DNS server addresses to advertise.
          - If I(state=deleted), options other than I(address) are not considered.
        type: list
        elements: dict
        suboptions:
          address:
            description:
              - Recursive DNS server address to be advertised.
            type: str
            required: true
          valid_lifetime:
            description:
              - Specifies the valid lifetime in seconds.
              - The range if from 0 to 4294967295.
              - Value of 4294967295 represents infinite valid lifetime.
            type: int
  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided interface-specific IPv6 router advertisement configuration with on-device configuration.
      - C(replaced) - Replaces on-device IPv6 router advertisement configuration of the specified interfaces with provided configuration.
      - C(overridden) - Overrides all on-device interface-specific IPv6 router advertisement configurations with the provided configuration.
      - C(deleted) - Deletes on-device interface-specific IPv6 router advertisement configuration.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""
EXAMPLES = """
# Using merged
#
# Before State:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd prefix 1000:0:0:1000::/64 86400 86400 off-link no-autoconfig
# !

- name: Add IPv6 Router Advertisement configurations
  dellemc.enterprise_sonic.sonic_ipv6_router_advertisement:
    config:
      - name: 'Eth1/1'
        suppress: false
        router_preference: high
        ra_interval: 180
        min_ra_interval: 60
        ra_lifetime: 360
        ra_retrans_interval: 30000
        ra_hop_limit: 10
        dnssl:
          - dnssl_name: 'test.com'
            valid_lifetime: 3600
        rdnss:
          - address: 100::100
          - address: 100::200
      - name: 'Eth1/2'
        adv_interval_option: true
        ra_fast_retrans: false
        reachable_time: 7200000
        ra_prefixes:
          - prefix: 1000:0:0:2000::/64
            valid_lifetime: 86400
            preferred_lifetime: 86400
            off_link: true
            no_autoconfig: true
    state: merged

# After State:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-hop-limit 10
#  ipv6 nd ra-interval 180
#  ipv6 nd min-ra-interval 60
#  ipv6 nd ra-lifetime 360
#  ipv6 nd ra-retrans-interval 30000
#  ipv6 nd router-preference high
#  ipv6 nd dnssl test.com 3600
#  ipv6 nd rdnss 100::100
#  ipv6 nd rdnss 100::200
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  no ipv6 nd ra-fast-retrans
#  ipv6 nd adv-interval-option
#  ipv6 nd reachable-time 1200000
#  ipv6 nd prefix 1000:0:0:1000::/64 86400 86400 off-link no-autoconfig
#  ipv6 nd prefix 1000:0:0:2000::/64 86400 86400 off-link no-autoconfig
# !


# Using deleted
#
# Before State:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-hop-limit 10
#  ipv6 nd ra-interval 180
#  ipv6 nd min-ra-interval 60
#  ipv6 nd ra-lifetime 360
#  ipv6 nd ra-retrans-interval 30000
#  ipv6 nd router-preference high
#  ipv6 nd dnssl test.com 3600
#  ipv6 nd dnssl test2.com 7200
#  ipv6 nd rdnss 100::100 3600
#  ipv6 nd rdnss 100::200 7200
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  no ipv6 nd ra-fast-retrans
#  ipv6 nd adv-interval-option
#  ipv6 nd min-ra-interval msec 45500
#  ipv6 nd reachable-time 1200000
#  ipv6 nd prefix 1000:0:0:1000::/64 86400 86400 off-link no-autoconfig
#  ipv6 nd prefix 1000:0:0:2000::/64 86400 86400 off-link no-autoconfig
# !

- name: Delete IPv6 Router Advertisement configurations
  dellemc.enterprise_sonic.sonic_ipv6_router_advertisement:
    config:
      - name: 'Eth1/1'
        ra_hop_limit: 10
        router_preference: high
        dnssl:
          - dnssl_name: test2.com
        rdnss:
          - address: 100::200
      - name: 'Eth1/2'
        adv_interval_option: true
        ra_fast_retrans: false
        ra_prefixes:
          - prefix: 1000:0:0:2000::/64
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-interval 180
#  ipv6 nd min-ra-interval 60
#  ipv6 nd ra-lifetime 360
#  ipv6 nd ra-retrans-interval 30000
#  ipv6 nd dnssl test.com 3600
#  ipv6 nd rdnss 100::100 3600
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd min ra-interval msec 45500
#  ipv6 nd reachable-time 1200000
#  ipv6 nd prefix 1000:0:0:1000::/64 86400 86400 off-link no-autoconfig
# !


# Using deleted
#
# Before State:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-hop-limit 10
#  ipv6 nd ra-interval 180
#  ipv6 nd min-ra-interval 60
#  ipv6 nd ra-lifetime 360
#  ipv6 nd ra-retrans-interval 30000
#  ipv6 nd dnssl test.com 3600
#  ipv6 nd rdnss 100::100 3600
#  ipv6 nd rdnss 100::200 7200
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd adv-interval-option
#  ipv6 nd router-preference low
#  ipv6 nd prefix 1000:0:0:1000::/64 86400 86400 off-link no-autoconfig
# !

- name: Delete all IPv6 Router Advertisement configurations for interface Eth1/1
  dellemc.enterprise_sonic.sonic_ipv6_router_advertisement:
    config:
      - name: 'Eth1/1'
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd adv-interval-option
#  ipv6 nd router-preference low
#  ipv6 nd prefix 1000:0:0:1000::/64 86400 86400 off-link no-autoconfig
# !


# Using deleted
#
# Before State:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-hop-limit 10
#  ipv6 nd ra-interval 180
#  ipv6 nd min-ra-interval 60
#  ipv6 nd ra-lifetime 360
#  ipv6 nd ra-retrans-interval 30000
#  ipv6 nd dnssl test.com 3600
#  ipv6 nd rdnss 100::100 3600
#  ipv6 nd rdnss 100::200 7200
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd adv-interval-option
#  ipv6 nd router-preference low
#  ipv6 nd prefix 1000:0:0:1000::/64 86400 86400 off-link no-autoconfig
# !

- name: Delete all IPv6 Router Advertisement configurations
  dellemc.enterprise_sonic.sonic_ipv6_router_advertisement:
    config:
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
# !


# Using replaced
#
# Before State:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-hop-limit 10
#  ipv6 nd ra-interval 180
#  ipv6 nd min-ra-interval 60
#  ipv6 nd ra-lifetime 360
#  ipv6 nd router-preference high
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  no ipv6 nd ra-fast-retrans
#  ipv6 nd adv-interval-option
#  ipv6 nd min-ra-interval msec 45500
#  ipv6 nd ra-hop-limit 10
#  ipv6 nd reachable-time 1200000
#  ipv6 nd prefix 1000:0:0:1000::/64 86400 86400 off-link no-autoconfig
#  ipv6 nd prefix 1000:0:0:2000::/64 86400 86400 off-link no-autoconfig
# !

- name: Replace IPv6 Router Advertisement configurations for interface Eth1/2
  dellemc.enterprise_sonic.sonic_ipv6_router_advertisement:
    config:
      - name: 'Eth1/2'
        suppress: false
        ra_interval: 300
        router_preference: high
        ra_prefixes:
          - prefix: 2000:0:0:1000::/64
            valid_lifetime: 3600
            preferred_lifetime: 3600
            router_address: true
    state: replaced

# After State:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-hop-limit 10
#  ipv6 nd ra-interval 180
#  ipv6 nd min-ra-interval 60
#  ipv6 nd ra-lifetime 360
#  ipv6 nd router-preference high
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-interval 300
#  ipv6 nd router-preference high
#  ipv6 nd prefix 2000:0:0:1000::/64 3600 3600 router-address
# !


# Using overridden
#
# Before State:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-hop-limit 10
#  ipv6 nd ra-interval 180
#  ipv6 nd min-ra-interval 60
#  ipv6 nd ra-lifetime 360
#  ipv6 nd router-preference high
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd ra-interval 300
#  ipv6 nd router-preference high
#  ipv6 nd prefix 2000:0:0:1000::/64 3600 3600 router-address
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
# !

- name: Override all IPv6 Router Advertisement configurations
  dellemc.enterprise_sonic.sonic_ipv6_router_advertisement:
    config:
      - name: 'Eth1/1'
        suppress: false
        home_agent_config: true
        home_agent_lifetime: 7200
        home_agent_preference: 100
      - name: 'Eth1/3'
        suppress: false
        managed_config: true
        other_config: true
        ra_retrans_interval: 30000
    state: overridden

# After State:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd home-agent-config-flag
#  ipv6 nd home-agent-lifetime 7200
#  ipv6 nd home-agent-preference 100
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  no ipv6 nd suppress-ra
#  ipv6 nd managed-config-flag
#  ipv6 nd other-config-flag
#  ipv6 nd ra-retrans-interval 30000
# !
"""
RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The configuration resulting from module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after(generated):
  description: The configuration that would be generated by module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ipv6_router_advertisement.ipv6_router_advertisement import (
    Ipv6_router_advertisementArgs
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ipv6_router_advertisement.ipv6_router_advertisement import (
    Ipv6_router_advertisement
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ipv6_router_advertisementArgs.argument_spec,
                           supports_check_mode=True)

    result = Ipv6_router_advertisement(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
