#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_lag_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_lag_interfaces
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage link aggregation group (LAG) interface parameters
description:
  - This module manages attributes of link aggregation group (LAG) interfaces of
    devices running Enterprise SONiC Distribution by Dell Technologies.
author: Abirami N (@abirami-n)

options:
  config:
    description: A list of LAG configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - ID of the LAG.
        type: str
        required: True
      members:
        description:
          - The list of interfaces that are part of the group.
        type: dict
        suboptions:
          interfaces:
            description:
              - The list of interfaces that are part of the group.
            type: list
            elements: dict
            suboptions:
              member:
                description:
                  - The interface name.
                type: str
      mode:
        description:
          - Specifies mode of the port-channel while creation.
          - Functional default is C(lacp).
        type: str
        choices:
          - static
          - lacp
      ethernet_segment:
        description:
          - Specifies Ethernet segment.
          - I(esi_type) and I(esi) can not be deleted separately.
          - When I(state=deleted) and both I(esi) and I(df_preference) are not specifed, the entire Ethernet segment will be deleted.
        version_added: 2.5.0
        type: dict
        suboptions:
          esi_type:
            description:
              - Specifies type of Ethernet Segment Identifier.
            required: True
            type: str
            choices:
              - auto_lacp
              - auto_system_mac
              - ethernet_segment_id
          esi:
            description:
              - Specifies value of Ethernet Segment Identifier.
              - Only C(AUTO) is supported when I(esi_type=auto_lacp) or I(esi_type=auto_system_mac).
            type: str
          df_preference:
            description:
              - The preference for Designated Forwarder election method.
              - The range of df_preference value is from 1 to 65535.
            type: int
      fallback:
        description:
          - Enable fallback mode.
        version_added: 3.1.0
        type: bool
      fast_rate:
        description:
          - Enable LACP fast rate mode.
        version_added: 3.1.0
        type: bool
      graceful_shutdown:
        description:
          - Enable graceful shutdown.
        version_added: 3.1.0
        type: bool
      lacp_individual:
        description:
          - Specifies LACP individual configuration.
          - Applicable only when I(mode=lacp).
        version_added: 3.1.0
        type: dict
        suboptions:
          enable:
            description:
              - Enable LACP individual.
            type: bool
          timeout:
            description:
              - Specifies LACP individual timeout in seconds.
              - The range is from 3 to 90.
            type: int
      min_links:
        description:
          - Specifies minimum number of links.
          - The range is from 1 to 32.
        version_added: 3.1.0
        type: int
      system_mac:
        description:
          - Specifies system MAC address for the portchannel.
        version_added: 3.1.0
        type: str
  state:
    description:
      - The state that the configuration should be left in.
    type: str
    choices:
     - merged
     - replaced
     - overridden
     - deleted
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# interface Eth1/10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel10
#  no shutdown
#

- name: Merge LAG interfaces configuration
  dellemc.enterprise_sonic.sonic_lag_interfaces:
    config:
      - name: PortChannel10
        fallback: true
        fast_rate: true
        graceful_shutdown: true
        members:
          interfaces:
            - member: Eth1/10
        system_mac: "12:12:12:12:12:12"
        ethernet_segment:
          esi_type: auto_lacp
          df_preference: 2222
      - name: PortChannel12
        min_links: 2
        members:
          interfaces:
            - member: Eth1/15
            - member: Eth1/16
            - member: Eth1/17
        lacp_individual:
          enable: true
          timeout: 30
    state: merged

# After state:
# ------------
#
# interface Eth1/10
#  channel-group 10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/15
#  channel-group 12
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/16
#  channel-group 12
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/17
#  channel-group 12
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel10
#  fast_rate
#  fallback
#  graceful-shutdown
#  no shutdown
#  system-mac 12:12:12:12:12:12
#  !
#  evpn ethernet-segment auto-lacp
#   df-preference 2222
#  !
# !
# interface PortChannel12
#  min-links 2
#  lacp individual
#  lacp individual timeout 30
#  no shutdown
#

# Using "replaced" state
#
# Before state:
# -------------
#
# interface Eth1/5
#  channel-group 10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/7
#  no channel-group
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel10
#  graceful-shutdown
#  no shutdown
#  system-mac 12:12:12:12:12:12
#  !
#  evpn ethernet-segment auto-lacp
#   df-preference 2222
#

- name: Replace LAG configurations of specified LAG interfaces
  dellemc.enterprise_sonic.sonic_lag_interfaces:
    config:
      - name: PortChannel20
        members:
          interfaces:
            - member: Eth1/6
        system_mac: "14:14:14:14:14:14"
        ethernet_segment:
          esi_type: auto_system_mac
          df_preference: 6666
      - name: PortChannel10
        members:
          interfaces:
            - member: Eth1/7
        system_mac: "14:14:14:14:14:14"
        ethernet_segment:
          esi_type: auto_system_mac
          df_preference: 3333
    state: replaced

# After state:
# ------------
#
# interface Eth1/5
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/6
#  channel-group 20
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/7
#  channel-group 10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel10
#  no shutdown
#  system-mac 14:14:14:14:14:14
#  !
#  evpn ethernet-segment auto-system-mac
#   df-preference 3333
# !
# interface PortChanne20
#  no shutdown
#  system-mac 14:14:14:14:14:14
#  !
#  evpn ethernet-segment auto-system-mac
#   df-preference 6666
#

# Using "overridden" state
#
# Before state:
# -------------
#
# interface Eth1/5
#  channel-group 10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/6
#  no channel-group
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel10
#  fast_rate
#  fallback
#  no shutdown
#  !
#  evpn ethernet-segment auto-system-mac
#   df-preference 2222
#

- name: Override all LAG interface configurations
  dellemc.enterprise_sonic.sonic_lag_interfaces:
    config:
      - name: PortChannel20
        min_links: 2
        members:
          interfaces:
            - member: Eth1/6
            - member: Eth1/7
            - member: Eth1/8
        system_mac: "12:12:12:12:12:12"
        ethernet_segment:
          esi_type: auto_lacp
          df_preference: 3333
        lacp_individual:
          enable: true
          timeout: 60
    state: overridden

# After state:
# ------------
#
# interface Eth1/5
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/6
#  channel-group 20
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/7
#  channel-group 20
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/8
#  channel-group 20
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel20
#  min-links 2
#  lacp individual
#  lacp individual timeout 60
#  no shutdown
#  system-mac 12:12:12:12:12:12
#  !
#  evpn ethernet-segment auto-lacp
#   df-preference 3333
#

# Using "deleted" state
#
# Before state:
# -------------
#
# interface Eth1/10
#  channel-group 10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/15
#  channel-group 12
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/16
#  channel-group 12
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel 10
#  no shutdown
#  system-mac 12:12:12:12:12:12
#  !
#  evpn ethernet-segment auto-lacp
#   df-preference 2222
# !
# interface PortChannel 12
#  fast_rate
#  fallback
#  graceful-shutdown
#  min-links 2
#  no shutdown
#

- name: Delete all LAG interfaces
  dellemc.enterprise_sonic.sonic_lag_interfaces:
    config:
    state: deleted

# After state:
# -------------
#
# interface Eth1/10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/15
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/16
#  mtu 9100
#  speed 100000
#  no shutdown
#

# Using "deleted" state
#
# Before state:
# -------------
# interface Eth1/10
#  channel-group 10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/11
#  channel-group 10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/20
#  channel-group 20
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel10
#  min-links 2
#  no shutdown
#  system-mac 12:12:12:12:12:12
#  !
#  evpn ethernet-segment auto-lacp
#   df-preference 2222
# !
# interface PortChannel20
#  no shutdown
#

- name: Delete specified LAG configurations and LAG interfaces
  dellemc.enterprise_sonic.sonic_lag_interfaces:
    config:
      - name: PortChannel10
        min_links: 2
        members:
          interfaces:
            - member: Eth1/10
        system_mac: "12:12:12:12:12:12"
        ethernet_segment:
          esi_type: auto_lacp
      - name: PortChannel20
    state: deleted

# After state:
# -------------
#
# interface Eth1/10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/11
#  channel-group 10
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface Eth1/20
#  mtu 9100
#  speed 100000
#  no shutdown
# !
# interface PortChannel10
#  no shutdown
#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration that is returned is always in the same format
    as the parameters above.
after:
  description: The resulting configuration on module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned is always in the same format
    as the parameters above.
after(generated):
  description: The configuration expected as a result of module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.lag_interfaces.lag_interfaces import Lag_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.lag_interfaces.lag_interfaces import Lag_interfaces


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Lag_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = Lag_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
