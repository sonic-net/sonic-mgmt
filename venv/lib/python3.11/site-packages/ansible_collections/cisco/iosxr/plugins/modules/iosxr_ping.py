#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_ping
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_ping
short_description: Tests reachability using ping from IOSXR switch.
description:
- Tests reachability using ping from switch to a remote destination.
- For a general purpose network module, see the L(net_ping,https://docs.ansible.com/ansible/latest/collections/ansible/netcommon/net_ping_module.html)
  module.
- For Windows targets, use the L(win_ping,https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_ping_module.html)
  module instead.
- For targets running Python, use the L(ping,https://docs.ansible.com/ansible/latest/collections/ansible/builtin/ping_module.html)
  module instead.
notes:
- Tested against IOSXR 7.2.2.
- This module works with connection C(network_cli).
- For a general purpose network module, see the L(net_ping,https://docs.ansible.com/ansible/latest/collections/ansible/netcommon/net_ping_module.html)
  module.
- For Windows targets, use the L(win_ping,https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_ping_module.html)
  module instead.
- For targets running Python, use the L(ping,https://docs.ansible.com/ansible/latest/collections/ansible/builtin/ping_module.html) module instead.

author: Sagar Paul (@KB-perByte)
options:
  count:
    description:
    - Repeat count the number of packets to send.
    type: int
  afi:
    description:
    - Define echo type ipv4 or ipv6.
    choices:
    - ipv4
    - ipv6
    default: ipv4
    type: str
  dest:
    description:
    - The IP Address or hostname (resolvable by switch) of the remote node.
    required: true
    type: str
  df_bit:
    description:
    - Set the DF bit in IP-header.
    default: false
    type: bool
  sweep:
    description:
    - Sweep ping.
    default: false
    type: bool
  validate:
    description:
    - Validate return packet.
    default: false
    type: bool
  source:
    description:
    - Source address or source interface.
    type: str
  size:
    description:
    - Datagram size the size of packets to send.
    type: int
  state:
    description:
    - Determines if the expected result is success or fail.
    choices:
    - absent
    - present
    default: present
    type: str
  vrf:
    description:
    - The VRF to use for forwarding.
    type: str
"""

EXAMPLES = """
- name: Test reachability to 198.51.100.251 using default vrf
  cisco.iosxr.iosxr_ping:
    dest: 198.51.100.251

- name: Test reachability to 198.51.100.252 using prod vrf
  cisco.iosxr.iosxr_ping:
    dest: 198.51.100.252
    vrf: prod
    afi: ipv4

- name: Test unreachability to 198.51.100.253 using default vrf
  cisco.iosxr.iosxr_ping:
    dest: 198.51.100.253
    state: absent

- name: Test reachability to 198.51.100.250 using prod vrf and setting count and source
  cisco.iosxr.iosxr_ping:
    dest: 198.51.100.250
    source: loopback0
    vrf: prod
    count: 20

- name: Test reachability to 198.51.100.249 using df-bit and size
  cisco.iosxr.iosxr_ping:
    dest: 198.51.100.249
    df_bit: true
    size: 1400

- name: Test reachability to ipv6 address
  cisco.iosxr.iosxr_ping:
    dest: 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
    afi: ipv6
"""

RETURN = """
commands:
  description: Show the command sent.
  returned: always
  type: list
  sample: ["ping vrf prod 198.51.100.251 count 20 source loopback0"]
packet_loss:
  description: Percentage of packets lost.
  returned: always
  type: str
  sample: "0%"
packets_rx:
  description: Packets successfully received.
  returned: always
  type: int
  sample: 20
packets_tx:
  description: Packets successfully transmitted.
  returned: always
  type: int
  sample: 20
rtt:
  description: Show RTT stats.
  returned: always
  type: dict
  sample: {"avg": 2, "max": 8, "min": 1}
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.ping.ping import (
    PingArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.ping.ping import Ping


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=PingArgs.argument_spec)

    result = Ping(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
