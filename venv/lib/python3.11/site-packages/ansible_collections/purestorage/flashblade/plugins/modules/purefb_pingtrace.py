#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2023, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_pingtrace
version_added: '1.11.0'
short_description: Employ the internal FlashBlade ping and trace mechanisms
description:
- Ping or trace a destination
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  action:
    description:
    - Which action is required, ping or trace
    type: str
    choices: [ ping, trace ]
    default: ping
  count:
    description:
    - Used by ping to specify the number of packets to send
    type: int
    default: 1
  resolve:
    description:
    - Specify whether or not to map IP addresses to host names
    type: bool
    default: True
  latency:
    description:
    - Specify whether or not to print the full user-to-user latency
    type: bool
    default: False
  packet_size:
    description:
    - Used by ping to specify the number of data bytes to send per packet
    type: int
    default: 56
  destination:
    description:
    - IP addtress or hostname used to run ping or trace against.
    type: str
    required: true
  method:
    description:
    - Used by trace to specify the method to use for operations
    type: str
    choices: [ icmp, tcp, udp ]
    default: udp
  fragment:
    description:
    - Used by trace to specify whether or not to fragment packets
    type: bool
    default: true
  discover_mtu:
    description:
    - Used by trace to specify whether or not to discover the MTU
      along the path being traced
    type: bool
    default: false
  port:
    description:
    - Used by trace to specify a destination port
    type: str
  source:
    description:
    - IP address or hostname used by ping and trace to specify where
      to start to run the specified operation
    - If not specified will use all available sources
    type: str
  component:
    description:
    - Used by ping and trace to specify where to run the operation.
    - Valid values are controllers and blades from hardware list.
    - If not specified defaults to all available controllers and selected blades
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: ping Google DNS server
  purestorage.flashblade.purefb_pingtrace:
    destination: 8.8.8.8
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: trace to Google DNS server from CH1.FM0
  purestorage.flashblade.purefb_pingtrace:
    action: trace
    destination: 8.8.8.8
    fragment_packet: true
    source: CH1.FM0
    discover_mtu: true
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)
import re

MIN_REQUIRED_API_VERSION = "2.6"


def run_ping(module, blade):
    """Run network ping"""
    ping_fact = {}
    if module.params["source"] and module.params["component"]:
        res = blade.get_network_interfaces_ping(
            destination=module.params["destination"],
            component_name=module.params["component"],
            source=module.params["source"],
            packet_size=module.params["packet_size"],
            count=module.params["count"],
            print_latency=module.params["latency"],
            resolve_hostname=module.params["resolve"],
        )
    elif module.params["source"] and not module.params["component"]:
        res = blade.get_network_interfaces_ping(
            destination=module.params["destination"],
            source=module.params["source"],
            packet_size=module.params["packet_size"],
            count=module.params["count"],
            print_latency=module.params["latency"],
            resolve_hostname=module.params["resolve"],
        )
    elif not module.params["source"] and module.params["component"]:
        res = blade.get_network_interfaces_ping(
            destination=module.params["destination"],
            component_name=module.params["component"],
            packet_size=module.params["packet_size"],
            count=module.params["count"],
            print_latency=module.params["latency"],
            resolve_hostname=module.params["resolve"],
        )
    else:
        res = blade.get_network_interfaces_ping(
            destination=module.params["destination"],
            packet_size=module.params["packet_size"],
            count=module.params["count"],
            print_latency=module.params["latency"],
            resolve_hostname=module.params["resolve"],
        )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to run ping. Error: {0}".format(res.errors[0].message)
        )
    else:
        responses = list(res.items)
        for resp in range(len(responses)):
            transmitted, received, packet_loss, time_ms = map(
                int,
                re.search(
                    r"(\d+) packets transmitted, (\d+) received, (\d+)% packet loss, time (\d+)ms",
                    responses[resp].details,
                ).groups(),
            )
            comp_name = responses[resp].component_name.replace(".", "_")
            ping_fact[comp_name] = {
                "destination": module.params["destination"],
                "source": module.params["source"],
                "packet_loss": str(packet_loss) + "%",
                "packet_tx": transmitted,
                "packet_rx": received,
                "time": str(time_ms) + "ms",
                "details": responses[resp].details,
            }

    module.exit_json(changed=False, pingfact=ping_fact)


def run_trace(module, blade):
    """Run network trace"""
    trace_fact = {}
    if module.params["source"] and module.params["component"]:
        res = blade.get_network_interfaces_trace(
            port=module.params["port"],
            destination=module.params["destination"],
            component_name=module.params["component"],
            discover_mtu=module.params["discover_mtu"],
            source=module.params["source"],
            fragment_packet=module.params["fragment"],
            method=module.params["method"],
            resolve_hostname=module.params["resolve"],
        )
    elif module.params["source"] and not module.params["component"]:
        res = blade.get_network_interfaces_trace(
            port=module.params["port"],
            destination=module.params["destination"],
            discover_mtu=module.params["discover_mtu"],
            source=module.params["source"],
            fragment_packet=module.params["fragment"],
            method=module.params["method"],
            resolve_hostname=module.params["resolve"],
        )
    elif not module.params["source"] and module.params["component"]:
        res = blade.get_network_interfaces_trace(
            port=module.params["port"],
            destination=module.params["destination"],
            discover_mtu=module.params["discover_mtu"],
            component_name=module.params["component"],
            fragment_packet=module.params["fragment"],
            method=module.params["method"],
            resolve_hostname=module.params["resolve"],
        )
    else:
        res = blade.get_network_interfaces_trace(
            port=module.params["port"],
            destination=module.params["destination"],
            discover_mtu=module.params["discover_mtu"],
            fragment_packet=module.params["fragment"],
            method=module.params["method"],
            resolve_hostname=module.params["resolve"],
        )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to run trace. Error: {0}".format(res.errors[0].message)
        )
    else:
        responses = list(res.items)
        for resp in range(len(responses)):
            comp_name = responses[resp].component_name.replace(".", "_")
            trace_fact[comp_name] = {
                "details": responses[resp].details,
            }

    module.exit_json(changed=False, tracefact=trace_fact)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            action=dict(type="str", choices=["ping", "trace"], default="ping"),
            method=dict(type="str", choices=["icmp", "tcp", "udp"], default="udp"),
            destination=dict(type="str", required=True),
            source=dict(type="str"),
            component=dict(type="str"),
            port=dict(type="str"),
            count=dict(type="int", default=1),
            packet_size=dict(type="int", default=56),
            resolve=dict(type="bool", default=True),
            fragment=dict(type="bool", default=True),
            latency=dict(type="bool", default=False),
            discover_mtu=dict(type="bool", default=False),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    blade = get_system(module)
    api_version = list(blade.get_versions().items)

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashBlade REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )

    blade = get_system(module)
    if module.params["action"] == "ping":
        run_ping(module, blade)
    else:
        run_trace(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
