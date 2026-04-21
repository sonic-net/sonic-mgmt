#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ecmp_load_share
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ecmp_load_share
version_added: 3.1.0
author: M. Zhang (@mingjunzhang2019)
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: IP ECMP load share mode configuration handling for SONiC.
description:
  - This module provides configuration management for IP ECMP load share mode on
  - devices running SONiC.
options:
  config:
    description:
      - IP ECMP load share mode configuration.
    type: dict
    suboptions:
      hash_algorithm:
        description:
          - Load share hash algorithm.
        type: str
        choices:
          - CRC
          - XOR
          - CRC_32LO
          - CRC_32HI
          - CRC_CCITT
          - CRC_XOR
          - JENKINS_HASH_LO
          - JENKINS_HASH_HI
      hash_ingress_port:
        description:
          - Include the ingress port in the load share hash calculation.
        type: bool
      hash_offset:
        description:
          - Load share hash offset.
        type: dict
        suboptions:
          offset:
            description:
              - IP ECMP hash offset value.
              - The range of values is from 0 to 15.
            type: int
          flow_based:
            description:
              - Enable flow-based IP ECMP hashing.
              - If this option is set to true, the configured 'offset' value is ignored.
            type: bool
      hash_roce_qpn:
        description:
          - Include the ROCE Queue-Pair Number in the load share hash calculation.
        type: bool
      hash_seed:
        description:
          - IP ECMP hash seed value.
          - The range of values is from 0 to 16777215.
        type: int
      ipv4:
        description:
          - IPv4 ECMP Load share hash parameters.
        type: dict
        suboptions:
          ipv4_dst_ip:
            description:
              - Include the IPv4 destination IP address in the load share hash calculation.
            type: bool
          ipv4_src_ip:
            description:
              - Include the IPv4 source IP address in the load share hash calculation.
            type: bool
          ipv4_ip_proto:
            description:
              - Include the IPv4 protocol value in the load share hash calculation.
            type: bool
          ipv4_l4_dst_port:
            description:
              - Include the IPv4 L4 source port in the load share hash calculation.
            type: bool
          ipv4_l4_src_port:
            description:
              - IPv4 L4 source port.
            type: bool
          ipv4_symmetric:
            description:
              - IPv4 symmetric hash mode.
            type: bool
      ipv6:
        description:
          - IPv6 ECMP Load share hash parameters.
        type: dict
        suboptions:
          ipv6_dst_ip:
            description:
              - Include the IPv6 destination IP address in the load share hash calculation.
            type: bool
          ipv6_src_ip:
            description:
              - Include the IPv6 source IP address in the load share hash calculation.
            type: bool
          ipv6_next_hdr:
            description:
              - Include the IPv6 "next header" value (usually the Transport Layer protocol type) in the
              - load share hash calculation.
            type: bool
          ipv6_l4_dst_port:
            description:
              - Include the IPv6 L4 destination port in the load share hash calculation.
            type: bool
          ipv6_l4_src_port:
            description:
              - Include the IPv6 L4 source port in the load share hash calculation.
            type: bool
          ipv6_symmetric:
            description:
              - IPv6 symmetric hash mode.
            type: bool
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
# sonic# show running-configuration | grep load-share
# ip load-share hash offset flow-based
# ip load-share hash seed 8888
# ip load-share hash ipv4 ipv4-dst-ip
# ip load-share hash ipv4 ipv4-src-ip
# ip load-share hash ipv4 ipv4-ip-proto
# ip load-share hash ipv4 ipv4-l4-src-port
# ip load-share hash ipv4 ipv4-l4-dst-port
# ip load-share hash algorithm CRC
# ip load-share hash ingress-port
# ip load-share hash roce qpn

- name: Delete some configuration
  sonic_ecmp_load_share:
    config:
      hash_algorithm: CRC
      hash_offset:
        flow_based: true
      hash_roce_qpn: true
      hash_seed: 8888
      ipv4:
        ipv4_l4_dst_port: true
        ipv4_l4_src_port: true
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep load-share
# ip load-share hash ipv4 ipv4-dst-ip
# ip load-share hash ipv4 ipv4-src-ip
# ip load-share hash ipv4 ipv4-ip-proto
# ip load-share hash ingress-port


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep load-share
# ip load-share hash seed 8888
# ip load-share hash ipv4 ipv4-dst-ip
# ip load-share hash algorithm CRC

- name: Merge some configuration
  sonic_ecmp_load_share:
    config:
      hash_algorithm: CRC_32LO
      hash_ingress_port: true
      hash_offset:
        offset: 12
        flow_based: true
      hash_roce_qpn: true
      hash_seed: 9999
      ipv4:
        ipv4_src_ip: true
        ipv4_ip_proto: true
        ipv4_l4_dst_port: true
        ipv4_l4_src_port: true
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep load-share
# ip load-share hash seed 9999
# ip load-share hash ipv4 ipv4-dst-ip
# ip load-share hash ipv4 ipv4-src-ip
# ip load-share hash ipv4 ipv4-ip-proto
# ip load-share hash ipv4 ipv4-l4-src-port
# ip load-share hash ipv4 ipv4-l4-dst-port
# ip load-share hash algorithm CRC_32LO
# ip load-share hash ingress-port


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep load-share
# ip load-share hash offset flow-based
# ip load-share hash seed 8888
# ip load-share hash ipv4 ipv4-dst-ip
# ip load-share hash ipv4 ipv4-src-ip
# ip load-share hash algorithm CRC
# ip load-share hash ingress-port

- name: Replace some configuration
  sonic_ecmp_load_share:
    config:
      hash_algorithm: XOR
      hash_ingress_port: true
      hash_offset:
        flow_based: true
      hash_seed: 7777
      ipv4:
        ipv4_src_ip: true
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration | grep load-share
# ip load-share hash offset flow-based
# ip load-share hash seed 7777
# ip load-share hash ipv4 ipv4-src-ip
# ip load-share hash algorithm XOR
# ip load-share hash ingress-port


# Using overridden
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep load-share
# ip load-share hash offset flow-based
# ip load-share hash seed 9999
# ip load-share hash ipv4 ipv4-src-ip
# ip load-share hash ipv4 ipv4-ip-proto
# ip load-share hash ipv4 ipv4-l4-src-port
# ip load-share hash ipv4 ipv4-l4-dst-port
# ip load-share hash algorithm XOR
# ip load-share hash ingress-port

- name: Override some configuration
  sonic_ecmp_load_share:
    config:
      hash_algorithm: CRC_32LO
      hash_ingress_port: true
      hash_offset:
        flow_based: true
      hash_seed: 1234
      ipv4:
        ipv4_l4_dst_port: true
        ipv4_l4_src_port: true
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration | grep load-share
# ip load-share hash offset flow-based
# ip load-share hash seed 1234
# ip load-share hash ipv4 ipv4-l4-src-port
# ip load-share hash ipv4 ipv4-l4-dst-port
# ip load-share hash algorithm CRC_32LO
# ip load-share hash ingress-port
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: dict
after:
  description: The configuration resulting from module invocation.
  returned: when changed
  type: dict
after(generated):
  description: The configuration that would result from non-check-mode module invocation.
  returned: when C(check_mode)
  type: dict
commands:
  description: The set of commands pushed to the remote device. In C(check_mode) the needed commands are displayed, but not pushed to the device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ecmp_load_share.ecmp_load_share import Ecmp_load_shareArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ecmp_load_share.ecmp_load_share import Ecmp_load_share


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ecmp_load_shareArgs.argument_spec,
                           supports_check_mode=True)

    result = Ecmp_load_share(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
