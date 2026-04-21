#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_fbs_classifiers
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_fbs_classifiers
version_added: 3.1.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage flow based services (FBS) classifiers configuration on SONiC
description:
  - This module provides configuration management of FBS classifiers for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - FBS classifiers configuration
      - I(match_acl) and I(match_hdr_fields) are mutually exclusive.
    type: list
    elements: dict
    suboptions:
      class_name:
        description:
          - Name of classifier
        type: str
        required: true
      class_description:
        description:
          - Description of classifier
        type: str
      match_type:
        description:
          - Classifier match type
          - The classifier match type is required for classifier creation and corresponds to either 'match_acl' or 'match_hdr_fields' configuration.
        type: str
        choices: ['acl', 'fields']
      match_acl:
        description:
          - Match ACL configuration
        type: dict
        suboptions:
          acl_name:
            description:
              - Name of ACL to be used as match criteria
            type: str
            required: true
          acl_type:
            description:
              - Type of ACL to be used as match criteria
            type: str
            choices: ['ip', 'ipv6', 'mac']
            required: true
      match_hdr_fields:
        description:
          - Match header fields configuration
          - I(ipv4) and I(ipv6) are mutually exclusive.
        type: dict
        suboptions:
          ip:
            description:
              - IP field configuration
            type: dict
            suboptions:
              dscp:
                description:
                  - Value of diffserv code point, range 0-63
                type: int
              protocol:
                description:
                  - IP protocol
                type: str
                choices: ['auth', 'gre', 'icmp', 'icmpv6', 'igmp', 'l2tp', 'pim', 'rsvp', 'tcp', 'udp']
          ipv4:
            description:
              - IPv4 field configuration
            type: dict
            suboptions:
              source_address:
                description:
                  - Source IPv4 address prefix
                type: str
              destination_address:
                description:
                  - Destination IPv4 address prefix
                type: str
          ipv6:
            description:
              - IPv6 field configuration
            type: dict
            suboptions:
              source_address:
                description:
                  - Source IPv6 address prefix
                type: str
              destination_address:
                description:
                  - Destination IPv6 address prefix
                type: str
          l2:
            description:
              - Ethernet field configuration
            type: dict
            suboptions:
              source_mac:
                description:
                  - Source MAC address
                type: str
              source_mac_mask:
                description:
                  - Source MAC address mask
                type: str
              destination_mac:
                description:
                  - Destination MAC address
                type: str
              destination_mac_mask:
                description:
                  - Destination MAC address mask
                type: str
              dei:
                description:
                  - Drop eligible indicator, range 0-1
                type: int
              ethertype:
                description:
                  - Ethertype field to match in ethernet packets
                type: str
                choices: ['arp', 'ipv4', 'ipv6', 'lldp', 'mpls', 'roce', 'vlan']
              pcp:
                description:
                  - Priority code point, range 0-7
                type: int
              vlanid:
                description:
                  - VLAN ID, range 1-4094
                type: int
          transport:
            description:
              - Transport field configuration
            type: dict
            suboptions:
              source_port:
                description:
                  - Source port or range
                  - For specifying a range use '..' as a delimeter, e.g. '1..3'.
                type: str
              destination_port:
                description:
                  - Destination port or range
                  - For specifying a range use '..' as a delimeter, e.g. '1..3'.
                type: str
              icmp_code:
                description:
                  - ICMP or ICMPv6 code, range 0-255
                type: int
              icmp_type:
                description:
                  - ICMP or ICMPv6 type, range 0-255
                type: int
              tcp_flags:
                description:
                  - List of TCP flags to match
                type: list
                elements: str
                choices: ['ack', 'fin', 'psh', 'rst', 'syn', 'urg']
  state:
    description:
      - The state of the configuration after module completion
    type: str
    choices: ['merged', 'deleted', 'replaced', 'overridden']
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show class-map
# (No 'class-map' configuration present)

- name: Merge FBS classifiers configuration
  dellemc.enterprise_sonic.sonic_fbs_classifiers:
    config:
      - class_name: class1
        class_description: xyz
        match_type: fields
        match_hdr_fields:
          ip:
            dscp: 0
            protocol: tcp
          ipv4:
            source_address: 1.1.1.1/1
            destination_address: 2.2.2.2/2
          l2:
            source_mac: 1a:2b:3c:4d:5e:6f
            source_mac_mask: 6a:5b:4c:3d:2e:1f
            destination_mac: 2a:4b:6c:8d:10:20
            destination_mac_mask: 20:10:8d:6c:4b:2a
            dei: 0
            ethertype: ipv4
            pcp: 0
            vlanid: 1
          transport:
            source_port: 1..3
            destination_port: 4..6
            tcp_flags:
              - ack
              - fin
              - psh
    state: merged

# After state:
# ------------
#
# sonic# show class-map
# Class-map class1 match-type fields
#   Description: xyz
#   Match:
#     ethertype ip
#     src-mac 1a:2b:3c:4d:5e:6f/6a:5b:4c:3d:2e:1f
#     dst-mac 2a:4b:6c:8d:10:20/20:10:8d:6c:4b:2a
#     vlan 1
#     pcp be
#     dei 0
#     ip protocol tcp
#     src-ip 1.1.1.1/1
#     dst-ip 2.2.2.2/2
#     dscp default
#     src-port 1-3
#     dst-port 4-6
#     tcp-flags fin psh ack
#   Referenced in flows:


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show class-map
# Class-map class1 match-type fields
#   Description: xyz
#   Match:
#     ethertype ip
#     src-mac 1a:2b:3c:4d:5e:6f/6a:5b:4c:3d:2e:1f
#     dst-mac 2a:4b:6c:8d:10:20/20:10:8d:6c:4b:2a
#     vlan 1
#     pcp be
#     dei 0
#     ip protocol tcp
#     src-ip 1.1.1.1/1
#     dst-ip 2.2.2.2/2
#     dscp default
#     src-port 1-3
#     dst-port 4-6
#     tcp-flags fin psh ack
#   Referenced in flows:
#
# Class-map class2 match-type acl
#   Description: abc
#   Match:
#     ip access-group acl1
#   Referenced in flows:

- name: Replace FBS classifiers configuration
  dellemc.enterprise_sonic.sonic_fbs_classifiers:
    config:
      - class_name: class1
        match_hdr_fields:
          l2:
            source_mac: 9a:8b:7c:6d:5e:4f
            source_mac_mask: 2a:4b:1c:9b:1e:0f
            destination_mac: 1a:6c:3c:4f:40:22
            destination_mac_mask: 26:44:8c:9d:4b:6f
            ethertype: vlan
            pcp: 6
            vlanid: 2
    state: replaced

# After state:
# ------------
#
# sonic# show class-map
# Class-map class1 match-type fields
#   Description: xyz
#   Match:
#     ethertype 0x8100
#     src-mac 9a:8b:7c:6d:5e:4f/2a:4b:1c:9b:1e:0f
#     dst-mac 1a:6c:3c:4f:40:22/26:44:8c:9d:4b:6f
#     vlan 2
#     pcp ic
#   Referenced in flows:
#
# Class-map class2 match-type acl
#   Description: abc
#   Match:
#     ip access-group acl1
#   Referenced in flows:


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show class-map
# Class-map class1 match-type fields
#   Description: xyz
#   Match:
#     ethertype 0x8100
#     src-mac 9a:8b:7c:6d:5e:4f/2a:4b:1c:9b:1e:0f
#     dst-mac 1a:6c:3c:4f:40:22/26:44:8c:9d:4b:6f
#     vlan 2
#     pcp ic
#   Referenced in flows:

- name: Override FBS classifiers configuration
  dellemc.enterprise_sonic.sonic_fbs_classifiers:
    config:
      - class_name: class2
        class_description: abc
        match_type: acl
        match_acl:
          acl_name: acl1
          acl_type: ip

# After state:
# ------------
#
# sonic# show class-map
# Class-map class2 match-type acl
#   Description: abc
#   Match:
#     ip access-group acl1
#   Referenced in flows:


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show class-map
# Class-map class1 match-type fields
#   Description: xyz
#   Match:
#     ethertype 0x8100
#     src-mac 9a:8b:7c:6d:5e:4f/2a:4b:1c:9b:1e:0f
#     dst-mac 1a:6c:3c:4f:40:22/26:44:8c:9d:4b:6f
#     vlan 2
#     pcp ic
#   Referenced in flows:
#
# Class-map class2 match-type acl
#   Description: abc
#   Match:
#     ip access-group acl1
#   Referenced in flows:

- name: Delete FBS classifiers configuration
  dellemc.enterprise_sonic.sonic_fbs_classifiers:
    config:
      - class_name: class1
        class_description: xyz
        match_hdr_fields:
          l2:
            source_mac: 9a:8b:7c:6d:5e:4f
            source_mac_mask: 2a:4b:1c:9b:1e:0f
            destination_mac: 1a:6c:3c:4f:40:22
            destination_mac_mask: 26:44:8c:9d:4b:6f
            ethertype: vlan
            pcp: 6
            vlanid: 2
      - class_name: class2
    state: deleted

# After state:
# ------------
#
# sonic# show class-map
# Class-map class1 match-type fields
#   Description:
#   Match:
#   Referenced in flows:


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show class-map
# Class-map class1 match-type fields
#   Description: xyz
#   Match:
#     ethertype 0x8100
#     src-mac 9a:8b:7c:6d:5e:4f/2a:4b:1c:9b:1e:0f
#     dst-mac 1a:6c:3c:4f:40:22/26:44:8c:9d:4b:6f
#     vlan 2
#     pcp ic
#   Referenced in flows:
#
# Class-map class2 match-type acl
#   Description: abc
#   Match:
#     ip access-group acl1
#   Referenced in flows:

- name: Delete all FBS classifiers configuration
  dellemc.enterprise_sonic.sonic_fbs_classifiers:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show class-map
# (No 'class-map' configuration present)
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
after(generated):
  description: The generated configuration from module invocation.
  returned: when C(check_mode)
  type: list
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.fbs_classifiers.fbs_classifiers import Fbs_classifiersArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.fbs_classifiers.fbs_classifiers import Fbs_classifiers


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Fbs_classifiersArgs.argument_spec,
                           supports_check_mode=True)

    result = Fbs_classifiers(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
