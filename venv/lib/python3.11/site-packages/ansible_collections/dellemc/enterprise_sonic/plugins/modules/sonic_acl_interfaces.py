#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_acl_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_acl_interfaces
version_added: '2.1.0'
notes:
  - Supports C(check_mode).
short_description: Manage access control list (ACL) to interface binding on SONiC
description:
  - This module provides configuration management of applying access control lists (ACL)
    to interfaces in devices running SONiC.
  - ACL needs to be created earlier in the device.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran)'
options:
  config:
    description:
      - Specifies interface access-group configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the interface, i.e. Eth1/1.
        type: str
        required: true
      access_groups:
        description:
          - Access-group configurations to be set for the interface.
        type: list
        elements: dict
        suboptions:
          type:
            description:
              - Type of the ACLs to be applied on the interface.
            type: str
            required: true
            choices:
              - mac
              - ipv4
              - ipv6
          acls:
            description:
              - List of ACLs for the given type.
            type: list
            elements: dict
            suboptions:
              name:
                description:
                  - Name of the ACL to be applied on the interface.
                type: str
                required: true
              direction:
                description:
                  - Specifies the direction of the packets that the ACL will be applied on.
                type: str
                required: true
                choices:
                  - in
                  - out
  state:
    description:
      - The state of the configuration after module completion.
      - I(merged) - Merges provided interface access-group configuration with on-device configuration.
      - I(replaced) - Replaces on-device access-group configuration of the specified interfaces with provided configuration.
      - I(overridden) - Overrides all on-device interface access-group configurations with the provided configuration.
      - I(deleted) - Deletes on-device interface access-group configuration.
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
# sonic# show mac access-group
# sonic#
# sonic# show ip access-group
# sonic#
# sonic# show ipv6 access-group
# Ingress IPV6 access-list ipv6-acl-1 on Eth1/1
# sonic#

- name: Merge provided interface access-group configurations
  dellemc.enterprise_sonic.sonic_acl_interfaces:
    config:
      - name: 'Eth1/1'
        access_groups:
          - type: 'mac'
            acls:
              - name: 'mac-acl-1'
                direction: 'in'
              - name: 'mac-acl-2'
                direction: 'out'
          - type: 'ipv6'
            acls:
              - name: 'ipv6-acl-2'
                direction: 'out'
      - name: 'Eth1/2'
        access_groups:
          - type: 'ipv4'
            acls:
              - name: 'ip-acl-1'
                direction: 'in'
    state: merged

# After state:
# ------------
#
# sonic# show mac access-group
# Ingress MAC access-list mac-acl-1 on Eth1/1
# Egress MAC access-list mac-acl-2 on Eth1/1
# sonic#
# sonic# show ip access-group
# Ingress IP access-list ip-acl-1 on Eth1/2
# sonic#
# sonic# show ipv6 access-group
# Ingress IPV6 access-list ipv6-acl-1 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/1
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show mac access-group
# Ingress MAC access-list mac-acl-1 on Eth1/1
# Egress MAC access-list mac-acl-2 on Eth1/1
# sonic#
# sonic# show ip access-group
# Ingress IP access-list ip-acl-1 on Eth1/2
# sonic#
# sonic# show ipv6 access-group
# Ingress IPV6 access-list ipv6-acl-1 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/1
# sonic#

- name: Replace device access-group configuration of specified interfaces with provided configuration
  dellemc.enterprise_sonic.sonic_acl_interfaces:
    config:
      - name: 'Eth1/2'
        access_groups:
          - type: 'ipv6'
            acls:
              - name: 'ipv6-acl-2'
                direction: 'out'
      - name: 'Eth1/3'
        access_groups:
          - type: 'ipv4'
            acls:
              - name: 'ip-acl-2'
                direction: 'out'
    state: replaced

# After state:
# ------------
#
# sonic# show mac access-group
# Ingress MAC access-list mac-acl-1 on Eth1/1
# Egress MAC access-list mac-acl-2 on Eth1/1
# sonic#
# sonic# show ip access-group
# Egress IP access-list ip-acl-2 on Eth1/3
# sonic#
# sonic# show ipv6 access-group
# Ingress IPV6 access-list ipv6-acl-1 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/2
# sonic#


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show mac access-group
# Ingress MAC access-list mac-acl-1 on Eth1/1
# Egress MAC access-list mac-acl-2 on Eth1/1
# sonic#
# sonic# show ip access-group
# Egress IP access-list ip-acl-2 on Eth1/3
# sonic#
# sonic# show ipv6 access-group
# Ingress IPV6 access-list ipv6-acl-1 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/2
# sonic#

- name: Override all interfaces access-group device configuration with provided configuration
  dellemc.enterprise_sonic.sonic_acl_interfaces:
    config:
      - name: 'Eth1/1'
        access_groups:
          - type: 'ip'
            acls:
              - name: 'ip-acl-2'
                direction: 'out'
      - name: 'Eth1/2'
        access_groups:
          - type: 'ip'
            acls:
              - name: 'ip-acl-2'
                direction: 'out'
    state: overridden

# After state:
# ------------
#
# sonic# show mac access-group
# sonic#
# sonic# show ip access-group
# Egress IP access-list ip-acl-2 on Eth1/1
# Egress IP access-list ip-acl-2 on Eth1/2
# sonic#
# sonic# show ipv6 access-group
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show mac access-group
# Ingress MAC access-list mac-acl-1 on Eth1/1
# Egress MAC access-list mac-acl-2 on Eth1/1
# sonic#
# sonic# show ip access-group
# Egress IP access-list ip-acl-2 on Eth1/3
# sonic#
# sonic# show ipv6 access-group
# Ingress IPV6 access-list ipv6-acl-1 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/2
# sonic#

- name: Delete specified interfaces access-group configurations
  dellemc.enterprise_sonic.sonic_l2_acls:
    config:
      - name: 'Eth1/1'
        access_groups:
          - type: 'mac'
            acls:
              - name: 'mac-acl-1'
                direction: 'in'
          - type: 'ipv6'
      - name: 'Eth1/2'
    state: deleted

# After state:
# ------------
#
# sonic# show mac access-group
# Egress MAC access-list mac-acl-2 on Eth1/1
# sonic#
# sonic# show ip access-group
# Egress IP access-list ip-acl-2 on Eth1/3
# sonic#
# sonic# show ipv6 access-group
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show mac access-group
# Ingress MAC access-list mac-acl-1 on Eth1/1
# Egress MAC access-list mac-acl-2 on Eth1/1
# sonic#
# sonic# show ip access-group
# Egress IP access-list ip-acl-2 on Eth1/3
# sonic#
# sonic# show ipv6 access-group
# Ingress IPV6 access-list ipv6-acl-1 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/1
# Egress IPV6 access-list ipv6-acl-2 on Eth1/2
# sonic#

- name: Delete all interface access-group configurations
  dellemc.enterprise_sonic.sonic_acl_interfaces:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show mac access-group
# sonic#
# sonic# show ip access-group
# sonic#
# sonic# show ipv6 access-group
# sonic#
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.acl_interfaces.acl_interfaces import Acl_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.acl_interfaces.acl_interfaces import Acl_interfaces


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Acl_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = Acl_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
