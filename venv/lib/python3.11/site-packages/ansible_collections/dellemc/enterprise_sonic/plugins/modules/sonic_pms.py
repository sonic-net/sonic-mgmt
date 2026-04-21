#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_pms
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_pms
version_added: '3.1.0'
notes:
  - Supports C(check_mode).
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
short_description: Configure interface mode port security settings on SONiC.
description:
  - This module provides configuration management of port security interface mode parameters on devices running SONiC.
  - Configure switchport before configuring port security in interfaces.
author: "Santhosh kumar T (@santhosh-kt)"
options:
  config:
    description:
      - Specifies the port security interface configurations.
    type: list
    elements: dict
    suboptions:
      name:
        required: true
        type: str
        description:
          - Full name of the interface, i.e. Ethernet1.
      port_security_enable:
        required: true
        type: bool
        description:
          - Enables port security at interface level.
          - If I(port_security_enable=False), entire port security configurations will be deleted.
      max_allowed_macs:
        type: int
        description:
          - Maximum no. of secure MACs allowed on the interface. (1 to 4097)
          - If I(port_security_enable=True) and I(max_allowed_macs) not configured, default is C(1).
      violation:
        type: str
        description:
          - Configure the action to be taken in the event of security violation.
          - C(SHUTDOWN) - Shutdown the interface.
          - C(PROTECT) - Drop packets received on the interface.
          - If I(port_security_enable=True) and I(violation) not configured, default is C(PROTECT).
        choices:
          - SHUTDOWN
          - PROTECT
      sticky_mac:
        type: bool
        description:
          - Enable sticky MAC feature on the interface.
          - If I(port_security_enable=True) and I(sticky_mac) not configured, default is C(False).
  state:
    description:
      - Specifies the operation to be performed on the port security related interfaces configured on the device.
      - In case of merged, the input configuration will be merged with the existing port security interfaces related configuration on the device.
      - In case of deleted, the existing OSPFv2 interfaces configuration will be removed from the device.
      - In case of overridden, all the existing OSPFv2 interfaces configuration will be deleted and the specified input configuration will be installed.
      - In case of replaced, the existing interface configuration on the device will be replaced by the configuration in the playbook for
        each interface group configured by the playbook.
    type: str
    default: merged
    choices: ['merged', 'deleted', 'replaced', 'overridden']
"""

EXAMPLES = """
# Using "deleted" state

# Before state:
# -------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet0           Y            1               0           0                 PROTECT         N
#     Ethernet10          N            1               0           0                 PROTECT         Y
# sonic#

- name: Delete the PMS configurations
  sonic_pms:
    config:
      - name: 'Ethernet0'
        port_security_enable: true
      - name: 'Ethernet10'
        port_security_enable: false
        sticky_mac: true
    state: deleted

# After state:
# ------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet10          N            1               0           0                 PROTECT         N
# sonic#


# Using "deleted" state

# Before state:
# -------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet0           Y            1               0           0                 PROTECT         N
#     Ethernet3           Y            10              0           0                 PROTECT         N
#     Ethernet4           N            15              0           0                 SHUTDOWN        N
#     Ethernet5           Y            30              0           0                 SHUTDOWN        N
#     Ethernet10          N            1               0           0                 PROTECT         Y
# sonic#

- name: Delete all the PMS configurations
  sonic_pms:
    config: []
    state: deleted

# After state:
# ------------
#
# sonic# show port-security
# sonic#


# Using "merged" state

# Before state:
# -------------
#
# sonic# show port-security
# sonic#

- name: Add the PMS configurations new to interfaces
  sonic_pms:
    config:
      - name: 'Ethernet0'
        sticky_mac: true
        port_security_enable: true
        max_allowed_macs: 10
      - name: 'Ethernet3'
        port_security_enable: false
        max_allowed_macs: 10
      - name: 'Ethernet4'
        port_security_enable: true
        violation: SHUTDOWN
    state: merged

# After state:
# ------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet0           Y            10              0           0                 PROTECT         Y
#     Ethernet3           N            10              0           0                 PROTECT         N
#     Ethernet4           Y            1               0           0                 SHUTDOWN        N
# sonic#


# Using "merged" state

# Before state:
# -------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet0           Y            10              0           0                 PROTECT         Y
#     Ethernet3           N            10              0           0                 PROTECT         N
#     Ethernet4           Y            1               0           0                 SHUTDOWN        N
# sonic#

- name: Disable a PMS interface by merge
  sonic_pms:
    config:
      - name: 'Ethernet10'
        port_security_enable: false
        max_allowed_macs: 12
        violation: SHUTDOWN
        sticky_mac: true
      - name: 'Ethernet4'
        port_security_enable: false
    state: merged

# After state:
# ------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet0           Y            10              0           0                 PROTECT         Y
#     Ethernet3           N            10              0           0                 PROTECT         N
#     Ethernet10          N            12              0           0                 SHUTDOWN        Y
# sonic#


# Using "replaced" state

# Before state:
# -------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet0           Y            1               0           0                 PROTECT         N
#     Ethernet3           Y            10              0           0                 PROTECT         N
#     Ethernet4           N            15              0           0                 SHUTDOWN        N
#     Ethernet5           Y            30              0           0                 SHUTDOWN        N
#     Ethernet10          N            12              0           0                 SHUTDOWN        Y
# sonic#

- name: Replace the PMS configurations by interface level
  sonic_pms:
    config:
      - name: 'Ethernet10'
        port_security_enable: true
      - name: 'Ethernet3'
        port_security_enable: false
        violation: 'PROTECT'
        sticky_mac: true
      - name: 'Ethernet7'
        port_security_enable: true
    state: replaced

# After state:
# ------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet0           Y            1               0           0                 PROTECT         N
#     Ethernet3           N            10              0           0                 PROTECT         Y
#     Ethernet4           N            15              0           0                 SHUTDOWN        N
#     Ethernet5           Y            30              0           0                 SHUTDOWN        N
#     Ethernet7           Y            1               0           0                 PROTECT         N
#     Ethernet10          Y            1               0           0                 PROTECT         N
# sonic#


# Using "overridden" state

# Before state:
# -------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet0           Y            1               0           0                 PROTECT         N
#     Ethernet3           Y            10              0           0                 PROTECT         N
#     Ethernet4           N            15              0           0                 SHUTDOWN        N
#     Ethernet5           Y            30              0           0                 SHUTDOWN        N
#     Ethernet10          N            12              0           0                 SHUTDOWN        Y
# sonic#

- name: Override the PMS configurations
  sonic_pms:
    config:
      - name: 'Ethernet7'
        port_security_enable: true
      - name: 'Ethernet10'
        port_security_enable: false
        max_allowed_macs: 12
        violation: SHUTDOWN
        sticky_mac: true
    state: overridden

# After state:
# ------------
#
# sonic# show port-security
#
# Secure Port         isEnabled    MaxSecureAddr   FdbCount    ViolationCount    SecurityAction  StickyMac
# ---------------------------------------------------------------------------------------------------------
#     Ethernet7           Y            1               0           0                 PROTECT         N
#     Ethernet10          N            12              0           0                 SHUTDOWN        Y
# sonic#
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
  description: The configuration that would be generated by non-check-mode module invocation.
  returned: when C(check_mode)
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.pms.pms import PmsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.pms.pms import Pms


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=PmsArgs.argument_spec,
                           supports_check_mode=True)

    result = Pms(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
