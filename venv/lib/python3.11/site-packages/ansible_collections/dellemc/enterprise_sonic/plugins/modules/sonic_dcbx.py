#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_dcbx
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_dcbx
version_added: '3.1.0'
short_description: Manage DCBx configurations on SONiC
description:
  - This module provides configuration management of DCBx parameters
    in devices running SONiC.
author: 'Bing Sun(@bsun-sudo), Haemanthi Sree KR (@haemanthisree)'
options:
  config:
    description: The set of DCBx attribute configurations
    type: dict
    suboptions:
      global:
        description:
          - Global DCBx configuration
        type: dict
        suboptions:
          enabled:
            description:
              - This argument is a boolean value to enable or disable DCBx.
              - It has a default value of False in SONiC and has an operational
              - default value of False for the enterproise_sonic Ansible collection
            type: bool
      interfaces:
        description:
          - Interfaces DCBx configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Interface name for which DCBx needs to be configured.
              - This must be a physical (Ethernet) interface.
            type: str
            required: true
          enabled:
            description:
              - This argument is a boolean value to enable or disable DCBx.
              - It has a default value of True in SONiC and has an operational
              - default value of True for the enterprise_sonic Ansible collection
              - This command is supported only on physical interfaces and not on logical interfaces.
            type: bool
          pfc_tlv_enabled:
            description:
              - This command can be used to select whether to advertise and receive PFC TLV.
              - It has a default value of True in SONiC and has an operational
              - default value of True for the enterproise_sonic Ansible collection
            type: bool
          ets_configuration_tlv_enabled:
            description:
              - This command can be used to select whether to advertise and receive ETS configuration TLV.
              - It has a default value of True in SONiC and has an operational
              - default value of True for the enterproise_sonic Ansible collection
            type: bool
          ets_recommendation_tlv_enabled:
            description:
              - This command can be used to select whether to advertise and receive ETS recommendation TLV.
              - It has a default value of True in SONiC and has an operational
              - default value of True for the enterproise_sonic Ansible collection
            type: bool
  state:
    description:
      - The state specifies the type of configuration update to be performed on the device.
      - If the state is "merged", merge specified attributes with existing configured attributes.
      - For "deleted", delete the specified attributes from existing configuration.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""

EXAMPLES = """
# Using "merged" state for DCBx interface configuration
#
# Before State:
# -------------
#
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown

- name: Modify DCBx Interface configurations
  dellemc.enterprise_sonic.sonic_dcbx:
    config:
      -interfaces:
        - name: Ethernet0
          enabled: false
          pfc_tlv_enabled: false
          ets_configuration_tlv_enabled: false
          ets_recommendation_tlv_enabled: false
    state: merged

# After State:
# ------------
#
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#  no dcbx tlv-select pfc
#  no dcbx tlv-select ets-conf
#  no dcbx tlv-select ets-reco

# Using "merged" state for DCBx global configuration
#
# Before State:
# -------------
#
# sonic# show running-configuration | grep dcbx
# sonic#

- name: Modify DCBX configurations
  dellemc.enterprise_sonic.sonic_dcbx:
    config:
      global:
        enabled: true
    state: merged

# After State:
# ------------
#
# sonic# show running-configuration | grep dcbx
# !
# dcbx enable
# !

# Using "merged" state for DCBx interface configuration
#
# Before State:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#  no dcbx tlv-select pfc
#  no dcbx tlv-select ets-conf
#  no dcbx tlv-select ets-reco


- name: Modify DCBx Interface configurations
  dellemc.enterprise_sonic.sonic_dcbx:
    config:
      interfaces:
        - name: Ethernet0
          enabled: true
          pfc_tlv_enabled: true
          ets_configuration_tlv_enabled: true
          ets_recommendation_tlv_enabled: true
    state: merged

# After State:
# ------------
#
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown

# Using "deleted" state for DCBx interface configuration
#
# Before State:
# -------------
#
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#  no dcbx tlv-select pfc
#  no dcbx tlv-select ets-conf
#  no dcbx tlv-select ets-reco


- name: Delete and set default DCBx Interface configurations
  dellemc.enterprise_sonic.sonic_dcbx:
    config:
      interfaces:
        - name: Ethernet0
          enabled: false
          pfc_tlv_enabled: false
          ets_configuration_tlv_enabled: false
          ets_recommendation_tlv_enabled: false
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown

# Using "replaced" state for DCBx interface configuration
#
# Before State:
# -------------
#
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx tlv-select pfc
#  no dcbx tlv-select ets-conf
#  no dcbx tlv-select ets-reco
#
# sonic# show running-configuration interface Ethernet4
# !
# interface Ethernet4
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#  no dcbx tlv-select pfc

- name: Modify DCBx Interface configurations
  dellemc.enterprise_sonic.sonic_dcbx:
    config:
      -interfaces:
        - name: Ethernet0
          enabled: false
    state: replaced

# After State:
# ------------
#
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#
# sonic# show running-configuration interface Ethernet4
# !
# interface Ethernet4
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#  no dcbx tlv-select pfc

# Using "overridden" state for DCBx interface configuration
#
# Before State:
# -------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx tlv-select pfc
#  no dcbx tlv-select ets-conf
#  no dcbx tlv-select ets-reco
#
# sonic# show running-configuration interface Ethernet4
# !
# interface Ethernet4
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#  no dcbx tlv-select pfc
#
# sonic# show running-configuration interface Ethernet8
# !
# interface Ethernet8
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#  no dcbx tlv-select pfc
#  no dcbx tlv-select ets-conf
#  no dcbx tlv-select ets-reco
#
# sonic# show running-configuration interface Ethernet12
# !
# interface Ethernet12
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown

- name: Modify DCBx Interface configurations
  dellemc.enterprise_sonic.sonic_dcbx:
    config:
      -interfaces:
        - name: Ethernet0
          enabled: false
    state: overridden

# After State:
# ------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#  no dcbx enable
#
# sonic# show running-configuration interface Ethernet4
# !
# interface Ethernet4
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#
# sonic# show running-configuration interface Ethernet8
# !
# interface Ethernet8
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown
#
# sonic# show running-configuration interface Ethernet12
# !
# interface Ethernet12
#  mtu 9100
#  speed 25000
#  unreliable-los auto
#  no shutdown

# Using "deleted" state for DCBx global configuration
#
# Before State:
# -------------
#
# sonic# show running-configuration | grep dcbx
# !
# dcbx enable
# !

- name: Delete DCBX mode configuration
  dellemc.enterprise_sonic.sonic_dcbx:
    config:
      global:
        enabled: true
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration | grep dcbx
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
  description: The resulting configuration from module invocation.
  returned: when changed, if C(check_mode) is not set
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after(generated):
  description: The generated (simulated) configuration from module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.dcbx.dcbx import DcbxArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.dcbx.dcbx import Dcbx


def main():
    """
    Main entry point for module execution

    :returns: the result from module invocation
    """
    module = AnsibleModule(argument_spec=DcbxArgs.argument_spec,
                           supports_check_mode=True)

    result = Dcbx(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
