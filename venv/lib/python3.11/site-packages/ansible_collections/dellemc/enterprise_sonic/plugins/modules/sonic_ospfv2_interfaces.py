#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ospfv2_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_ospfv2_interfaces
version_added: '2.5.0'
notes:
- Supports C(check_mode).
short_description: Configure OSPFv2 interface mode protocol settings on SONiC.
description:
  - This module provides configuration management of OSPFv2 interface mode parameters on devices running SONiC.
  - Configure VRF instance before configuring OSPF in a VRF.
  - Configure OSPF instance before configuring OSPF in interfaces.
author: "Santhosh kumar T (@santhosh-kt)"
options:
  config:
    description:
      - Specifies the OSPFv2 interface configurations.
    type: list
    elements: dict
    suboptions:
      name:
        required: True
        type: str
        description:
          - Full name of the interface, i.e. Ethernet1.
      ospf_attributes:
        description:
          - Specifies OSPFv2 configurations for the interface.
          - If I(address) is not specified, the IPv4 address of the interface is considered.
          - I(dead_interval) and I(hello_multiplier) are mutually exclusive.
        type: list
        elements: dict
        suboptions:
          address:
            description:
              - Specifies the interface IPv4 address.
            type: str
          area_id:
            description:
              - OSPFv2 Area ID of the network (A.B.C.D or 0 to 4294967295).
            type: str
          authentication_type:
            description:
              - Enable OSPFv2 authentication and its type.
              - C(MD5HMAC) - Enable Message digest authentication type.
              - C(NONE) - Enable null authentication.
              - C(TEXT) - Enable plain text authentication.
            type: str
            choices:
              - 'MD5HMAC'
              - 'NONE'
              - 'TEXT'
          authentication:
            description:
              - Configure OSPFv2 plain text authentication type password.
              - Authentication key shall be max 8 charater long.
            type: dict
            suboptions:
              password:
                description:
                  - Specifies the authentication password.
                  - Plain text password i.e. password with I(encrypted=false) will be stored in encrypted format in running-config, so idempotency will
                    not be maintained and hence the task output will always be I(changed=true).
                type: str
                required: true
              encrypted:
                description:
                  - Indicates whether the password is in encrypted format.
                type: bool
          cost:
            description:
              - Configure OSPFv2 interface cost (1 to 65535).
            type: int
          dead_interval:
            description:
              - Configure OSPFv2 adjacency dead interval (1 to 65535).
            type: int
          hello_multiplier:
            description:
              - Minimal 1s dead-interval with fast sub-second hellos.
              - Number of Hellos to send each second (1 to 10).
            type: int
          hello_interval:
            description:
              - Configure OSPFv2 neighbour hello interval (1 to 65535).
            type: int
          md_authentication:
            description:
              - Configure OSPFv2 message digest keys and password.
              - Uses MD5 algorithm.
            type: list
            elements: dict
            suboptions:
              key_id:
                description:
                  - Specifies the OSPFv2 message digest key ID (1 to 255).
                type: int
                required: True
              md5key:
                description:
                  - Specifies the OSPFv2 message digest password.
                  - Plain text password i.e. password with I(encrypted=false) will be stored in encrypted format in running-config, so idempotency will
                    not be maintained and hence the task output will always be I(changed=true).
                type: str
              encrypted:
                description:
                  - Indicates whether the password is in encrypted format.
                type: bool
          mtu_ignore:
            description:
              - Disable OSPFv2 MTU mismatch detection.
            type: bool
          priority:
            description:
              - Configure OSPFv2 adjacency router priority (0 to 255).
            type: int
          retransmit_interval:
            description:
              - Configure OSPFv2 retransmit interval (2 to 65535).
            type: int
          transmit_delay:
            description:
              - Configure OSPFv2 transmit delay (1 to 65535).
            type: int
      bfd:
        description:
          - Configure OSPFv2 interface BFD.
        type: dict
        suboptions:
          enable:
            description:
              - Enable BFD support for OSPFv2.
            type: bool
            required: true
          bfd_profile:
            description:
              - Configure BFD profile.
            type: str
      network:
        description:
          - Configure OSPFv2 interface network type
        type: str
        choices:
          - broadcast
          - point_to_point
  state:
    description:
      - Specifies the operation to be performed on the OSPFv2 interfaces configured on the device.
      - In case of merged, the input configuration will be merged with the existing OSPFv2 interfaces configuration on the device.
      - In case of deleted, the existing OSPFv2 interfaces configuration will be removed from the device.
      - In case of overridden, all the existing OSPFv2 interfaces configuration will be deleted and the specified input configuration will be installed.
      - In case of replaced, the existing OSPFv2 interface configuration on the device will be replaced by the configuration in the playbook for
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
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile2
# ip ospf cost 30
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network point-to-point
# ip ospf priority 20
# ip ospf authentication null 10.10.120.1
# ip ospf authentication-key U2FsdGVkX1/Ml24vwe6RSjUUqI+54BdDyDL0eKUezJw= encrypted 10.10.120.1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# ip ospf authentication null 10.19.119.1
# ip ospf message-digest-key 10 md5 U2FsdGVkX1/Bq/+x8a3fsBo9ZrAX56ynmPKnRM87kfQ= encrypted 10.19.119.1
# !
# interface Eth1/2
# ip ospf bfd
# ip ospf network point-to-point
# !
# interface Eth1/3
# ip ospf bfd
# ip ospf network point-to-point
# ip ospf area 3.3.3.3 10.19.120.2
# ip ospf authentication message-digest 10.19.120.2
# ip ospf authentication-key U2FsdGVkX19HqGCcf2pzGur9MDnb0VzLNRvoFij3Os0= encrypted 10.19.120.2
# ip ospf dead-interval minimal hello-multiplier 5 10.19.120.2
# !
# sonic#

- name: Delete the OSPFv2_interface configurations
  sonic_ospfv2_interfaces:
    config:
      - name: 'Eth1/1'
        ospf_attributes:
          - area_id: '2.2.2.2'
            cost: 30
            priority: 20
            hello_interval: 10
            dead_interval: 40
            mtu_ignore: true
          - address: '10.10.120.1'
            authentication_type: 'NONE'
            authentication:
              password: 'pass2'
          - address: '10.19.119.1'
        bfd:
          enable: true
          bfd_profile: 'profile2'
        network: point_to_point
      - name: 'Eth1/2'
        bfd:
          enable: true
      - name: 'Eth1/3'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# !
# interface Eth1/2
# ip ospf network point-to-point
# !
# interface Eth1/3
# !
# sonic#


# Using "deleted" state

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile2
# ip ospf cost 30
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network point-to-point
# ip ospf priority 20
# ip ospf authentication null 10.10.120.1
# ip ospf authentication-key U2FsdGVkX1/Ml24vwe6RSjUUqI+54BdDyDL0eKUezJw= encrypted 10.10.120.1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# ip ospf authentication null 10.19.119.1
# ip ospf message-digest-key 10 md5 U2FsdGVkX1/Bq/+x8a3fsBo9ZrAX56ynmPKnRM87kfQ= encrypted 10.19.119.1
# !
# interface Eth1/2
# ip ospf bfd
# ip ospf network point-to-point
# !
# interface Eth1/3
# ip ospf bfd
# ip ospf network point-to-point
# ip ospf area 3.3.3.3 10.19.120.2
# ip ospf authentication message-digest 10.19.120.2
# ip ospf authentication-key U2FsdGVkX19HqGCcf2pzGur9MDnb0VzLNRvoFij3Os0= encrypted 10.19.120.2
# ip ospf dead-interval minimal hello-multiplier 5 10.19.120.2
# !
# sonic#

- name: Delete the OSPFv2_interface configurations
  sonic_ospfv2_interfaces:
    config:
      - name: 'Eth1/1'
      - name: 'Eth1/2'
        bfd:
          enable: true
      - name: 'Eth1/3'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# !
# interface Eth1/2
# ip ospf network point-to-point
# !
# interface Eth1/3
# !
# sonic#


# Using "merged" state

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# !
# interface Eth1/2
# !
# interface Eth1/3
# !
# sonic#

- name: Add the OSPFv2_interface configurations
  sonic_ospfv2_interfaces:
    config:
      - name: 'Eth1/1'
        ospf_attributes:
          - area_id: '2.2.2.2'
            cost: 20
            priority: 20
            hello_interval: 10
            dead_interval: 40
            mtu_ignore: true
            -address: '10.10.120.1'
            authentication_type: 'MD5HMAC'
            authentication:
              password: 'password'
            hello_multiplier: 5
        bfd:
          enable: true
          bfd_profile: 'profile1'
        network: broadcast
      - name: 'Eth1/3'
        ospf_attributes:
          - area_id: '3.3.3.3'
            address: '10.19.120.2'
            authentication_type: 'MD5HMAC'
            authentication:
              password: 'password'
            hello_multiplier: 5
        bfd:
          enable: true
        network: point_to_point
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile1
# ip ospf cost 20
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network broadcast
# ip ospf priority 20
# ip ospf authentication message-digest 10.10.120.1
# ip ospf authentication-key U2FsdGVkX1+ozJSEI69XJb2KR9Pu1Sa3Ou6ujTRalbQ= encrypted 10.10.120.1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# !
# interface Eth1/2
# !
# interface Eth1/3
# ip ospf bfd
# ip ospf network point-to-point
# ip ospf area 3.3.3.3 10.19.120.2
# ip ospf authentication message-digest 10.19.120.2
# ip ospf authentication-key U2FsdGVkX19HqGCcf2pzGur9MDnb0VzLNRvoFij3Os0= encrypted 10.19.120.2
# ip ospf dead-interval minimal hello-multiplier 5 10.19.120.2
# !
# sonic#


# Using "merged" state

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile1
# ip ospf cost 20
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network broadcast
# ip ospf priority 20
# ip ospf authentication message-digest 10.10.120.1
# ip ospf authentication-key U2FsdGVkX1+ozJSEI69XJb2KR9Pu1Sa3Ou6ujTRalbQ= encrypted 10.10.120.1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# !
# interface Eth1/2
# !
# interface Eth1/3
# ip ospf bfd
# ip ospf network point-to-point
# ip ospf area 3.3.3.3 10.19.120.2
# ip ospf authentication message-digest 10.19.120.2
# ip ospf authentication-key U2FsdGVkX19HqGCcf2pzGur9MDnb0VzLNRvoFij3Os0= encrypted 10.19.120.2
# ip ospf dead-interval minimal hello-multiplier 5 10.19.120.2
# !
# sonic#

- name: Add the OSPFv2_interface configurations
  sonic_ospfv2_interfaces:
    config:
      - name: 'Eth1/1'
        ospf_attributes:
          - area_id: '2.2.2.2'
            cost: 30
            priority: 20
            hello_interval: 10
            dead_interval: 40
            mtu_ignore: true
          - address: '10.10.120.1'
            authentication_type: 'NONE'
            authentication:
              password: 'pass2'
          - address: '10.19.119.1'
            authentication_type: 'NONE'
            md_authentication:
              - key_id: 10
                md5key: 'U2FsdGVkX1/Bq/+x8a3fsBo9ZrAX56ynmPKnRM87kfQ='
                encrypted: true
        bfd:
          enable: true
          bfd_profile: 'profile2'
        network: point_to_point
      - name: 'Eth1/2'
        bfd:
          enable: true
        network: point_to_point
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile2
# ip ospf cost 30
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network point-to-point
# ip ospf priority 20
# ip ospf authentication null 10.10.120.1
# ip ospf authentication-key U2FsdGVkX1/Ml24vwe6RSjUUqI+54BdDyDL0eKUezJw= encrypted 10.10.120.1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# ip ospf authentication null 10.19.119.1
# ip ospf message-digest-key 10 md5 U2FsdGVkX1/Bq/+x8a3fsBo9ZrAX56ynmPKnRM87kfQ= encrypted 10.19.119.1
# !
# interface Eth1/2
# ip ospf bfd
# ip ospf network point-to-point
# !
# interface Eth1/3
# ip ospf bfd
# ip ospf network point-to-point
# ip ospf area 3.3.3.3 10.19.120.2
# ip ospf authentication message-digest 10.19.120.2
# ip ospf authentication-key U2FsdGVkX19HqGCcf2pzGur9MDnb0VzLNRvoFij3Os0= encrypted 10.19.120.2
# ip ospf dead-interval minimal hello-multiplier 5 10.19.120.2
# !
# sonic#


# Using "replaced" state

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile1
# ip ospf cost 20
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network broadcast
# ip ospf priority 20
# ip ospf authentication message-digest 10.10.120.1
# ip ospf authentication-key U2FsdGVkX1+ozJSEI69XJb2KR9Pu1Sa3Ou6ujTRalbQ= encrypted 10.10.120.1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# !
# interface Eth1/2
# !
# interface Eth1/3
# ip ospf bfd
# ip ospf network point-to-point
# ip ospf area 3.3.3.3 10.19.120.2
# ip ospf authentication message-digest 10.19.120.2
# ip ospf authentication-key U2FsdGVkX19HqGCcf2pzGur9MDnb0VzLNRvoFij3Os0= encrypted 10.19.120.2
# ip ospf dead-interval minimal hello-multiplier 5 10.19.120.2
# !
# sonic#

- name: Replace the OSPFv2_interface configurations
  sonic_ospfv2_interfaces:
    config:
      - name: 'Eth1/3'
        ospf_attributes:
          - area_id: '2.2.2.2'
            cost: 30
            priority: 20
            hello_interval: 10
            dead_interval: 40
            mtu_ignore: true
          - address: '10.10.120.1'
            authentication_type: 'NONE'
            authentication:
              password: 'pass2'
          - address: '10.19.119.1'
            authentication_type: 'NONE'
            md_authentication:
              - key_id: 10
                md5key: 'U2FsdGVkX1/Bq/+x8a3fsBo9ZrAX56ynmPKnRM87kfQ='
                encrypted: true
        bfd:
          enable: true
          bfd_profile: 'profile2'
        network: broadcast
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile1
# ip ospf cost 20
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network broadcast
# ip ospf priority 20
# ip ospf authentication message-digest 10.10.120.1
# ip ospf authentication-key U2FsdGVkX1+ozJSEI69XJb2KR9Pu1Sa3Ou6ujTRalbQ= encrypted 10.10.120.1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# !
# interface Eth1/2
# !
# interface Eth1/3
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile2
# ip ospf cost 30
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network broadcast
# ip ospf priority 20
# ip ospf authentication null 10.10.120.1
# ip ospf authentication-key U2FsdGVkX186k2R2hUXaDloW8hfkApn5Zx5hCQy9usc= encrypted 10.10.120.1
# ip ospf authentication null 10.19.119.1
# ip ospf message-digest-key 10 md5 U2FsdGVkX1/Bq/+x8a3fsBo9ZrAX56ynmPKnRM87kfQ= encrypted 10.19.119.1
# !
# sonic#


# Using "overridden" state

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile1
# ip ospf cost 20
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network broadcast
# ip ospf priority 20
# ip ospf authentication message-digest 10.10.120.1
# ip ospf authentication-key U2FsdGVkX1+ozJSEI69XJb2KR9Pu1Sa3Ou6ujTRalbQ= encrypted 10.10.120.1
# ip ospf dead-interval minimal hello-multiplier 5 10.10.120.1
# !
# interface Eth1/2
# !
# interface Eth1/3
# ip ospf bfd
# ip ospf network point-to-point
# ip ospf area 3.3.3.3 10.19.120.2
# ip ospf authentication message-digest 10.19.120.2
# ip ospf authentication-key U2FsdGVkX19HqGCcf2pzGur9MDnb0VzLNRvoFij3Os0= encrypted 10.19.120.2
# ip ospf dead-interval minimal hello-multiplier 5 10.19.120.2
# !
# sonic#

- name: Override the OSPFv2_interface configurations
  sonic_ospfv2_interfaces:
    config:
      - name: 'Eth1/3'
        ospf_attributes:
          - area_id: '2.2.2.2'
            cost: 30
            priority: 20
            hello_interval: 10
            dead_interval: 40
            mtu_ignore: true
          - address: '10.10.120.1'
            authentication_type: 'NONE'
            authentication:
              password: 'pass2'
          - address: '10.19.119.1'
            authentication_type: 'NONE'
            md_authentication:
              - key_id: 10
                md5key: 'U2FsdGVkX1/Bq/+x8a3fsBo9ZrAX56ynmPKnRM87kfQ='
                encrypted: true
        bfd:
          enable: true
          bfd_profile: 'profile2'
        network: broadcast
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# !
# interface Eth1/2
# !
# interface Eth1/3
# ip ospf area 2.2.2.2
# ip ospf bfd
# ip ospf bfd profile profile2
# ip ospf cost 30
# ip ospf dead-interval 40
# ip ospf hello-interval 10
# ip ospf mtu-ignore
# ip ospf network broadcast
# ip ospf priority 20
# ip ospf authentication null 10.10.120.1
# ip ospf authentication-key U2FsdGVkX186k2R2hUXaDloW8hfkApn5Zx5hCQy9usc= encrypted 10.10.120.1
# ip ospf authentication null 10.19.119.1
# ip ospf message-digest-key 10 md5 U2FsdGVkX1/Bq/+x8a3fsBo9ZrAX56ynmPKnRM87kfQ= encrypted 10.19.119.1
# !
# sonic#
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after(generated):
  description: The generated configuration model invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv2_interfaces.ospfv2_interfaces import Ospfv2_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ospfv2_interfaces.ospfv2_interfaces import Ospfv2_interfaces


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ospfv2_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = Ospfv2_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
