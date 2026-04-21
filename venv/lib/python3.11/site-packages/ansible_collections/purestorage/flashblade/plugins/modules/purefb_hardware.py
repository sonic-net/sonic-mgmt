#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
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
module: purefb_hardware
version_added: '1.15.0'
short_description: Manage FlashBlade Hardware
description:
- Enable or disable FlashBlade visual identification lights and set connector parameters
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of hardware component
    type: str
    required: true
  enabled:
    description:
    - State of the component identification LED
    type: bool
  speed:
    description:
    - If the component specified is a connector, set the configured speed
      of each lane in the connector in gigabits-per-second
    type: int
    choices: [ 10, 25, 40 ]
  ports:
    description:
    - If the component specificed is a connector, the number of configured
      ports in the connector
    type: int
    choices: [ 1, 4 ]
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Set connector to be 4 x 40Gb ports
  purestorage.flashblade.purefb_hardware:
    name: "CH1.FM1.ETH1"
    speed: 40
    ports: 4
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Enable identification LED
  purestorage.flashblade.purefb_hardware:
    name: "CH1.FB1"
    enabled: true
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Disable identification LED
  purestorage.flashblade.purefb_hardware:
    name: "CH1.FB1"
    enabled: false
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flashblade
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            enabled=dict(type="bool"),
            name=dict(type="str", required=True),
            speed=dict(
                type="int",
                choices=[10, 25, 40],
            ),
            ports=dict(
                type="int",
                choices=[1, 4],
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    api_version = list(blade.get_versions().items)

    if module.params["speed"]:
        speed = module.params["speed"] * 1000000000
    changed = False
    hardware = None
    res = blade.get_hardware(names=[module.params["name"]])
    if res.status_code == 200:
        hardware = list(res.items)[0]
        if hardware.identify_enabled != module.params["enabled"]:
            changed = True
            if not module.check_mode:
                res = blade.patch_hardware(
                    names=[module.params["name"]],
                    hardware=flashblade.Hardware(
                        identify_enabled=module.params["enabled"]
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to set identification LED for {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
    res = blade.get_hardware_connectors(names=[module.params["name"]])
    if res.status_code == 200:
        connector = list(res.items)[0]
        if connector.port_count != module.params["ports"]:
            changed = True
            if not module.check_mode:
                res = blade.patch_hardware_connectors(
                    names=[module.params["name"]],
                    hardware_connector=flashblade.HardwareConnector(
                        port_count=module.params["ports"]
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change connector port count {0}. Error: Invalid port count".format(
                            module.params["name"]
                        )
                    )
        if connector.lane_speed != speed:
            changed = True
            if not module.check_mode:
                res = blade.patch_hardware_connectors(
                    names=[module.params["name"]],
                    hardware_connector=flashblade.HardwareConnector(lane_speed=speed),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change connector lane speed {0}. Error: Invalid lane speed".format(
                            module.params["name"]
                        )
                    )

    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
