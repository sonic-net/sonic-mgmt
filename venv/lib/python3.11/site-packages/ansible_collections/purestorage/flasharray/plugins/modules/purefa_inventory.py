#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
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
module: purefa_inventory
short_description: Collect information from Pure Storage FlashArray
version_added: '1.0.0'
description:
  - Collect hardware inventory information from a Pure Storage Flasharray
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
extends_documentation_fragment:
  - purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: collect FlashArray invenroty
  purestorage.flasharray.purefa_inventory:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: show inventory information
  debug:
    msg: "{{ array_info['purefa_inv'] }}"
"""

RETURN = r"""
purefa_inventory:
  description: Returns the inventory information for the FlashArray
  returned: always
  type: dict
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)


SFP_API_VERSION = "2.16"


def generate_new_hardware_dict(array):
    hw_info = {
        "fans": {},
        "controllers": {},
        "drives": {},
        "interfaces": {},
        "power": {},
        "chassis": {},
        "temperature": {},
    }
    components = list(array.get_hardware().items)
    for component in range(0, len(components)):
        component_name = components[component].name
        if components[component].type == "chassis":
            hw_info["chassis"][component_name] = {
                "status": components[component].status,
                "serial": components[component].serial,
                "model": components[component].model,
                "identify_enabled": components[component].identify_enabled,
            }
        if components[component].type == "controller":
            hw_info["controllers"][component_name] = {
                "status": components[component].status,
                "serial": components[component].serial,
                "model": components[component].model,
                "identify_enabled": components[component].identify_enabled,
            }
        if components[component].type == "cooling":
            hw_info["fans"][component_name] = {
                "status": components[component].status,
            }
        if components[component].type == "temp_sensor":
            hw_info["controllers"][component_name] = {
                "status": components[component].status,
                "temperature": components[component].temperature,
            }
        if components[component].type == "drive_bay":
            hw_info["drives"][component_name] = {
                "status": components[component].status,
                "identify_enabled": components[component].identify_enabled,
                "serial": getattr(components[component], "serial", None),
            }
        if components[component].type in [
            "sas_port",
            "fc_port",
            "eth_port",
            "ib_port",
        ]:
            hw_info["interfaces"][component_name] = {
                "type": components[component].type,
                "status": components[component].status,
                "speed": components[component].speed,
                "connector_type": None,
                "rx_los": None,
                "rx_power": None,
                "static": {},
                "temperature": None,
                "tx_bias": None,
                "tx_fault": None,
                "tx_power": None,
                "voltage": None,
            }
        if components[component].type == "power_supply":
            hw_info["power"][component_name] = {
                "status": components[component].status,
                "voltage": getattr(components[component], "voltage", None),
                "serial": getattr(components[component], "serial", None),
                "model": getattr(components[component], "model", None),
            }
    drives = list(array.get_drives().items)
    for drive in range(0, len(drives)):
        drive_name = drives[drive].name
        hw_info["drives"][drive_name] = {
            "capacity": drives[drive].capacity,
            "capacity_installed": getattr(
                drives[drive], "capacity_installed", drives[drive].capacity
            ),
            "status": drives[drive].status,
            "protocol": getattr(drives[drive], "protocol", None),
            "details": getattr(drives[drive], "details", None),
            "type": drives[drive].type,
        }
    api_version = array.get_rest_version()
    if LooseVersion(SFP_API_VERSION) <= LooseVersion(api_version):
        port_details = list(array.get_network_interfaces_port_details().items)
        for port_detail in range(0, len(port_details)):
            port_name = port_details[port_detail].name
            hw_info["interfaces"][port_name]["interface_type"] = port_details[
                port_detail
            ].interface_type
            if not getattr(port_details[port_detail], "rx_los", None) is None:
                hw_info["interfaces"][port_name]["rx_los"] = (
                    port_details[port_detail].rx_los[0].flag
                )
            if not getattr(port_details[port_detail], "rx_power", None) is None:
                hw_info["interfaces"][port_name]["rx_power"] = (
                    port_details[port_detail].rx_power[0].measurement
                )
            hw_info["interfaces"][port_name]["static"] = {
                "connector_type": getattr(
                    port_details[port_detail].static, "connector_type", None
                ),
                "vendor_name": getattr(
                    port_details[port_detail].static, "vendor_name", None
                ),
                "vendor_oui": getattr(
                    port_details[port_detail].static, "vendor_oui", None
                ),
                "vendor_serial_number": getattr(
                    port_details[port_detail].static, "vendor_serial_number", None
                ),
                "vendor_part_number": getattr(
                    port_details[port_detail].static, "vendor_part_number", None
                ),
                "vendor_date_code": getattr(
                    port_details[port_detail].static, "vendor_date_code", None
                ),
                "signaling_rate": getattr(
                    port_details[port_detail].static, "signaling_rate", None
                ),
                "wavelength": getattr(
                    port_details[port_detail].static, "wavelength", None
                ),
                "rate_identifier": getattr(
                    port_details[port_detail].static, "rate_identifier", None
                ),
                "identifier": getattr(
                    port_details[port_detail].static, "identifier", None
                ),
                "link_length": getattr(
                    port_details[port_detail].static, "link_length", None
                ),
                "fc_speeds": getattr(
                    port_details[port_detail].static, "fc_speeds", None
                ),
                "fc_technology": getattr(
                    port_details[port_detail].static, "fc_technology", None
                ),
                "encoding": getattr(port_details[port_detail].static, "encoding", None),
                "fc_link_lengths": getattr(
                    port_details[port_detail].static, "fc_link_lengths", None
                ),
                "fc_transmission_media": getattr(
                    port_details[port_detail].static, "fc_transmission_media", None
                ),
                "extended_identifier": getattr(
                    port_details[port_detail].static, "extended_identifier", None
                ),
            }
            if (
                not getattr(
                    port_details[port_detail].static, "voltage_thresholds", None
                )
                is None
            ):
                hw_info["interfaces"][port_name]["voltage_thresholds"] = {
                    "alarm_high": getattr(
                        port_details[port_detail].static.voltage_thresholds,
                        "alarm_high",
                        None,
                    ),
                    "alarm_low": getattr(
                        port_details[port_detail].static.voltage_thresholds,
                        "alarm_low",
                        None,
                    ),
                    "warn_high": getattr(
                        port_details[port_detail].static.voltage_thresholds,
                        "warn_high",
                        None,
                    ),
                    "warn_low": getattr(
                        port_details[port_detail].static.voltage_thresholds,
                        "warn_low",
                        None,
                    ),
                }
            if (
                not getattr(
                    port_details[port_detail].static, "tx_power_thresholds", None
                )
                is None
            ):
                hw_info["interfaces"][port_name]["tx_power_thresholds"] = {
                    "alarm_high": getattr(
                        port_details[port_detail].static.tx_power_thresholds,
                        "alarm_high",
                        None,
                    ),
                    "alarm_low": getattr(
                        port_details[port_detail].static.tx_power_thresholds,
                        "alarm_low",
                        None,
                    ),
                    "warn_high": getattr(
                        port_details[port_detail].static.tx_power_thresholds,
                        "warn_high",
                        None,
                    ),
                    "warn_low": getattr(
                        port_details[port_detail].static.tx_power_thresholds,
                        "warn_low",
                        None,
                    ),
                }
            if (
                not getattr(
                    port_details[port_detail].static, "rx_power_thresholds", None
                )
                is None
            ):
                hw_info["interfaces"][port_name]["rx_power_thresholds"] = {
                    "alarm_high": getattr(
                        port_details[port_detail].static.rx_power_thresholds,
                        "alarm_high",
                        None,
                    ),
                    "alarm_low": getattr(
                        port_details[port_detail].static.rx_power_thresholds,
                        "alarm_low",
                        None,
                    ),
                    "warn_high": getattr(
                        port_details[port_detail].static.rx_power_thresholds,
                        "warn_high",
                        None,
                    ),
                    "warn_low": getattr(
                        port_details[port_detail].static.rx_power_thresholds,
                        "warn_low",
                        None,
                    ),
                }
            if (
                not getattr(
                    port_details[port_detail].static, "tx_bias_thresholds", None
                )
                is None
            ):
                hw_info["interfaces"][port_name]["tx_bias_thresholds"] = {
                    "alarm_high": getattr(
                        port_details[port_detail].static.tx_bias_thresholds,
                        "alarm_high",
                        None,
                    ),
                    "alarm_low": getattr(
                        port_details[port_detail].static.tx_bias_thresholds,
                        "alarm_low",
                        None,
                    ),
                    "warn_high": getattr(
                        port_details[port_detail].static.tx_bias_thresholds,
                        "warn_high",
                        None,
                    ),
                    "warn_low": getattr(
                        port_details[port_detail].static.tx_bias_thresholds,
                        "warn_low",
                        None,
                    ),
                }
            if (
                not getattr(
                    port_details[port_detail].static, "temperature_thresholds", None
                )
                is None
            ):
                hw_info["interfaces"][port_name]["temperature_thresholds"] = {
                    "alarm_high": getattr(
                        port_details[port_detail].static.temperature_thresholds,
                        "alarm_high",
                        None,
                    ),
                    "alarm_low": getattr(
                        port_details[port_detail].static.temperature_thresholds,
                        "alarm_low",
                        None,
                    ),
                    "warn_high": getattr(
                        port_details[port_detail].static.temperature_thresholds,
                        "warn_high",
                        None,
                    ),
                    "warn_low": getattr(
                        port_details[port_detail].static.temperature_thresholds,
                        "warn_low",
                        None,
                    ),
                }
            if not getattr(port_details[port_detail], "temperature", None) is None:
                hw_info["interfaces"][port_name]["temperature"] = getattr(
                    port_details[port_detail].temperature[0], "measurement", None
                )
            if not getattr(port_details[port_detail], "tx_bias", None) is None:
                hw_info["interfaces"][port_name]["tx_bias"] = getattr(
                    port_details[port_detail].tx_bias[0], "measurement", None
                )
            if not getattr(port_details[port_detail], "tx_fault", None) is None:
                hw_info["interfaces"][port_name]["tx_fault"] = getattr(
                    port_details[port_detail].tx_fault[0], "flag", None
                )
            if not getattr(port_details[port_detail], "tx_power", None) is None:
                hw_info["interfaces"][port_name]["tx_power"] = getattr(
                    port_details[port_detail].tx_power[0], "measurement", None
                )
            if not getattr(port_details[port_detail], "voltage", None) is None:
                hw_info["interfaces"][port_name]["voltage"] = getattr(
                    port_details[port_detail].voltage[0], "measurement", None
                )
    return hw_info


def main():
    argument_spec = purefa_argument_spec()
    inv_info = {}
    module = AnsibleModule(argument_spec, supports_check_mode=True)
    array = get_array(module)
    inv_info = generate_new_hardware_dict(array)
    module.exit_json(changed=False, purefa_inv=inv_info)


if __name__ == "__main__":
    main()
