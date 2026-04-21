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
module: purefb_lag
version_added: '1.7.0'
short_description: Manage FlashBlade Link Aggregation Groups
description:
- Maintain FlashBlade Link Aggregation Groups
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the Link Aggregation Group
    type: str
    default: uplink
  state:
    description:
    - Define whether the LAG should be added or deleted
    default: present
    choices: [ absent, present ]
    type: str
  ports:
    description:
    - Name of network ports assigned to the LAG
    - Format should be CHx.ETHy, where CHx is the chassis number and
      ETHy is the ethernet port number.
    - Matched port pairs from each Fabric Module in the Chassis will
      be used.
    - To modify required ports for a LAG specify only the ports required
      by the LAG. Any ports currently used by the LAG not specified will be
      disconnected from the LAG.
    type: list
    elements: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Add LAG
  purestorage.flashblade.purefb_lag:
    name: lag2
    ports:
    - ch1.eth2
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Upate LAG
  purestorage.flashblade.purefb_lag:
    name: lag2
    ports:
    - ch1.eth2
    - ch1.eth4
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Delete LAG
  purestorage.flashblade.purefb_lag:
    name: lag2
    state: absent
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
lag:
    description: A dictionary describing the LAG.
    type: dict
    returned: success
    contains:
        lag_speed:
            description: Combined speed of all ports in the LAG in Gb/s
            type: str
        port_speed:
            description: Configured speed of each port in the LAG in Gb/s
            type: str
        mac_address:
            description: Unique MAC address assigned to the LAG
            type: str
        status:
            description: Health status of the LAG.
            type: str
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


def delete_lag(module, blade):
    """Delete Link Aggregation Group"""
    changed = True
    if not module.check_mode:
        res = blade.delete_link_aggregation_groups(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete LAG {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_lag(module, blade):
    """Update Link Aggregation Group"""
    changed = False
    used_ports = []
    current_ports = []
    lagfact = []
    current_lag = list(
        blade.get_link_aggregation_groups(names=[module.params["name"]]).items
    )[0]
    for port in range(len(current_lag.ports)):
        used_ports.append(current_lag.ports[port].name)
    for lag_port in range(len(module.params["ports"]), 2):
        if (
            not (
                module.params["ports"][lag_port].split(".")[0].upper()
                + ".FM1."
                + module.params["ports"][lag_port].split(".")[1].upper()
            )
            in used_ports
        ):
            current_lags = list(blade.get_link_aggregation_groups().items)
            for lag in range(len(current_lags)):
                for port in range(len(current_lags[lag].ports)):
                    current_ports.append(current_lags[lag].ports[port].name)
            for current_lag_port in range(len(current_ports)):
                if (
                    module.params["ports"][current_lag_port].split(".")[0].upper()
                    + ".FM1."
                    + module.params["ports"][current_lag_port].split(".")[1].upper()
                ) in current_ports:
                    module.fail_json(
                        msg="Selected port {0} is currently in use by another LAG.".format(
                            module.params["ports"][lag_port].upper()
                        )
                    )
    new_ports = []
    for port in range(len(module.params["ports"])):
        if module.params["ports"][port].split(".")[0].upper()[0] != "X":
            new_ports.append(
                module.params["ports"][port].split(".")[0].upper()
                + ".FM1."
                + module.params["ports"][port].split(".")[1].upper()
            )
            new_ports.append(
                module.params["ports"][port].split(".")[0].upper()
                + ".FM2."
                + module.params["ports"][port].split(".")[1].upper()
            )
        else:
            new_ports.append(module.params["ports"][port].upper())
    ports = []
    for final_port in range(len(new_ports)):
        ports.append(flashblade.Reference(name=new_ports[final_port]))
    link_aggregation_group = flashblade.LinkAggregationGroup(ports=[])
    link_aggregation_group["ports"] = ports
    if sorted(used_ports) != sorted(new_ports):
        changed = True
        if not module.check_mode:
            res = blade.patch_link_aggregation_groups(
                names=[module.params["name"]],
                link_aggregation_group=link_aggregation_group,
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update LAG {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
            else:
                response = list(res.items)[0]
                lagfact = {
                    "mac_address": response.mac_address,
                    "port_speed": str(response.port_speed / 1000000000) + "Gb/s",
                    "lag_speed": str(response.lag_speed / 1000000000) + "Gb/s",
                    "status": response.status,
                }
    module.exit_json(changed=changed, lag=lagfact)


def create_lag(module, blade):
    """Create Link Aggregation Group"""
    changed = True
    used_ports = []
    lagfact = []
    current_lags = list(blade.get_link_aggregation_groups().items)
    for lag in range(len(current_lags)):
        for port in range(len(current_lags[lag].ports)):
            used_ports.append(current_lags[lag].ports[port].name)
    for lag_port in range(len(module.params["ports"])):
        if (
            module.params["ports"][lag_port].split(".")[0].upper()
            + ".FM1."
            + module.params["ports"][0].split(".")[1].upper()
        ) in used_ports:
            module.fail_json(
                msg="Selected port {0} is currently in use by another LAG.".format(
                    module.params["ports"][lag_port].upper()
                )
            )
    new_ports = []
    for new_port in range(len(module.params["ports"])):
        new_ports.append(
            module.params["ports"][new_port].split(".")[0].upper()
            + ".FM1."
            + module.params["ports"][new_port].split(".")[1].upper()
        )
        new_ports.append(
            module.params["ports"][new_port].split(".")[0].upper()
            + ".FM2."
            + module.params["ports"][new_port].split(".")[1].upper()
        )
    ports = []
    module.warn("new_ports: {0}".format(new_ports))
    for final_port in range(len(new_ports)):
        ports.append(flashblade.FixedReference(name=new_ports[final_port]))
    link_aggregation_group = flashblade.LinkAggregationGroup(ports=ports)
    module.warn("LAG: {0}".format(link_aggregation_group))
    if not module.check_mode:
        res = blade.post_link_aggregation_groups(
            names=[module.params["name"]], link_aggregation_group=link_aggregation_group
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create LAG {0}. Error: {1}".format(
                    module.params["name"],
                    res.errors[0].message,
                )
            )
        else:
            response = list(res.items)[0]
            lagfact = {
                "mac_address": response.mac_address,
                "port_speed": str(response.port_speed / 1000000000) + "Gb/s",
                "lag_speed": str(response.lag_speed / 1000000000) + "Gb/s",
                "status": response.status,
            }
    module.exit_json(changed=changed, lag=lagfact)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str", default="uplink"),
            ports=dict(type="list", elements="str"),
        )
    )

    required_if = [["state", "present", ["ports"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    state = module.params["state"]

    exists = bool(
        blade.get_link_aggregation_groups(names=[module.params["name"]]).status_code
        == 200
    )
    if module.params["ports"]:
        # Remove duplicates
        module.params["ports"] = list(dict.fromkeys(module.params["ports"]))
    if not exists and state == "present":
        create_lag(module, blade)
    elif exists and state == "present":
        update_lag(module, blade)
    elif exists and state == "absent":
        if module.params["name"].lower() == "uplink":
            module.fail_json(
                msg="Preconfigured Link Aggregation Group cannot be deleted"
            )
        else:
            delete_lag(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
