#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
---
module: purefb_subnet
version_added: "1.0.0"
short_description:  Manage network subnets in a Pure Storage FlashBlade
description:
    - This module manages network subnets on Pure Storage FlashBlade.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Subnet Name.
    required: true
    type: str
  state:
    description:
      - Create, delete or modifies a subnet.
    required: false
    default: present
    choices: [ "present", "absent" ]
    type: str
  lag:
    description:
      - Name of the Link Aggreation Group to use for the subnet.
    default: uplink
    type: str
    version_added: "1.7.0"
  gateway:
    description:
      - IPv4 or IPv6 address of subnet gateway.
    required: false
    type: str
  mtu:
    description:
      - MTU size of the subnet. Range is 1280 to 9216.
    required: false
    default: 1500
    type: int
  prefix:
    description:
      - IPv4 or IPv6 address associated with the subnet.
      - Supply the prefix length (CIDR) as well as the IP address.
      - Required for subnet creation.
    required: false
    type: str
  vlan:
    description:
      - VLAN ID of the subnet.
    required: false
    default: 0
    type: int
extends_documentation_fragment:
    - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = """
- name: Create new network subnet named foo
  purestorage.flashblade.purefb_subnet:
    name: foo
    prefix: "10.21.200.3/24"
    gateway: 10.21.200.1
    mtu: 9000
    vlan: 2200
    lag: bar
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Change configuration of existing subnet foo
  purestorage.flashblade.purefb_subnet:
    name: foo
    state: present
    prefix: "10.21.100.3/24"
    gateway: 10.21.100.1
    mtu: 1500
    address: 10.21.200.123
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete network subnet named foo
  purestorage.flashblade.purefb_subnet:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = """
"""

HAS_PURITY_FB = True
try:
    from pypureclient.flashblade import Subnet, Reference
except ImportError:
    HAS_PURITY_FB = False

try:
    import netaddr

    HAS_NETADDR = True
except ImportError:
    HAS_NETADDR = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def get_subnet(module, blade):
    """Return Subnet or None"""
    res = blade.get_subnets(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def create_subnet(module, blade):
    """Create Subnet"""
    changed = True
    if not module.params["prefix"]:
        module.fail_json(msg="prefix is required for subnet creation")
    if not module.check_mode:
        if module.params["gateway"]:
            res = blade.post_subnets(
                names=[module.params["name"]],
                subnet=Subnet(
                    prefix=module.params["prefix"],
                    vlan=module.params["vlan"],
                    mtu=module.params["mtu"],
                    gateway=module.params["gateway"],
                    link_aggregation_group=Reference(name=module.params["lag"]),
                ),
            )
        else:
            res = blade.post_subnets(
                names=[module.params["name"]],
                subnet=Subnet(
                    prefix=module.params["prefix"],
                    vlan=module.params["vlan"],
                    mtu=module.params["mtu"],
                    link_aggregation_group=Reference(name=module.params["lag"]),
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create subnet {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def modify_subnet(module, blade):
    """Modify Subnet settings"""
    changed = False
    subnet = get_subnet(module, blade)
    if module.params["prefix"]:
        if module.params["prefix"] != subnet.prefix:
            changed = True
            if not module.check_mode:
                res = blade.patch_subnets(
                    names=[module.params["name"]],
                    subnet=Subnet(prefix=module.params["prefix"]),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change subnet {0} prefix to {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["prefix"],
                            res.errors[0].message,
                        )
                    )
    if module.params["vlan"]:
        if module.params["vlan"] != subnet.vlan:
            changed = True
            if not module.check_mode:
                res = blade.patch_subnets(
                    names=[module.params["name"]],
                    subnet=Subnet(vlan=module.params["vlan"]),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change subnet {0} VLAN to {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["vlan"],
                            res.errors[0].message,
                        )
                    )
    if module.params["gateway"]:
        if module.params["gateway"] != subnet.gateway:
            changed = True
            if not module.check_mode:
                res = blade.patch_subnets(
                    names=[module.params["name"]],
                    subnet=Subnet(gateway=module.params["gateway"]),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change subnet {0} gateway to {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["gateway"],
                            res.errors[0].message,
                        )
                    )
    if module.params["mtu"]:
        if module.params["mtu"] != subnet.mtu:
            changed = True
            if not module.check_mode:
                res = blade.patch_subnets(
                    names=[module.params["name"]],
                    subnet=Subnet(mtu=module.params["mtu"]),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change subnet {0} MTU to {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["mtu"],
                            res.errors[0].message,
                        )
                    )
    module.exit_json(changed=changed)


def delete_subnet(module, blade):
    """Delete Subnet"""
    changed = True
    if not module.check_mode:
        res = blade.delete_subnets(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete subnet {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(default="present", choices=["present", "absent"]),
            gateway=dict(),
            lag=dict(type="str", default="uplink"),
            mtu=dict(type="int", default=1500),
            prefix=dict(),
            vlan=dict(type="int", default=0),
        )
    )

    required_if = [["state", "present", ["prefix"]]]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    if not HAS_NETADDR:
        module.fail_json(msg="netaddr module is required")

    state = module.params["state"]
    blade = get_system(module)
    subnet = get_subnet(module, blade)
    res = blade.get_link_aggregation_groups(names=[module.params["lag"]])
    if res.status_code != 200:
        module.fail_json(msg="LAG {0} does not exist.".format(module.params["lag"]))

    if state == "present":
        if not (1280 <= module.params["mtu"] <= 9216):
            module.fail_json(
                msg="MTU {0} is out of range (1280 to 9216)".format(
                    module.params["mtu"]
                )
            )
        if not (0 <= module.params["vlan"] <= 4094):
            module.fail_json(
                msg="VLAN ID {0} is out of range (0 to 4094)".format(
                    module.params["vlan"]
                )
            )
        if module.params["gateway"]:
            if netaddr.IPAddress(module.params["gateway"]) not in netaddr.IPNetwork(
                module.params["prefix"]
            ):
                module.fail_json(msg="Gateway and subnet are not compatible.")
        subnets = list(blade.get_subnets().items)
        nrange = netaddr.IPSet([module.params["prefix"]])
        for sub in range(len(subnets)):
            if (
                subnets[sub].vlan == module.params["vlan"]
                and subnets[sub].name != module.params["name"]
                and hasattr(subnets[sub].link_aggregation_group, "name")
            ):
                module.fail_json(
                    msg="VLAN ID {0} is already in use.".format(module.params["vlan"])
                )
            if (
                nrange & netaddr.IPSet([subnets[sub].prefix])
                and subnets[sub].name != module.params["name"]
            ):
                module.fail_json(msg="Prefix CIDR overlaps with existing subnet.")

    if state == "present" and not subnet:
        create_subnet(module, blade)
    elif state == "present" and subnet:
        modify_subnet(module, blade)
    elif state == "absent" and subnet:
        delete_subnet(module, blade)
    elif state == "absent" and not subnet:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
