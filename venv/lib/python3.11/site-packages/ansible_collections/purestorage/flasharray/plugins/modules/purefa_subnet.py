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


DOCUMENTATION = """
---
module: purefa_subnet
version_added: '1.0.0'
short_description:  Manage network subnets in a Pure Storage FlashArray
description:
    - This module manages the network subnets on a Pure Storage FlashArray.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Subnet name.
    required: true
    type: str
  state:
    description:
      - Create or delete subnet.
    required: false
    default: present
    choices: [ "present", "absent" ]
    type: str
  enabled:
    description:
      - whether the subnet should be enabled or not
    default: true
    type: bool
  prefix:
    description:
      - Set the IPv4 or IPv6 address to be associated with the subnet.
    required: false
    type: str
  gateway:
    description:
    - IPv4 or IPv6 address of subnet gateway.
    - To clear the gateway enter "0.0.0.0" or "::" depending on IP type
    required: false
    type: str
  mtu:
    description:
      - MTU size of the subnet. Range is 568 to 9000.
    required: false
    type: int
  vlan:
    description:
      - VLAN ID. Range is 0 to 4094.
    required: false
    type: int
extends_documentation_fragment:
    - purestorage.flasharray.purestorage.fa
"""

EXAMPLES = """
- name: Create subnet subnet100
  purestorage.flasharray.purefa_subnet:
    name: subnet100
    vlan: 100
    gateway: 10.21.200.1
    prefix: "10.21.200.0/24"
    mtu: 9000
    state: present
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40

- name: Disable subnet subnet100
  purestorage.flasharray.purefa_subnet:
    name: subnet100
    enabled: false
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40

- name: Delete subnet subnet100
  purestorage.flasharray.purefa_subnet:
    name: subnet100
    state: absent
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40
"""

RETURN = """
"""

try:
    from netaddr import IPNetwork, valid_ipv4, valid_ipv6

    HAS_NETADDR = True
except ImportError:
    HAS_NETADDR = False

try:
    from pypureclient.flasharray import SubnetPatch, SubnetPost

    HAS_PURESTORAGE = True
except ImportError:
    HAS_PURESTORAGE = False

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)


def _get_subnet(module, array):
    """Return subnet or None"""
    res = array.get_subnets(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def update_subnet(module, array, subnet):
    """Modify subnet settings"""
    changed = False
    current_state = {
        "mtu": subnet.mtu,
        "vlan": getattr(subnet, "vlan", 0),
        "prefix": subnet.prefix,
        "gateway": getattr(subnet, "gateway", None),
    }
    address = str(subnet.prefix.split("/", 1)[0])
    if not current_state["gateway"]:
        if valid_ipv4(address):
            current_state["gateway"] = "0.0.0.0"
        elif valid_ipv6(address):
            current_state["gateway"] = "::"
        else:
            module.fail_json(msg="Prefix address is not valid IPv4 or IPv6")

    if not module.params["prefix"]:
        prefix = subnet.prefix
    else:
        if module.params["gateway"] and not (
            module.params["gateway"] in ["0.0.0.0", "::"]
        ):
            if module.params["gateway"] and module.params["gateway"] not in IPNetwork(
                module.params["prefix"]
            ):
                module.fail_json(msg="Gateway and subnet are not compatible.")
            elif (
                not module.params["gateway"]
                and subnet.gateway
                and subnet.gateway not in IPNetwork(module.params["prefix"])
            ):
                module.fail_json(msg="Gateway and subnet are not compatible.")
        prefix = module.params["prefix"]
    if not module.params["vlan"]:
        vlan = subnet.vlan
        if not vlan:
            vlan = 0
    else:
        if not 0 <= module.params["vlan"] <= 4094:
            module.fail_json(
                msg="VLAN {0} is out of range (0 to 4094)".format(module.params["vlan"])
            )
        else:
            vlan = module.params["vlan"]
    if not module.params["mtu"]:
        mtu = subnet.mtu
    else:
        if not 568 <= module.params["mtu"] <= 9000:
            module.fail_json(
                msg="MTU {0} is out of range (568 to 9000)".format(module.params["mtu"])
            )
        else:
            mtu = module.params["mtu"]
    if not module.params["gateway"]:
        gateway = subnet["gateway"]
    else:
        if module.params["gateway"] and not (
            module.params["gateway"] in ["0.0.0.0", "::"]
        ):
            if module.params["gateway"] not in IPNetwork(prefix):
                module.fail_json(msg="Gateway and subnet are not compatible.")
        gateway = module.params["gateway"]
    new_state = {"prefix": prefix, "mtu": mtu, "gateway": gateway, "vlan": vlan}
    if new_state != current_state:
        changed = True
        if not module.check_mode:
            res = array.patch_subnets(
                names=[subnet.name],
                subnet=SubnetPatch(
                    prefix=new_state["prefix"],
                    mtu=new_state["mtu"],
                    vlan=new_state["vlan"],
                    gateway=new_state["gateway"],
                ),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change settings for subnet {0}. Error: {1}".format(
                        subnet.name, res.errors[0].message
                    )
                )
    if subnet.enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            res = array.patch_subnets(
                names=[subnet.name],
                subnet=SubnetPatch(enabled=module.params["enabled"]),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to enable/disable subnet {0}. Error: {1}".format(
                        subnet.name, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_subnet(module, array):
    """Create subnet"""
    changed = True
    if not module.params["prefix"]:
        module.fail_json(msg="Prefix required when creating subnet.")
    else:
        if module.params["gateway"] and not (
            module.params["gateway"] in ["0.0.0.0", "::"]
        ):
            if module.params["gateway"] and module.params["gateway"] not in IPNetwork(
                module.params["prefix"]
            ):
                module.fail_json(msg="Gateway and subnet are not compatible.")
        prefix = module.params["prefix"]
    if module.params["vlan"]:
        if not 0 <= module.params["vlan"] <= 4094:
            module.fail_json(
                msg="VLAN {0} is out of range (0 to 4094)".format(module.params["vlan"])
            )
        else:
            vlan = module.params["vlan"]
    else:
        vlan = 0
    mtu = 1500  # Initialize at default value
    if module.params["mtu"]:
        if not 568 <= module.params["mtu"] <= 9000:
            module.fail_json(
                msg="MTU {0} is out of range (568 to 9000)".format(module.params["mtu"])
            )
        else:
            mtu = module.params["mtu"]
    if module.params["gateway"] and not (module.params["gateway"] in ["0.0.0.0", "::"]):
        if module.params["gateway"] not in IPNetwork(prefix):
            module.fail_json(msg="Gateway and subnet are not compatible.")
        gateway = module.params["gateway"]
    else:
        gateway = ""
    if not module.check_mode:
        res = array.post_subnets(
            names=[module.params["name"]],
            subnet=SubnetPost(
                prefix=prefix,
                mtu=mtu,
                vlan=vlan,
                gateway=gateway,
                enabled=module.params["enabled"],
            ),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create subnet {0}.Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_subnet(module, array):
    """Delete subnet"""
    changed = True
    if not module.check_mode:
        res = array.delete_subnets(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete subnet {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            prefix=dict(type="str"),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            gateway=dict(type="str"),
            enabled=dict(type="bool", default=True),
            mtu=dict(type="int"),
            vlan=dict(type="int"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client module is required")
    if not HAS_NETADDR:
        module.fail_json(msg="netaddr module is required")
    pattern = re.compile(r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    if not pattern.match(module.params["name"]):
        module.fail_json(
            msg="name must be between 1 and 63 characters in length and begin and end "
            "with a letter or number. The name must include at least one letter or '-'."
        )
    state = module.params["state"]
    array = get_array(module)
    subnet = _get_subnet(module, array)
    if module.params["prefix"]:
        module.params["prefix"] = module.params["prefix"].strip("[]")
    if module.params["gateway"]:
        module.params["gateway"] = module.params["gateway"].strip("[]")
    if state == "present" and not subnet:
        create_subnet(module, array)
    if state == "present" and subnet:
        update_subnet(module, array, subnet)
    elif state == "absent" and subnet:
        delete_subnet(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
