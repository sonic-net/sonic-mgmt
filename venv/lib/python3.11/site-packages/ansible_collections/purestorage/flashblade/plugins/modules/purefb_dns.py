#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2024, Simon Dodsley (simon@purestorage.com)
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
module: purefb_dns
version_added: '1.0.0'
short_description: Configure FlashBlade DNS settings
description:
- Set or erase configuration for the DNS settings.
- Nameservers provided will overwrite any existing nameservers.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the DNS configuration.
    - Default value only supported for management service
    default: management
    type: str
  state:
    description:
    - Set or delete directory service configuration
    default: present
    type: str
    choices: [ absent, present ]
  domain:
    description:
    - Domain suffix to be appended when performing DNS lookups.
    type: str
  nameservers:
    description:
    - List of up to 3 unique DNS server IP addresses. These can be
      IPv4 or IPv6 - No validation is done of the addresses is performed.
    type: list
    elements: str
  source:
    description:
    - A virtual network interface (vip)
    - The network interfaces must have a I(service) value of I(data)
    type: str
  service:
    description:
    - The service utilizing the DNS configuration.
    - Only aplicable when creating a new DNS configuration.
    type: str
    choices: [ management, data ]
    default: data
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Set managemnt DNS settings
  purestorage.flashblade.purefb_dns:
    domain: purestorage.com
    nameservers:
      - 8.8.8.8
      - 8.8.4.4
    fa_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Delete exisitng management DNS settings
  purestorage.flashblade.purefb_dns:
    state: absent
    fa_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Set DNS settings with alternate name
  purestorage.flashblade.purefb_dns:
    name: server1
    domain: purestorage.com
    nameservers:
      - 8.8.8.8
      - 8.8.4.4
    fa_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import Dns, DnsPatch, DnsPost, Reference
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

NON_MGMT_DNS = "2.15"


def remove(duplicate):
    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)
    return final_list


def _get_source(module, blade):
    res = blade.get_network_interfaces(names=[module.params["source"]])
    return bool(res.status_code == 200)


def delete_dns(module, blade):
    """Delete DNS settings"""
    changed = False
    current_dns = list(blade.get_dns().items)[0]
    if getattr(current_dns, "domain", None) in ["", None] and getattr(
        current_dns, "nameservers", None
    ) in [[""], None]:
        module.exit_json(changed=changed)
    else:
        changed = True
        if not module.check_mode:
            res = blade.delete_dns(names=["management"])
        if res.status_code != 200:
            module.fail_json(
                msg="Delete DNS settigs failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_dns(module, blade):
    """Set DNS settings"""
    changed = False
    current_dns = list(blade.get_dns().items)[0]
    if current_dns["domain"] != module.params["domain"] or sorted(
        module.params["nameservers"]
    ) != sorted(current_dns["nameservers"]):
        changed = True
        if not module.check_mode:
            res = blade.post_dns(
                names=["management"],
                dns=DnsPatch(
                    domain=module.params["domain"],
                    nameservers=module.params["nameservers"][0:3],
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Set DNS settings failed. Error: {0}".format(res.errors[0].message)
            )
    module.exit_json(changed=changed)


def update_multi_dns(module, blade):
    """Update a DNS configuration"""
    changed = False
    current_dns = list(blade.get_dns(names=[module.params["name"]]).items)[0]
    new_dns = current_dns
    if module.params["domain"] and current_dns.domain != module.params["domain"]:
        new_dns.domain = module.params["domain"]
        changed = True
    if module.params["nameservers"] and sorted(current_dns.nameservers) != sorted(
        module.params["nameservers"]
    ):
        new_dns.nameservers = module.params["nameservers"]
        changed = True
    if (module.params["source"] or module.params["source"] == "") and getattr(
        current_dns.sources[0], "name", ""
    ) != module.params["source"]:
        new_dns.sources[0].name = module.params["source"]
        changed = True
    if changed and not module.check_mode:
        res = blade.patch_dns(
            names=[module.params["name"]],
            dns=Dns(
                domain=new_dns.domain,
                nameservers=new_dns.nameservers,
                sources=[Reference(name=module.params["source"])],
            ),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Update to DNS configuration {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_multi_dns(module, blade):
    """Delete a DNS configuration"""
    changed = True
    if module.params["name"] == "management":
        module.fail_json(msg="Management DNS configuration cannot be deleted")
    else:
        if not module.check_mode:
            res = blade.delete_dns(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete DNS configuration {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_multi_dns(module, blade):
    """Create a DNS configuration"""
    changed = True
    if not module.check_mode:
        if module.params["service"] == "data":
            if module.params["source"]:
                res = blade.post_dns(
                    names=[module.params["name"]],
                    dns=DnsPost(
                        services=[module.params["service"]],
                        domain=module.params["domain"],
                        nameservers=module.params["nameservers"],
                        sources=[Reference(name=module.params["source"].lower())],
                    ),
                )
            else:
                res = blade.post_dns(
                    names=[module.params["name"]],
                    dns=DnsPost(
                        services=[module.params["service"]],
                        domain=module.params["domain"],
                        nameservers=module.params["nameservers"],
                    ),
                )
        else:
            res = blade.post_dns(
                names=[module.params["name"]],
                dns=DnsPost(
                    services=[module.params["service"]],
                    domain=module.params["domain"],
                    nameservers=module.params["nameservers"],
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create {0} DNS configuration {1}. Error: {2}".format(
                    module.params["service"],
                    module.params["name"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str", default="management"),
            domain=dict(type="str"),
            source=dict(type="str"),
            nameservers=dict(type="list", elements="str"),
            service=dict(type="str", choices=["management", "data"], default="data"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    blade = get_system(module)
    api_version = list(blade.get_versions().items)
    if module.params["nameservers"]:
        module.params["nameservers"] = remove(module.params["nameservers"])

    if NON_MGMT_DNS in api_version:
        configs = list(blade.get_dns().items)
        exists = False
        for config in range(len(configs)):
            if configs[config].name == module.params["name"]:
                exists = True
        if module.params["source"] and not _get_source(module, blade):
            module.fail_json(
                msg="Specified VIP {0} does not exist.".format(module.params["source"])
            )
        if state == "present" and exists:
            update_multi_dns(module, blade)
        elif state == "present" and not exists:
            if not module.params["nameservers"] and not module.params["domain"]:
                module.fail_json(
                    msg="DNS configuration must have at least one domain "
                    "or nameserver defined."
                )
            create_multi_dns(module, blade)
        elif exists and state == "absent":
            delete_multi_dns(module, blade)
        else:
            module.exit_json(changed=False)
    else:
        if state == "absent":
            delete_dns(module, blade)
        elif state == "present":
            if not module.params["domain"] or not module.params["nameservers"]:
                module.fail_json(
                    msg="DNS configuration must have at least one domain "
                    "or nameserver defined."
                )
            create_dns(module, blade)
        else:
            module.exit_json(changed=False)


if __name__ == "__main__":
    main()
