#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
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
module: purefb_ntp
version_added: '1.0.0'
short_description: Configure Pure Storage FlashBlade NTP settings
description:
- Set or erase NTP configuration for Pure Storage FlashBlades.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete NTP servers configuration
    type: str
    default: present
    choices: [ absent, present ]
  ntp_servers:
    type: list
    elements: str
    description:
    - A list of up to 4 alternate NTP servers. These may include IPv4,
      IPv6 or FQDNs. Invalid IP addresses will cause the module to fail.
      No validation is performed for FQDNs.
    - If more than 4 servers are provided, only the first 4 unique
      nameservers will be used.
    - if no servers are given a default of I(0.pool.ntp.org) will be used.
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Delete exisitng NTP server entries
  purestorage.flashblade.purefb_ntp:
    state: absent
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set array NTP servers
  purestorage.flashblade.purefb_ntp:
    state: present
    ntp_servers:
      - "0.pool.ntp.org"
      - "1.pool.ntp.org"
      - "2.pool.ntp.org"
      - "3.pool.ntp.org"
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURITY_FB = True
try:
    from pypureclient.flashblade import Array
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def remove(duplicate):
    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)
    return final_list


def delete_ntp(module, blade):
    """Delete NTP Servers"""
    changed = True
    if not module.check_mode:
        if list(blade.get_arrays().items)[0].ntp_servers != []:
            res = blade.patch_arrays(array=Array(ntp_servers=[]))
            if res.status_code != 200:
                module.fail_json(
                    msg="Deletion of NTP servers failed. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_ntp(module, blade):
    """Set NTP Servers"""
    changed = True
    if not module.check_mode:
        if not module.params["ntp_servers"]:
            module.params["ntp_servers"] = ["0.pool.ntp.org"]
        res = blade.patch_arrays(
            array=Array(ntp_servers=module.params["ntp_servers"][0:4])
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Update of NTP servers failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            ntp_servers=dict(type="list", elements="str"),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    required_if = [["state", "present", ["ntp_servers"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)

    if module.params["state"] == "absent":
        delete_ntp(module, blade)
    else:
        module.params["ntp_servers"] = remove(module.params["ntp_servers"])
        if sorted(list(blade.get_arrays().items)[0].ntp_servers) != sorted(
            module.params["ntp_servers"][0:4]
        ):
            create_ntp(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
