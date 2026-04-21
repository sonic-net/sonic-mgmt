#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
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
module: purefa_proxy
version_added: '1.0.0'
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
short_description: Configure FlashArray phonehome HTTPs proxy settings
description:
- Set or erase configuration for the HTTPS phonehome proxy settings.
options:
  state:
    description:
    - Set or delete proxy configuration
    default: present
    type: str
    choices: [ absent, present ]
  protocol:
    description:
    - The proxy protocol.
    choices: [http, https ]
    default: https
    type: str
    version_added: '1.20.0'
  host:
    description:
    - The proxy host name.
    type: str
  port:
    description:
    - The proxy TCP/IP port number.
    type: int
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete exisitng proxy settings
  purestorage.flasharray.purefa_proxy:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set proxy settings
  purestorage.flasharray.purefa_proxy:
    host: purestorage.com
    port: 8080
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import SupportPatch
except ImportError:
    HAS_PURESTORAGE = False


def delete_proxy(module, array):
    """Delete proxy settings"""
    changed = False
    current_proxy = list(array.get_support().items)[0].proxy
    if current_proxy != "":
        changed = True
        if not module.check_mode:
            res = array.patch_support(support=SupportPatch(proxy=""))
            if res.status_code != 200:
                module.fail_json(
                    msg="Delete proxy settigs failed. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_proxy(module, array):
    """Set proxy settings"""
    changed = False
    current_proxy = list(array.get_support().items)[0].proxy
    if current_proxy != "":
        new_proxy = (
            module.params["protocol"]
            + "://"
            + module.params["host"]
            + ":"
            + str(module.params["port"])
        )
        if new_proxy != current_proxy:
            changed = True
            if not module.check_mode:
                res = array.patch_support(support=SupportPatch(proxy=new_proxy))
                if res.status_code != 200:
                    module.fail_json(
                        msg="Set phone home proxy failed. Error: {0}".format(
                            res.errors[0].message
                        )
                    )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            protocol=dict(type="str", default="https", choices=["http", "https"]),
            host=dict(type="str"),
            port=dict(type="int"),
        )
    )

    required_together = [["host", "port"]]

    module = AnsibleModule(
        argument_spec, required_together=required_together, supports_check_mode=True
    )
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    array = get_array(module)

    if state == "absent":
        delete_proxy(module, array)
    elif state == "present":
        create_proxy(module, array)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
