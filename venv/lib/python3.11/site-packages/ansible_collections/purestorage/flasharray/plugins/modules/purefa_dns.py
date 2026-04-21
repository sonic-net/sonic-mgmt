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
module: purefa_dns
version_added: '1.0.0'
short_description: Configure FlashArray DNS settings
description:
- Set or erase configuration for the DNS settings.
- Nameservers provided will overwrite any existing nameservers.
- From Purity//FA 6.3.3 DNS setting for FA-File can be configured seperately
  to the management DNS settings
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the DNS configuration.
    - Default value only supported for management service
    default: management
    type: str
    version_added: 1.14.0
  state:
    description:
    - Set or delete directory service configuration
    default: present
    type: str
    choices: [ absent, present ]
  domain:
    description:
    - Domain suffix to be appended when perofrming DNS lookups.
    type: str
  nameservers:
    description:
    - List of up to 3 unique DNS server IP addresses. These can be
      IPv4 or IPv6 - No validation is done of the addresses is performed.
    type: list
    elements: str
  service:
    description:
    - Type of ser vice the DNS will work with
    type: str
    version_added: 1.14.0
    choices: [ management, file ]
    default: management
  source:
    description:
    - A virtual network interface (vif)
    type: str
    version_added: 1.14.0
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: 1.40.0
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete exisitng management DNS settings
  purestorage.flasharray.purefa_dns:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set managemnt DNS settings
  purestorage.flasharray.purefa_dns:
    domain: purestorage.com
    nameservers:
      - 8.8.8.8
      - 8.8.4.4
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set file DNS settings
  purestorage.flasharray.purefa_dns:
    domain: purestorage.com
    nameservers:
      - 8.8.8.8
      - 8.8.4.4
    name: ad_dns
    service: file
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete file DNS settings
  purestorage.flasharray.purefa_dns:
    state: absent
    name: ad_dns
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import DnsPost, DnsPatch, ReferenceNoId
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)

MULTIPLE_DNS = "2.15"
CONTEXT_API_VERSION = "2.47"


def remove(duplicate):
    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)
    return final_list


def _get_source(module, array):
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_network_interfaces(
            names=[module.params["source"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_network_interfaces(names=[module.params["source"]])
    return bool(res.status_code == 200)


def delete_dns(module, array):
    """Delete DNS settings"""
    changed = False
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        current_dns = list(
            array.get_dns(context_names=[module.params["context"]]).items
        )[0]
    else:
        current_dns = list(array.get_dns().items)[0]
    if getattr(current_dns, "domain", None) in ["", None] and getattr(
        current_dns, "nameservers", None
    ) in [[""], None]:
        module.exit_json(changed=changed)
    else:
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.delete_dns(
                    names=["management"], context_names=[module.params["context"]]
                )
            else:
                res = array.delete_dns(names=["management"])
        if res.status_code != 200:
            module.fail_json(
                msg="Delete DNS settigs failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_dns(module, array):
    """Set DNS settings"""
    changed = False
    api_version = array.get_rest_version()
    current_dns = list(array.get_dns().items)[0]
    if current_dns["domain"] != module.params["domain"] or sorted(
        module.params["nameservers"]
    ) != sorted(current_dns["nameservers"]):
        changed = True
        if not module.check_mode:
            res = array.patch_dns(
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


def update_multi_dns(module, array):
    """Update a DNS configuration"""
    changed = False
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        current_dns = list(
            array.get_dns(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        current_dns = list(array.get_dns(names=[module.params["name"]]).items)[0]
    new_dns = current_dns
    if module.params["domain"] and current_dns.domain != module.params["domain"]:
        new_dns.domain = module.params["domain"]
        changed = True
    if module.params["service"] and current_dns.services != [module.params["service"]]:
        module.fail_json(msg="Changing service type is not permitted")
    if module.params["nameservers"] and sorted(current_dns.nameservers) != sorted(
        module.params["nameservers"]
    ):
        new_dns.nameservers = module.params["nameservers"]
        changed = True
    if (module.params["source"] or module.params["source"] == "") and getattr(
        current_dns.source, "name", ""
    ) != module.params["source"]:
        new_dns.source.name = module.params["source"]
        changed = True
    if changed and not module.check_mode:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_dns(
                names=[module.params["name"]],
                dns=DnsPatch(
                    domain=new_dns.domain,
                    nameservers=new_dns.nameservers,
                    source=ReferenceNoId(name=module.params["source"]),
                ),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_dns(
                names=[module.params["name"]],
                dns=DnsPatch(
                    domain=new_dns.domain,
                    nameservers=new_dns.nameservers,
                    source=ReferenceNoId(name=module.params["source"]),
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Update to DNS service {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_multi_dns(module, array):
    """Delete a DNS configuration"""
    changed = True
    api_version = array.get_rest_version()
    if module.params["name"] == "management":
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_dns(
                names=[module.params["name"]],
                dns=DnsPatch(domain="", nameservers=[]),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_dns(
                names=[module.params["name"]],
                dns=DnsPatch(domain="", nameservers=[]),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Management DNS configuration not deleted. Error: {0}".format(
                    res.errors[0].message
                )
            )
    else:
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.delete_dns(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.delete_dns(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete DNS configuration {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_multi_dns(module, array):
    """Create a DNS configuration"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        if module.params["service"] == "file":
            if module.params["source"]:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_dns(
                        names=[module.params["name"]],
                        dns=DnsPost(
                            services=[module.params["service"]],
                            domain=module.params["domain"],
                            nameservers=module.params["nameservers"],
                            source=ReferenceNoId(name=module.params["source"].lower()),
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_dns(
                        names=[module.params["name"]],
                        dns=DnsPost(
                            services=[module.params["service"]],
                            domain=module.params["domain"],
                            nameservers=module.params["nameservers"],
                            source=ReferenceNoId(name=module.params["source"].lower()),
                        ),
                    )
            else:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_dns(
                        names=[module.params["name"]],
                        dns=DnsPost(
                            services=[module.params["service"]],
                            domain=module.params["domain"],
                            nameservers=module.params["nameservers"],
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_dns(
                        names=[module.params["name"]],
                        dns=DnsPost(
                            services=[module.params["service"]],
                            domain=module.params["domain"],
                            nameservers=module.params["nameservers"],
                        ),
                    )
        else:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.post_dns(
                    names=[module.params["name"]],
                    dns=DnsPost(
                        services=[module.params["service"]],
                        domain=module.params["domain"],
                        nameservers=module.params["nameservers"],
                    ),
                    context_names=[module.params["context"]],
                )
            else:
                res = array.post_dns(
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
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str", default="management"),
            service=dict(
                type="str", default="management", choices=["management", "file"]
            ),
            domain=dict(type="str"),
            source=dict(type="str"),
            nameservers=dict(type="list", elements="str"),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    array = get_array(module)
    api_version = array.get_rest_version()
    if module.params["nameservers"]:
        module.params["nameservers"] = remove(module.params["nameservers"])
        if module.params["service"] == "management":
            module.params["nameservers"] = module.params["nameservers"][0:3]

    if LooseVersion(MULTIPLE_DNS) <= LooseVersion(api_version):
        configs = list(array.get_dns().items)
        exists = False
        for config in range(0, len(configs)):
            if configs[config].name == module.params["name"]:
                exists = True
        if (
            module.params["service"] == "management"
            and module.params["name"] != "management"
            and not exists
        ):
            module.warn("Overriding configuration name to management")
            module.params["name"] = "management"
        if module.params["source"] and not _get_source(module, array):
            module.fail_json(
                msg="Specified VIF {0} does not exist.".format(module.params["source"])
            )
        if state == "present" and exists:
            update_multi_dns(module, array)
        elif state == "present" and not exists:
            if len(configs) == 2:
                module.fail_json(
                    msg="Only 2 DNS configurations are currently "
                    "supported. One for management and one for file services"
                )
            create_multi_dns(module, array)
        elif exists and state == "absent":
            delete_multi_dns(module, array)
        else:
            module.exit_json(changed=False)
    else:
        if state == "absent":
            delete_dns(module, array)
        elif state == "present":
            if not module.params["domain"] or not module.params["nameservers"]:
                module.fail_json(
                    msg="`domain` and `nameservers` are required for DNS configuration"
                )
            create_dns(module, array)
        else:
            module.exit_json(changed=False)


if __name__ == "__main__":
    main()
