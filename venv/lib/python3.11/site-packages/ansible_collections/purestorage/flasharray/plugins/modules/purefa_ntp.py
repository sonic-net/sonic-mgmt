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
module: purefa_ntp
version_added: '1.0.0'
short_description: Configure Pure Storage FlashArray NTP settings
description:
- Set, erase or test NTP configuration for Pure Storage FlashArrays.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create, delete or test NTP servers configuration
    type: str
    default: present
    choices: [ absent, present, test ]
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
  ntp_key:
    type: str
    description:
    - The NTP symmetric key to be used for NTP authentication.
    - If it is an ASCII string, it cannot contain the character "#"
      and cannot be longer than 20 characters.
    - If it is a hex-encoded string, it cannot be longer than 64 characters.
    - Setting this parameter is not idempotent.
    version_added: "1.22.0"
  context:
    description:
    - Name of fleet member on which to perform the ntp operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.37.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete exisitng NTP server entries
  purestorage.flasharray.purefa_ntp:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set array NTP servers
  purestorage.flasharray.purefa_ntp:
    state: present
    ntp_servers:
      - "0.pool.ntp.org"
      - "1.pool.ntp.org"
      - "2.pool.ntp.org"
      - "3.pool.ntp.org"
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
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import Arrays
except ImportError:
    HAS_PURESTORAGE = False


KEY_API_VERSION = "2.26"
CONTEXT_API_VERSION = "2.38"


def _is_cbs(array, is_cbs=False):
    """Is the selected array a Cloud Block Store"""
    # api_version = array.get_rest_version()
    #
    # Until get_controller has context_names we can check against a target system
    # CBS can't be support for Fusion
    #
    # if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
    #    model = list(
    #        array.get_controllers(context_names=[module.params["context"]]).items
    #    )[0].model
    # else:
    model = list(array.get_controllers().items)[0].model
    is_cbs = bool("CBS" in model)
    return is_cbs


def remove(duplicate):
    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)
    return final_list


def test_ntp(module, array):
    """Test NTP configuration"""
    # api_version = array.get_rest_version()
    test_response = []
    #
    # Until get_arrays_ntp_test has context_names we can check against a target system
    # test_ntp is not supported with context
    #
    # if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
    #     response = list(array.get_arrays_ntp_test(context_names=[module.params["context"]]).items)
    # else:
    response = list(array.get_arrays_ntp_test().items)
    for component in range(0, len(response)):
        if response[component].enabled:
            enabled = "true"
        else:
            enabled = "false"
        if response[component].success:
            success = "true"
        else:
            success = "false"
        test_response.append(
            {
                "component_address": response[component].component_address,
                "component_name": response[component].component_name,
                "description": response[component].description,
                "destination": response[component].destination,
                "enabled": enabled,
                "result_details": getattr(response[component], "result_details", ""),
                "success": success,
                "test_type": response[component].test_type,
                "resource_name": response[component].resource.name,
            }
        )
    module.exit_json(changed=True, test_response=test_response)


def delete_ntp(module, array):
    """Delete NTP Servers"""
    api_version = array.get_rest_version()
    changed = False
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        array_list = array.get_arrays(context_names=[module.params["context"]])
    else:
        array_list = array.get_arrays()
    if list(array_list.items)[0].ntp_servers != []:
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_arrays(
                    array=Arrays(ntp_servers=[]),
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_arrays(array=Arrays(ntp_servers=[]))
            if res.status_code != 200:
                module.fail_json(
                    msg="Deletion of NTP servers failed. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_ntp(module, array):
    """Set NTP Servers"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        if not module.params["ntp_servers"]:
            module.params["ntp_servers"] = ["0.pool.ntp.org"]
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_arrays(
                array=Arrays(ntp_servers=module.params["ntp_servers"][0:4]),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_arrays(
                array=Arrays(ntp_servers=module.params["ntp_servers"][0:4])
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Update of NTP servers failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_ntp_key(module, array):
    """Update NTP Symmetric Key"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        array_list = array.get_arrays(context_names=[module.params["context"]])
    else:
        array_list = array.get_arrays()
    if module.params["ntp_key"] == "" and not getattr(
        list(array_list.items)[0], "ntp_symmetric_key", None
    ):
        changed = False
    else:
        try:
            int(module.params["ntp_key"], 16)
            if len(module.params["ntp_key"]) > 64:
                module.fail_json(msg="HEX string cannot be longer than 64 characters")
        except ValueError:
            if len(module.params["ntp_key"]) > 20:
                module.fail_json(msg="ASCII string cannot be longer than 20 characters")
            if "#" in module.params["ntp_key"]:
                module.fail_json(msg="ASCII string cannot contain # character")
            if not all(ord(c) < 128 for c in module.params["ntp_key"]):
                module.fail_json(msg="NTP key is non-ASCII")
        changed = True
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_arrays(
                array=Arrays(ntp_symmetric_key=module.params["ntp_key"]),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_arrays(
                array=Arrays(ntp_symmetric_key=module.params["ntp_key"])
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to update NTP Symmetric Key. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)

    if len(module.params["ntp_key"]) > 20:
        # Must be HEX string is greter than 20 characters
        try:
            int(module.params["ntp_key"], 16)
        except ValueError:
            module.fail_json(msg="NTP key is not HEX")


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            ntp_servers=dict(type="list", elements="str"),
            ntp_key=dict(type="str", no_log=True),
            state=dict(
                type="str", default="present", choices=["absent", "present", "test"]
            ),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()
    if _is_cbs(array):
        module.warn("NTP settings are not necessary for a CBS array - ignoring...")
        module.exit_json(changed=False)

    if module.params["state"] == "absent":
        delete_ntp(module, array)
    elif module.params["state"] == "test":
        # Fail if context is set as not supported
        if not module.params["context"]:
            module.fail_json(msg="NTP testing is not supported with context")
        test_ntp(module, array)
    elif module.params["ntp_servers"]:
        module.params["ntp_servers"] = remove(module.params["ntp_servers"])
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            array_list = array.get_arrays(context_names=[module.params["context"]])
        else:
            array_list = array.get_arrays()
        if sorted(list(array_list.items)[0].ntp_servers) != sorted(
            module.params["ntp_servers"][0:4]
        ):
            create_ntp(module, array)
    if module.params["ntp_key"] or module.params["ntp_key"] == "":
        if LooseVersion(KEY_API_VERSION) > LooseVersion(api_version):
            module.fail_json(msg="REST API does not support setting NTP Symmetric Key")
        else:
            update_ntp_key(module, array)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
