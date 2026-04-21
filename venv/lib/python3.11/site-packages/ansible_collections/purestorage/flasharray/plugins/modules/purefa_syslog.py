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
module: purefa_syslog
version_added: '1.0.0'
short_description: Configure Pure Storage FlashArray syslog settings
description:
- Configure syslog configuration for Pure Storage FlashArrays.
- Manage individual syslog servers.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create, updatee, delete or test syslog servers configuration
    default: present
    type: str
    choices: [ absent, present, test ]
  protocol:
    description:
    - Protocol which server uses
    required: true
    type: str
    choices: [ tcp, tls, udp ]
  port:
    description:
    - Port at which the server is listening. If no port is specified
      the system will use 514
    type: str
  address:
    description:
    - Syslog server address.
      This field supports IPv4, IPv6 or FQDN.
      An invalid IP addresses will cause the module to fail.
      No validation is performed for FQDNs.
    type: str
    required: true
  name:
    description:
    - A user-specified name.
      The name must be locally unique and cannot be changed.
    type: str
    required: true
  context:
    description:
    - Name of fleet member on which to perform the syslog operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.37.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete existing syslog server entry
  purestorage.flasharray.purefa_syslog:
    name: syslog1
    address: syslog1.com
    protocol: tcp
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Add syslog server entry
  purestorage.flasharray.purefa_syslog:
    name: syslog1
    address: syslog1.com
    port: 8081
    protocol: udp
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update syslog server entry
  purestorage.flasharray.purefa_syslog:
    name: syslog1
    address: syslog1.com
    port: 8081
    protocol: tcp
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import SyslogServer
except ImportError:
    HAS_PURESTORAGE = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

CONTEXT_API_VERSION = "2.38"


def test_syslog(module, array):
    """Test syslog configuration"""
    api_version = array.get_rest_version()
    test_response = []
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        response = list(
            array.get_syslog_servers_test(
                context_names=[module.params["context"]]
            ).items
        )
    else:
        response = list(array.get_syslog_servers_test().items)
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


def delete_syslog(module, array):
    """Delete Syslog Server"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.delete_syslog_servers(
                names=[module.params["name"]],
                context_names=[module.params["context"]],
            )
        else:
            res = array.delete_syslog_servers(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to remove syslog server {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def add_syslog(module, array):
    """Add Syslog Server"""
    api_version = array.get_rest_version()
    changed = True
    noport_address = module.params["protocol"] + "://" + module.params["address"]

    if module.params["port"]:
        full_address = noport_address + ":" + module.params["port"]
    else:
        full_address = noport_address
    if not module.check_mode:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.post_syslog_servers(
                names=[module.params["name"]],
                syslog_server=SyslogServer(
                    name=module.params["name"], uri=full_address
                ),
                context_names=[module.params["context"]],
            )
        else:
            res = array.post_syslog_servers(
                names=[module.params["name"]],
                syslog_server=SyslogServer(
                    name=module.params["name"], uri=full_address
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Adding syslog server {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_syslog(module, array):
    """Update Syslog Server"""
    api_version = array.get_rest_version()
    changed = False
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        syslog_server_list = array.get_syslog_servers(
            names=[module.params["name"]],
            context_names=[module.params["context"]],
        )
    else:
        syslog_server_list = array.get_syslog_servers(names=[module.params["name"]])
    syslog_config = list(syslog_server_list.items)[0]
    noport_address = module.params["protocol"] + "://" + module.params["address"]

    if module.params["port"]:
        full_address = noport_address + ":" + module.params["port"]
    else:
        full_address = noport_address
    if full_address != syslog_config.uri:
        changed = True
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_syslog_servers(
                names=[module.params["name"]],
                syslog_server=SyslogServer(uri=full_address),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_syslog_servers(
                names=[module.params["name"]],
                syslog_server=SyslogServer(uri=full_address),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Updating syslog server {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            address=dict(type="str", required=True),
            protocol=dict(type="str", choices=["tcp", "tls", "udp"], required=True),
            port=dict(type="str"),
            name=dict(type="str", required=True),
            state=dict(
                type="str", default="present", choices=["absent", "present", "test"]
            ),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    array = get_array(module)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_syslog_servers(
            names=[module.params["name"]],
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_syslog_servers(names=[module.params["name"]])
    exists = bool(res.status_code == 200)

    if module.params["state"] == "absent" and exists:
        delete_syslog(module, array)
    elif module.params["state"] == "present" and not exists:
        add_syslog(module, array)
    elif module.params["state"] == "present" and exists:
        update_syslog(module, array)
    elif module.params["state"] == "test" and exists:
        test_syslog(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
