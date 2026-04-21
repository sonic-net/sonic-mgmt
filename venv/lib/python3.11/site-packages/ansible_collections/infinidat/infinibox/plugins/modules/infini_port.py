#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-list-literal,use-dict-literal,line-too-long,wrong-import-position,multiple-statements

"""This module manages ports on an Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_port
version_added: 2.9.0
short_description: Add and Delete fiber channel and iSCSI ports to a host on Infinibox
description:
    - This module adds or deletes fiber channel or iSCSI ports to hosts on
      Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  host:
    description:
      - Host Name
    type: str
    required: true
  state:
    description:
      - Creates mapping when present, removes when absent, or provides
        details of a mapping when stat.
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
    type: str
  wwns:
    description:
      - List of wwns of the host
    required: false
    default: []
    type: list
    elements: str
  iqns:
    description:
      - List of iqns of the host
    required: false
    default: []
    type: list
    elements: str
extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Make sure host bar is available with wwn/iqn ports
  infini_host:
    name: bar.example.com
    state: present
    wwns:
      - "00:00:00:00:00:00:00"
      - "11:11:11:11:11:11:11"
    iqns:
      - "iqn.yyyy-mm.reverse-domain:unique-string"
    system: ibox01
    user: admin
    password: secret
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    get_host,
    merge_two_dicts,
)

try:
    from infi.dtypes.wwn import WWN
    from infi.dtypes.iqn import make_iscsi_name
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


@api_wrapper
def update_ports(module, system):
    """
    Updated mapping of volume to host. If already mapped, exit_json with changed False.
    """
    changed = False

    host = system.hosts.get(name=module.params["host"])

    for wwn_port in module.params["wwns"]:
        wwn = WWN(wwn_port)
        if not system.hosts.get_host_by_initiator_address(wwn) == host:
            if not module.check_mode:
                host.add_port(wwn)
            changed = True

    for iscsi_port in module.params["iqns"]:
        iscsi_name = make_iscsi_name(iscsi_port)
        if not system.hosts.get_host_by_initiator_address(iscsi_name) == host:
            if not module.check_mode:
                host.add_port(iscsi_name)
            changed = True

    return changed


@api_wrapper
def delete_ports(module, system):
    """
    Remove ports from host.
    """
    changed = False

    host = system.hosts.get(name=module.params["host"])
    for wwn_port in module.params["wwns"]:
        wwn = WWN(wwn_port)
        if system.hosts.get_host_by_initiator_address(wwn) == host:
            if not module.check_mode:
                host.remove_port(wwn)
            changed = True
    for iscsi_port in module.params["iqns"]:
        iscsi_name = make_iscsi_name(iscsi_port)
        if system.hosts.get_host_by_initiator_address(iscsi_name) == host:
            if not module.check_mode:
                host.remove_port(iscsi_name)
            changed = True
    return changed


def get_sys_host(module):
    """ Get parameters """
    system = get_system(module)
    host = get_host(module, system)
    return (system, host)


def edit_initiator_keys(host_initiators, include_key_list):
    """
    For each host initiator, remove keys not in the include_key_list.
    For FCs, add a long address. This is the address with colons inserted.
    Return the edited host initiators list.
    """
    trimmed_initiators = []
    for init in host_initiators:
        if init["type"] == "FC" and "address" in init.keys():
            # Add address_long key to init whose value is the address with colons inserted.
            address_str = str(init["address"])
            address_iter = iter(address_str)
            long_address = ":".join(a + b for a, b in zip(address_iter, address_iter))
            init["address_long"] = long_address

        trimmed_item = {
            key: val for key, val in init.items() if key in include_key_list
        }
        trimmed_initiators.append(trimmed_item)
    return trimmed_initiators


def find_host_initiators_data(module, system, host, initiator_type):
    """
    Given a host object, find its initiators that match initiator_type.
    Only include desired initiator keys for each initiator.
    Return the filtered and edited host initiator list.
    """
    request = f"initiators?page=1&page_size=1000&host_id={host.id}"
    # print("\nrequest:", request, "initiator_type:", initiator_type)
    get_initiators_result = system.api.get(request, check_version=False)
    result_code = get_initiators_result.status_code
    if result_code != 200:
        msg = f"get initiators REST call failed. code: {result_code}"
        module.fail_json(msg=msg)

    # Only return initiators of the desired type.
    host_initiators_by_type = [
        initiator
        for initiator in get_initiators_result.get_result()
        if initiator["type"] == initiator_type
    ]

    # print("host_initiators_by_type:", host_initiators_by_type)
    # print()

    # Only include certain keys in the returned initiators
    if initiator_type == "FC":
        include_key_list = [
            "address",
            "address_long",
            "host_id",
            "port_key",
            "targets",
            "type",
        ]
    elif initiator_type == "ISCSI":
        include_key_list = ["address", "host_id", "port_key", "targets", "type"]
    else:
        msg = "Cannot search for host initiator types other than FC and ISCSI"
        module.fail_json(msg=msg)
    host_initiators_by_type = edit_initiator_keys(
        host_initiators_by_type, include_key_list
    )

    return host_initiators_by_type


def get_port_fields(module, system, host):  # pylint: disable=too-many-locals
    """
    Return a dict with desired fields from FC and ISCSI ports associated with the host.
    """
    host_fc_initiators = find_host_initiators_data(
        module, system, host, initiator_type="FC"
    )
    host_iscsi_initiators = find_host_initiators_data(
        module, system, host, initiator_type="ISCSI"
    )

    field_dict = dict(ports=[],)

    connectivity_lut = {0: "DISCONNECTED", 1: "DEGRADED", 2: "DEGRADED", 3: "CONNECTED"}

    ports = host.get_ports()
    for port in ports:
        if str(type(port)) == "<class 'infi.dtypes.wwn.WWN'>":
            found_initiator = False
            for initiator in host_fc_initiators:
                if initiator["address"] == str(port).replace(":", ""):
                    found_initiator = True
                    # print("initiator targets:", initiator['targets'])
                    unique_initiator_target_ids = {
                        target["node_id"] for target in initiator["targets"]
                    }
                    port_dict = {
                        "address": str(port),
                        "address_long": initiator["address_long"],
                        "connectivity": connectivity_lut[
                            len(unique_initiator_target_ids)
                        ],
                        "targets": initiator["targets"],
                        "type": initiator["type"],
                    }

            if not found_initiator:
                address_str = str(port)
                address_iter = iter(address_str)
                long_address = ":".join(
                    a + b for a, b in zip(address_iter, address_iter)
                )
                port_dict = {
                    "address": str(port),
                    "address_long": long_address,
                    "connectivity": connectivity_lut[0],
                    "targets": [],
                    "type": "FC",
                }

            field_dict["ports"].append(port_dict)

        if str(type(port)) == "<class 'infi.dtypes.iqn.IQN'>":
            found_initiator = False
            for initiator in host_iscsi_initiators:
                if initiator["address"] == str(port):
                    found_initiator = True
                    # print("initiator targets:", initiator['targets'])
                    unique_initiator_target_ids = {
                        target["node_id"] for target in initiator["targets"]
                    }
                    port_dict = {
                        "address": str(port),
                        "connectivity": connectivity_lut[
                            len(unique_initiator_target_ids)
                        ],
                        "targets": initiator["targets"],
                        "type": initiator["type"],
                    }

            if not found_initiator:
                port_dict = {
                    "address": str(port),
                    "connectivity": connectivity_lut[0],
                    "targets": [],
                    "type": "ISCSI",
                }

            field_dict["ports"].append(port_dict)

    return field_dict


def handle_stat(module):
    """
    Handle stat state. Fail if host is None.
    Return json with status.
    """
    system, host = get_sys_host(module)
    host_name = module.params["host"]
    if not host:
        module.fail_json(msg=f"Host {host_name} not found")

    field_dict = get_port_fields(module, system, host)
    result = dict(changed=False, msg=f"Host {host_name} ports found")
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """
    Handle present state. Fail if host is None.
    """
    system, host = get_sys_host(module)
    host_name = module.params["host"]
    if not host:
        module.fail_json(msg=f"Host {host_name} not found")

    changed = update_ports(module, system)
    if changed:
        msg = f"Mapping created for host {host_name}"
    else:
        msg = f"No mapping changes were required for host {host_name}"

    result = dict(changed=changed, msg=msg,)
    module.exit_json(**result)


def handle_absent(module):
    """
    Handle absent state. Fail if host is None.
    """
    system, host = get_sys_host(module)
    host_name = module.params["host"]
    if not host:
        module.exit_json(
            changed=False, msg=f"Host {host_name} not found"
        )

    changed = delete_ports(module, system)
    if changed:
        msg = f"Mapping removed from host {host_name}"
    else:
        msg = f"No mapping changes were required. Mapping already removed from host {host_name}"

    result = dict(changed=changed, msg=msg,)
    module.exit_json(**result)


def execute_state(module):
    """
    Handle states. Always logout.
    """
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        elif state == "absent":
            handle_absent(module)
        else:
            module.fail_json(
                msg=f"Internal handler error. Invalid state: {state}"
            )
    finally:
        system = get_system(module)
        system.logout()


def main():
    """
    Gather auguments and manage mapping of vols to hosts.
    """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            host=dict(required=True, type="str"),
            state=dict(default="present", choices=["stat", "present", "absent"]),
            wwns=dict(type="list", elements="str", default=list()),
            iqns=dict(type="list", elements="str", default=list()),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    execute_state(module)


if __name__ == "__main__":
    main()
