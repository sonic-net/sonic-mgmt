#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-list-literal,use-dict-literal,line-too-long,wrong-import-position

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""This module creates, deletes or modifies network spaces on Infinibox."""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_network_space
version_added: '2.12.0'
short_description: Create, Delete and Modify network spaces on Infinibox
description:
    - This module creates, deletes or modifies network spaces on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - Network space name
    type: str
    required: true
  state:
    description:
      - Creates/Modifies network spaces when present. Removes when absent. Shows status when stat.
    type: str
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
  interfaces:
    description:
      - A list of interface IDs for the space.
    required: false
    type: list
    elements: int
    default: []
  network_config:
    description:
      - A network description.
    type: dict
    default: {}
    required: false
  service:
    description:
      - Choose a service.
    type: str
    required: false
    default: "RMR_SERVICE"
    choices: ["RMR_SERVICE", "NAS_SERVICE", "ISCSI_SERVICE"]
  mtu:
    description:
      - Set an MTU. If not specified, defaults to 1500 bytes.
    required: false
    type: int
  network:
    description:
      - Starting IP address.
    required: false
    type: str
  netmask:
    description:
      - Network mask.
    required: false
    type: int
  default_gateway:
    description:
      - Default gateway.
    type: str
    required: false
  ips:
    description:
      - List of IPs.
    required: false
    default: []
    type: list
    elements: str
  rate_limit:
    description:
      - Specify the throughput limit per node.
      - The limit is specified in Mbps, megabits per second (not megabytes).
      - Note the limit affects NFS, iSCSI and async-replication traffic.
      - It does not affect sync-replication or active-active traffic.
    required: false
    type: int
  async_only:
    description:
      - Run asynchronously only.
    required: false
    type: bool
    default: false
extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Create new network space
  infini_network_space:
    name: iSCSI
    state: present
    interfaces:
      - 1680
      - 1679
      - 1678
    service: ISCSI_SERVICE
    netmask: 19
    network: 172.31.32.0
    default_gateway: 172.31.63.254
    ips:
      - 172.31.32.145
      - 172.31.32.146
      - 172.31.32.147
      - 172.31.32.148
      - 172.31.32.149
      - 172.31.32.150
    user: admin
    password: secret
    system: ibox001
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    merge_two_dicts,
    get_net_space,
)

try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


@api_wrapper
def create_empty_network_space(module, system):
    """ Create an empty network space """
    # Create network space
    network_space_name = module.params["name"]
    service = module.params["service"]
    rate_limit = module.params["rate_limit"]
    mtu = module.params["mtu"]
    network_config = {
        "netmask": module.params["netmask"],
        "network": module.params["network"],
        "default_gateway": module.params["default_gateway"],
    }
    interfaces = module.params["interfaces"]

    # product_id = system.api.get('system/product_id')

    net_create_url = "network/spaces"
    net_create_data = {
        "name": network_space_name,
        "service": service,
        "network_config": network_config,
        "interfaces": interfaces,
    }
    if rate_limit:
        net_create_data["rate_limit"] = rate_limit
    if mtu:
        net_create_data["mtu"] = mtu

    try:
        system.api.post(
            path=net_create_url,
            data=net_create_data
        )
    except APICommandFailed as err:
        module.fail_json(msg=f"Cannot create empty network space {network_space_name}: {err}")


@api_wrapper
def find_network_space_id(module, system):
    """
    Find the ID of this network space
    """
    network_space_name = module.params["name"]
    net_id_url = f"network/spaces?name={network_space_name}&fields=id"
    net_id = system.api.get(
        path=net_id_url
    )
    result = net_id.get_json()['result'][0]
    space_id = result['id']
    return space_id


@api_wrapper
def add_ips_to_network_space(module, system, space_id):
    """ Add IPs to space. Ignore address conflict errors. """
    network_space_name = module.params["name"]
    ips = module.params["ips"]
    for ip in ips:
        ip_url = f"network/spaces/{space_id}/ips"
        ip_data = ip
        try:
            system.api.post(path=ip_url, data=ip_data)
        except APICommandFailed as err:
            if err.error_code != "NET_SPACE_ADDRESS_CONFLICT":  # Ignore
                module.fail_json(msg=f"Cannot add IP {ip} to network space {network_space_name}: {err}")


@api_wrapper
def create_network_space(module, system):
    """ Create a network space """
    if not module.check_mode:
        # Create space
        create_empty_network_space(module, system)
        # Find space's ID
        space_id = find_network_space_id(module, system)
        # Add IPs to space
        add_ips_to_network_space(module, system, space_id)

        changed = True
    else:
        changed = False

    return changed


def update_network_space(module, system):
    """
    Update network space.
    Update fields individually. If grouped the API will generate
    a NOT_SUPPORTED_MULTIPLE_UPDATE error.
    """
    space_id = find_network_space_id(module, system)
    datas = [
        {"interfaces": module.params["interfaces"]},
        {"mtu": module.params["mtu"]},
        {"network_config":
         {
             "default_gateway": module.params["default_gateway"],
             "netmask": module.params["netmask"],
             "network": module.params["network"],
         }
         },
        {"rate_limit": module.params["rate_limit"]},
        {"properties":
         {
             "is_async_only": module.params["async_only"],
         }
         },
    ]
    for data in datas:
        try:
            system.api.put(
                path=f"network/spaces/{space_id}",
                data=data
            )
        except APICommandFailed as err:
            msg = f"Cannot update network space: {err}"
            module.fail_json(msg=msg)
    add_ips_to_network_space(module, system, space_id)
    changed = True
    return changed


def get_network_space_fields(network_space):
    """ Get the network space fields and return as a dict """
    fields = network_space.get_fields(from_cache=True, raw_value=True)

    field_dict = dict(
        name=fields["name"],
        network_space_id=fields["id"],
        netmask=fields["network_config"]["netmask"],
        network=fields["network_config"]["network"],
        default_gateway=fields["network_config"]["default_gateway"],
        interface_ids=fields["interfaces"],
        service=fields["service"],
        ips=fields["ips"],
        properties=fields["properties"],
        automatic_ip_failback=fields["automatic_ip_failback"],
        mtu=fields["mtu"],
        rate_limit=fields["rate_limit"],
    )
    return field_dict


def handle_stat(module):
    """ Return details about the space """
    network_space_name = module.params["name"]
    system = get_system(module)
    net_space = get_net_space(module, system)

    if not net_space:
        module.fail_json(msg=f"Network space {network_space_name} not found")

    field_dict = get_network_space_fields(net_space)
    result = dict(
        changed=False,
        msg=f"Network space {network_space_name} stat found"
    )
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """
    If it does not already exist, create namespace. Otherwise, update namespace.
    """
    network_space_name = module.params["name"]
    system = get_system(module)
    net_space = get_net_space(module, system)
    if net_space:
        changed = update_network_space(module, system)
        msg = f"Network space named {network_space_name} updated"
    else:
        changed = create_network_space(module, system)
        msg = f"Network space named {network_space_name} created"
    module.exit_json(changed=changed, msg=msg)


def disable_and_delete_ip(module, network_space, ip):
    """
    Disable and delete a network space IP
    """
    if not ip:
        return  # Nothing to do
    addr = ip['ip_address']
    network_space_name = module.params["name"]
    ip_type = ip['type']
    mgmt = ""
    if ip_type == "MANAGEMENT":
        mgmt = "management "  # Trailing space by design

    try:
        try:
            network_space.disable_ip_address(addr)
        except APICommandFailed as err:
            if err.error_code == "IP_ADDRESS_ALREADY_DISABLED":
                pass
            else:
                module.fail_json(msg=f"Disabling of network space {network_space_name} IP {mgmt}{addr} API command failed")

        network_space.remove_ip_address(addr)
    except Exception as err:  # pylint: disable=broad-exception-caught
        module.fail_json(msg=f"Disabling or removal of network space {network_space_name} IP {mgmt}{addr} failed: {err}")


def handle_absent(module):
    """
    Remove a namespace. First, may disable and remove the namespace's IPs.
    """
    network_space_name = module.params["name"]
    system = get_system(module)
    network_space = get_net_space(module, system)
    if not network_space:
        changed = False
        msg = f"Network space {network_space_name} already absent"
    else:
        # Find IPs from space
        ips = list(network_space.get_ips())

        # Disable and delete IPs from space
        if not module.check_mode:
            management_ip = None  # Must be disabled and deleted last
            for ip in ips:
                if ip['type'] == 'MANAGEMENT':
                    management_ip = ip
                    continue
                disable_and_delete_ip(module, network_space, ip)
            disable_and_delete_ip(module, network_space, management_ip)

            # Delete space
            network_space.delete()
            changed = True
            msg = f"Network space {network_space_name} removed"
        else:
            changed = False
            msg = f"Network space {network_space_name} not altered due to checkmode"

    module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    """ Execute a state """
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
    """ Main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(
                default="present", required=False, choices=["stat", "present", "absent"]
            ),
            service=dict(
                default="RMR_SERVICE",
                required=False,
                choices=["RMR_SERVICE", "NAS_SERVICE", "ISCSI_SERVICE"],
            ),
            mtu=dict(default=None, required=False, type="int"),
            network=dict(default=None, required=False),
            netmask=dict(default=None, required=False, type="int"),
            default_gateway=dict(default=None, required=False),
            interfaces=dict(default=list(), required=False, type="list", elements="int"),
            network_config=dict(default=dict(), required=False, type="dict"),
            ips=dict(default=list(), required=False, type="list", elements="str"),
            rate_limit=dict(default=None, required=False, type="int"),
            async_only=dict(default=False, required=False, type="bool"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    execute_state(module)


if __name__ == "__main__":
    main()
