#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: network_info

short_description: Gather info about your Hetzner Cloud networks.


description:
    - Gather info about your Hetzner Cloud networks.

author:
    - Christopher Schmitt (@cschmitt-hcloud)

options:
    id:
        description:
            - The ID of the network you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the network you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the network you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud network info
  local_action:
    module: hcloud_network_info

- name: Print the gathered info
  debug:
    var: hcloud_network_info
"""

RETURN = """
hcloud_network_info:
    description: The network info as list
    returned: always
    type: complex
    contains:
        id:
            description: Numeric identifier of the network
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the network
            returned: always
            type: str
            sample: awesome-network
        ip_range:
            description: IP range of the network
            returned: always
            type: str
            sample: 10.0.0.0/16
        subnetworks:
            description: Subnetworks belonging to the network
            returned: always
            type: complex
            contains:
                type:
                    description: Type of the subnetwork.
                    returned: always
                    type: str
                    sample: cloud
                network_zone:
                    description: Network of the subnetwork.
                    returned: always
                    type: str
                    sample: eu-central
                ip_range:
                    description: IP range of the subnetwork
                    returned: always
                    type: str
                    sample: 10.0.0.0/24
                gateway:
                    description: Gateway of this subnetwork
                    returned: always
                    type: str
                    sample: 10.0.0.1
        routes:
            description: Routes belonging to the network
            returned: always
            type: complex
            contains:
                ip_range:
                    description: Destination network or host of this route.
                    returned: always
                    type: str
                    sample: 10.0.0.0/16
                gateway:
                    description: Gateway of this route
                    returned: always
                    type: str
                    sample: 10.0.0.1
        expose_routes_to_vswitch:
            description: Indicates if the routes from this network should be exposed to the vSwitch connection.
            returned: always
            type: bool
            sample: false
        servers:
            description: Servers attached to the network
            returned: always
            type: complex
            contains:
                id:
                    description: Numeric identifier of the server
                    returned: always
                    type: int
                    sample: 1937415
                name:
                    description: Name of the server
                    returned: always
                    type: str
                    sample: my-server
                status:
                    description: Status of the server
                    returned: always
                    type: str
                    sample: running
                server_type:
                    description: Name of the server type of the server
                    returned: always
                    type: str
                    sample: cx22
                ipv4_address:
                    description: Public IPv4 address of the server, None if not existing
                    returned: always
                    type: str
                    sample: 116.203.104.109
                ipv6:
                    description: IPv6 network of the server, None if not existing
                    returned: always
                    type: str
                    sample: 2a01:4f8:1c1c:c140::/64
                location:
                    description: Name of the location of the server
                    returned: always
                    type: str
                    sample: fsn1
                datacenter:
                    description: Name of the datacenter of the server
                    returned: always
                    type: str
                    sample: fsn1-dc14
                rescue_enabled:
                    description: True if rescue mode is enabled, Server will then boot into rescue system on next reboot
                    returned: always
                    type: bool
                    sample: false
                backup_window:
                    description: Time window (UTC) in which the backup will run, or null if the backups are not enabled
                    returned: always
                    type: bool
                    sample: 22-02
                labels:
                    description: User-defined labels (key-value pairs)
                    returned: always
                    type: dict
        delete_protection:
            description: True if the network is protected for deletion
            returned: always
            type: bool
            version_added: "0.1.0"
        labels:
            description: Labels of the network
            returned: always
            type: dict
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.networks import BoundNetwork


class AnsibleHCloudNetworkInfo(AnsibleHCloud):
    represent = "hcloud_network_info"

    hcloud_network_info: list[BoundNetwork] | None = None

    def _prepare_result(self):
        tmp = []

        for network in self.hcloud_network_info:
            if network is None:
                continue

            subnets = []
            for subnet in network.subnets:
                prepared_subnet = {
                    "type": subnet.type,
                    "ip_range": subnet.ip_range,
                    "network_zone": subnet.network_zone,
                    "gateway": subnet.gateway,
                }
                subnets.append(prepared_subnet)

            routes = []
            for route in network.routes:
                prepared_route = {"destination": route.destination, "gateway": route.gateway}
                routes.append(prepared_route)

            servers = []
            for server in network.servers:
                prepared_server = {
                    "id": server.id,
                    "name": server.name,
                    "ipv4_address": server.public_net.ipv4.ip if server.public_net.ipv4 is not None else None,
                    "ipv6": server.public_net.ipv6.ip if server.public_net.ipv6 is not None else None,
                    "image": server.image.name if server.image is not None else None,
                    "server_type": server.server_type.name,
                    "datacenter": server.datacenter.name,
                    "location": server.datacenter.location.name,
                    "rescue_enabled": server.rescue_enabled,
                    "backup_window": server.backup_window,
                    "labels": server.labels,
                    "status": server.status,
                }
                servers.append(prepared_server)

            tmp.append(
                {
                    "id": network.id,
                    "name": network.name,
                    "ip_range": network.ip_range,
                    "subnetworks": subnets,
                    "routes": routes,
                    "expose_routes_to_vswitch": network.expose_routes_to_vswitch,
                    "servers": servers,
                    "labels": network.labels,
                    "delete_protection": network.protection["delete"],
                }
            )
        return tmp

    def get_networks(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_network_info = [self.client.networks.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_network_info = [self.client.networks.get_by_name(self.module.params.get("name"))]
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_network_info = self.client.networks.get_all(
                    label_selector=self.module.params.get("label_selector")
                )
            else:
                self.hcloud_network_info = self.client.networks.get_all()

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                label_selector={"type": "str"},
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudNetworkInfo.define_module()
    hcloud = AnsibleHCloudNetworkInfo(module)

    hcloud.get_networks()
    result = hcloud.get_result()

    info = {"hcloud_network_info": result["hcloud_network_info"]}
    module.exit_json(**info)


if __name__ == "__main__":
    main()
