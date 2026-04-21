# Copyright (c) 2019 Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = """
name: hcloud
short_description: Ansible dynamic inventory plugin for the Hetzner Cloud.

description:
  - Reads inventories from the Hetzner Cloud API.
  - Uses a YAML configuration file that ends with C(hcloud.yml) or C(hcloud.yaml).

author:
  - Lukas Kaemmerling (@lkaemmerling)

requirements:
  - python-dateutil >= 2.7.5
  - requests >=2.20

extends_documentation_fragment:
  - constructed
  - inventory_cache

options:
  plugin:
    description: Mark this as an P(hetzner.hcloud.hcloud#inventory) inventory instance.
    required: true
    choices: [hcloud, hetzner.hcloud.hcloud]

  api_token:
    description:
      - The API Token for the Hetzner Cloud.
    type: str
    required: true
    aliases: [token]
    env:
      - name: HCLOUD_TOKEN
  api_endpoint:
    description:
      - The API Endpoint for the Hetzner Cloud.
    type: str
    default: https://api.hetzner.cloud/v1
    env:
      - name: HCLOUD_ENDPOINT

  group:
    description: The group all servers are automatically added to.
    default: hcloud
    type: str
    required: false
  connect_with:
    description: |
      Connect to the server using the value from this field. This sets the C(ansible_host)
      variable to the value indicated, if that value is available. If you need further
      customization, like falling back to private ipv4 if the server has no public ipv4,
      you can use O(compose) top-level key.
    default: public_ipv4
    type: str
    choices:
      - public_ipv4
      - public_ipv6
      - hostname
      - ipv4_dns_ptr
      - private_ipv4

  locations:
    description: Populate inventory with instances in this location.
    default: []
    type: list
    elements: str
    required: false
  types:
    description: Populate inventory with instances with this type.
    default: []
    type: list
    elements: str
    required: false
  images:
    description: Populate inventory with instances with this image name, only available for system images.
    default: []
    type: list
    elements: str
    required: false
  label_selector:
    description: Populate inventory with instances with this label.
    default: ""
    type: str
    required: false
  network:
    description: Populate inventory with instances which are attached to this network name or ID.
    default: ""
    type: str
    required: false
  status:
    description: Populate inventory with instances with this status.
    default: []
    type: list
    elements: str
    required: false

  hostvars_prefix:
    description:
      - The prefix for host variables names coming from Hetzner Cloud.
    default: hcloud_
    type: str
    version_added: 2.5.0
  hostvars_suffix:
    description:
      - The suffix for host variables names coming from Hetzner Cloud.
    type: str
    version_added: 2.5.0

  hostname:
    description:
      - A template for the instances hostname, if not provided the Hetzner Cloud server name will be used.
      - Available variables are the Hetzner Cloud host variables.
      - The available variables names are provide with the O(hostvars_prefix) or O(hostvars_suffix) modifications.
    type: str
    version_added: 3.0.0
"""

EXAMPLES = """
# Minimal example. 'HCLOUD_TOKEN' is exposed in environment.
plugin: hetzner.hcloud.hcloud

---
# Example with templated token, e.g. provided through extra vars.
plugin: hetzner.hcloud.hcloud
api_token: "{{ _vault_hetzner_cloud_token }}"

---
# Example with locations, types, status
plugin: hetzner.hcloud.hcloud
locations:
  - nbg1
types:
  - cx22
status:
  - running

---
# Group by a location with prefix e.g. "hcloud_location_nbg1"
# and image_os_flavor without prefix and separator e.g. "ubuntu"
# and status with prefix e.g. "server_status_running"
plugin: hetzner.hcloud.hcloud
keyed_groups:
  - key: hcloud_location
    prefix: hcloud_location
  - key: image_os_flavor
    separator: ""
  - key: hcloud_status
    prefix: server_status

---
# Use a custom hostname template.
plugin: hetzner.hcloud.hcloud

# Available variables are for example:
## Server
#   hcloud_id: 42984895
#   hcloud_name: "my-server"
#   hcloud_labels:
#     foo: "bar"
#   hcloud_status: "running"
## Server Type
#   hcloud_type: "cx22"
#   hcloud_server_type: "cx22"
#   hcloud_architecture: "x86"
## Image
#   hcloud_image_id: 114690387
#   hcloud_image_name: "debian-12"
#   hcloud_image_os_flavor: "debian"
## Datacenter
#   hcloud_datacenter: "hel1-dc2"
#   hcloud_location: "hel1"
## Network
#   hcloud_ipv4: "65.109.140.95" # Value is optional!
#   hcloud_ipv6: "2a01:4f9:c011:b83f::1" # Value is optional!
#   hcloud_ipv6_network: 2a01:4f9:c011:b83f::" # Value is optional!
#   hcloud_ipv6_network_mask: "64" # Value is optional!
#   hcloud_private_ipv4: "10.0.0.3" # Value is optional!
#   hcloud_private_networks:
#     - id: 114690387
#       name: "my-private-network"
#       ip: "10.0.0.3"
#
hostname: "my-prefix-{{ hcloud_datacenter }}-{{ hcloud_name }}-{{ hcloud_server_type }}"
"""

import sys
from ipaddress import IPv6Network

from ansible.errors import AnsibleError
from ansible.inventory.manager import InventoryData
from ansible.module_utils.common.text.converters import to_native
from ansible.plugins.inventory import BaseInventoryPlugin, Cacheable, Constructable
from ansible.utils.display import Display
from ansible.utils.vars import combine_vars

from ..module_utils.client import (
    Client,
    ClientException,
    client_check_required_lib,
    client_get_by_name_or_id,
)
from ..module_utils.vendor.hcloud import APIException
from ..module_utils.vendor.hcloud.networks import Network
from ..module_utils.vendor.hcloud.servers import Server
from ..module_utils.version import version

if sys.version_info >= (3, 11):
    # The typed dicts are only used to help development and we prefer not requiring
    # the additional typing-extensions dependency
    from typing import NotRequired, TypedDict

    class InventoryPrivateNetwork(TypedDict):
        id: int
        name: str
        ip: str

    class InventoryServer(TypedDict):
        id: int
        name: str
        status: str

        # Server Type
        type: str
        server_type: str
        architecture: str

        # Datacenter
        datacenter: str
        location: str

        # Labels
        labels: dict[str, str]

        # Network
        ipv4: NotRequired[str]
        ipv6: NotRequired[str]
        ipv6_network: NotRequired[str]
        ipv6_network_mask: NotRequired[str]
        private_ipv4: NotRequired[str]
        private_networks: list[InventoryPrivateNetwork]

        # Image
        image_id: int
        image_name: str
        image_os_flavor: str

        # Ansible
        ansible_host: str

else:
    InventoryServer = dict


def first_ipv6_address(network: str) -> str:
    """
    Return the first address for a ipv6 network.

    :param network: IPv6 Network.
    """
    return str(next(IPv6Network(network).hosts()))


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    NAME = "hetzner.hcloud.hcloud"

    inventory: InventoryData
    display: Display

    client: Client

    network: Network | None

    def _configure_hcloud_client(self):
        api_token = self.get_option("api_token")
        api_endpoint = self.get_option("api_endpoint")

        # Resolve template string
        api_token = self.templar.template(api_token)

        self.client = Client(
            token=api_token,
            api_endpoint=api_endpoint,
            application_name="ansible-inventory",
            application_version=version,
        )

        try:
            # Ensure the api token is valid
            self.client.locations.get_list()
        except APIException as exception:
            raise AnsibleError("Invalid Hetzner Cloud API Token.") from exception

    def _validate_options(self) -> None:
        if self.get_option("network"):
            network_param: str = self.get_option("network")
            network_param = self.templar.template(network_param)

            try:
                self.network = client_get_by_name_or_id(self.client, "networks", network_param)
            except (ClientException, APIException) as exception:
                raise AnsibleError(to_native(exception)) from exception

    def _fetch_servers(self) -> list[Server]:
        self._validate_options()

        get_servers_params = {}
        if self.get_option("label_selector"):
            get_servers_params["label_selector"] = self.get_option("label_selector")

        if self.get_option("status"):
            get_servers_params["status"] = self.get_option("status")

        servers = self.client.servers.get_all(**get_servers_params)

        if self.get_option("network"):
            servers = [s for s in servers if self.network.id in [p.network.id for p in s.private_net]]

        if self.get_option("locations"):
            locations: list[str] = self.get_option("locations")
            servers = [s for s in servers if s.datacenter.location.name in locations]

        if self.get_option("types"):
            server_types: list[str] = self.get_option("types")
            servers = [s for s in servers if s.server_type.name in server_types]

        if self.get_option("images"):
            images: list[str] = self.get_option("images")
            servers = [s for s in servers if s.image is not None and s.image.os_flavor in images]

        return servers

    def _build_inventory_server(self, server: Server) -> InventoryServer:
        server_dict: InventoryServer = {}
        server_dict["id"] = server.id
        server_dict["name"] = server.name
        server_dict["status"] = server.status

        # Server Type
        server_dict["type"] = server.server_type.name
        server_dict["server_type"] = server.server_type.name
        server_dict["architecture"] = server.server_type.architecture

        # Network
        if server.public_net.ipv4:
            server_dict["ipv4"] = server.public_net.ipv4.ip

        if server.public_net.ipv6:
            server_dict["ipv6"] = first_ipv6_address(server.public_net.ipv6.ip)
            server_dict["ipv6_network"] = server.public_net.ipv6.network
            server_dict["ipv6_network_mask"] = server.public_net.ipv6.network_mask

        server_dict["private_networks"] = [
            {"id": v.network.id, "name": v.network.name, "ip": v.ip} for v in server.private_net
        ]

        if self.get_option("network"):
            for private_net in server.private_net:
                # Set private_ipv4 if user filtered for one network
                if private_net.network.id == self.network.id:
                    server_dict["private_ipv4"] = private_net.ip
                    break

        # Datacenter
        server_dict["datacenter"] = server.datacenter.name
        server_dict["location"] = server.datacenter.location.name

        # Image
        if server.image is not None:
            server_dict["image_id"] = server.image.id
            server_dict["image_os_flavor"] = server.image.os_flavor
            server_dict["image_name"] = server.image.name or server.image.description

        # Labels
        server_dict["labels"] = dict(server.labels)

        try:
            server_dict["ansible_host"] = self._get_server_ansible_host(server)
        except AnsibleError as exception:
            # Log warning that for this host can not be connected to, using the
            # method specified in 'connect_with'. Users might use 'compose' to
            # override the connection method, or implement custom logic, so we
            # do not need to abort if nothing matched.
            self.display.v(f"[hcloud] {exception}", server.name)

        return server_dict

    def _get_server_ansible_host(self, server: Server):
        if self.get_option("connect_with") == "public_ipv4":
            if server.public_net.ipv4:
                return server.public_net.ipv4.ip
            raise AnsibleError("Server has no public ipv4, but connect_with=public_ipv4 was specified")

        if self.get_option("connect_with") == "public_ipv6":
            if server.public_net.ipv6:
                return first_ipv6_address(server.public_net.ipv6.ip)
            raise AnsibleError("Server has no public ipv6, but connect_with=public_ipv6 was specified")

        if self.get_option("connect_with") == "hostname":
            # every server has a name, no need to guard this
            return server.name

        if self.get_option("connect_with") == "ipv4_dns_ptr":
            if server.public_net.ipv4:
                return server.public_net.ipv4.dns_ptr
            raise AnsibleError("Server has no public ipv4, but connect_with=ipv4_dns_ptr was specified")

        if self.get_option("connect_with") == "private_ipv4":
            if self.get_option("network"):
                for private_net in server.private_net:
                    if private_net.network.id == self.network.id:
                        return private_net.ip

            else:
                raise AnsibleError("You can only connect via private IPv4 if you specify a network")

    def verify_file(self, path):
        """Return the possibly of a file being consumable by this plugin."""
        return super().verify_file(path) and path.endswith(("hcloud.yaml", "hcloud.yml"))

    def _get_cached_result(self, path, cache) -> tuple[list[InventoryServer], bool]:
        # false when refresh_cache or --flush-cache is used
        if not cache:
            return [], False

        # get the user-specified directive
        if not self.get_option("cache"):
            return [], False

        cache_key = self.get_cache_key(path)
        try:
            cached_result = self._cache[cache_key]
        except KeyError:
            # if cache expires or cache file doesn"t exist
            return [], False

        return cached_result, True

    def _update_cached_result(self, path, cache, result: list[InventoryServer]):
        if not self.get_option("cache"):
            return

        cache_key = self.get_cache_key(path)
        # We weren't explicitly told to flush the cache, and there's already a cache entry,
        # this means that the result we're being passed came from the cache.  As such we don't
        # want to "update" the cache as that could reset a TTL on the cache entry.
        if cache and cache_key in self._cache:
            return

        self._cache[cache_key] = result

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)

        try:
            client_check_required_lib()
        except ClientException as exception:
            raise AnsibleError(to_native(exception)) from exception

        # Allow using extra variables arguments as template variables (e.g.
        # '--extra-vars my_var=my_value')
        self.templar.available_variables = self._vars

        self._read_config_data(path)
        self._configure_hcloud_client()

        servers, cached = self._get_cached_result(path, cache)
        if not cached:
            with self.client.cached_session():
                servers = [self._build_inventory_server(s) for s in self._fetch_servers()]

        # Add a top group
        self.inventory.add_group(group=self.get_option("group"))

        hostvars_prefix = self.get_option("hostvars_prefix")
        hostvars_suffix = self.get_option("hostvars_suffix")
        hostname_template = self.get_option("hostname")

        for server in servers:
            hostvars = {}
            for key, value in server.items():
                # Add hostvars prefix and suffix for variables coming from the Hetzner Cloud.
                if hostvars_prefix or hostvars_suffix:
                    if key not in ("ansible_host",):
                        if hostvars_prefix:
                            key = hostvars_prefix + key
                        if hostvars_suffix:
                            key = key + hostvars_suffix

                hostvars[key] = value

            if hostname_template:
                templar = self.templar
                templar.available_variables = combine_vars(hostvars, self._vars)
                hostname = templar.template(hostname_template)
            else:
                hostname = server["name"]

            self.inventory.add_host(hostname, group=self.get_option("group"))
            for key, value in hostvars.items():
                self.inventory.set_variable(hostname, key, value)

            # Use constructed if applicable
            strict = self.get_option("strict")

            # Composed variables
            self._set_composite_vars(
                self.get_option("compose"),
                self.inventory.get_host(hostname).get_vars(),
                hostname,
                strict=strict,
            )

            # Complex groups based on jinja2 conditionals, hosts that meet the conditional are added to group
            self._add_host_to_composed_groups(
                self.get_option("groups"),
                {},
                hostname,
                strict=strict,
            )

            # Create groups based on variable values and add the corresponding hosts to it
            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"),
                {},
                hostname,
                strict=strict,
            )

        self._update_cached_result(path, cache, servers)
