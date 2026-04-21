#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: server

short_description: Create and manage cloud servers on the Hetzner Cloud.


description:
    - Create, update and manage cloud servers on the Hetzner Cloud.
    - To manage the DNS pointer of a Server, use the M(hetzner.hcloud.rdns) module.

author:
    - Lukas Kaemmerling (@LKaemmerling)

options:
    id:
        description:
            - ID of the Hetzner Cloud Server to manage.
            - Only required if no server O(name) is given
        type: int
    name:
        description:
            - Name of the Hetzner Cloud Server to manage.
            - Only required if no server O(id) is given or a server does not exist.
        type: str
    server_type:
        description:
            - Hetzner Cloud Server Type (name or ID) of the server.
            - Required if server does not exist.
        type: str
    ssh_keys:
        description:
            - List of Hetzner Cloud SSH Keys (name or ID) to create the server with.
            - Only used during the server creation.
        type: list
        elements: str
    volumes:
        description:
            - List of Hetzner Cloud Volumes (name or ID) that should be attached to the server.
            - Only used during the server creation.
        type: list
        elements: str
    firewalls:
        description:
            - List of Hetzner Cloud Firewalls (name or ID) that should be attached to the server.
        type: list
        elements: str
    image:
        description:
            - Hetzner Cloud Image (name or ID) to create the server from.
            - Required if server does not exist or when O(state=rebuild).
        type: str
    image_allow_deprecated:
        description:
            - Allows the creation of servers with deprecated images.
        type: bool
        default: false
        aliases: [allow_deprecated_image]
    location:
        description:
            - Hetzner Cloud Location (name or ID) to create the server in.
            - Required if no O(datacenter) is given and server does not exist.
            - Only used during the server creation.
        type: str
    datacenter:
        description:
            - Hetzner Cloud Datacenter (name or ID) to create the server in.
            - Required if no O(location) is given and server does not exist.
            - Only used during the server creation.
        type: str
    backups:
        description:
            - Enable or disable Backups for the given Server.
        type: bool
    upgrade_disk:
        description:
            - Resize the disk size, when resizing a server.
            - If you want to downgrade the server later, this value should be False.
        type: bool
        default: false
    enable_ipv4:
        description:
            - Enables the public ipv4 address.
        type: bool
        default: true
    enable_ipv6:
        description:
            - Enables the public ipv6 address.
        type: bool
        default: true
    ipv4:
        description:
            - Hetzner Cloud Primary IPv4 (name or ID) to use.
            - If omitted and O(enable_ipv4=true), a new ipv4 Primary IP will automatically be created.
        type: str
    ipv6:
        description:
            - Hetzner Cloud Primary IPv6 (name or ID) to use.
            - If omitted and O(enable_ipv6=true), a new ipv6 Primary IP will automatically be created.
        type: str
    private_networks:
        description:
            - List of Hetzner Cloud Networks (name or ID) the server should be attached to.
            - If None, private networks are left as they are (e.g. if previously added by hcloud_server_network),
              if it has any other value (including []), only those networks are attached to the server.
        type: list
        elements: str
    force:
        description:
            - Force the update of the server.
            - May power off the server if update is applied.
        type: bool
        default: false
    user_data:
        description:
            - User Data to be passed to the server on creation.
            - Only used during the server creation.
        type: str
    rescue_mode:
        description:
            - Add the Hetzner rescue system type you want the server to be booted into.
        type: str
    labels:
        description:
            - User-defined labels (key-value pairs).
        type: dict
    delete_protection:
        description:
            - Protect the Server for deletion.
            - Needs to be the same as O(rebuild_protection).
        type: bool
    rebuild_protection:
        description:
            - Protect the Server for rebuild.
            - Needs to be the same as O(delete_protection).
        type: bool
    placement_group:
        description:
            - Hetzner Cloud Placement Group (name or ID) to create the server in.
        type: str
    state:
        description:
            - State of the server.
        default: present
        choices: [ absent, present, created, restarted, started, stopped, rebuild ]
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Create a basic server
  hetzner.hcloud.server:
    name: my-server
    server_type: cx22
    image: ubuntu-22.04
    state: present

- name: Create a basic server with ssh key
  hetzner.hcloud.server:
    name: my-server
    server_type: cx22
    image: ubuntu-22.04
    location: fsn1
    ssh_keys:
      - me@myorganisation
    state: present

- name: Resize an existing server
  hetzner.hcloud.server:
    name: my-server
    server_type: cx32
    upgrade_disk: true
    state: present

- name: Ensure the server is absent (remove if needed)
  hetzner.hcloud.server:
    name: my-server
    state: absent

- name: Ensure the server is started
  hetzner.hcloud.server:
    name: my-server
    state: started

- name: Ensure the server is stopped
  hetzner.hcloud.server:
    name: my-server
    state: stopped

- name: Ensure the server is restarted
  hetzner.hcloud.server:
    name: my-server
    state: restarted

- name: Ensure the server is will be booted in rescue mode and therefore restarted
  hetzner.hcloud.server:
    name: my-server
    rescue_mode: linux64
    state: restarted

- name: Ensure the server is rebuild
  hetzner.hcloud.server:
    name: my-server
    image: ubuntu-22.04
    state: rebuild

- name: Add server to placement group
  hetzner.hcloud.server:
    name: my-server
    placement_group: my-placement-group
    force: true
    state: present

- name: Remove server from placement group
  hetzner.hcloud.server:
    name: my-server
    placement_group:
    state: present

- name: Add server with private network only
  hetzner.hcloud.server:
    name: my-server
    enable_ipv4: false
    enable_ipv6: false
    private_networks:
      - my-network
      - 4711
    state: present
"""

RETURN = """
hcloud_server:
    description: The server instance
    returned: Always
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
        created:
            description: Point in time when the Server was created (in ISO-8601 format)
            returned: always
            type: str
            sample: "2023-11-06T13:36:56+00:00"
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
            description: Public IPv4 address of the server
            returned: always
            type: str
            sample: 116.203.104.109
        ipv6:
            description: IPv6 network of the server
            returned: always
            type: str
            sample: 2a01:4f8:1c1c:c140::/64
        private_networks:
            description: List of private networks the server is attached to (name or ID)
            returned: always
            type: list
            elements: str
            sample: ['my-network', 'another-network', '4711']
        private_networks_info:
            description: List of private networks the server is attached to (dict with name and ip)
            returned: always
            type: list
            elements: dict
            sample: [{'name': 'my-network', 'ip': '192.168.1.1'}, {'name': 'another-network', 'ip': '10.185.50.40'}]
        location:
            description: Name of the location of the server
            returned: always
            type: str
            sample: fsn1
        placement_group:
            description: Placement Group of the server
            type: str
            returned: always
            sample: 4711
            version_added: "1.5.0"
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
            description: True if server is protected for deletion
            type: bool
            returned: always
            sample: false
            version_added: "0.1.0"
        rebuild_protection:
            description: True if server is protected for rebuild
            type: bool
            returned: always
            sample: false
            version_added: "0.1.0"
root_password:
    description: Root password for the server
    returned: when created without ssh_keys
    type: str
    sample: YItygq1v3GYjjMomLaKc
"""

from datetime import timedelta
from typing import TYPE_CHECKING, Literal

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.deprecation import deprecated_server_type_warning
from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.firewalls import FirewallResource
from ..module_utils.vendor.hcloud.servers import (
    BoundServer,
    Server,
    ServerCreatePublicNetwork,
)

if TYPE_CHECKING:
    from ..module_utils.vendor.hcloud.actions import BoundAction
    from ..module_utils.vendor.hcloud.firewalls import BoundFirewall
    from ..module_utils.vendor.hcloud.networks import BoundNetwork
    from ..module_utils.vendor.hcloud.placement_groups import BoundPlacementGroup
    from ..module_utils.vendor.hcloud.primary_ips import PrimaryIP
    from ..module_utils.vendor.hcloud.server_types import ServerType


class AnsibleHCloudServer(AnsibleHCloud):
    represent = "hcloud_server"

    hcloud_server: BoundServer | None = None

    def _prepare_result(self):
        return {
            "id": self.hcloud_server.id,
            "name": self.hcloud_server.name,
            "created": self.hcloud_server.created.isoformat(),
            "ipv4_address": (
                self.hcloud_server.public_net.ipv4.ip if self.hcloud_server.public_net.ipv4 is not None else None
            ),
            "ipv6": self.hcloud_server.public_net.ipv6.ip if self.hcloud_server.public_net.ipv6 is not None else None,
            "private_networks": [net.network.name for net in self.hcloud_server.private_net],
            "private_networks_info": [
                {"name": net.network.name, "ip": net.ip} for net in self.hcloud_server.private_net
            ],
            "image": self.hcloud_server.image.name if self.hcloud_server.image is not None else None,
            "server_type": self.hcloud_server.server_type.name,
            "datacenter": self.hcloud_server.datacenter.name,
            "location": self.hcloud_server.datacenter.location.name,
            "placement_group": (
                self.hcloud_server.placement_group.name if self.hcloud_server.placement_group is not None else None
            ),
            "rescue_enabled": self.hcloud_server.rescue_enabled,
            "backup_window": self.hcloud_server.backup_window,
            "labels": self.hcloud_server.labels,
            "delete_protection": self.hcloud_server.protection["delete"],
            "rebuild_protection": self.hcloud_server.protection["rebuild"],
            "status": self.hcloud_server.status,
        }

    def _get_server(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_server = self.client.servers.get_by_id(self.module.params.get("id"))
            else:
                self.hcloud_server = self.client.servers.get_by_name(self.module.params.get("name"))
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create_server(self):
        self.module.fail_on_missing_params(required_params=["name", "server_type", "image"])

        server_type = self._client_get_by_name_or_id("server_types", self.module.params.get("server_type"))
        image = self._get_image(server_type)

        params = {
            "name": self.module.params.get("name"),
            "labels": self.module.params.get("labels"),
            "server_type": server_type,
            "image": image,
            "user_data": self.module.params.get("user_data"),
            "public_net": ServerCreatePublicNetwork(
                enable_ipv4=self.module.params.get("enable_ipv4"),
                enable_ipv6=self.module.params.get("enable_ipv6"),
            ),
        }

        if self.module.params.get("placement_group") is not None:
            params["placement_group"] = self._client_get_by_name_or_id(
                "placement_groups", self.module.params.get("placement_group")
            )

        if self.module.params.get("ipv4") is not None:
            params["public_net"].ipv4 = self._client_get_by_name_or_id("primary_ips", self.module.params.get("ipv4"))

        if self.module.params.get("ipv6") is not None:
            params["public_net"].ipv6 = self._client_get_by_name_or_id("primary_ips", self.module.params.get("ipv6"))

        if self.module.params.get("private_networks") is not None:
            params["networks"] = [
                self._client_get_by_name_or_id("networks", name_or_id)
                for name_or_id in self.module.params.get("private_networks")
            ]

        if self.module.params.get("ssh_keys") is not None:
            params["ssh_keys"] = [
                self._client_get_by_name_or_id("ssh_keys", name_or_id)
                for name_or_id in self.module.params.get("ssh_keys")
            ]

        if self.module.params.get("volumes") is not None:
            params["volumes"] = [
                self._client_get_by_name_or_id("volumes", name_or_id)
                for name_or_id in self.module.params.get("volumes")
            ]

        if self.module.params.get("firewalls") is not None:
            params["firewalls"] = [
                self._client_get_by_name_or_id("firewalls", name_or_id)
                for name_or_id in self.module.params.get("firewalls")
            ]

        server_type_location = None

        if self.module.params.get("location") is None and self.module.params.get("datacenter") is None:
            # When not given, the API will choose the location.
            params["location"] = None
            params["datacenter"] = None
        elif self.module.params.get("location") is not None and self.module.params.get("datacenter") is None:
            params["location"] = self._client_get_by_name_or_id("locations", self.module.params.get("location"))
            server_type_location = params["location"]
        elif self.module.params.get("location") is None and self.module.params.get("datacenter") is not None:
            params["datacenter"] = self._client_get_by_name_or_id("datacenters", self.module.params.get("datacenter"))
            server_type_location = params["datacenter"].location

        if self.module.params.get("state") == "stopped" or self.module.params.get("state") == "created":
            params["start_after_create"] = False

        server_type_deprecation_printed = deprecated_server_type_warning(
            self.module,
            server_type,
            server_type_location,
        )

        if not self.module.check_mode:
            try:
                resp = self.client.servers.create(**params)

                if not server_type_deprecation_printed:
                    deprecated_server_type_warning(
                        self.module,
                        resp.server.server_type,
                        resp.server.datacenter.location,
                    )

                self.result["root_password"] = resp.root_password
                # Action should take 60 to 90 seconds on average, but can be >10m when creating a
                # server from a custom images
                resp.action.wait_until_finished(max_retries=362)  # 362 retries >= 1802 seconds
                for action in resp.next_actions:
                    # Starting the server or attaching to the network might take a few minutes,
                    # depending on the current activity in the project.
                    # This waits up to 30minutes for each action in series, but in the background
                    # the actions are mostly running in parallel, so after the first one the other
                    # actions are usually completed already.
                    action.wait_until_finished(max_retries=362)  # 362 retries >= 1802 seconds

                rescue_mode = self.module.params.get("rescue_mode")
                if rescue_mode:
                    self._get_server()
                    self._set_rescue_mode(rescue_mode)

                backups = self.module.params.get("backups")
                if backups:
                    self._get_server()
                    action = self.hcloud_server.enable_backup()
                    action.wait_until_finished()

                delete_protection = self.module.params.get("delete_protection")
                rebuild_protection = self.module.params.get("rebuild_protection")
                if delete_protection is not None and rebuild_protection is not None:
                    self._get_server()
                    action = self.hcloud_server.change_protection(
                        delete=delete_protection,
                        rebuild=rebuild_protection,
                    )
                    action.wait_until_finished()
            except HCloudException as exception:
                self.fail_json_hcloud(exception)
        self._mark_as_changed()
        self._get_server()

    def _get_image(self, server_type: ServerType):
        image = self.client.images.get_by_name_and_architecture(
            name=self.module.params.get("image"),
            architecture=server_type.architecture,
            include_deprecated=True,
        )
        if image is None:
            image = self.client.images.get_by_id(self.module.params.get("image"))

        if image.deprecated is not None:
            available_until = image.deprecated + timedelta(days=90)
            if self.module.params.get("image_allow_deprecated"):
                self.module.warn(
                    f"You try to use a deprecated image. The image {image.name} will "
                    f"continue to be available until {available_until.strftime('%Y-%m-%d')}."
                )
            else:
                self.module.fail_json(
                    msg=(
                        f"You try to use a deprecated image. The image {image.name} will "
                        f"continue to be available until {available_until.strftime('%Y-%m-%d')}. "
                        "If you want to use this image use image_allow_deprecated=true."
                    )
                )
        return image

    def _update_server(self) -> None:
        try:
            previous_server_status = self.hcloud_server.status

            update_params = {}

            name = self.module.params.get("name")
            if name is not None and self.hcloud_server.name != name:
                self.module.fail_on_missing_params(required_params=["id"])
                update_params["name"] = name

            labels = self.module.params.get("labels")
            if labels is not None and labels != self.hcloud_server.labels:
                update_params["labels"] = labels

            if update_params:
                if not self.module.check_mode:
                    self.hcloud_server.update(**update_params)
                self._mark_as_changed()

            rescue_mode = self.module.params.get("rescue_mode")
            if rescue_mode and self.hcloud_server.rescue_enabled is False:
                if not self.module.check_mode:
                    self._set_rescue_mode(rescue_mode)
                self._mark_as_changed()
            elif not rescue_mode and self.hcloud_server.rescue_enabled is True:
                if not self.module.check_mode:
                    action = self.hcloud_server.disable_rescue()
                    action.wait_until_finished()
                self._mark_as_changed()

            backups = self.module.params.get("backups")
            if backups and self.hcloud_server.backup_window is None:
                if not self.module.check_mode:
                    action = self.hcloud_server.enable_backup()
                    action.wait_until_finished()
                self._mark_as_changed()
            elif backups is not None and not backups and self.hcloud_server.backup_window is not None:
                if not self.module.check_mode:
                    action = self.hcloud_server.disable_backup()
                    action.wait_until_finished()
                self._mark_as_changed()

            if self.module.params.get("firewalls") is not None:
                self._update_server_firewalls()

            if self.module.params.get("placement_group") is not None:
                self._update_server_placement_group()

            if self.module.params.get("ipv4") is not None:
                self._update_server_ip("ipv4")

            if self.module.params.get("ipv6") is not None:
                self._update_server_ip("ipv6")

            if self.module.params.get("private_networks") is not None:
                self._update_server_networks()

            if self.module.params.get("server_type") is not None:
                self._update_server_server_type()

            if not self.module.check_mode and (
                (self.module.params.get("state") == "present" and previous_server_status == Server.STATUS_RUNNING)
                or self.module.params.get("state") == "started"
            ):
                self.start_server()

            delete_protection = self.module.params.get("delete_protection")
            rebuild_protection = self.module.params.get("rebuild_protection")
            if (delete_protection is not None and rebuild_protection is not None) and (
                delete_protection != self.hcloud_server.protection["delete"]
                or rebuild_protection != self.hcloud_server.protection["rebuild"]
            ):
                if not self.module.check_mode:
                    action = self.hcloud_server.change_protection(
                        delete=delete_protection,
                        rebuild=rebuild_protection,
                    )
                    action.wait_until_finished()
                self._mark_as_changed()
            self._get_server()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _update_server_placement_group(self) -> None:
        current: BoundPlacementGroup | None = self.hcloud_server.placement_group
        wanted = self.module.params.get("placement_group")

        # Return if nothing changed
        if current is not None and current.has_id_or_name(wanted):
            return

        # Fetch resource if parameter is truthy
        if wanted:
            placement_group = self._client_get_by_name_or_id("placement_groups", wanted)

        # Remove if current is defined
        if current is not None:
            if not self.module.check_mode:
                action = self.hcloud_server.remove_from_placement_group()
                action.wait_until_finished()
            self._mark_as_changed()

        # Return if parameter is falsy
        if not wanted:
            return

        # Assign new
        self.stop_server_if_forced()
        if not self.module.check_mode:
            action = self.hcloud_server.add_to_placement_group(placement_group)
            action.wait_until_finished()
        self._mark_as_changed()

    def _update_server_server_type(self) -> None:
        current: ServerType = self.hcloud_server.server_type
        wanted = self.module.params.get("server_type")

        # Return if nothing changed
        if current.has_id_or_name(wanted):
            # Check if we should warn for using an deprecated server type
            deprecated_server_type_warning(
                self.module,
                self.hcloud_server.server_type,
                self.hcloud_server.datacenter.location,
            )
            return

        server_type = self._client_get_by_name_or_id("server_types", wanted)

        # Check if we should warn for updating to a deprecated server type
        deprecated_server_type_warning(
            self.module,
            server_type,
            self.hcloud_server.datacenter.location,
        )

        self.stop_server_if_forced()

        if not self.module.check_mode:
            upgrade_disk = self.module.params.get("upgrade_disk")

            action = self.hcloud_server.change_type(
                server_type=server_type,
                upgrade_disk=upgrade_disk,
            )
            # Upgrading a server takes 160 seconds on average, upgrading the disk should
            # take more time
            # 122 retries >= 602 seconds
            # 38 retries >= 182 seconds
            action.wait_until_finished(max_retries=122 if upgrade_disk else 38)
        self._mark_as_changed()

    def _update_server_ip(self, kind: Literal["ipv4", "ipv6"]) -> None:
        current: PrimaryIP | None = getattr(self.hcloud_server.public_net, f"primary_{kind}")
        wanted = self.module.params.get(kind)
        enable = self.module.params.get(f"enable_{kind}")

        # Return if nothing changed
        if current is not None and current.has_id_or_name(wanted) and enable:
            return

        # Fetch resource if parameter is truthy
        if wanted:
            primary_ip = self._client_get_by_name_or_id("primary_ips", wanted)

        # Remove if current is defined
        if current is not None:
            self.stop_server_if_forced()
            if not self.module.check_mode:
                action = self.client.primary_ips.unassign(current)
                action.wait_until_finished()
            self._mark_as_changed()

        # Return if parameter is falsy or resource is disabled
        if not wanted or not enable:
            return

        # Assign new
        self.stop_server_if_forced()
        if not self.module.check_mode:
            action = self.client.primary_ips.assign(
                primary_ip,
                assignee_id=self.hcloud_server.id,
                assignee_type="server",
            )
            action.wait_until_finished()
        self._mark_as_changed()

    def _update_server_networks(self) -> None:
        current: list[BoundNetwork] = [item.network for item in self.hcloud_server.private_net]
        wanted: list[BoundNetwork] = [
            self._client_get_by_name_or_id("networks", name_or_id)
            for name_or_id in self.module.params.get("private_networks")
        ]

        current_ids = {item.id for item in current}
        wanted_ids = {item.id for item in wanted}

        # Removing existing but not wanted networks
        actions: list[BoundAction] = []
        for current_network in current:
            if current_network.id in wanted_ids:
                continue

            self._mark_as_changed()
            if self.module.check_mode:
                continue

            actions.append(self.hcloud_server.detach_from_network(current_network))

        for action in actions:
            action.wait_until_finished()

        # Adding wanted networks that doesn't exist yet
        actions: list[BoundAction] = []
        for wanted_network in wanted:
            if wanted_network.id in current_ids:
                continue

            self._mark_as_changed()
            if self.module.check_mode:
                continue

            actions.append(self.hcloud_server.attach_to_network(wanted_network))

        for action in actions:
            action.wait_until_finished()

    def _update_server_firewalls(self) -> None:
        current: list[BoundFirewall] = [item.firewall for item in self.hcloud_server.public_net.firewalls]
        wanted: list[BoundFirewall] = [
            self._client_get_by_name_or_id("firewalls", name_or_id)
            for name_or_id in self.module.params.get("firewalls")
        ]

        current_ids = {item.id for item in current}
        wanted_ids = {item.id for item in wanted}

        # Removing existing but not wanted firewalls
        actions: list[BoundAction] = []
        for current_firewall in current:
            if current_firewall.id in wanted_ids:
                continue

            self._mark_as_changed()
            if self.module.check_mode:
                continue

            actions.extend(
                self.client.firewalls.remove_from_resources(
                    current_firewall,
                    [FirewallResource(type="server", server=self.hcloud_server)],
                )
            )

        for action in actions:
            action.wait_until_finished()

        # Adding wanted firewalls that doesn't exist yet
        actions: list[BoundAction] = []
        for wanted_firewall in wanted:
            if wanted_firewall.id in current_ids:
                continue

            self._mark_as_changed()
            if self.module.check_mode:
                continue

            actions.extend(
                self.client.firewalls.apply_to_resources(
                    wanted_firewall,
                    [FirewallResource(type="server", server=self.hcloud_server)],
                )
            )

        for action in actions:
            action.wait_until_finished()

    def _set_rescue_mode(self, rescue_mode):
        if self.module.params.get("ssh_keys"):
            resp = self.hcloud_server.enable_rescue(
                type=rescue_mode,
                ssh_keys=[
                    self.client.ssh_keys.get_by_name(ssh_key_name).id
                    for ssh_key_name in self.module.params.get("ssh_keys")
                ],
            )
        else:
            resp = self.hcloud_server.enable_rescue(type=rescue_mode)
        resp.action.wait_until_finished()
        self.result["root_password"] = resp.root_password

    def start_server(self):
        try:
            if self.hcloud_server:
                if self.hcloud_server.status != Server.STATUS_RUNNING:
                    if not self.module.check_mode:
                        action = self.client.servers.power_on(self.hcloud_server)
                        action.wait_until_finished()
                    self._mark_as_changed()
                self._get_server()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def stop_server(self):
        try:
            if self.hcloud_server:
                if self.hcloud_server.status != Server.STATUS_OFF:
                    if not self.module.check_mode:
                        action = self.client.servers.power_off(self.hcloud_server)
                        action.wait_until_finished()
                    self._mark_as_changed()
                self._get_server()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def stop_server_if_forced(self):
        previous_server_status = self.hcloud_server.status
        if previous_server_status == Server.STATUS_RUNNING and not self.module.check_mode:
            if self.module.params.get("force") or self.module.params.get("state") == "stopped":
                self.stop_server()  # Only stopped server can be upgraded
                return previous_server_status

            self.module.warn(
                f"You can not upgrade a running instance {self.hcloud_server.name}. "
                "You need to stop the instance or use force=true."
            )

        return None

    def rebuild_server(self):
        self._get_server()
        if self.hcloud_server is None:
            self._create_server()
        else:
            self._update_server()

            # Only rebuild the server if it already existed.
            self.module.fail_on_missing_params(required_params=["image"])
            try:
                if not self.module.check_mode:
                    image = self._get_image(self.hcloud_server.server_type)
                    resp = self.client.servers.rebuild(self.hcloud_server, image)
                    # When we rebuild the server progress takes some more time.
                    resp.action.wait_until_finished(max_retries=202)  # 202 retries >= 1002 seconds
                self._mark_as_changed()

                self._get_server()
            except HCloudException as exception:
                self.fail_json_hcloud(exception)

    def present_server(self):
        self._get_server()
        if self.hcloud_server is None:
            self._create_server()
        else:
            self._update_server()

    def delete_server(self):
        try:
            self._get_server()
            if self.hcloud_server is not None:
                if not self.module.check_mode:
                    action = self.client.servers.delete(self.hcloud_server)
                    action.wait_until_finished()
                self._mark_as_changed()
            self.hcloud_server = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                image={"type": "str"},
                image_allow_deprecated={"type": "bool", "default": False, "aliases": ["allow_deprecated_image"]},
                server_type={"type": "str"},
                location={"type": "str"},
                datacenter={"type": "str"},
                user_data={"type": "str"},
                ssh_keys={"type": "list", "elements": "str", "no_log": False},
                volumes={"type": "list", "elements": "str"},
                firewalls={"type": "list", "elements": "str"},
                labels={"type": "dict"},
                backups={"type": "bool"},
                upgrade_disk={"type": "bool", "default": False},
                enable_ipv4={"type": "bool", "default": True},
                enable_ipv6={"type": "bool", "default": True},
                ipv4={"type": "str"},
                ipv6={"type": "str"},
                private_networks={"type": "list", "elements": "str", "default": None},
                force={"type": "bool", "default": False},
                rescue_mode={"type": "str"},
                delete_protection={"type": "bool"},
                rebuild_protection={"type": "bool"},
                placement_group={"type": "str"},
                state={
                    "choices": ["absent", "present", "created", "restarted", "started", "stopped", "rebuild"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name"]],
            mutually_exclusive=[["location", "datacenter"]],
            required_together=[["delete_protection", "rebuild_protection"]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudServer.define_module()

    hcloud = AnsibleHCloudServer(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.delete_server()
    elif state == "present":
        hcloud.present_server()
        hcloud.start_server()
    elif state == "created":
        hcloud.present_server()
    elif state == "started":
        hcloud.present_server()
        hcloud.start_server()
    elif state == "stopped":
        hcloud.present_server()
        hcloud.stop_server()
    elif state == "restarted":
        hcloud.present_server()
        hcloud.stop_server()
        hcloud.start_server()
    elif state == "rebuild":
        hcloud.rebuild_server()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
