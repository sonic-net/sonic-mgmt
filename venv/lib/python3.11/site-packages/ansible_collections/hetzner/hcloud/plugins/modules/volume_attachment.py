#!/usr/bin/python

# Copyright: (c) 2025, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: volume_attachment

short_description: Manage the attachment of Hetzner Cloud Volumes


description:
    - Attach and detach Volumes from Hetzner Cloud Servers.

author:
    - Amirhossein Shaerpour (@shaerpour)

options:
    volume:
        description:
            - Name or ID of the Hetzner Cloud Volume to attach/detach.
        type: str
        required: true
    server:
        description:
            - Name or ID of the Hetzner Cloud Server to attach the Volume to.
            - Required if O(state=present).
        type: str
    automount:
        description:
            - Automatically mount the Volume in the Server.
        type: bool
    state:
        description:
            - State of the Volume.
        type: str
        default: present
        choices: [ present, absent ]

extends_documentation_fragment:
    - hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Attach my-volume to my-server
  hetzner.hcloud.volume_attachment:
    volume: my-volume
    server: my-server

- name: Detach my-volume from my-server
  hetzner.hcloud.volume_attachment:
    volume: my-volume
    state: absent

- name: Attach my-volume using id to my-server with automount enabled
  hetzner.hcloud.volume_attachment:
    volume: 123456
    server: my-server
    automount: true
    state: present
"""

RETURN = """
hcloud_volume_attachment:
    description: The relationship between a Server and a Volume
    returned: always
    type: complex
    contains:
        volume:
            description: Name of the Volume
            type: str
            returned: always
            sample: my-volume
        server:
            description: Name of the attached Server
            type: str
            returned: always
            sample: my-server
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.servers import BoundServer
from ..module_utils.vendor.hcloud.volumes import BoundVolume


class AnsibleHCloudVolumeAttachment(AnsibleHCloud):
    represent = "hcloud_volume_attachment"

    # We must the hcloud_volume_attachment name instead of hcloud_volume, because
    # AnsibleHCloud.get_result does funny things.
    hcloud_volume_attachment: BoundVolume | None = None
    hcloud_server: BoundServer | None = None

    def _prepare_result(self):
        return {
            "volume": self.hcloud_volume_attachment.name,
            "server": (
                self.hcloud_volume_attachment.server.name if self.hcloud_volume_attachment.server is not None else None
            ),
        }

    def _get_volume(self):
        try:
            self.hcloud_volume_attachment = self._client_get_by_name_or_id(
                "volumes",
                self.module.params.get("volume"),
            )
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _get_server(self):
        try:
            self.hcloud_server = self._client_get_by_name_or_id(
                "servers",
                self.module.params.get("server"),
            )
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def attach_volume(self):
        self.module.fail_on_missing_params(required_params=["server"])

        try:
            self._get_volume()
            self._get_server()

            if self.hcloud_volume_attachment.server is not None:
                if self.hcloud_volume_attachment.server.id == self.hcloud_server.id:
                    return

                if not self.module.check_mode:
                    action = self.hcloud_volume_attachment.detach()
                    action.wait_until_finished()

                self.hcloud_volume_attachment.server = None
                self._mark_as_changed()

            if not self.module.check_mode:
                action = self.hcloud_volume_attachment.attach(
                    server=self.hcloud_server,
                    automount=self.module.params.get("automount"),
                )
                action.wait_until_finished()

            self.hcloud_volume_attachment.server = self.hcloud_server
            self._mark_as_changed()

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def detach_volume(self):
        try:
            self._get_volume()

            if self.hcloud_volume_attachment.server is not None:
                if not self.module.check_mode:
                    action = self.hcloud_volume_attachment.detach()
                    action.wait_until_finished()

                self.hcloud_volume_attachment.server = None
                self._mark_as_changed()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                volume={"type": "str", "required": True},
                server={"type": "str"},
                automount={"type": "bool"},
                state={
                    "choices": ["present", "absent"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudVolumeAttachment.define_module()

    hcloud = AnsibleHCloudVolumeAttachment(module)
    state = module.params["state"]
    if state == "present":
        hcloud.attach_volume()
    elif state == "absent":
        hcloud.detach_volume()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
