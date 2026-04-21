#!/usr/bin/python

# Copyright: (c) 2022, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: primary_ip

short_description: Create and manage cloud Primary IPs on the Hetzner Cloud.


description:
    - Create, update and manage cloud Primary IPs on the Hetzner Cloud.
    - To manage the DNS pointer of a Primary IP, use the M(hetzner.hcloud.rdns) module.

author:
    - Lukas Kaemmerling (@lkaemmerling)
version_added: 1.8.0
options:
    id:
        description:
            - The ID of the Hetzner Cloud Primary IPs to manage.
            - Only required if no Primary IP I(name) is given.
        type: int
    name:
        description:
            - The Name of the Hetzner Cloud Primary IPs to manage.
            - Only required if no Primary IP I(id) is given or a Primary IP does not exist.
        type: str
    datacenter:
        description:
            - Home Location of the Hetzner Cloud Primary IP.
            - Required if no I(server) is given and Primary IP does not exist.
        type: str
    server:
        description:
            - Name or ID of the Hetzner Cloud Server the Primary IP should be assigned to.
            - The Primary IP cannot be assigned to a running server.
            - Required if no O(datacenter) is given and the Primary IP does not exist.
        type: str
    type:
        description:
            - Type of the Primary IP.
            - Required if Primary IP does not exist
        choices: [ ipv4, ipv6 ]
        type: str
    auto_delete:
        description:
            - Delete the Primary IP when the resource it is assigned to is deleted.
        type: bool
        default: false
    delete_protection:
        description:
            - Protect the Primary IP for deletion.
        type: bool
    labels:
        description:
            - User-defined labels (key-value pairs).
        type: dict
    state:
        description:
            - State of the Primary IP.
        default: present
        choices: [ absent, present ]
        type: str

extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a IPv4 Primary IP
  hetzner.hcloud.primary_ip:
    name: my-primary-ip
    datacenter: fsn1-dc14
    type: ipv4
    state: present

- name: Create a IPv6 Primary IP
  hetzner.hcloud.primary_ip:
    name: my-primary-ip
    datacenter: fsn1-dc14
    type: ipv6
    state: present

- name: Delete a Primary IP
  hetzner.hcloud.primary_ip:
    name: my-primary-ip
    state: absent

- name: Ensure the server is stopped
  hetzner.hcloud.server:
    name: my-server
    state: stopped
- name: Create a Primary IP attached to a Server
  hetzner.hcloud.primary_ip:
    name: my-primary-ip
    server: my-server
    type: ipv4
    state: present
- name: Ensure the server is started
  hetzner.hcloud.server:
    name: my-server
    state: started
"""

RETURN = """
hcloud_primary_ip:
    description: The Primary IP instance
    returned: Always
    type: complex
    contains:
        id:
            description: ID of the Primary IP
            type: int
            returned: Always
            sample: 12345
        name:
            description: Name of the Primary IP
            type: str
            returned: Always
            sample: my-primary-ip
        ip:
            description: IP Address of the Primary IP
            type: str
            returned: Always
            sample: 116.203.104.109
        type:
            description: Type of the Primary IP
            type: str
            returned: Always
            sample: ipv4
        datacenter:
            description: Name of the datacenter of the Primary IP
            type: str
            returned: Always
            sample: fsn1-dc14
        delete_protection:
            description: True if Primary IP is protected for deletion
            type: bool
            returned: always
            sample: false
        labels:
            description: User-defined labels (key-value pairs)
            type: dict
            returned: Always
            sample:
                key: value
                mylabel: 123
        assignee_id:
            description: ID of the resource the Primary IP is assigned to, null if it is not assigned.
            type: int
            returned: always
            sample: 1937415
        assignee_type:
            description: Resource type the Primary IP can be assigned to.
            type: str
            returned: always
            sample: server
        auto_delete:
            description: Delete the Primary IP when the resource it is assigned to is deleted.
            type: bool
            returned: always
            sample: false
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.primary_ips import BoundPrimaryIP


class AnsibleHCloudPrimaryIP(AnsibleHCloud):
    represent = "hcloud_primary_ip"

    hcloud_primary_ip: BoundPrimaryIP | None = None

    def _prepare_result(self):
        return {
            "id": self.hcloud_primary_ip.id,
            "name": self.hcloud_primary_ip.name,
            "ip": self.hcloud_primary_ip.ip,
            "type": self.hcloud_primary_ip.type,
            "datacenter": self.hcloud_primary_ip.datacenter.name,
            "labels": self.hcloud_primary_ip.labels,
            "delete_protection": self.hcloud_primary_ip.protection["delete"],
            "assignee_id": (
                self.hcloud_primary_ip.assignee_id if self.hcloud_primary_ip.assignee_id is not None else None
            ),
            "assignee_type": self.hcloud_primary_ip.assignee_type,
            "auto_delete": self.hcloud_primary_ip.auto_delete,
        }

    def _get_primary_ip(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_primary_ip = self.client.primary_ips.get_by_id(self.module.params.get("id"))
            else:
                self.hcloud_primary_ip = self.client.primary_ips.get_by_name(self.module.params.get("name"))
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create_primary_ip(self):
        self.fail_on_invalid_params(
            required=["type", "name"],
            required_one_of=[["server", "datacenter"]],
        )
        try:
            params = {
                "type": self.module.params.get("type"),
                "name": self.module.params.get("name"),
                "auto_delete": self.module.params.get("auto_delete"),
            }

            if self.module.params.get("datacenter") is not None:
                params["datacenter"] = self.client.datacenters.get_by_name(self.module.params.get("datacenter"))
            elif self.module.params.get("server") is not None:
                params["assignee_id"] = self._client_get_by_name_or_id("servers", self.module.params.get("server")).id

            if self.module.params.get("labels") is not None:
                params["labels"] = self.module.params.get("labels")
            if not self.module.check_mode:
                resp = self.client.primary_ips.create(**params)
                if resp.action is not None:
                    resp.action.wait_until_finished()
                self.hcloud_primary_ip = resp.primary_ip

                delete_protection = self.module.params.get("delete_protection")
                if delete_protection is not None:
                    action = self.hcloud_primary_ip.change_protection(delete=delete_protection)
                    action.wait_until_finished()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)
        self._mark_as_changed()
        self._get_primary_ip()

    def _update_primary_ip(self):
        try:
            changes = {}

            auto_delete = self.module.params.get("auto_delete")
            if auto_delete is not None and auto_delete != self.hcloud_primary_ip.auto_delete:
                changes["auto_delete"] = auto_delete

            labels = self.module.params.get("labels")
            if labels is not None and labels != self.hcloud_primary_ip.labels:
                changes["labels"] = labels

            if changes:
                if not self.module.check_mode:
                    self.hcloud_primary_ip.update(**changes)
                self._mark_as_changed()

            delete_protection = self.module.params.get("delete_protection")
            if delete_protection is not None and delete_protection != self.hcloud_primary_ip.protection["delete"]:
                if not self.module.check_mode:
                    action = self.hcloud_primary_ip.change_protection(delete=delete_protection)
                    action.wait_until_finished()
                self._mark_as_changed()

            self._get_primary_ip()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def present_primary_ip(self):
        self._get_primary_ip()
        if self.hcloud_primary_ip is None:
            self._create_primary_ip()
        else:
            self._update_primary_ip()

    def delete_primary_ip(self):
        try:
            self._get_primary_ip()
            if self.hcloud_primary_ip is not None:
                if not self.module.check_mode:
                    self.client.primary_ips.delete(self.hcloud_primary_ip)
                self._mark_as_changed()
            self.hcloud_primary_ip = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                datacenter={"type": "str"},
                server={"type": "str"},
                auto_delete={"type": "bool", "default": False},
                type={"choices": ["ipv4", "ipv6"]},
                labels={"type": "dict"},
                delete_protection={"type": "bool"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name"]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudPrimaryIP.define_module()

    hcloud = AnsibleHCloudPrimaryIP(module)
    state = module.params["state"]
    if state == "absent":
        hcloud.delete_primary_ip()
    elif state == "present":
        hcloud.present_primary_ip()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
