#!/usr/bin/python

# Copyright: (c) 2020, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: placement_group

short_description: Create and manage placement groups on the Hetzner Cloud.


description:
    - Create, update and manage placement groups on the Hetzner Cloud.

author:
    - Adrian Huber (@Adi146)

options:
    id:
        description:
            - The ID of the Hetzner Cloud placement group to manage.
            - Only required if no placement group I(name) is given
        type: int
    name:
        description:
            - The Name of the Hetzner Cloud placement group to manage.
            - Only required if no placement group I(id) is given, or a placement group does not exist.
        type: str
    labels:
        description:
            - User-defined labels (key-value pairs)
        type: dict
    type:
        description:
            - The Type of the Hetzner Cloud placement group.
        type: str
    state:
        description:
            - State of the placement group.
        default: present
        choices: [ absent, present ]
        type: str

extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a basic placement group
  hetzner.hcloud.placement_group:
    name: my-placement-group
    state: present
    type: spread

- name: Create a placement group with labels
  hetzner.hcloud.placement_group:
    name: my-placement-group
    type: spread
    labels:
      key: value
      mylabel: 123
    state: present

- name: Ensure the placement group is absent (remove if needed)
  hetzner.hcloud.placement_group:
    name: my-placement-group
    state: absent
"""

RETURN = """
hcloud_placement_group:
    description: The placement group instance
    returned: Always
    type: complex
    contains:
        id:
            description: Numeric identifier of the placement group
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the placement group
            returned: always
            type: str
            sample: my placement group
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
        type:
            description: Type of the placement group
            returned: always
            type: str
            sample: spread
        servers:
            description: Server IDs of the placement group
            returned: always
            type: list
            elements: int
            sample:
                - 4711
                - 4712
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.placement_groups import BoundPlacementGroup


class AnsibleHCloudPlacementGroup(AnsibleHCloud):
    represent = "hcloud_placement_group"

    hcloud_placement_group: BoundPlacementGroup | None = None

    def _prepare_result(self):
        return {
            "id": self.hcloud_placement_group.id,
            "name": self.hcloud_placement_group.name,
            "labels": self.hcloud_placement_group.labels,
            "type": self.hcloud_placement_group.type,
            "servers": self.hcloud_placement_group.servers,
        }

    def _get_placement_group(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_placement_group = self.client.placement_groups.get_by_id(self.module.params.get("id"))
            elif self.module.params.get("name") is not None:
                self.hcloud_placement_group = self.client.placement_groups.get_by_name(self.module.params.get("name"))
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create_placement_group(self):
        self.module.fail_on_missing_params(required_params=["name"])
        params = {
            "name": self.module.params.get("name"),
            "type": self.module.params.get("type"),
            "labels": self.module.params.get("labels"),
        }
        if not self.module.check_mode:
            try:
                self.client.placement_groups.create(**params)
            except HCloudException as exception:
                self.fail_json_hcloud(exception, params=params)
        self._mark_as_changed()
        self._get_placement_group()

    def _update_placement_group(self):
        name = self.module.params.get("name")
        if name is not None and self.hcloud_placement_group.name != name:
            self.module.fail_on_missing_params(required_params=["id"])
            if not self.module.check_mode:
                self.hcloud_placement_group.update(name=name)
            self._mark_as_changed()

        labels = self.module.params.get("labels")
        if labels is not None and self.hcloud_placement_group.labels != labels:
            if not self.module.check_mode:
                self.hcloud_placement_group.update(labels=labels)
            self._mark_as_changed()

        self._get_placement_group()

    def present_placement_group(self):
        self._get_placement_group()
        if self.hcloud_placement_group is None:
            self._create_placement_group()
        else:
            self._update_placement_group()

    def delete_placement_group(self):
        self._get_placement_group()
        if self.hcloud_placement_group is not None:
            if not self.module.check_mode:
                self.client.placement_groups.delete(self.hcloud_placement_group)
            self._mark_as_changed()
        self.hcloud_placement_group = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                labels={"type": "dict"},
                type={"type": "str"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name"]],
            required_if=[["state", "present", ["name"]]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudPlacementGroup.define_module()

    hcloud = AnsibleHCloudPlacementGroup(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.delete_placement_group()
    elif state == "present":
        hcloud.present_placement_group()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
