#!/usr/bin/python

# Copyright: (c) 2025, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: zone_rrset

short_description: Create and manage Zone RRSets on the Hetzner Cloud.

description:
  - Create, update and delete Zone RRSets on the Hetzner Cloud.
  - See the L(Zone RRSets API documentation,https://docs.hetzner.cloud/reference/cloud#zone-rrsets) for more details.
  - B(Experimental:) DNS API is in beta, breaking changes may occur within minor releases.
    See https://docs.hetzner.cloud/changelog#2025-10-07-dns-beta for more details.

author:
    - Jonas Lammler (@jooola)

options:
    zone:
        description:
            - Name or ID of the parent Zone.
        type: str
        required: true
    id:
        description:
            - ID of the Zone RRSet to manage.
            - Only required if no Zone RRSet O(name) and O(type) are given.
        type: int
    name:
        description:
            - Name of the Zone RRSet to manage.
            - Only required if no Zone RRSet O(id) is given or the Zone RRSet does not exist.
        type: str
    type:
        description:
            - Type of the Zone RRSet to manage.
            - Only required if no Zone RRSet O(id) is given or the Zone RRSet does not exist.
        type: str
    ttl:
        description:
            - TTL of the Zone RRSet.
        type: int
    records:
        description:
            - Records of the Zone RRSet.
        type: list
        elements: dict
        suboptions:
            value:
                description:
                    - Value of the record.
                type: str
            comment:
                description:
                    - Comment of the record.
                type: str
    change_protection:
        description:
            - Protect the Zone RRSet from changes (deletion and updates).
        type: bool
    labels:
        description:
            - User-defined key-value pairs.
        type: dict
    state:
        description:
            - State of the Zone RRSet.
        default: present
        choices: [absent, present]
        type: str

extends_documentation_fragment:
  - hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a Zone RRSet
  hetzner.hcloud.zone_rrset:
    zone: example.com
    name: www
    type: A
    ttl: 300
    records:
      - value: 201.118.10.2
        comment: web server 1
      - value: 201.118.10.3
        comment: web server 2
    state: present

- name: Delete a Zone RRSet
  hetzner.hcloud.zone_rrset:
    zone: 42
    name: www
    type: A
    state: absent
"""

RETURN = """
hcloud_zone_rrset:
    description: Zone RRSet instance.
    returned: always
    type: dict
    contains:
        zone:
            description: ID of the parent Zone.
            type: int
            returned: always
            sample: 42
        id:
            description: ID of the Zone RRSet.
            type: str
            returned: always
            sample: www/A
        name:
            description: Name of the Zone RRSet.
            type: str
            returned: always
            sample: my-zone
        type:
            description: Type of the Zone RRSet.
            type: str
            returned: always
            sample: A
        ttl:
            description: TTL of the Zone RRSet.
            type: int
            returned: always
            sample: 3600
        labels:
            description: User-defined labels (key-value pairs)
            type: dict
            returned: always
            sample:
                key: value
        change_protection:
            description: Protect the Zone RRSet from changes (deletion and updates).
            type: bool
            returned: always
            sample: false
        records:
            description: Records of the Zone RRSet.
            returned: always
            type: list
            elements: dict
            contains:
                value:
                    description: Value of the Record.
                    returned: always
                    type: str
                    sample: 203.0.113.1
                comment:
                    description: Comment of the Record.
                    returned: always
                    type: str
                    sample: webserver 1
"""

from typing import Literal

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.experimental import dns_experimental_warning
from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import APIException, HCloudException
from ..module_utils.vendor.hcloud.actions import BoundAction
from ..module_utils.vendor.hcloud.zones import BoundZoneRRSet, Zone, ZoneRecord


class AnsibleHCloudZoneRRSet(AnsibleHCloud):
    represent = "hcloud_zone_rrset"

    hcloud_zone_rrset: BoundZoneRRSet | None = None

    def __init__(self, module: AnsibleModule):
        dns_experimental_warning(module)
        super().__init__(module)

    def _prepare_result(self):
        return {
            # Do not use the zone name to prevent a request to the API.
            "zone": self.hcloud_zone_rrset.zone.id,
            "id": self.hcloud_zone_rrset.id,
            "name": self.hcloud_zone_rrset.name,
            "type": self.hcloud_zone_rrset.type,
            "ttl": self.hcloud_zone_rrset.ttl,
            "labels": self.hcloud_zone_rrset.labels,
            "change_protection": self.hcloud_zone_rrset.protection["change"],
            "records": [self._prepare_result_record(o) for o in self.hcloud_zone_rrset.records or []],
        }

    def _prepare_result_record(self, record: ZoneRecord):
        return {
            "value": record.value,
            "comment": record.comment,
        }

    def _get(self):
        try:
            if self.module.params.get("id") is not None:
                # pylint: disable=disallowed-name
                rrset_name, _, rrset_type = self.module.params.get("id").partition("/")
            else:
                rrset_name, rrset_type = self.module.params.get("name"), self.module.params.get("type")

            try:
                self.hcloud_zone_rrset = self.client.zones.get_rrset(
                    # zone name and id are interchangeable
                    zone=Zone(self.module.params.get("zone")),
                    name=rrset_name,
                    type=rrset_type,
                )
            except APIException as api_exception:
                if api_exception.code != "not_found":
                    raise
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create(self):
        self.module.fail_on_missing_params(required_params=["name", "type"])
        params = {
            "name": self.module.params.get("name"),
            "type": self.module.params.get("type"),
        }

        if self.module.params.get("ttl") is not None:
            params["ttl"] = self.module.params.get("ttl")

        if self.module.params.get("labels") is not None:
            params["labels"] = self.module.params.get("labels")

        if self.module.params.get("records") is not None:
            params["records"] = [ZoneRecord.from_dict(o) for o in self.module.params.get("records")]

        if not self.module.check_mode:
            try:
                resp = self.client.zones.create_rrset(
                    # zone name and id are interchangeable
                    zone=Zone(self.module.params.get("zone")),
                    **params,
                )
                resp.action.wait_until_finished()

                self.hcloud_zone_rrset = resp.rrset

                if self.module.params.get("change_protection") is not None:
                    action = self.hcloud_zone_rrset.change_rrset_protection(
                        change=self.module.params.get("change_protection"),
                    )
                    action.wait_until_finished()

            except HCloudException as exception:
                self.fail_json_hcloud(exception)

        self._mark_as_changed()
        self._get()

    def _update(self):
        try:
            # The "change" protection prevents us from updating the rrset. To reach the
            # state the user provided, we must update the "change" protection:
            # - before other updates if the current change protection is enabled,
            # - after other updates if the current change protection is disabled.
            update_protection_when: Literal["after", "before"] | None = None

            change_protection = self.module.params.get("change_protection")
            if change_protection is not None and change_protection != self.hcloud_zone_rrset.protection["change"]:
                update_protection_when = "before" if self.hcloud_zone_rrset.protection["change"] else "after"

            if update_protection_when == "before":
                if not self.module.check_mode:
                    action = self.hcloud_zone_rrset.change_rrset_protection(change=change_protection)
                    action.wait_until_finished()
                self._mark_as_changed()

            actions: list[BoundAction] = []

            ttl = self.module.params.get("ttl")
            if ttl is not None and ttl != self.hcloud_zone_rrset.ttl:
                if not self.module.check_mode:
                    action = self.hcloud_zone_rrset.change_rrset_ttl(ttl=ttl)
                    actions.append(action)
                self._mark_as_changed()

            records = self.module.params.get("records")
            if records is not None and self._diff_records():
                if not self.module.check_mode:
                    action = self.hcloud_zone_rrset.set_rrset_records(
                        records=[ZoneRecord.from_dict(o) for o in records]
                    )
                    actions.append(action)
                self._mark_as_changed()

            for action in actions:
                action.wait_until_finished()

            labels = self.module.params.get("labels")
            if labels is not None and labels != self.hcloud_zone_rrset.labels:
                if not self.module.check_mode:
                    self.hcloud_zone_rrset.update_rrset(labels=labels)
                self._mark_as_changed()

            if update_protection_when == "after":
                if not self.module.check_mode:
                    action = self.hcloud_zone_rrset.change_rrset_protection(change=change_protection)
                    action.wait_until_finished()
                self._mark_as_changed()

            self._get()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _diff_records(self) -> bool:
        current = [self._prepare_result_record(o) for o in self.hcloud_zone_rrset.records]
        wanted = [self._prepare_result_record(ZoneRecord.from_dict(o)) for o in self.module.params.get("records")]

        return current != wanted

    def present(self):
        self._get()
        if self.hcloud_zone_rrset is None:
            self._create()
        else:
            self._update()

    def absent(self):
        try:
            self._get()
            if self.hcloud_zone_rrset is not None:
                if not self.module.check_mode:
                    resp = self.hcloud_zone_rrset.delete_rrset()
                    resp.action.wait_until_finished()
                self._mark_as_changed()

            self.hcloud_zone_rrset = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                zone={"type": "str", "required": True},
                id={"type": "int"},
                name={"type": "str"},
                type={"type": "str"},
                ttl={"type": "int"},
                labels={"type": "dict"},
                records={
                    "type": "list",
                    "elements": "dict",
                    "options": dict(
                        value={"type": "str"},
                        comment={"type": "str"},
                    ),
                },
                change_protection={"type": "bool"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name"]],
            required_together=[["name", "type"]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudZoneRRSet.define_module()

    hcloud = AnsibleHCloudZoneRRSet(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.absent()
    else:
        hcloud.present()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
