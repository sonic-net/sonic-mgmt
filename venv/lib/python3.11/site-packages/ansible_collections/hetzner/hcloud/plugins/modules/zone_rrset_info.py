#!/usr/bin/python

# Copyright: (c) 2025, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: zone_rrset_info

short_description: Gather infos about your Hetzner Cloud Zone RRSets.

description:
    - Gather infos about your Hetzner Cloud Zone RRSets.
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
            - ID of the Zone RRSet you want to get.
        type: str
    name:
        description:
            - Name of the Zone RRSets you want to get.
        type: str
    type:
        description:
            - Type of the Zone RRSets you want to get.
        type: str
    label_selector:
        description:
            - Label selector to filter the Zone RRSets you want to get.
        type: str

extends_documentation_fragment:
    - hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Gather Zone RRSet infos
  hetzner.hcloud.zone_rrset_info:
  register: output
- name: Print the gathered infos
  debug:
    var: output.hcloud_zone_rrset_info
"""

RETURN = """
hcloud_zone_rrset_info:
    description: Zone RRSet infos as list.
    returned: always
    type: list
    elements: dict
    contains:
        zone:
            description: ID of the parent Zone.
            type: int
            returned: always
            sample: 42
        id:
            description: ID of the Zone RRSet.
            returned: always
            type: str
            sample: www/A
        name:
            description: Name of the Zone RRSet.
            returned: always
            type: str
            sample: www
        type:
            description: Mode of the Zone RRSet.
            returned: always
            type: str
            sample: A
        ttl:
            description: TTL of the Zone RRSet.
            returned: always
            type: int
            sample: 10800
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
            sample:
                key: value
        change_protection:
            description: Protect the Zone RRSet from changes (deletion and updates).
            returned: always
            type: bool
            sample: false
        records:
            description: Record of the Zone RRSet.
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

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.experimental import dns_experimental_warning
from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import APIException, HCloudException
from ..module_utils.vendor.hcloud.zones import BoundZoneRRSet, Zone, ZoneRecord


class AnsibleHCloudZoneRRSetInfo(AnsibleHCloud):
    represent = "hcloud_zone_rrset_info"

    hcloud_zone_rrset_info: list[BoundZoneRRSet] | None = None

    def __init__(self, module: AnsibleModule):
        dns_experimental_warning(module)
        super().__init__(module)

    def _prepare_result(self):
        tmp = []

        for zone_rrset in self.hcloud_zone_rrset_info:
            if zone_rrset is None:
                continue

            tmp.append(
                {
                    # Do not use the zone name to prevent a request to the API.
                    "zone": zone_rrset.zone.id,
                    "id": zone_rrset.id,
                    "name": zone_rrset.name,
                    "type": zone_rrset.type,
                    "ttl": zone_rrset.ttl,
                    "labels": zone_rrset.labels,
                    "change_protection": zone_rrset.protection["change"],
                    "records": [self._prepare_result_record(o) for o in zone_rrset.records or []],
                }
            )

        return tmp

    def _prepare_result_record(self, record: ZoneRecord):
        return {
            "value": record.value,
            "comment": record.comment,
        }

    def get_zone_rrsets(self):
        try:
            self.hcloud_zone_rrset_info = []

            # zone name and id are interchangeable
            zone = Zone(self.module.params.get("zone"))

            if self.module.params.get("id") is not None:
                # pylint: disable=disallowed-name
                rrset_name, _, rrset_type = self.module.params.get("id").partition("/")
                try:
                    self.hcloud_zone_rrset_info = [
                        self.client.zones.get_rrset(
                            zone,
                            name=rrset_name,
                            type=rrset_type,
                        )
                    ]
                except APIException as api_exception:
                    if api_exception.code != "not_found":
                        raise
            elif self.module.params.get("name") is not None:
                rrset_name, rrset_type = self.module.params.get("name"), self.module.params.get("type")
                try:
                    self.hcloud_zone_rrset_info = [
                        self.client.zones.get_rrset(
                            zone,
                            name=rrset_name,
                            type=rrset_type,
                        )
                    ]
                except APIException as api_exception:
                    if api_exception.code != "not_found":
                        raise
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_zone_rrset_info = self.client.zones.get_rrset_all(
                    zone,
                    label_selector=self.module.params.get("label_selector"),
                )
            else:
                self.hcloud_zone_rrset_info = self.client.zones.get_rrset_all(zone)

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                zone={"type": "str", "required": True},
                id={"type": "str"},
                name={"type": "str"},
                type={"type": "str"},
                label_selector={"type": "str"},
                **super().base_module_arguments(),
            ),
            required_together=[("name", "type")],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudZoneRRSetInfo.define_module()
    hcloud = AnsibleHCloudZoneRRSetInfo(module)

    hcloud.get_zone_rrsets()
    result = hcloud.get_result()

    ansible_info = {"hcloud_zone_rrset_info": result["hcloud_zone_rrset_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
