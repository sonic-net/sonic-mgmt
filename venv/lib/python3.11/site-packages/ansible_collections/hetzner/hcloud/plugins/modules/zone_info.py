#!/usr/bin/python

# Copyright: (c) 2025, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: zone_info

short_description: Gather infos about your Hetzner Cloud Zones.

description:
    - Gather infos about your Hetzner Cloud Zones.
    - See the L(Zones API documentation,https://docs.hetzner.cloud/reference/cloud#zones) for more details.
    - B(Experimental:) DNS API is in beta, breaking changes may occur within minor releases.
      See https://docs.hetzner.cloud/changelog#2025-10-07-dns-beta for more details.

author:
    - Jonas Lammler (@jooola)

options:
    id:
        description:
            - ID of the Zone you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - Name of the Zone you want to get.
        type: str
    label_selector:
        description:
            - Label selector to filter the Zones you want to get.
        type: str

extends_documentation_fragment:
    - hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Gather Zone infos
  hetzner.hcloud.zone_info:
  register: output
- name: Print the gathered infos
  debug:
    var: output.hcloud_zone_info
"""

RETURN = """
hcloud_zone_info:
    description: Zone infos as list.
    returned: always
    type: list
    elements: dict
    contains:
        id:
            description: ID of the Zone.
            returned: always
            type: int
            sample: 12345
        name:
            description: Name of the Zone.
            returned: always
            type: str
            sample: example.com
        mode:
            description: Mode of the Zone.
            returned: always
            type: str
            sample: primary
        ttl:
            description: TTL of the Zone.
            returned: always
            type: int
            sample: 10800
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
            sample:
                key: value
        delete_protection:
            description: Protect the Zone from deletion.
            returned: always
            type: bool
            sample: false
        primary_nameservers:
            description: Primary nameservers of the Zone.
            returned: always
            type: list
            elements: dict
            contains:
                address:
                    description: Public IPv4 or IPv6 address of the primary nameserver.
                    returned: always
                    type: str
                    sample: 203.0.113.1
                port:
                    description: Port of the primary nameserver.
                    returned: always
                    type: int
                    sample: 53
                tsig_algorithm:
                    description: Transaction signature (TSIG) algorithm used to generate the TSIG key.
                    returned: always
                    type: str
                    sample: hmac-sha256
                tsig_key:
                    description: Transaction signature (TSIG) key.
                    returned: always
                    type: str
        status:
            description: Status of the Zone.
            returned: always
            type: str
            sample: ok
        registrar:
            description: Registrar of the Zone.
            returned: always
            type: str
            sample: hetzner
        authoritative_nameservers:
            description: Authoritative nameservers of the Zone.
            returned: always
            type: dict
            contains:
                assigned:
                    description: Authoritative Hetzner nameservers assigned to the Zone.
                    returned: always
                    type: list
                    elements: str
                    sample: ["hydrogen.ns.hetzner.com.", "oxygen.ns.hetzner.com.", "helium.ns.hetzner.de."]
                delegated:
                    description: Authoritative nameservers delegated to the parent DNS zone.
                    returned: always
                    type: list
                    elements: str
                    sample: ["hydrogen.ns.hetzner.com.", "oxygen.ns.hetzner.com.", "helium.ns.hetzner.de."]
                delegation_last_check:
                    description: Point in time when the DNS zone delegation was last checked (in ISO-8601 format).
                    returned: always
                    type: str
                    sample: "2023-11-06T13:36:56+00:00"
                delegation_status:
                    description: Status of the delegation.
                    returned: always
                    type: str
                    sample: valid
        record_count:
            description: Number of Resource Records (RR) within the Zone.
            returned: always
            type: int
            sample: 4
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.experimental import dns_experimental_warning
from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import APIException, HCloudException
from ..module_utils.vendor.hcloud.zones import BoundZone, ZonePrimaryNameserver


class AnsibleHCloudZoneInfo(AnsibleHCloud):
    represent = "hcloud_zone_info"

    hcloud_zone_info: list[BoundZone] | None = None

    def __init__(self, module: AnsibleModule):
        dns_experimental_warning(module)
        super().__init__(module)

    def _prepare_result(self):
        tmp = []

        for zone in self.hcloud_zone_info:
            if zone is None:
                continue

            tmp.append(
                {
                    "id": zone.id,
                    "name": zone.name,
                    "mode": zone.mode,
                    "labels": zone.labels,
                    "ttl": zone.ttl,
                    "primary_nameservers": [
                        self._prepare_result_primary_nameserver(o) for o in zone.primary_nameservers
                    ],
                    "delete_protection": zone.protection["delete"],
                    "status": zone.status,
                    "registrar": zone.registrar,
                    "authoritative_nameservers": {
                        "assigned": zone.authoritative_nameservers.assigned,
                        "delegated": zone.authoritative_nameservers.delegated,
                        "delegation_last_check": (
                            zone.authoritative_nameservers.delegation_last_check.isoformat()
                            if zone.authoritative_nameservers.delegation_last_check is not None
                            else None
                        ),
                        "delegation_status": zone.authoritative_nameservers.delegation_status,
                    },
                    "record_count": zone.record_count,
                }
            )

        return tmp

    def _prepare_result_primary_nameserver(self, o: ZonePrimaryNameserver):
        return {
            "address": o.address,
            "port": o.port,
            "tsig_algorithm": o.tsig_algorithm,
            "tsig_key": o.tsig_key,
        }

    def get_zones(self):
        try:
            self.hcloud_zone_info = []

            if self.module.params.get("id") is not None:
                self.hcloud_zone_info = [self.client.zones.get(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                try:
                    self.hcloud_zone_info = [self.client.zones.get(self.module.params.get("name"))]
                except APIException as api_exc:
                    if api_exc.code != "not_found":
                        raise
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_zone_info = self.client.zones.get_all(
                    label_selector=self.module.params.get("label_selector")
                )
            else:
                self.hcloud_zone_info = self.client.zones.get_all()

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
    module = AnsibleHCloudZoneInfo.define_module()
    hcloud = AnsibleHCloudZoneInfo(module)

    hcloud.get_zones()
    result = hcloud.get_result()

    ansible_info = {"hcloud_zone_info": result["hcloud_zone_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
