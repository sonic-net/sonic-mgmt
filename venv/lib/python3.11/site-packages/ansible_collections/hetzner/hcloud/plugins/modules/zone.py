#!/usr/bin/python

# Copyright: (c) 2025, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: zone

short_description: Create and manage DNS Zone on the Hetzner Cloud.

description:
  - Create, update and delete DNS Zone on the Hetzner Cloud.
  - See the L(Zones API documentation,https://docs.hetzner.cloud/reference/cloud#zones) for more details.
  - B(Experimental:) DNS API is in beta, breaking changes may occur within minor releases.
    See https://docs.hetzner.cloud/changelog#2025-10-07-dns-beta for more details.

author:
  - Jonas Lammler (@jooola)

options:
  id:
    description:
      - ID of the Zone to manage.
      - Only required if no Zone O(name) is given.
    type: int
  name:
    description:
      - Name of the Zone to manage.
      - Only required if no Zone O(id) is given or the Zone does not exist.
      - All names with well-known public suffixes (e.g. .de, .com, .co.uk) are supported. Subdomains are not supported.
      - The name must be in lower case and must not end with a dot.
      - Internationalized domain names must be transcribed to Punycode representation with ACE prefix, e.g. xn--mnchen-3ya.de (münchen.de).
    type: str
  mode:
    description:
      - Mode of the Zone.
      - Required if the Zone does not exist.
    type: str
    choices: [primary, secondary]
  ttl:
    description:
      - TTL of the Zone.
    type: int
  labels:
    description:
      - User-defined key-value pairs.
    type: dict
  delete_protection:
    description:
      - Protect the Zone from deletion.
    type: bool
  primary_nameservers:
    description:
      - Primary nameservers of the Zone.
      - Only applicable for Zones with O(mode=secondary).
    type: list
    elements: dict
    suboptions:
      address:
        description:
          - Public IPv4 or IPv6 address of the primary nameserver.
        type: str
      port:
        description:
          - Port of the primary nameserver.
        type: int
      tsig_algorithm:
        description:
          - Transaction signature (TSIG) algorithm used to generate the TSIG key.
        type: str
      tsig_key:
        description:
          - Transaction signature (TSIG) key.
        type: str
  zonefile:
    description:
      - Zone file to import.
      - Optional if O(state=present) and the Zone does not exist, ignored otherwise.
      - Required if O(state=import).
    type: str
  state:
    description:
      - State of the Zone.
      - C(import) is not idempotent.
    default: present
    choices: [absent, present, import]
    type: str

extends_documentation_fragment:
  - hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a primary Zone
  hetzner.hcloud.zone:
    name: example.com
    mode: primary
    ttl: 10800
    labels:
      key: value
    state: present

- name: Create a primary Zone using a zonefile
  hetzner.hcloud.zone:
    name: example.com
    mode: primary
    zonefile: |
      $ORIGIN	example.com.
      $TTL	3600

      @ 300 IN CAA 0 issue "letsencrypt.org"

      @	600	IN	A	192.168.254.2
      @	600	IN	A	192.168.254.3

      @	IN	AAAA	fdd0:367a:0cb7::2
      @	IN	AAAA	fdd0:367a:0cb7::3

      www	IN	CNAME	example.com.
      blog	IN	CNAME	example.com.

      anything	IN	TXT	"some value"
    state: present

- name: Create a primary Zone with Internationalized Domain Name (IDN)
  hetzner.hcloud.zone:
    # Leverage Python's encoding.idna module https://docs.python.org/3/library/codecs.html#module-encodings.idna
    name: "{{ 'këks-🍪-example.com'.encode('idna') }}"
    mode: primary
    state: present

- name: Create a secondary Zone
  hetzner.hcloud.zone:
    name: example.com
    mode: secondary
    primary_nameservers:
      - address: 203.0.113.1
        port: 53
    labels:
      key: value
    state: present

- name: Delete a Zone
  hetzner.hcloud.zone:
    name: example.com
    state: absent
"""

RETURN = """
hcloud_zone:
  description: Zone instance.
  returned: always
  type: dict
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
from ..module_utils.vendor.hcloud.actions import BoundAction
from ..module_utils.vendor.hcloud.zones import BoundZone, ZonePrimaryNameserver


class AnsibleHCloudZone(AnsibleHCloud):
    represent = "hcloud_zone"

    hcloud_zone: BoundZone | None = None

    def __init__(self, module: AnsibleModule):
        dns_experimental_warning(module)
        super().__init__(module)

    def _prepare_result(self):
        return {
            "id": self.hcloud_zone.id,
            "name": self.hcloud_zone.name,
            "mode": self.hcloud_zone.mode,
            "labels": self.hcloud_zone.labels,
            "ttl": self.hcloud_zone.ttl,
            "primary_nameservers": [
                self._prepare_result_primary_nameserver(o) for o in self.hcloud_zone.primary_nameservers
            ],
            "delete_protection": self.hcloud_zone.protection["delete"],
            "status": self.hcloud_zone.status,
            "registrar": self.hcloud_zone.registrar,
            "authoritative_nameservers": {
                "assigned": self.hcloud_zone.authoritative_nameservers.assigned,
                "delegated": self.hcloud_zone.authoritative_nameservers.delegated,
                "delegation_last_check": (
                    self.hcloud_zone.authoritative_nameservers.delegation_last_check.isoformat()
                    if self.hcloud_zone.authoritative_nameservers.delegation_last_check is not None
                    else None
                ),
                "delegation_status": self.hcloud_zone.authoritative_nameservers.delegation_status,
            },
            "record_count": self.hcloud_zone.record_count,
        }

    def _prepare_result_primary_nameserver(self, o: ZonePrimaryNameserver):
        return {
            "address": o.address,
            "port": o.port,
            "tsig_algorithm": o.tsig_algorithm,
            "tsig_key": o.tsig_key,
        }

    def _get(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_zone = self.client.zones.get(self.module.params.get("id"))
            else:
                try:
                    self.hcloud_zone = self.client.zones.get(self.module.params.get("name"))
                except APIException as api_exc:
                    if api_exc.code != "not_found":
                        raise
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create(self):
        self.module.fail_on_missing_params(required_params=["name", "mode"])
        params = {
            "name": self.module.params.get("name"),
            "mode": self.module.params.get("mode"),
        }

        if self.module.params.get("ttl") is not None:
            params["ttl"] = self.module.params.get("ttl")

        if self.module.params.get("labels") is not None:
            params["labels"] = self.module.params.get("labels")

        if self.module.params.get("primary_nameservers") is not None:
            params["primary_nameservers"] = [
                ZonePrimaryNameserver(
                    address=o["address"],
                    port=o["port"],
                )
                for o in self.module.params.get("primary_nameservers")
            ]

        if self.module.params.get("zonefile") is not None:
            params["zonefile"] = self.module.params.get("zonefile")

        if not self.module.check_mode:
            try:
                resp = self.client.zones.create(**params)
                resp.action.wait_until_finished()

                self.hcloud_zone = resp.zone

                if self.module.params.get("delete_protection") is not None:
                    action = self.hcloud_zone.change_protection(
                        delete=self.module.params.get("delete_protection"),
                    )
                    action.wait_until_finished()

            except HCloudException as exception:
                self.fail_json_hcloud(exception)

        self._mark_as_changed()
        self._get()

    def _update(self):
        try:
            actions: list[BoundAction] = []
            delete_protection = self.module.params.get("delete_protection")
            if delete_protection is not None and delete_protection != self.hcloud_zone.protection["delete"]:
                if not self.module.check_mode:
                    action = self.hcloud_zone.change_protection(delete=delete_protection)
                    actions.append(action)
                self._mark_as_changed()

            ttl = self.module.params.get("ttl")
            if ttl is not None and ttl != self.hcloud_zone.ttl:
                if not self.module.check_mode:
                    action = self.hcloud_zone.change_ttl(ttl=ttl)
                    actions.append(action)
                self._mark_as_changed()

            primary_nameservers = self.module.params.get("primary_nameservers")
            if primary_nameservers is not None and self._diff_primary_nameservers():
                if not self.module.check_mode:
                    action = self.hcloud_zone.change_primary_nameservers(
                        primary_nameservers=[ZonePrimaryNameserver.from_dict(o) for o in primary_nameservers]
                    )
                    actions.append(action)
                self._mark_as_changed()

            for action in actions:
                action.wait_until_finished()

            params = {}

            labels = self.module.params.get("labels")
            if labels is not None and labels != self.hcloud_zone.labels:
                params["labels"] = labels
                self._mark_as_changed()

            if not self.module.check_mode:
                self.hcloud_zone = self.hcloud_zone.update(**params)

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _diff_primary_nameservers(self) -> bool:
        current = [self._prepare_result_primary_nameserver(o) for o in self.hcloud_zone.primary_nameservers]
        wanted = [
            self._prepare_result_primary_nameserver(ZonePrimaryNameserver.from_dict(o))
            for o in self.module.params.get("primary_nameservers")
        ]

        return current != wanted

    def present(self):
        self._get()
        if self.hcloud_zone is None:
            self._create()
        else:
            self._update()

    def absent(self):
        try:
            self._get()
            if self.hcloud_zone is not None:
                if not self.module.check_mode:
                    resp = self.hcloud_zone.delete()
                    resp.action.wait_until_finished()
                self._mark_as_changed()

            self.hcloud_zone = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def import_(self):
        self._get()
        if self.hcloud_zone is None:
            self._create()
        else:
            try:
                if not self.module.check_mode:
                    action = self.hcloud_zone.import_zonefile(self.module.params.get("zonefile"))
                    action.wait_until_finished()

                self._mark_as_changed()
                self._get()

            except HCloudException as exception:
                self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                mode={"type": "str", "choices": ["primary", "secondary"]},
                primary_nameservers={
                    "type": "list",
                    "elements": "dict",
                    "options": dict(
                        address={"type": "str"},
                        port={"type": "int"},
                        tsig_algorithm={"type": "str", "default": None},
                        tsig_key={"type": "str", "default": None, "no_log": True},
                    ),
                },
                ttl={"type": "int"},
                labels={"type": "dict"},
                delete_protection={"type": "bool"},
                zonefile={"type": "str"},
                state={
                    "choices": ["absent", "present", "import"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name"]],
            required_if=[["state", "import", ["zonefile"]]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudZone.define_module()

    hcloud = AnsibleHCloudZone(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.absent()
    elif state == "import":
        hcloud.import_()
    else:
        hcloud.present()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
