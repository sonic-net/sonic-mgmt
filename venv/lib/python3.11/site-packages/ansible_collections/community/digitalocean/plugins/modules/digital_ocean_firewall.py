#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2018, Anthony Bond <ajbond2005@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: digital_ocean_firewall
short_description: Manage cloud firewalls within DigitalOcean
description:
    - This module can be used to add or remove firewalls on the DigitalOcean cloud platform.
author:
    - Anthony Bond (@BondAnthony)
    - Lucas Basquerotto (@lucasbasquerotto)
version_added: "1.1.0"
options:
  name:
    type: str
    description:
     - Name of the firewall rule to create or manage
    required: true
  state:
    type: str
    choices: ['present', 'absent']
    default: present
    description:
      - Assert the state of the firewall rule. Set to 'present' to create or update and 'absent' to remove.
  droplet_ids:
    type: list
    elements: str
    description:
     - List of droplet ids to be assigned to the firewall
    required: false
  tags:
    type: list
    elements: str
    description:
      - List of tags to be assigned to the firewall
    required: false
  inbound_rules:
    type: list
    elements: dict
    description:
      - Firewall rules specifically targeting inbound network traffic into DigitalOcean
    required: false
    suboptions:
      protocol:
        type: str
        choices: ['udp', 'tcp', 'icmp']
        default: tcp
        description:
          - Network protocol to be accepted.
        required: false
      ports:
        type: str
        description:
          - The ports on which traffic will be allowed, single, range, or all
        required: true
      sources:
        type: dict
        description:
          - Dictionary of locations from which inbound traffic will be accepted
        required: true
        suboptions:
          addresses:
            type: list
            elements: str
            description:
              - List of strings containing the IPv4 addresses, IPv6 addresses, IPv4 CIDRs,
                and/or IPv6 CIDRs to which the firewall will allow traffic
            required: false
          droplet_ids:
            type: list
            elements: str
            description:
              - List of integers containing the IDs of the Droplets to which the firewall will allow traffic
            required: false
          load_balancer_uids:
            type: list
            elements: str
            description:
              - List of strings containing the IDs of the Load Balancers to which the firewall will allow traffic
            required: false
          tags:
            type: list
            elements: str
            description:
              - List of strings containing the names of Tags corresponding to groups of Droplets to
                which the Firewall will allow traffic
            required: false
  outbound_rules:
    type: list
    elements: dict
    description:
      - Firewall rules specifically targeting outbound network traffic from DigitalOcean
    required: false
    suboptions:
      protocol:
        type: str
        choices: ['udp', 'tcp', 'icmp']
        default: tcp
        description:
          - Network protocol to be accepted.
        required: false
      ports:
        type: str
        description:
          - The ports on which traffic will be allowed, single, range, or all
        required: true
      destinations:
        type: dict
        description:
          - Dictionary of locations from which outbound traffic will be allowed
        required: true
        suboptions:
          addresses:
            type: list
            elements: str
            description:
              - List of strings containing the IPv4 addresses, IPv6 addresses, IPv4 CIDRs,
                and/or IPv6 CIDRs to which the firewall will allow traffic
            required: false
          droplet_ids:
            type: list
            elements: str
            description:
              - List of integers containing the IDs of the Droplets to which the firewall will allow traffic
            required: false
          load_balancer_uids:
            type: list
            elements: str
            description:
              - List of strings containing the IDs of the Load Balancers to which the firewall will allow traffic
            required: false
          tags:
            type: list
            elements: str
            description:
              - List of strings containing the names of Tags corresponding to groups of Droplets to
                which the Firewall will allow traffic
            required: false
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
"""

EXAMPLES = """
# Allows tcp connections to port 22 (SSH) from specific sources
# Allows tcp connections to ports 80 and 443 from any source
# Allows outbound access to any destination for protocols tcp, udp and icmp
# The firewall rules will be applied to any droplets with the tag "sample"
- name: Create a Firewall named my-firewall
  digital_ocean_firewall:
    name: my-firewall
    state: present
    inbound_rules:
      - protocol: "tcp"
        ports: "22"
        sources:
          addresses: ["1.2.3.4"]
          droplet_ids: ["my_droplet_id_1", "my_droplet_id_2"]
          load_balancer_uids: ["my_lb_id_1", "my_lb_id_2"]
          tags: ["tag_1", "tag_2"]
      - protocol: "tcp"
        ports: "80"
        sources:
          addresses: ["0.0.0.0/0", "::/0"]
      - protocol: "tcp"
        ports: "443"
        sources:
          addresses: ["0.0.0.0/0", "::/0"]
    outbound_rules:
      - protocol: "tcp"
        ports: "1-65535"
        destinations:
          addresses: ["0.0.0.0/0", "::/0"]
      - protocol: "udp"
        ports: "1-65535"
        destinations:
          addresses: ["0.0.0.0/0", "::/0"]
      - protocol: "icmp"
        ports: "1-65535"
        destinations:
          addresses: ["0.0.0.0/0", "::/0"]
    droplet_ids: []
    tags: ["sample"]
"""

RETURN = """
data:
    description: DigitalOcean firewall resource
    returned: success
    type: dict
    sample: {
        "created_at": "2020-08-11T18:41:30Z",
        "droplet_ids": [],
        "id": "7acd6ee2-257b-434f-8909-709a5816d4f9",
        "inbound_rules": [
            {
                "ports": "443",
                "protocol": "tcp",
                "sources": {
                  "addresses": [
                      "1.2.3.4"
                  ],
                  "droplet_ids": [
                      "my_droplet_id_1",
                      "my_droplet_id_2"
                  ],
                  "load_balancer_uids": [
                      "my_lb_id_1",
                      "my_lb_id_2"
                  ],
                  "tags": [
                      "tag_1",
                      "tag_2"
                  ]
                }
            },
            {
                "sources": {
                    "addresses": [
                        "0.0.0.0/0",
                        "::/0"
                    ]
                },
                "ports": "80",
                "protocol": "tcp"
            },
            {
                "sources": {
                    "addresses": [
                        "0.0.0.0/0",
                        "::/0"
                    ]
                },
                "ports": "443",
                "protocol": "tcp"
            }
        ],
        "name": "my-firewall",
        "outbound_rules": [
            {
                "destinations": {
                    "addresses": [
                        "0.0.0.0/0",
                        "::/0"
                    ]
                },
                "ports": "1-65535",
                "protocol": "tcp"
            },
            {
                "destinations": {
                    "addresses": [
                        "0.0.0.0/0",
                        "::/0"
                    ]
                },
                "ports": "1-65535",
                "protocol": "udp"
            },
            {
                "destinations": {
                    "addresses": [
                        "0.0.0.0/0",
                        "::/0"
                    ]
                },
                "ports": "1-65535",
                "protocol": "icmp"
            }
        ],
        "pending_changes": [],
        "status": "succeeded",
        "tags": ["sample"]
    }
"""

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)
from ansible.module_utils._text import to_native

address_spec = dict(
    addresses=dict(type="list", elements="str", required=False),
    droplet_ids=dict(type="list", elements="str", required=False),
    load_balancer_uids=dict(type="list", elements="str", required=False),
    tags=dict(type="list", elements="str", required=False),
)

inbound_spec = dict(
    protocol=dict(type="str", choices=["udp", "tcp", "icmp"], default="tcp"),
    ports=dict(type="str", required=True),
    sources=dict(type="dict", required=True, options=address_spec),
)

outbound_spec = dict(
    protocol=dict(type="str", choices=["udp", "tcp", "icmp"], default="tcp"),
    ports=dict(type="str", required=True),
    destinations=dict(type="dict", required=True, options=address_spec),
)


class DOFirewall(object):
    def __init__(self, module):
        self.rest = DigitalOceanHelper(module)
        self.module = module
        self.name = self.module.params.get("name")
        self.baseurl = "firewalls"
        self.firewalls = self.get_firewalls()

    def get_firewalls(self):
        base_url = self.baseurl + "?"
        response = self.rest.get("%s" % base_url)
        status_code = response.status_code
        status_code_success = 200

        if status_code != status_code_success:
            error = response.json
            info = response.info

            if error:
                error.update({"status_code": status_code})
                error.update({"status_code_success": status_code_success})
                self.module.fail_json(msg=error)
            elif info:
                info.update({"status_code_success": status_code_success})
                self.module.fail_json(msg=info)
            else:
                msg_error = "Failed to retrieve firewalls from DigitalOcean"
                self.module.fail_json(
                    msg=msg_error
                    + " (url="
                    + self.rest.baseurl
                    + "/"
                    + self.baseurl
                    + ", status="
                    + str(status_code or "")
                    + " - expected:"
                    + str(status_code_success)
                    + ")"
                )

        return self.rest.get_paginated_data(
            base_url=base_url, data_key_name="firewalls"
        )

    def get_firewall_by_name(self):
        rule = {}
        for firewall in self.firewalls:
            if firewall["name"] == self.name:
                rule.update(firewall)
                return rule
        return None

    def ordered(self, obj):
        if isinstance(obj, dict):
            return sorted((k, self.ordered(v)) for k, v in obj.items())
        if isinstance(obj, list):
            return sorted(self.ordered(x) for x in obj)
        else:
            return obj

    def fill_protocol_defaults(self, obj):
        if obj.get("protocol") is None:
            obj["protocol"] = "tcp"

        return obj

    def fill_source_and_destination_defaults_inner(self, obj):
        addresses = obj.get("addresses") or []

        droplet_ids = obj.get("droplet_ids") or []
        droplet_ids = [str(droplet_id) for droplet_id in droplet_ids]

        load_balancer_uids = obj.get("load_balancer_uids") or []
        load_balancer_uids = [str(uid) for uid in load_balancer_uids]

        tags = obj.get("tags") or []

        data = {
            "addresses": addresses,
            "droplet_ids": droplet_ids,
            "load_balancer_uids": load_balancer_uids,
            "tags": tags,
        }

        return data

    def fill_sources_and_destinations_defaults(self, obj, prop):
        value = obj.get(prop)

        if value is None:
            value = {}
        else:
            value = self.fill_source_and_destination_defaults_inner(value)

        obj[prop] = value

        return obj

    def fill_data_defaults(self, obj):
        inbound_rules = obj.get("inbound_rules")

        if inbound_rules is None:
            inbound_rules = []
        else:
            inbound_rules = [self.fill_protocol_defaults(x) for x in inbound_rules]
            inbound_rules = [
                self.fill_sources_and_destinations_defaults(x, "sources")
                for x in inbound_rules
            ]

        outbound_rules = obj.get("outbound_rules")

        if outbound_rules is None:
            outbound_rules = []
        else:
            outbound_rules = [self.fill_protocol_defaults(x) for x in outbound_rules]
            outbound_rules = [
                self.fill_sources_and_destinations_defaults(x, "destinations")
                for x in outbound_rules
            ]

        droplet_ids = obj.get("droplet_ids") or []
        droplet_ids = [str(droplet_id) for droplet_id in droplet_ids]

        tags = obj.get("tags") or []

        data = {
            "name": obj.get("name"),
            "inbound_rules": inbound_rules,
            "outbound_rules": outbound_rules,
            "droplet_ids": droplet_ids,
            "tags": tags,
        }

        return data

    def data_to_compare(self, obj):
        return self.ordered(self.fill_data_defaults(obj))

    def update(self, obj, id):
        if id is None:
            status_code_success = 202
            resp = self.rest.post(path=self.baseurl, data=obj)
        else:
            status_code_success = 200
            resp = self.rest.put(path=self.baseurl + "/" + id, data=obj)
        status_code = resp.status_code
        if status_code != status_code_success:
            error = resp.json
            error.update(
                {
                    "context": "error when trying to "
                    + ("create" if (id is None) else "update")
                    + " firewalls"
                }
            )
            error.update({"status_code": status_code})
            error.update({"status_code_success": status_code_success})
            self.module.fail_json(msg=error)
        self.module.exit_json(changed=True, data=resp.json["firewall"])

    def create(self):
        rule = self.get_firewall_by_name()
        data = {
            "name": self.module.params.get("name"),
            "inbound_rules": self.module.params.get("inbound_rules"),
            "outbound_rules": self.module.params.get("outbound_rules"),
            "droplet_ids": self.module.params.get("droplet_ids"),
            "tags": self.module.params.get("tags"),
        }
        if rule is None:
            self.update(data, None)
        else:
            rule_data = {
                "name": rule.get("name"),
                "inbound_rules": rule.get("inbound_rules"),
                "outbound_rules": rule.get("outbound_rules"),
                "droplet_ids": rule.get("droplet_ids"),
                "tags": rule.get("tags"),
            }

            user_data = {
                "name": data.get("name"),
                "inbound_rules": data.get("inbound_rules"),
                "outbound_rules": data.get("outbound_rules"),
                "droplet_ids": data.get("droplet_ids"),
                "tags": data.get("tags"),
            }

            if self.data_to_compare(user_data) == self.data_to_compare(rule_data):
                self.module.exit_json(changed=False, data=rule)
            else:
                self.update(data, rule.get("id"))

    def destroy(self):
        rule = self.get_firewall_by_name()
        if rule is None:
            self.module.exit_json(changed=False, data="Firewall does not exist")
        else:
            endpoint = self.baseurl + "/" + rule["id"]
            resp = self.rest.delete(path=endpoint)
            status_code = resp.status_code
            if status_code != 204:
                self.module.fail_json(msg="Failed to delete firewall")
            self.module.exit_json(
                changed=True,
                data="Deleted firewall rule: {0} - {1}".format(
                    rule["name"], rule["id"]
                ),
            )


def core(module):
    state = module.params.get("state")
    firewall = DOFirewall(module)

    if state == "present":
        firewall.create()
    elif state == "absent":
        firewall.destroy()


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
        droplet_ids=dict(type="list", elements="str", required=False),
        tags=dict(type="list", elements="str", required=False),
        inbound_rules=dict(
            type="list", elements="dict", options=inbound_spec, required=False
        ),
        outbound_rules=dict(
            type="list", elements="dict", options=outbound_spec, required=False
        ),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[("state", "present", ["inbound_rules", "outbound_rules"])],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
