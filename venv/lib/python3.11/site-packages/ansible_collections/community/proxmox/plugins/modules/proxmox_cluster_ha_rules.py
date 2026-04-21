#!/usr/bin/python

# Copyright (c) 2025, Reto Kupferschmid <kupferschmid@puzzle.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-FileCopyrightText: (c) 2025, Reto Kupferschmid <kupferschmid@puzzle.ch>
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: proxmox_cluster_ha_rules

short_description: Management of HA rules

version_added: 1.4.0

description:
  - Configure ha rules C(/cluster/ha/rules).

attributes:
  check_mode:
    support: full
  diff_mode:
    support: full

options:
    affinity:
        description: |
            Describes whether the HA resource are supposed to be kept on the same node V(positive),
            or are supposed to be kept on separate nodes V(negative).
            Required if O(type=resource-affinity).
        required: false
        choices: ['positive', 'negative']
        type: str
    comment:
        description: Description
        required: false
        type: str
    disable:
        description: Whether the HA rule is disabled. If not specified, the Proxmox API default C(false) will be used.
        required: false
        type: bool
    force:
        description: |
          Existing rules with a specific O(type) can not be changed to the other type.
          If V(force=true), the existing rule will be deleted and recreated with the new type.
        required: false
        default: false
        type: bool
    name:
        description: HA rule identifier.
        required: true
        type: str
    nodes:
        description: |
            List of cluster node members, where a priority can be given to each node. A resource bound to a group will run on the
            available nodes with the highest priority. If there are more nodes in the highest priority class, the services will
            get distributed to those nodes. The priorities have a
            relative meaning only. The higher the number, the higher the priority.
            It can either be a string C(node_name:priority,node_name:priority) or an actual list of strings.
            Required if O(type=node-affinity).
        required: false
        type: list
        elements: str
    resources:
        description: List of HA resource IDs. It can either be a string C(vm:100,ct:101) or an actual list of strings.
        required: false
        type: list
        elements: str
    state:
        description: create or delete rule
        required: true
        choices: ['present', 'absent']
        type: str
    strict:
        description: |
            If false, the HA resource can also be moved to other nodes if there is none of the specified nodes available.
            If not specified, the Proxmox API default C(false) will be used.
        required: false
        type: bool
    type:
        description: HA rule type.
        required: false
        choices: ['node-affinity', 'resource-affinity']
        type: str

extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes

author:
    - Reto Kupferschmid (@rekup)
"""

EXAMPLES = r"""
- name: Configure ha rule (node-affinity)
  community.proxmox.proxmox_cluster_ha_rules:
    api_host: "{{ proxmox_api_host }}"
    api_user: "{{ proxmox_api_user }}"
    api_token_id: "{{ proxmox_api_token_id }}"
    api_token_secret: "{{ proxmox_api_token_secret }}"
    name: node-affinity-rule-1
    state: present
    type: node-affinity
    comment: VM 100 is supposed run on proxmox02
    nodes:
      - proxmox01:10
      - proxmox02:20
    resources:
      - vm:100
    disable: false
  delegate_to: localhost

- name: Configure ha rule (node-affinity) - nodes and resources can also be provided as str
  community.proxmox.proxmox_cluster_ha_rules:
    api_host: "{{ proxmox_api_host }}"
    api_user: "{{ proxmox_api_user }}"
    api_token_id: "{{ proxmox_api_token_id }}"
    api_token_secret: "{{ proxmox_api_token_secret }}"
    name: node-affinity-rule-2
    state: present
    type: node-affinity
    comment: VM 100 is supposed to run on proxmox02
    nodes: proxmox01:10,proxmox02:20
    resources: vm:100
    disable: false
  delegate_to: localhost

- name: Configure ha rule (resource-affinity) - resource affinity
  community.proxmox.proxmox_cluster_ha_rules:
    api_host: "{{ proxmox_api_host }}"
    api_user: "{{ proxmox_api_user }}"
    api_token_id: "{{ proxmox_api_token_id }}"
    api_token_secret: "{{ proxmox_api_token_secret }}"
    name: resource-affinity-rule-1
    state: present
    type: resource-affinity
    comment: VM 100 and 101 are supposed to be kept on the same node
    affinity: positive
    resources:
      - vm:100
      - vm:101
    disable: false
  delegate_to: localhost

- name: Configure ha rule (resource-affinity) - resource anti-affinity
  community.proxmox.proxmox_cluster_ha_rules:
    api_host: "{{ proxmox_api_host }}"
    api_user: "{{ proxmox_api_user }}"
    api_token_id: "{{ proxmox_api_token_id }}"
    api_token_secret: "{{ proxmox_api_token_secret }}"
    name: resource-affinity-rule-1
    state: present
    type: resource-affinity
    comment: VM 100 and 101 are supposed to be kept on different nodes
    affinity: negative
    resources:
      - vm:100
      - vm:101
    disable: false
  delegate_to: localhost
"""

RETURN = r"""
rule:
  description: A representation of the rule.
  returned: success
  type: dict
  sample: {
      "comment": "My first ha rule",
      "digest": "f19acd44b43052343763cd9fd45a03b7449b3e2f",
      "disable": 0,
      "nodes": "proxmox01:10,proxmox02:10",
      "order": 2,
      "resources": "vm:100",
      "rule": "ha-rule1",
      "strict": 0,
      "type": "node-affinity"
    }

"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec,
    ProxmoxAnsible,
)


class ProxmoxClusterHARuleAnsible(ProxmoxAnsible):
    def get(self):
        rules = self.proxmox_api.cluster.ha.rules.get()
        return rules

    def _post(self, data):
        return self.proxmox_api.cluster.ha.rules.post(**data)

    def _put(self, name, data):
        return self.proxmox_api.cluster.ha.rules(name).put(**data)

    def _delete(self, name):
        return self.proxmox_api.cluster.ha.rules(name).delete()

    def create_payload(self):
        payload: dict = {
            "rule": self.module.params["name"],
            "type": self.module.params["type"],
        }

        if self.module.params["comment"] is not None:
            payload["comment"] = self.module.params["comment"]

        if self.module.params["disable"] is not None:
            payload["disable"] = int(self.module.params["disable"])

        if self.module.params["resources"] is not None:
            payload["resources"] = ",".join(sorted(self.module.params["resources"]))

        if self.module.params["type"] == "node-affinity":
            if self.module.params["strict"] is not None:
                payload["strict"] = int(self.module.params["strict"])
            if self.module.params["nodes"] is not None:
                payload["nodes"] = ",".join(sorted(self.module.params["nodes"]))

        if self.module.params["type"] == "resource-affinity":
            payload["affinity"] = self.module.params["affinity"]

        return dict(sorted(payload.items()))

    def create(self, existing_rule):
        changed: bool = False
        diff: dict = {"before": {}, "after": {}}

        name = self.module.params["name"]

        if existing_rule and existing_rule.get("type") != self.module.params["type"]:
            if self.module.params["force"]:
                diff["before"] = existing_rule.copy()
                if not self.module.check_mode:
                    self._delete(name=name)
                existing_rule = {}
            else:
                self.module.fail_json(
                    changed=False,
                    msg=(
                        "Rule %s already exists with type=%s. "
                        "The type of an existing rule can not be changed. "
                        "Use force=true to delete the existing rule and recreate it with type=%s"
                        % (
                            name,
                            existing_rule.get("type"),
                            self.module.params.get("type"),
                        )
                    ),
                )

        if existing_rule:
            # if the rule is enabled the "disabled" key is missing from the api response
            existing_rule.setdefault("disable", 0)

            # if the rule has no comment, the "comment" key is missing from the api response
            existing_rule.setdefault("comment", "")

            # sort fields to ensure idempotency
            for key in ["nodes", "resources"]:
                if existing_rule.get(key, None) is not None:
                    value_list = existing_rule.get(key).split(",")
                    existing_rule[key] = ",".join(sorted(value_list))

            payload = self.create_payload()
            updated_rule = {**existing_rule, **payload}

            diff["before"] = existing_rule
            diff["after"] = updated_rule
            changed = existing_rule != updated_rule

            if changed and not self.module.check_mode:
                self._put(name, payload)

        else:
            changed = True
            payload = self.create_payload()

            if not self.module.check_mode:
                self._post(payload)

                # fetch the new rule and update the diff
                rules = self.get()
                diff["after"] = next(
                    (item for item in rules if item.get("rule") == name), {}
                )
            else:
                diff["after"] = payload

        return {"changed": changed, "rule": diff["after"], "diff": diff}

    def delete(self, existing_rule, name):
        diff: dict = {"before": {}, "after": {}}

        if existing_rule:
            diff.update({"before": existing_rule})
            if not self.module.check_mode:
                self._delete(name)
            return {"changed": True, "diff": diff}

        return {"changed": False, "diff": diff}


def run_module():
    module_args = proxmox_auth_argument_spec()

    acl_args = dict(
        affinity=dict(choices=["positive", "negative"], required=False),
        comment=dict(type="str", required=False),
        disable=dict(type="bool", required=False),
        force=dict(type="bool", default=False, required=False),
        name=dict(type="str", required=True),
        nodes=dict(type="list", elements="str", required=False),
        resources=dict(type="list", elements="str", required=False),
        state=dict(choices=["present", "absent"], required=True),
        strict=dict(type="bool", required=False),
        type=dict(choices=["node-affinity", "resource-affinity"], required=False),
    )

    module_args.update(acl_args)

    result = dict(
        changed=False,
        rule={},
        diff={},
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[("api_password", "api_token_id")],
        required_together=[("api_token_id", "api_token_secret")],
        required_if=[
            ("state", "present", ["type", "resources"]),
            ("type", "node-affinity", ["nodes"]),
            ("type", "resource-affinity", ["affinity"]),
        ],
        supports_check_mode=True,
    )

    proxmox = ProxmoxClusterHARuleAnsible(module)

    name = module.params["name"]
    state = module.params["state"]

    try:
        rules = proxmox.get()

        existing: dict = next((item for item in rules if item.get("rule") == name), {})

        if state == "present":
            result = proxmox.create(existing)
            result.update(**result)
        else:
            result = proxmox.delete(existing, name=name)
            result.update(**result)

    except Exception as e:
        module.fail_json(msg=str(e), **result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
