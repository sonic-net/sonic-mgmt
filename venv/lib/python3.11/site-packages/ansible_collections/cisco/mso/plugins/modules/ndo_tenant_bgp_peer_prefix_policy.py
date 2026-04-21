#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_tenant_bgp_peer_prefix_policy
short_description: Manage BGP Peer Prefix Policies in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage BGP Peer Prefix Policies in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the tenant template.
    type: str
    aliases: [ tenant_template ]
    required: true
  name:
    description:
    - The name of the BGP Peer Prefix Policy.
    type: str
    aliases: [ bgp_peer_prefix_policy ]
  uuid:
    description:
    - The UUID of the BGP Peer Prefix Policy.
    - This parameter is required when the BGP Peer Prefix Policy O(name) needs to be updated.
    type: str
  description:
    description:
    - The description of the BGP Peer Prefix Policy.
    - Providing an empty string will remove the O(description="") from the BGP Peer Prefix Policy.
    type: str
  action:
    description:
    - The action of the BGP Peer Prefix Policy.
    - The default value is C(reject).
    type: str
    choices: [ log, reject, restart, shutdown ]
  max_number_of_prefixes:
    description:
    - The maximum number of prefixes for the BGP Peer Prefix Policy.
    - The value must be between 1 and 300000.
    - The default value is 20000 prefixes.
    type: int
    aliases: [ max_prefix, max ]
  threshold_percentage:
    description:
    - The threshold percentage of the BGP Peer Prefix Policy.
    - The value must be between 1 and 100.
    - The default value is 75%.
    type: int
    aliases: [ threshold ]
  restart_time:
    description:
    - The restart time of the BGP Peer Prefix Policy in seconds.
    - The value must be between 1 and 65535.
    - The default value is 1 second.
    type: int
    aliases: [ restart ]
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Tenant template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new BGP Peer Prefix Policy object
  cisco.mso.ndo_tenant_bgp_peer_prefix_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: bgp_peer_prefix_policy_1
    action: restart
    max_number_of_prefixes: 1000
    threshold_percentage: 50
    restart_time: 60
    state: present
  register: bgp_peer_prefix_policy_1

- name: Update a BGP Peer Prefix Policy object name with UUID
  cisco.mso.ndo_tenant_bgp_peer_prefix_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: bgp_peer_prefix_policy_2
    uuid: "{{ bgp_peer_prefix_policy_1.current.uuid }}"
    state: present

- name: Query a BGP Peer Prefix Policy object with name
  cisco.mso.ndo_tenant_bgp_peer_prefix_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: bgp_peer_prefix_policy_1
    state: query
  register: query_uuid

- name: Query a BGP Peer Prefix Policy object with UUID
  cisco.mso.ndo_tenant_bgp_peer_prefix_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    uuid: "{{ bgp_peer_prefix_policy_1.current.uuid }}"
    state: query
  register: query_uuid

- name: Query all BGP Peer Prefix Policy objects in a Tenant Template
  cisco.mso.ndo_tenant_bgp_peer_prefix_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    state: query
  register: query_all

- name: Delete a BGP Peer Prefix Policy object with name
  cisco.mso.ndo_tenant_bgp_peer_prefix_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: bgp_peer_prefix_policy_1
    state: absent

- name: Delete a BGP Peer Prefix Policy object with UUID
  cisco.mso.ndo_tenant_bgp_peer_prefix_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    uuid: "{{ bgp_peer_prefix_policy_1.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["tenant_template"]),
        name=dict(type="str", aliases=["bgp_peer_prefix_policy"]),
        uuid=dict(type="str"),
        description=dict(type="str"),
        action=dict(type="str", choices=["log", "reject", "restart", "shutdown"]),
        max_number_of_prefixes=dict(type="int", aliases=["max_prefix", "max"]),
        threshold_percentage=dict(type="int", aliases=["threshold"]),
        restart_time=dict(type="int", aliases=["restart"]),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    action = module.params.get("action")
    max_number_of_prefixes = module.params.get("max_number_of_prefixes")
    threshold_percentage = module.params.get("threshold_percentage")
    restart_time = module.params.get("restart_time")

    state = module.params.get("state")

    template_object = MSOTemplate(mso, "tenant", template)
    template_object.validate_template("tenantPolicy")

    bgp_peer_prefix_policies = template_object.template.get("tenantPolicyTemplate", {}).get("template", {}).get("bgpPeerPrefixPolicies", [])
    object_description = "BGP Peer Prefix Policy"
    bgp_peer_prefix_policy_attrs_path = None
    match = None

    if state in ["query", "absent"] and bgp_peer_prefix_policies == []:
        mso.exit_json()
    elif state == "query" and not (name or uuid):
        mso.existing = bgp_peer_prefix_policies
    elif bgp_peer_prefix_policies and (name or uuid):
        match = template_object.get_object_by_key_value_pairs(
            object_description, bgp_peer_prefix_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)]
        )
        if match:
            bgp_peer_prefix_policy_attrs_path = "/tenantPolicyTemplate/template/bgpPeerPrefixPolicies/{0}".format(match.index)
            mso.existing = mso.previous = copy.deepcopy(match.details)

    ops = []

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if mso.existing and match:
            proposed_payload = copy.deepcopy(match.details)

            if name and mso.existing.get("name") != name:
                ops.append(dict(op="replace", path=bgp_peer_prefix_policy_attrs_path + "/name", value=name))
                proposed_payload["name"] = name

            if description is not None and mso.existing.get("description") != description:
                ops.append(dict(op="replace", path=bgp_peer_prefix_policy_attrs_path + "/description", value=description))
                proposed_payload["description"] = description

            if action and mso.existing.get("action") != action:
                ops.append(dict(op="replace", path=bgp_peer_prefix_policy_attrs_path + "/action", value=action))
                proposed_payload["action"] = action

            if max_number_of_prefixes and mso.existing.get("maxPrefixes") != max_number_of_prefixes:
                ops.append(dict(op="replace", path=bgp_peer_prefix_policy_attrs_path + "/maxPrefixes", value=max_number_of_prefixes))
                proposed_payload["maxPrefixes"] = max_number_of_prefixes

            if threshold_percentage and mso.existing.get("threshold") != threshold_percentage:
                ops.append(dict(op="replace", path=bgp_peer_prefix_policy_attrs_path + "/threshold", value=threshold_percentage))
                proposed_payload["threshold"] = threshold_percentage

            if restart_time and mso.existing.get("restartTime") != restart_time:
                ops.append(dict(op="replace", path=bgp_peer_prefix_policy_attrs_path + "/restartTime", value=restart_time))
                proposed_payload["restartTime"] = restart_time

            mso.sanitize(proposed_payload, collate=True)
        else:
            payload = dict(name=name)
            if description:
                payload["description"] = description
            if action:
                payload["action"] = action
            if max_number_of_prefixes:
                payload["maxPrefixes"] = max_number_of_prefixes
            if threshold_percentage:
                payload["threshold"] = threshold_percentage
            if restart_time:
                payload["restartTime"] = restart_time

            mso.sanitize(payload)
            ops.append(dict(op="add", path="/tenantPolicyTemplate/template/bgpPeerPrefixPolicies/-", value=payload))

    elif state == "absent":
        if mso.existing and match:
            ops.append(dict(op="remove", path=bgp_peer_prefix_policy_attrs_path))

    if not module.check_mode and ops:
        response_object = mso.request(template_object.template_path, method="PATCH", data=ops)
        bgp_peer_prefix_policies = response_object.get("tenantPolicyTemplate", {}).get("template", {}).get("bgpPeerPrefixPolicies", [])
        match = template_object.get_object_by_key_value_pairs(
            object_description, bgp_peer_prefix_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)]
        )
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
