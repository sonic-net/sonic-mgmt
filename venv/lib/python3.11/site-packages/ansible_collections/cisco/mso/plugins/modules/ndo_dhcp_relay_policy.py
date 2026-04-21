#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_dhcp_relay_policy
short_description: Manage DHCP Relay Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage DHCP Relay Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be a tenant template.
    type: str
    required: true
  relay_policy:
    description:
    - The name of the DHCP Relay Policy.
    type: str
    aliases: [ name ]
  relay_policy_uuid:
    description:
    - The uuid of the DHCP Relay Policy.
    - This parameter is required when the O(relay_policy) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the DHCP Relay Policy.
    type: str
  providers:
    description:
    - A list of providers attached to the DHCP Relay Policy.
    - The list of configured providers must contain at least one provider.
    - When the list of providers is null the update will not change existing providers configuration.
    type: list
    elements: dict
    suboptions:
      schema:
        description:
        - The name of the schema for the (External) EPG.
        type: str
        required: true
      template:
        description:
        - The name of the template for the (External) EPG.
        type: str
        required: true
      anp:
        description:
        - The name of the Application Profile (ANP).
        - This parameter is required when O(providers.epg) is provided.
        type: str
      epg:
        description:
        - The name of the Endpoint Group (EPG).
        - O(providers.epg) and O(providers.external_epg) are mutually exclusive.
        - O(providers.epg) is required when O(providers.external_epg) is not provided.
        type: str
      external_epg:
        description:
        - The name of the External Endpoint Group (EPG).
        - O(providers.external_epg) and O(providers.epg) are mutually exclusive.
        - O(providers.external_epg) is required when O(providers.epg) is not provided.
        type: str
      ip:
        description:
        - The IP address of the DHCP server.
        type: str
        required: true
      use_server_vrf:
        description:
        - Use the server VRF.
        type: bool
        default: false
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new dhcp relay policy
  cisco.mso.ndo_dhcp_relay_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    relay_policy: ansible_test_relay_policy
    providers:
      - schema: ansible_test_schema
        template: ansible_test_template
        anp: ansible_test_anp
        epg: ansible_test_epg_1
        ip: 1.1.1.1
    state: present
  register: create

- name: Query a dhcp relay policy with name
  cisco.mso.ndo_dhcp_relay_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    relay_policy: ansible_test_relay_policy
    state: query
  register: query_one

- name: Query a dhcp relay policy with UUID
  cisco.mso.ndo_dhcp_relay_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    relay_policy_uuid: '{{ create.current.uuid }}'
    state: query
  register: query_with_uuid

- name: Query all dhcp relay policy in the template
  cisco.mso.ndo_dhcp_relay_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete a dhcp relay policy
  cisco.mso.ndo_dhcp_relay_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    relay_policy: ansible_test_relay_policy
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        relay_policy=dict(type="str", aliases=["name"]),
        relay_policy_uuid=dict(type="str", aliases=["uuid"]),
        description=dict(type="str"),
        providers=dict(
            type="list",
            elements="dict",
            options=dict(
                schema=dict(type="str", required=True),
                template=dict(type="str", required=True),
                anp=dict(type="str"),
                epg=dict(type="str"),
                external_epg=dict(type="str"),
                ip=dict(type="str", required=True),
                use_server_vrf=dict(type="bool", default=False),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["relay_policy"]],
            ["state", "present", ["relay_policy"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    relay_policy = module.params.get("relay_policy")
    relay_policy_uuid = module.params.get("relay_policy_uuid")
    providers = get_providers_payload(mso, module.params.get("providers")) if module.params.get("providers") else []
    description = module.params.get("description")
    state = module.params.get("state")

    ops = []
    match = None
    err_message_min_providers = "At least one provider is required when state is present."

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")

    path = "/tenantPolicyTemplate/template/dhcpRelayPolicies"
    match = get_dhcp_relay_policy(mso_template, relay_policy_uuid, relay_policy)

    if relay_policy_uuid or relay_policy:
        if match:
            mso.existing = mso.previous = copy.deepcopy(insert_dhcp_relay_policy_relation_name(match.details, mso_template))  # Query a specific object
    elif match:
        mso.existing = [insert_dhcp_relay_policy_relation_name(dhcp_relay_policy, mso_template) for dhcp_relay_policy in match]  # Query all objects

    if state == "present":
        if match:
            if module.params.get("providers") is not None and len(providers) == 0:
                mso.fail_json(msg=err_message_min_providers)

            if relay_policy and match.details.get("name") != relay_policy:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=relay_policy))
                match.details["name"] = relay_policy

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if module.params.get("providers") is not None and match.details.get("providers") != providers:
                ops.append(dict(op="replace", path="{0}/{1}/providers".format(path, match.index), value=providers))
                match.details["providers"] = providers

            mso.sanitize(match.details)

        else:
            if not providers:
                mso.fail_json(msg=err_message_min_providers)

            payload = {"name": relay_policy, "providers": providers}
            if description:
                payload["description"] = description

            ops.append(dict(op="add", path="{0}/-".format(path), value=payload))

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))
        mso.existing = {}

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = get_dhcp_relay_policy(mso_template, relay_policy_uuid, relay_policy)
        if match:
            mso.existing = insert_dhcp_relay_policy_relation_name(match.details, mso_template)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def insert_dhcp_relay_policy_relation_name(dhcp_relay_policy, mso_template):
    for provider in dhcp_relay_policy.get("providers"):
        if provider.get("epgRef"):
            provider["epgName"] = mso_template.get_template_object_name_by_uuid("epg", provider.get("epgRef"))
        if provider.get("externalEpgRef"):
            provider["externalEpgName"] = mso_template.get_template_object_name_by_uuid("externalEpg", provider.get("externalEpgRef"))
    return dhcp_relay_policy


def get_dhcp_relay_policy(mso_template, uuid=None, name=None, fail_module=False):
    match = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("dhcpRelayPolicies", [])
    if uuid or name:  # Query a specific object
        return mso_template.get_object_by_key_value_pairs("DHCP Relay Policy", match, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
    return match  # Query all objects


def get_providers_payload(mso, providers):
    # Cache used to reduce the number of schema queries done by MSOSchema function.
    schema_cache = {}

    payload = []
    for provider in providers:
        schema = provider.get("schema")
        template = provider.get("template")
        anp = provider.get("anp")
        epg = provider.get("epg")
        external_epg = provider.get("external_epg")
        ip = provider.get("ip")

        provider_payload = {"ip": ip, "useServerVrf": provider.get("use_server_vrf")}

        # Check if schema is already in cache, if not create a new MSOSchema object and add it to the cache.
        if not schema_cache.get(schema):
            schema_cache[schema] = MSOSchema(mso, schema)

        schema_cache[schema].set_template(template)

        if epg and not anp:
            mso.fail_json(msg="The anp argument is required for each provider when the epg argument is provided.")
        elif not epg and not external_epg:
            mso.fail_json(msg="The epg or external_epg argument is required for each provider.")
        elif epg and external_epg:
            mso.fail_json(msg="The epg and external_epg arguments are mutually exclusive for each provider.")
        elif external_epg and anp:
            mso.fail_json(msg="The anp and external_epg arguments are mutually exclusive for each provider.")
        elif epg:
            schema_cache[schema].set_template_anp(anp)
            schema_cache[schema].set_template_anp_epg(epg)
            provider_payload["epgRef"] = schema_cache[schema].schema_objects["template_anp_epg"].details.get("uuid")
            provider_payload["epgName"] = epg
        else:
            schema_cache[schema].set_template_external_epg(external_epg)
            provider_payload["externalEpgRef"] = schema_cache[schema].schema_objects.get("template_external_epg").details.get("uuid")
            provider_payload["externalEpgName"] = external_epg

        payload.append(provider_payload)
    return payload


if __name__ == "__main__":
    main()
