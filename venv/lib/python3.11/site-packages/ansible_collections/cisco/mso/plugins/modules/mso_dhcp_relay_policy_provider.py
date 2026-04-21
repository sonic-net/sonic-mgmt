#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Jorge Gomez Velasquez <jgomezve@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: mso_dhcp_relay_policy_provider
short_description: Manage DHCP providers in a DHCP Relay policy.
description:
- Manage DHCP providers in a DHCP Relay policy on Cisco Multi-Site Orchestrator.
- This module is only supported on NDO version prior to v4.0.
author:
- Jorge Gomez (@jorgegome2307)
options:
  dhcp_relay_policy:
    description:
    - Name of the DHCP Relay Policy
    type: str
    required: true
    aliases: [ name ]
  ip:
    description:
    - IP address of the DHCP Server
    type: str
  tenant:
    description:
    - Tenant where the DHCP provider is located.
    type: str
  schema:
    description:
    - Schema where the DHCP provider is configured
    type: str
  template:
    description:
    - template where the DHCP provider is configured
    type: str
  application_profile:
    description:
    - Application Profile where the DHCP provider is configured
    type: str
    aliases: [ anp ]
  endpoint_group:
    description:
    - EPG where the DHCP provider is configured
    type: str
    aliases: [ epg ]
  external_endpoint_group:
    description:
    - External EPG where the DHCP provider is configured
    type: str
    aliases: [ ext_epg, external_epg ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new provider to a DHCP Relay Policy
  cisco.mso.mso_dhcp_relay_policy_provider:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_relay_policy: my_test_dhcp_policy
    tenant: ansible_test
    schema: ansible_test
    template: Template 1
    application_profile: ansible_test
    endpoint_group: ansible_test
    state: present

- name: Remove a provider to a DHCP Relay Policy
  cisco.mso.mso_dhcp_relay_policy_provider:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_relay_policy: my_test_dhcp_policy
    tenant: ansible_test
    schema: ansible_test
    template: Template 1
    application_profile: ansible_test
    endpoint_group: ansible_test
    state: absent

- name: Query a provider to a DHCP Relay Policy
  cisco.mso.mso_dhcp_relay_policy_provider:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_relay_policy: my_test_dhcp_policy
    tenant: ansible_test
    schema: ansible_test
    template: Template 1
    application_profile: ansible_test
    endpoint_group: ansible_test
    state: query
  register: query_result

- name: Query all provider of a DHCP Relay Policy
  cisco.mso.mso_dhcp_relay_policy_provider:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_relay_policy: my_test_dhcp_policy
    state: query
  register: query_result
"""

RETURN = r"""
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dhcp_relay_policy=dict(type="str", required=True, aliases=["name"]),
        ip=dict(type="str"),
        tenant=dict(type="str"),
        schema=dict(type="str"),
        template=dict(type="str"),
        application_profile=dict(type="str", aliases=["anp"]),
        endpoint_group=dict(type="str", aliases=["epg"]),
        external_endpoint_group=dict(type="str", aliases=["ext_epg", "external_epg"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["ip", "tenant", "schema", "template"]],
            ["state", "absent", ["tenant", "schema", "template"]],
        ],
    )

    dhcp_relay_policy = module.params.get("dhcp_relay_policy")
    ip = module.params.get("ip")
    tenant = module.params.get("tenant")
    schema = module.params.get("schema")
    template = module.params.get("template")
    if template is not None:
        template = template.replace(" ", "")
    application_profile = module.params.get("application_profile")
    endpoint_group = module.params.get("endpoint_group")
    external_endpoint_group = module.params.get("external_endpoint_group")
    state = module.params.get("state")

    mso = MSOModule(module)

    path = "policies/dhcp/relay"

    tenant_id = mso.lookup_tenant(tenant)
    # Get schema_id
    schema_id = mso.lookup_schema(schema)

    provider = dict(
        addr=ip,
        externalEpgRef="",
        epgRef="",
        l3Ref="",
        tenantId=tenant_id,
    )
    provider_index = None
    previous_provider = {}

    if application_profile is not None and endpoint_group is not None:
        provider["epgRef"] = "/schemas/{schemaId}/templates/{templateName}/anps/{app}/epgs/{epg}".format(
            schemaId=schema_id,
            templateName=template,
            app=application_profile,
            epg=endpoint_group,
        )
    elif external_endpoint_group is not None:
        provider["externalEpgRef"] = "/schemas/{schemaId}/templates/{templateName}/externalEpgs/{ext_epg}".format(
            schemaId=schema_id, templateName=template, ext_epg=external_endpoint_group
        )

    # Query for existing object(s)
    dhcp_relay_obj = mso.get_obj(path, name=dhcp_relay_policy, key="DhcpRelayPolicies")
    if "id" not in dhcp_relay_obj:
        mso.fail_json(msg="DHCP Relay Policy '{0}' is not a valid DHCP Relay Policy name.".format(dhcp_relay_policy))
    policy_id = dhcp_relay_obj.get("id")
    providers = []
    if "provider" in dhcp_relay_obj:
        providers = dhcp_relay_obj.get("provider")
        for index, prov in enumerate(providers):
            if (provider.get("epgRef") != "" and prov.get("epgRef") == provider.get("epgRef")) or (
                provider.get("externalEpgRef") != "" and prov.get("externalEpgRef") == provider.get("externalEpgRef")
            ):
                previous_provider = prov
                provider_index = index

    # If we found an existing object, continue with it
    path = "{0}/{1}".format(path, policy_id)

    if state == "query":
        mso.existing = providers
        if endpoint_group is not None or external_endpoint_group is not None:
            mso.existing = previous_provider
        mso.exit_json()

    if endpoint_group is None and external_endpoint_group is None:
        mso.fail_json(msg="Missing either endpoint_group or external_endpoint_group required attribute.")

    mso.previous = previous_provider
    if state == "absent":
        provider = {}
        if previous_provider:
            if provider_index is not None:
                providers.pop(provider_index)

    elif state == "present":
        if provider_index is not None:
            providers[provider_index] = provider
        else:
            providers.append(provider)

    if module.check_mode:
        mso.existing = provider
    else:
        mso.existing = dhcp_relay_obj
        dhcp_relay_obj["provider"] = providers
        mso.sanitize(dhcp_relay_obj, collate=True)
        new_dhcp_relay_obj = mso.request(path, method="PUT", data=mso.sent)
        mso.existing = {}
        for index, prov in enumerate(new_dhcp_relay_obj.get("provider")):
            if (provider.get("epgRef") != "" and prov.get("epgRef") == provider.get("epgRef")) or (
                provider.get("externalEpgRef") != "" and prov.get("externalEpgRef") == provider.get("externalEpgRef")
            ):
                mso.existing = prov

    mso.exit_json()


if __name__ == "__main__":
    main()
