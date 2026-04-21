#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akiniross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_vrf_rp
short_description: Manage VRF Rendezvous Points (RP) in schema templates.
description:
- Manage VRF Rendezvous Points (RP) in schema templates on Cisco ACI Multi-Site.
- RPs can only be configured when the VRF has Layer 3 Multicast is enabled.
author:
- Akini Ross (@akinross)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  vrf:
    description:
    - The name of the VRF.
    type: str
    required: true
  ip:
    description:
    - The IP address of the RP.
    type: str
    aliases: [ ip_address ]
  type:
    description:
    - The type of the RP.
    type: str
    choices: [ fabric, static ]
  multicast_route_map_policy:
    description:
    - The name of the Multicast Route Map Policy.
    - The Multicast Route Map Policy must reside in the same tenant as the tenant associated to the schema.
    - Use O(multicast_route_map_policy="") to remove the Multicast Route Map Policy.
    type: str
    aliases: [ route_map_policy ]
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
- name: Add a new VRF RP
  cisco.mso.mso_schema_template_vrf_rp:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    ip: 1.1.1.1
    type: static
    multicast_route_map_policy: RouteMapPolicy1
    state: present

- name: Query a specific VRF RP
  cisco.mso.mso_schema_template_vrf_rp:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    ip: 1.1.1.1
    state: query
  register: query_result

- name: Query all VRF RPs
  cisco.mso.mso_schema_template_vrf_rp:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    state: query
  register: query_result

- name: Remove an VRF RP
  cisco.mso.mso_schema_template_vrf_rp:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    ip: 1.1.1.1
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        vrf=dict(type="str", required=True),
        ip=dict(type="str", aliases=["ip_address"]),
        type=dict(type="str", choices=["fabric", "static"]),
        multicast_route_map_policy=dict(type="str", aliases=["route_map_policy"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ip"]],
            ["state", "present", ["ip", "type"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    ip = module.params.get("ip")
    rp_type = module.params.get("type")
    multicast_route_map_policy = module.params.get("multicast_route_map_policy")
    state = module.params.get("state")

    rps_path = "/templates/{0}/vrfs/{1}/rpConfigs".format(template, vrf)

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_vrf(vrf)

    if state == "query":
        if ip:
            mso_schema.set_template_vrf_rp(ip)
            mso.existing = mso_schema.schema_objects.get("template_vrf_rp").details
        else:
            mso.existing = mso_schema.schema_objects.get("template_vrf").details.get("rpConfigs", [])
        mso.exit_json()

    mso_schema.set_template_vrf_rp(ip, False)

    rp = mso_schema.schema_objects.get("template_vrf_rp")
    ops = []

    mso.existing = mso.previous = rp.details if rp else mso.existing

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path="{0}/{1}".format(rps_path, rp.index)))

    elif state == "present":

        payload = dict(ipAddress=ip, rpType=rp_type)

        if multicast_route_map_policy:
            payload["mcastRtMapPolicyRef"] = get_route_map_uuid(
                mso, mso_schema.schema_objects.get("template").details.get("tenantId"), multicast_route_map_policy
            )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            rp_path = "{0}/{1}".format(rps_path, rp.index)
            if rp_type != mso.existing.get("rpType"):
                ops.append(dict(op="replace", path=rp_path + "/rpType", value=rp_type))
            if multicast_route_map_policy and payload.get("mcastRtMapPolicyRef") != mso.existing.get("mcastRtMapPolicyRef"):
                ops.append(
                    dict(
                        op="replace" if mso.existing.get("mcastRtMapPolicyRef") is not None else "add",
                        path=rp_path + "/mcastRtMapPolicyRef",
                        value=payload.get("mcastRtMapPolicyRef"),
                    )
                )
            if multicast_route_map_policy == "":
                ops.append(dict(op="remove", path=rp_path + "/mcastRtMapPolicyRef"))
        else:
            ops.append(dict(op="add", path=rps_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


def get_route_map_uuid(mso, tenant_id, multicast_route_map_policy):

    # Only tenant type templates contain the correct route map policies
    # Retrieves the list templates that contain the same tenant because only route map policies for the tenant assigned to the schema are options to be chosen
    templates = [
        MSOTemplate(mso, template_id=template.get("templateId")) for template in MSOTemplate(mso, "tenant").template if template.get("tenantId") == tenant_id
    ]

    # NDO restricts route map policies in the same tenant to have the same name thus we can loop through the route map policies to find the correct uuid
    for template in templates:
        for route_map_policy in template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("mcastRouteMapPolicies", []):
            if route_map_policy.get("name") == multicast_route_map_policy:
                return route_map_policy.get("uuid")

    mso.fail_json(msg="Multicast Route Map Policy '{0}' not found.".format(multicast_route_map_policy))


if __name__ == "__main__":
    main()
