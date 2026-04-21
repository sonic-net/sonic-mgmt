#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, 2023, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_external_epg
short_description: Manage External EPG in schema of sites.
description:
- Manage External EPG in schema of sites on Cisco ACI Multi-Site.
- This module can only be used on versions of MSO that are 3.3 or greater.
author:
- Anvitha Jain (@anvitha-jain)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template to change.
    type: str
    required: true
  l3out:
    description:
    - The L3Out associated with the external epg.
    - Required when site is of type on-premise.
    - In NDO versions over 4.2, the parameter is accessible only when an external EPG is
    - linked to the current schema-template's VRF.
    type: str
    aliases: [ l3out_name ]
  l3out_schema:
    description:
    - The schema that defines the referenced L3Out.
    - If this parameter is unspecified, it defaults to the current schema.
    type: str
  l3out_template:
    description:
    - The template that defines the referenced L3Out.
    - If this parameter is unspecified, it defaults to the current template.
    type: str
  l3out_on_apic:
    description:
    - If this parameter is specified, the constructed l3out reference will refer to a distinguished name (DN) in APIC.
    type: bool
  external_epg:
    description:
    - The name of the External EPG to be managed.
    type: str
    aliases: [ name ]
  site:
    description:
    - The name of the site.
    type: str
    required: true
  route_reachability:
    description:
    - Configures if an external EPG route is pointing to the internet or to an external remote network.
    - Only available when associated with an azure site.
    type: str
    choices: [ internet, site-ext ]
    default: internet
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_external_epg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a Site External EPG
  cisco.mso.mso_schema_site_external_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: External EPG 1
    l3out: L3out1
    state: present

- name: Remove a Site External EPG
  cisco.mso.mso_schema_site_external_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: External EPG 1
    l3out: L3out1
    state: absent

- name: Query a Site External EPG
  cisco.mso.mso_schema_site_external_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: External EPG 1
    l3out: L3out1
    state: query
  register: query_result

- name: Query all Site External EPGs
  cisco.mso.mso_schema_site_external_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        site=dict(type="str", required=True),
        l3out=dict(type="str", aliases=["l3out_name"]),
        l3out_schema=dict(type="str"),
        l3out_template=dict(type="str"),
        l3out_on_apic=dict(type="bool"),
        external_epg=dict(type="str", aliases=["name"]),
        route_reachability=dict(type="str", default="internet", choices=["internet", "site-ext"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["external_epg"]],
            ["state", "present", ["external_epg"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    site = module.params.get("site")
    external_epg = module.params.get("external_epg")
    l3out = module.params.get("l3out")
    l3out_schema = module.params.get("l3out_schema")
    l3out_template = module.params.get("l3out_template")
    l3out_on_apic = module.params.get("l3out_on_apic")
    route_reachability = module.params.get("route_reachability")
    state = module.params.get("state")

    mso = MSOModule(module)

    l3out_template = template if l3out_template is None else l3out_template.replace(" ", "")
    l3out_schema = schema if l3out_schema is None else l3out_schema
    l3out_schema_id = mso.lookup_schema(l3out_schema)

    mso_schema = MSOSchema(mso, schema, template, site)
    mso_objects = mso_schema.schema_objects

    mso_schema.set_template_external_epg(external_epg, fail_module=False)

    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(mso_objects.get("site").details.get("siteId"), template)

    payload = dict()
    op_path = "/sites/{0}/externalEpgs/-".format(site_template)

    # Get template External EPG
    if mso_objects.get("template_external_epg") is not None:
        ext_epg_ref = mso_objects.get("template_external_epg").details.get("externalEpgRef")
        external_epgs = [e.get("externalEpgRef") for e in mso_objects.get("site").details.get("externalEpgs")]

        # Get Site External EPG
        if ext_epg_ref in external_epgs:
            external_epg_idx = external_epgs.index(ext_epg_ref)
            mso.existing = mso_objects.get("site").details.get("externalEpgs")[external_epg_idx]
            op_path = "/sites/{0}/externalEpgs/{1}".format(site_template, external_epg)

    ops = []
    l3out_dn = ""
    if state == "query":
        if external_epg is None:
            mso.existing = mso_objects.get("site").details.get("externalEpgs")
        elif not mso.existing:
            mso.fail_json(msg="External EPG '{external_epg}' not found".format(external_epg=external_epg))
        mso.exit_json()

    mso.previous = mso.existing

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=op_path))

    elif state == "present":
        # Get external EPGs type from template level and verify template_external_epg type.
        if mso_objects.get("template_external_epg") is not None and mso_objects.get("template_external_epg").details.get("extEpgType") != "cloud":
            if l3out is not None:
                path = "tenants/{0}".format(mso_objects.get("template").details.get("tenantId"))
                tenant_name = mso.request(path, method="GET").get("name")
                l3out_dn = "uni/tn-{0}/out-{1}".format(tenant_name, l3out)
            else:
                mso.fail_json(msg="L3Out cannot be empty when template external EPG type is 'on-premise'.")

        payload = dict(
            externalEpgRef=dict(
                schemaId=mso_schema.id,
                templateName=template,
                externalEpgName=external_epg,
            ),
            l3outDn=l3out_dn,
            routeReachabilityInternetType=route_reachability,
        )

        if not l3out_on_apic:
            payload.update(
                l3outRef=dict(
                    schemaId=l3out_schema_id,
                    templateName=l3out_template,
                    l3outName=l3out,
                ),
            )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=op_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=op_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
