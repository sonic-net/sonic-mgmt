#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_anp_epg
short_description: Manage site-local Endpoint Groups (EPGs) in schema template
description:
- Manage site-local EPGs in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Gaspard Micol (@gmicol)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  site:
    description:
    - The name of the site.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  anp:
    description:
    - The name of the ANP.
    type: str
    required: true
  epg:
    description:
    - The name of the EPG to manage.
    type: str
    aliases: [ name ]
  private_link_label:
    description:
    - The private link label used to represent this subnet.
    - This parameter is available for MSO version greater than 3.3.
    type: str
  admin_state:
    description:
    - The EPG admin state.
    - Defaults to C(admin_up) when unset during creation.
    type: str
    choices: [ admin_up, admin_shut ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_site_anp
- module: cisco.mso.mso_schema_site_anp_epg_subnet
- module: cisco.mso.mso_schema_template_anp_epg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site EPG
  cisco.mso.mso_schema_site_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    state: present

- name: Remove a site EPG
  cisco.mso.mso_schema_site_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    state: absent

- name: Query a specific site EPGs
  cisco.mso.mso_schema_site_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    state: query
  register: query_result

- name: Query all site EPGs
  cisco.mso.mso_schema_site_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        private_link_label=dict(type="str"),
        admin_state=dict(type="str", choices=["admin_up", "admin_shut"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["epg"]],
            ["state", "present", ["epg"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    private_link_label = module.params.get("private_link_label")
    admin_state = module.params.get("admin_state")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if not schema_obj.get("sites"):
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get("siteId"), s.get("templateName")) for s in schema_obj.get("sites")]
    sites_list = [s.get("siteId") + "/" + s.get("templateName") for s in schema_obj.get("sites")]
    if (site_id, template) not in sites:
        mso.fail_json(
            msg="Provided site/siteId/template '{0}/{1}/{2}' does not exist. "
            "Existing siteIds/templates: {3}".format(site, site_id, template, ", ".join(sites_list))
        )

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(site_id, template)

    payload = {}
    ops = []
    op_path = ""
    epg_path = None

    # Get ANP
    anp_ref = mso.anp_ref(schema_id=schema_id, template=template, anp=anp)
    anps = [a.get("anpRef") for a in schema_obj["sites"][site_idx]["anps"]]
    anps_in_temp = [a.get("name") for a in schema_obj["templates"][template_idx]["anps"]]
    if anp not in anps_in_temp:
        mso.fail_json(msg="Provided anp '{0}' does not exist. Existing anps: {1}".format(anp, ", ".join(anps_in_temp)))
    else:
        # Get anp index at template level
        template_anp_idx = anps_in_temp.index(anp)

    # If anp not at site level but exists at template level
    if anp_ref not in anps:
        op_path = "/sites/{0}/anps".format(site_template)
        payload = dict(
            anpRef=dict(
                schemaId=schema_id,
                templateName=template,
                anpName=anp,
            ),
        )
    else:
        # Get anp index at site level
        anp_idx = anps.index(anp_ref)

    if epg is not None:
        # Get EPG
        epg_ref = mso.epg_ref(schema_id=schema_id, template=template, anp=anp, epg=epg)
        new_epg = dict(
            epgRef=dict(
                schemaId=schema_id,
                templateName=template,
                anpName=anp,
                epgName=epg,
            )
        )

        # If anp exists at site level
        if "anpRef" not in payload:
            epgs = [e.get("epgRef") for e in schema_obj["sites"][site_idx]["anps"][anp_idx]["epgs"]]

        # If anp already at site level AND if epg not at site level (or) anp not at site level?
        if ("anpRef" not in payload and epg_ref not in epgs) or "anpRef" in payload:
            epgs_in_temp = [e.get("name") for e in schema_obj["templates"][template_idx]["anps"][template_anp_idx]["epgs"]]

            # If EPG not at template level - Fail
            if epg not in epgs_in_temp:
                mso.fail_json(msg="Provided EPG '{0}' does not exist. Existing EPGs: {1}".format(epg, ", ".join(epgs_in_temp)))

            # EPG at template level but not at site level. Create payload at site level for EPG
            else:
                # If anp not in payload then, anp already exists at site level. New payload will only have new EPG payload
                if "anpRef" not in payload:
                    op_path = "/sites/{0}/anps/{1}/epgs".format(site_template, anp)
                    payload = new_epg
                else:
                    # If anp in payload, anp exists at site level. Update payload with EPG payload
                    payload["epgs"] = [new_epg]

        # Get index of EPG at site level
        else:
            epg_idx = epgs.index(epg_ref)
            epg_path = "/sites/{0}/anps/{1}/epgs/{2}".format(site_template, anp, epg)
            mso.existing = schema_obj.get("sites")[site_idx]["anps"][anp_idx]["epgs"][epg_idx]
            payload = new_epg

    ops = []

    if state == "query":
        if anp_ref not in anps:
            mso.fail_json(msg="Provided anp '{0}' does not exist at site level.".format(anp))
        if epg is None:
            mso.existing = schema_obj.get("sites")[site_idx]["anps"][anp_idx]["epgs"]
        elif not mso.existing:
            mso.fail_json(msg="EPG '{epg}' not found".format(epg=epg))
        mso.exit_json()

    # Workaround due to inconsistency in attributes REQUEST/RESPONSE API
    # FIX for MSO Error 400: Bad Request: (0)(0)(0)(0)/deploymentImmediacy error.path.missing
    mso.replace_keys_in_dict("deployImmediacy", "deploymentImmediacy")
    if mso.existing.get("epgRef"):
        epg_ref = mso.dict_from_ref(mso.existing.get("epgRef"))
        mso.existing["epgRef"] = epg_ref

    mso.previous = mso.existing

    if state == "absent":
        if mso.existing and epg_path:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=epg_path))

    elif state == "present":
        if private_link_label is not None:
            payload["privateLinkLabel"] = dict(name=private_link_label)
        if admin_state is not None:
            payload["shutdown"] = True if admin_state == "admin_shut" else False

        mso.sanitize(payload, collate=True)

        if mso.existing and epg_path:
            ops.append(dict(op="replace", path=epg_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=op_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
