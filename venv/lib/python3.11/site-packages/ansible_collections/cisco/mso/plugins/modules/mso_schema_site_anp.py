#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_anp
short_description: Manage site-local Application Network Profiles (ANPs) in schema template
description:
- Manage site-local ANPs in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
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
    - The name of the ANP to manage.
    type: str
    aliases: [ name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_site
- module: cisco.mso.mso_schema_site_anp_epg
- module: cisco.mso.mso_schema_template_anp
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site ANP
  cisco.mso.mso_schema_site_anp:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    state: present

- name: Remove a site ANP
  cisco.mso.mso_schema_site_anp:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    state: absent

- name: Query a specific site ANP
  cisco.mso.mso_schema_site_anp:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    state: query
  register: query_result

- name: Query all site ANPs
  cisco.mso.mso_schema_site_anp:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
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
        anp=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["anp"]],
            ["state", "present", ["anp"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

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

    # Get ANP
    anp_ref = mso.anp_ref(schema_id=schema_id, template=template, anp=anp)
    anps = [a.get("anpRef") for a in schema_obj.get("sites")[site_idx]["anps"]]

    if anp is not None and anp_ref in anps:
        anp_idx = anps.index(anp_ref)
        anp_path = "/sites/{0}/anps/{1}".format(site_template, anp)
        mso.existing = schema_obj.get("sites")[site_idx]["anps"][anp_idx]

    if state == "query":
        if anp is None:
            mso.existing = schema_obj.get("sites")[site_idx]["anps"]
        elif not mso.existing:
            mso.fail_json(msg="ANP '{anp}' not found".format(anp=anp))
        mso.exit_json()

    anps_path = "/sites/{0}/anps".format(site_template)
    ops = []

    # Workaround due to inconsistency in attributes REQUEST/RESPONSE API
    # FIX for MSO Error 400: Bad Request: (0)(0)(0)(0)/deploymentImmediacy error.path.missing
    mso.replace_keys_in_dict("deployImmediacy", "deploymentImmediacy")
    if mso.existing.get("anpRef"):
        anp_ref = mso.dict_from_ref(mso.existing.get("anpRef"))
        mso.existing["anpRef"] = anp_ref

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=anp_path))

    elif state == "present":
        payload = dict(
            anpRef=dict(
                schemaId=schema_id,
                templateName=template,
                anpName=anp,
            ),
        )

        if "epgs" in mso.existing:
            for epg in mso.existing.get("epgs"):
                epg = mso.recursive_dict_from_ref(epg)

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=anp_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=anps_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
