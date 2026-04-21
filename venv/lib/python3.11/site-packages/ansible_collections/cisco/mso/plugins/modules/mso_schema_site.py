#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site
short_description: Manage sites in schemas
description:
- Manage sites on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Shreyas Srish (@shrsr)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  site:
    description:
    - The name of the site to manage.
    type: str
    aliases: [ name ]
  template:
    description:
    - The name of the template.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_site
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site to a schema
  cisco.mso.mso_schema_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    site: Site1
    template: Template 1
    state: present

- name: Remove a site from a schema
  cisco.mso.mso_schema_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    site: Site1
    template: Template 1
    state: absent

- name: Query a schema site
  cisco.mso.mso_schema_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    site: Site1
    template: Template 1
    state: query
  register: query_result

- name: Query all schema sites
  cisco.mso.mso_schema_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
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
        site=dict(type="str", aliases=["name"]),
        template=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["site", "template"]],
            ["state", "present", ["site", "template"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template")
    if template is not None:
        template = template.replace(" ", "")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get site
    site_id = mso.lookup_site(site)

    mso.existing = {}
    site_path = None
    if "sites" in schema_obj:
        sites = [(s.get("siteId"), s.get("templateName")) for s in schema_obj.get("sites")]
        if template:
            if (site_id, template) in sites:
                site_idx = sites.index((site_id, template))
                site_path = "/sites/{0}".format(site_idx)
                mso.existing = schema_obj.get("sites")[site_idx]
        else:
            mso.existing = schema_obj.get("sites")

    if state == "query":
        if not mso.existing:
            if template:
                mso.fail_json(msg="Template '{0}' not found".format(template))
            else:
                mso.existing = []
        mso.exit_json()

    sites_path = "/sites"
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing and site_path:
            # Remove existing site
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=site_path))

    elif state == "present":
        if not mso.existing:
            # Add new site
            payload = dict(
                siteId=site_id,
                templateName=template,
                anps=[],
                bds=[],
                contracts=[],
                externalEpgs=[],
                intersiteL3outs=[],
                serviceGraphs=[],
                vrfs=[],
            )

            mso.sanitize(payload, collate=True)

            ops.append(dict(op="add", path=sites_path + "/-", value=mso.sent))

            mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
