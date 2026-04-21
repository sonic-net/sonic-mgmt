#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_deploy_status
short_description: Check query of objects before deployment to site
description:
- Check query of objects in a template of a schema
author:
- Shreyas Srish (@shrsr)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    aliases: [ name ]
  template:
    description:
    - The name of the template.
    type: str
  site:
    description:
    - The name of the site.
    type: str
  state:
    description:
    - Use C(query) for listing query of objects.
    type: str
    choices: [ query ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""

- name: Query status of objects in a template
  cisco.mso.mso_schema_template_deploy_status:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: query
  register: query_result

- name: Query status of objects using site
  cisco.mso.mso_schema_template_deploy_status:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    site: ansible_test
    state: query
  register: query_result

- name: Query status of objects in a template associated with a site
  cisco.mso.mso_schema_template_deploy_status:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    site: ansible_test
    state: query
  register: query_result

- name: Query status of objects in all templates
  cisco.mso.mso_schema_template_deploy_status:
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
        schema=dict(type="str", aliases=["name"]),
        template=dict(type="str"),
        site=dict(type="str"),
        state=dict(type="str", default="query", choices=["query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "query", ["schema"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template")
    if template is not None:
        template = template.replace(" ", "")
    site = module.params.get("site")
    state = module.params.get("state")

    mso = MSOModule(module)

    schema_id = None
    path = "schemas"

    get_schema = mso.get_obj(path, displayName=schema)
    if get_schema:
        schema_id = get_schema.get("id")
        path = "schemas/{id}/policy-states".format(id=schema_id)
    else:
        mso.fail_json(msg="Schema '{0}' not found.".format(schema))

    if state == "query":
        get_data = mso.request(path, method="GET")
        mso.existing = []
        if template:
            for configuration_objects in get_data.get("policyStates"):
                if configuration_objects.get("templateName") == template:
                    mso.existing.append(configuration_objects)
            if not mso.existing:
                mso.fail_json(msg="Template '{0}' not found.".format(template))

        if site:
            mso.existing.clear()
            for configuration_objects in get_data.get("policyStates"):
                if configuration_objects.get("siteId") == mso.lookup_site(site):
                    if template:
                        if configuration_objects.get("templateName") == template:
                            mso.existing = configuration_objects
                    else:
                        mso.existing.append(configuration_objects)
            if template is not None and not mso.existing:
                mso.fail_json(msg="Provided Template '{0}' not associated with Site '{1}'.".format(template, site))

        if template is None and site is None:
            mso.existing = get_data

    mso.exit_json()


if __name__ == "__main__":
    main()
