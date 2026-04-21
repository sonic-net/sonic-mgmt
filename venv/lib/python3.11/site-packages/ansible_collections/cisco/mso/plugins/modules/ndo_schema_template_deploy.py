#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_schema_template_deploy
short_description: Deploy schema templates to sites for NDO v3.7 and higher
description:
- Deploy schema templates to sites.
- Prior to deploy or redeploy a schema validation is executed.
- When schema validation fails, M(cisco.mso.ndo_schema_template_deploy) fails and deploy or redeploy will not be executed.
- Only supports NDO v3.7 and higher
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
  sites:
    description:
    - The name of the site(s).
    type: list
    elements: str
  state:
    description:
    - Use C(deploy) to deploy schema template.
    - Use C(redeploy) to redeploy schema template.
    - Use C(undeploy) to undeploy schema template from a site.
    - Use C(query) to get deployment status.
    type: str
    choices: [ deploy, redeploy, undeploy, query ]
    default: deploy
seealso:
- module: cisco.mso.mso_schema_site
- module: cisco.mso.mso_schema_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Deploy a schema template
  cisco.mso.ndo_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: deploy

- name: Redeploy a schema template
  cisco.mso.ndo_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: redeploy

- name: Undeploy a schema template
  cisco.mso.ndo_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    sites: [Site1, Site2]
    state: undeploy

- name: Query a schema template deploy status
  cisco.mso.ndo_schema_template_deploy:
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


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        sites=dict(type="list", elements="str"),
        state=dict(type="str", default="deploy", choices=["deploy", "redeploy", "undeploy", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "undeploy", ["sites"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    sites = module.params.get("sites")
    state = module.params.get("state")

    mso = MSOModule(module)
    schema_id = mso.lookup_schema(schema)

    if state == "query":
        path = "status/schema/{0}/template/{1}".format(schema_id, template)
        method = "GET"
        payload = None
    else:
        path = "task"
        method = "POST"
        payload = dict(schemaId=schema_id, templateName=template)
        if state == "deploy":
            mso.validate_schema(schema_id)
            payload.update(isRedeploy=False)
        elif state == "redeploy":
            mso.validate_schema(schema_id)
            payload.update(isRedeploy=True)
        elif state == "undeploy":
            payload.update(undeploy=[site.get("siteId") for site in mso.lookup_sites(sites)])

    if not module.check_mode:
        mso.existing = mso.request(path, method=method, data=payload)
    mso.exit_json()


if __name__ == "__main__":
    main()
