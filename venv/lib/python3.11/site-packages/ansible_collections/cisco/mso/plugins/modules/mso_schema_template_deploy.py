#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["deprecated"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_deploy
short_description: Deploy schema templates to sites
description:
- Deploy schema templates to sites.
- Prior to deploy a schema validation is executed for MSO releases running on the ND platform.
- When schema validation fails, M(cisco.mso.mso_schema_template_deploy) fails and deploy will not be executed.
author:
- Dag Wieers (@dagwieers)
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
    aliases: [ name ]
  site:
    description:
    - The name of the site B(to undeploy).
    type: str
  state:
    description:
    - Use C(deploy) to deploy schema template.
    - Use C(status) to get deployment status.
    - Use C(undeploy) to deploy schema template from a site.
    type: str
    choices: [ deploy, status, undeploy ]
    default: deploy

deprecated:
  removed_in: '3.0.0'
  why: Due to changes in the ND and NDO API, a new module (cisco.mso.ndo_schema_template_deploy) has been released for
    ND v2.2 (NDO v4.1) and later.
  alternative: Use M(cisco.mso.ndo_schema_template_deploy) instead.
seealso:
- module: cisco.mso.mso_schema_site
- module: cisco.mso.mso_schema_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Deploy a schema template
  cisco.mso.mso_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: deploy

- name: Undeploy a schema template
  cisco.mso.mso_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    site: Site 1
    state: undeploy

- name: Get deployment status
  cisco.mso.mso_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: status
  register: status_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True, aliases=["name"]),
        site=dict(type="str"),
        state=dict(type="str", default="deploy", choices=["deploy", "status", "undeploy"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "undeploy", ["site"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    site = module.params.get("site")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema id
    schema_id = mso.lookup_schema(schema)

    payload = dict(
        schemaId=schema_id,
        templateName=template,
    )

    qs = None
    if state == "deploy":
        if mso.platform == "nd":
            mso.validate_schema(schema_id)
        path = "execute/schema/{0}/template/{1}".format(schema_id, template)
    elif state == "status":
        path = "status/schema/{0}/template/{1}".format(schema_id, template)
    elif state == "undeploy":
        path = "execute/schema/{0}/template/{1}".format(schema_id, template)
        site_id = mso.lookup_site(site)
        qs = dict(undeploy=site_id)

    if not module.check_mode:
        status = mso.request(path, method="GET", data=payload, qs=qs)
        mso.exit_json(**status)
    else:
        mso.exit_json()


if __name__ == "__main__":
    main()
