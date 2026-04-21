#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_external_epg_selector
short_description: Manage External EPG selector in schema of cloud sites
description:
- Manage External EPG selector in schema of cloud sites on Cisco ACI Multi-Site.
author:
- Shreyas Srish (@shrsr)
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
  external_epg:
    description:
    - The name of the External EPG to be managed.
    type: str
    required: true
  site:
    description:
    - The name of the cloud site.
    type: str
    required: true
  selector:
    description:
    - The name of the selector.
    type: str
  expressions:
    description:
    - Expressions associated to this selector.
    type: list
    elements: dict
    suboptions:
      type:
        description:
        - The name of the expression which in this case is always IP address.
        required: true
        type: str
        choices: [ ip_address ]
      operator:
        description:
        - The operator associated with the expression which in this case is always equals.
        required: true
        type: str
        choices: [ equals ]
      value:
        description:
        - The value of the IP Address / Subnet associated with the expression.
        required: true
        type: str
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
- name: Add a selector to an External EPG
  cisco.mso.mso_schema_site_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_test
    template: Template1
    site: azure_ansible_test
    external_epg: ext1
    selector: test
    expressions:
      - type: ip_address
        operator: equals
        value: 10.0.0.0
    state: present

- name: Remove a Selector
  cisco.mso.mso_schema_site_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_test
    template: Template1
    site: azure_ansible_test
    external_epg: ext1
    selector: test
    state: absent

- name: Query a specific Selector
  cisco.mso.mso_schema_site_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_test
    template: Template1
    site: azure_ansible_test
    external_epg: ext1
    selector: selector_1
    state: query
  register: query_result

- name: Query all Selectors
  cisco.mso.mso_schema_site_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_test
    template: Template1
    site: azure_ansible_test
    external_epg: ext1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_expression_spec_ext_epg


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        site=dict(type="str", required=True),
        external_epg=dict(type="str", required=True),
        selector=dict(type="str"),
        expressions=dict(type="list", elements="dict", options=mso_expression_spec_ext_epg()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    site = module.params.get("site")
    external_epg = module.params.get("external_epg")
    selector = module.params.get("selector")
    expressions = module.params.get("expressions")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(
            msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=", ".join(templates))
        )

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

    payload = dict()
    op_path = ""
    selector_path = None

    # Get External EPG
    ext_epg_ref = mso.ext_epg_ref(schema_id=schema_id, template=template, external_epg=external_epg)
    external_epgs = [e.get("externalEpgRef") for e in schema_obj.get("sites")[site_idx]["externalEpgs"]]

    if ext_epg_ref not in external_epgs:
        op_path = "/sites/{0}/externalEpgs/-".format(site_template)
        payload = dict(
            externalEpgRef=dict(
                schemaId=schema_id,
                templateName=template,
                externalEpgName=external_epg,
            ),
            l3outDn="",
        )

    else:
        external_epg_idx = external_epgs.index(ext_epg_ref)

        # Get Selector
        selectors = [s.get("name") for s in schema_obj["sites"][site_idx]["externalEpgs"][external_epg_idx]["subnets"]]
        if selector in selectors:
            selector_idx = selectors.index(selector)
            selector_path = "/sites/{0}/externalEpgs/{1}/subnets/{2}".format(site_template, external_epg, selector_idx)
            mso.existing = schema_obj["sites"][site_idx]["externalEpgs"][external_epg_idx]["subnets"][selector_idx]

    selectors_path = "/sites/{0}/externalEpgs/{1}/subnets/-".format(site_template, external_epg)
    ops = []

    if state == "query":
        if selector is None:
            mso.existing = schema_obj["sites"][site_idx]["externalEpgs"][external_epg_idx]["subnets"]
        elif not mso.existing:
            mso.fail_json(msg="Selector '{selector}' not found".format(selector=selector))
        mso.exit_json()

    mso.previous = mso.existing

    if state == "absent":
        if mso.existing and selector_path:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=selector_path))

    elif state == "present":
        # Get expressions
        types = dict(ip_address="ipAddress")
        all_expressions = []
        if expressions:
            for expression in expressions:
                type_val = expression.get("type")
                operator = expression.get("operator")
                value = expression.get("value")
                all_expressions.append(
                    dict(
                        key=types.get(type_val),
                        operator=operator,
                        value=value,
                    )
                )
        else:
            mso.fail_json(msg="Missing expressions in selector")

        subnets = dict(name=selector, ip=all_expressions[0]["value"])

        if not external_epgs:
            payload["subnets"] = [subnets]
        else:
            payload = subnets
            op_path = selectors_path

        mso.sanitize(payload, collate=True)

        if mso.existing and selector_path:
            ops.append(dict(op="replace", path=selector_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=op_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
