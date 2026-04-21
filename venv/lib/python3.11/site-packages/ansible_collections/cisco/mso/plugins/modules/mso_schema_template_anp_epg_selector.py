#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_epg_selector
short_description: Manage EPG selector in schema templates
description:
- Manage EPG selector in schema templates on Cisco ACI Multi-Site.
author:
- Cindy Zhao (@cizhao)
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
  anp:
    description:
    - The name of the ANP.
    type: str
    required: true
  epg:
    description:
    - The name of the EPG to manage.
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
        - The name of the expression.
        required: true
        type: str
        aliases: [ tag ]
      operator:
        description:
        - The operator associated to the expression.
        required: true
        type: str
        choices: [ not_in, in, equals, not_equals, has_key, does_not_have_key ]
      value:
        description:
        - The value associated to the expression.
        - If the operator is in or not_in, the value should be a comma separated str.
        type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_anp_epg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a selector to an EPG
  cisco.mso.mso_schema_template_anp_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    selector: selector_1
    expressions:
      - type: expression_1
        operator: in
        value: test
    state: present

- name: Remove a Selector
  cisco.mso.mso_schema_template_anp_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    selector: selector_1
    state: absent

- name: Query a specific Selector
  cisco.mso.mso_schema_template_anp_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    selector: selector_1
    state: query
  register: query_result

- name: Query all Selectors
  cisco.mso.mso_schema_template_anp_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_expression_spec

EXPRESSION_KEYS = {
    "not_in": "notIn",
    "not_equals": "notEquals",
    "has_key": "keyExist",
    "does_not_have_key": "keyNotExist",
    "in": "in",
    "equals": "equals",
}


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", required=True),
        selector=dict(type="str"),
        expressions=dict(type="list", elements="dict", options=mso_expression_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["selector"]],
            ["state", "present", ["selector"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    selector = module.params.get("selector")
    expressions = module.params.get("expressions")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(
            msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=", ".join(templates))
        )
    template_idx = templates.index(template)

    # Get ANP
    anps = [a.get("name") for a in schema_obj.get("templates")[template_idx]["anps"]]
    if anp not in anps:
        mso.fail_json(msg="Provided anp '{anp}' does not exist. Existing anps: {anps}".format(anp=anp, anps=", ".join(anps)))
    anp_idx = anps.index(anp)

    # Get EPG
    epgs = [e.get("name") for e in schema_obj.get("templates")[template_idx]["anps"][anp_idx]["epgs"]]
    if epg not in epgs:
        mso.fail_json(msg="Provided epg '{epg}' does not exist. Existing epgs: {epgs}".format(epg=epg, epgs=", ".join(epgs)))
    epg_idx = epgs.index(epg)

    # Get Selector
    if selector and " " in selector:
        mso.fail_json(msg="There should not be any space in selector name.")
    selectors = [s.get("name") for s in schema_obj.get("templates")[template_idx]["anps"][anp_idx]["epgs"][epg_idx]["selectors"]]
    if selector in selectors:
        selector_idx = selectors.index(selector)
        selector_path = "/templates/{0}/anps/{1}/epgs/{2}/selectors/{3}".format(template, anp, epg, selector_idx)
        mso.existing = schema_obj.get("templates")[template_idx]["anps"][anp_idx]["epgs"][epg_idx]["selectors"][selector_idx]

    if state == "query":
        if selector is None:
            mso.existing = schema_obj.get("templates")[template_idx]["anps"][anp_idx]["epgs"][epg_idx]["selectors"]
        elif not mso.existing:
            mso.fail_json(msg="Selector '{selector}' not found".format(selector=selector))
        mso.exit_json()

    selectors_path = "/templates/{0}/anps/{1}/epgs/{2}/selectors/-".format(template, anp, epg)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        mso.sent = mso.existing = {}
        ops.append(dict(op="remove", path=selector_path))

    elif state == "present":
        # Get expressions
        all_expressions = []
        if expressions:
            for expression in expressions:
                tag = expression.get("type")
                operator = expression.get("operator")
                value = expression.get("value")
                if " " in tag:
                    mso.fail_json(msg="There should not be any space in 'type' attribute of expression '{0}'".format(tag))
                if operator in ["has_key", "does_not_have_key"] and value:
                    mso.fail_json(msg="Attribute 'value' is not supported for operator '{0}' in expression '{1}'".format(operator, tag))
                if operator in ["not_in", "in", "equals", "not_equals"] and not value:
                    mso.fail_json(msg="Attribute 'value' needed for operator '{0}' in expression '{1}'".format(operator, tag))
                all_expressions.append(
                    dict(
                        key="Custom:" + tag,
                        operator=EXPRESSION_KEYS.get(operator),
                        value=value,
                    )
                )

        payload = dict(
            name=selector,
            expressions=all_expressions,
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=selector_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=selectors_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
