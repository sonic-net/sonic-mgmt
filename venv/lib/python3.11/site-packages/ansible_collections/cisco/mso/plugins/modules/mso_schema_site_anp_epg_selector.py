#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_anp_epg_selector
short_description: Manage site-local EPG selector in schema templates
description:
- Manage EPG selector in schema template on Cisco ACI Multi-Site.
author:
- Cindy Zhao (@cizhao)
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
        - The type of the expression.
        - The type is custom or is one of region, zone and ip_address
        - The type can be zone only when the site is AWS.
        required: true
        type: str
        aliases: [ tag ]
      operator:
        description:
        - The operator associated to the expression.
        - Operator has_key or does_not_have_key is only available for custom type / tag
        required: true
        type: str
        choices: [ not_in, in, equals, not_equals, has_key, does_not_have_key ]
      value:
        description:
        - The value associated to the expression.
        - If the operator is in or not_in, the value should be a comma separated string.
        type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_site_anp_epg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a selector to a site EPG
  cisco.mso.mso_schema_site_anp_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    site: Site 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    selector: selector_1
    expressions:
      - type: expression_1
        operator: in
        value: test
    state: present

- name: Remove a Selector from a site EPG
  cisco.mso.mso_schema_site_anp_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    site: Site 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    selector: selector_1
    state: absent

- name: Query a specific Selector
  cisco.mso.mso_schema_site_anp_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    site: Site 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    selector: selector_1
    state: query
  register: query_result

- name: Query all Selectors
  cisco.mso.mso_schema_site_anp_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    site: Site 1
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
    "ip_address": "ipAddress",
    "region": "region",
    "zone": "zone",
}

EXPRESSION_OPERATORS = {
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
        site=dict(type="str", required=True),
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
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    selector = module.params.get("selector")
    expressions = module.params.get("expressions")
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

    # Get cloud type
    site_type = mso.get_obj("sites", name=site).get("cloudProviders")[0]

    # Get site_idx
    if not schema_obj.get("sites"):
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get("siteId"), s.get("templateName")) for s in schema_obj.get("sites")]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided site-template association '{0}-{1}' does not exist.".format(site, template))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(site_id, template)

    payload = dict()
    ops = []
    op_path = ""
    selector_path = None

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
        op_path = "/sites/{0}/anps/-".format(site_template)
        payload.update(
            anpRef=dict(
                schemaId=schema_id,
                templateName=template,
                anpName=anp,
            ),
        )

    else:
        # Get anp index at site level
        anp_idx = anps.index(anp_ref)

    # Get EPG
    epg_ref = mso.epg_ref(schema_id=schema_id, template=template, anp=anp, epg=epg)

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
            new_epg = dict(
                epgRef=dict(
                    schemaId=schema_id,
                    templateName=template,
                    anpName=anp,
                    epgName=epg,
                )
            )

            # If anp not in payload then, anp already exists at site level. New payload will only have new EPG payload
            if "anpRef" not in payload:
                op_path = "/sites/{0}/anps/{1}/epgs/-".format(site_template, anp)
                payload = new_epg
            else:
                # If anp in payload, anp exists at site level. Update payload with EPG payload
                payload["epgs"] = [new_epg]

    # Get index of EPG at site level
    else:
        epg_idx = epgs.index(epg_ref)

    # Get selectors
    # If anp at site level and epg is at site level
    if "anpRef" not in payload and "epgRef" not in payload:
        if selector and " " in selector:
            mso.fail_json(msg="There should not be any space in selector name.")
        selectors = [s.get("name") for s in schema_obj.get("sites")[site_idx]["anps"][anp_idx]["epgs"][epg_idx]["selectors"]]
        if selector in selectors:
            selector_idx = selectors.index(selector)
            selector_path = "/sites/{0}/anps/{1}/epgs/{2}/selectors/{3}".format(site_template, anp, epg, selector_idx)
            mso.existing = schema_obj["sites"][site_idx]["anps"][anp_idx]["epgs"][epg_idx]["selectors"][selector_idx]

    if state == "query":
        if "anpRef" in payload:
            mso.fail_json(msg="Anp '{anp}' does not exist in site level.".format(anp=anp))
        if "epgRef" in payload:
            mso.fail_json(msg="Epg '{epg}' does not exist in site level.".format(epg=epg))
        if selector is None:
            mso.existing = schema_obj["sites"][site_idx]["anps"][anp_idx]["epgs"][epg_idx]["selectors"]
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
        all_expressions = []
        if expressions:
            for expression in expressions:
                type = expression.get("type")
                operator = expression.get("operator")
                value = expression.get("value")
                if " " in type:
                    mso.fail_json(msg="There should not be any space in 'type' attribute of expression '{0}'".format(type))
                if operator in ["has_key", "does_not_have_key"] and value:
                    mso.fail_json(msg="Attribute 'value' is not supported for operator '{0}' in expression '{1}'".format(operator, type))
                if operator in ["not_in", "in", "equals", "not_equals"] and not value:
                    mso.fail_json(msg="Attribute 'value' needed for operator '{0}' in expression '{1}'".format(operator, type))
                if type in ["region", "zone", "ip_address"]:
                    if type == "zone" and site_type != "aws":
                        mso.fail_json(msg="Type 'zone' is only supported for aws")
                    if operator in ["has_key", "does_not_have_key"]:
                        mso.fail_json(msg="Operator '{0}' is not supported when expression type is '{1}'".format(operator, type))
                    type = EXPRESSION_KEYS.get(type)
                else:
                    type = "Custom:" + type
                all_expressions.append(
                    dict(
                        key=type,
                        operator=EXPRESSION_OPERATORS.get(operator),
                        value=value,
                    )
                )
        new_selector = dict(
            name=selector,
            expressions=all_expressions,
        )

        selectors_path = "/sites/{0}/anps/{1}/epgs/{2}/selectors/-".format(site_template, anp, epg)

        # if payload is empty, anp and epg already exist at site level
        if not payload:
            op_path = selectors_path
            payload = new_selector
        # if payload exist
        else:
            # if anp already exists at site level
            if "anpRef" not in payload:
                payload["selectors"] = [new_selector]
            else:
                payload["epgs"][0]["selectors"] = [new_selector]

        mso.sanitize(payload, collate=True)

        if mso.existing and selector_path:
            ops.append(dict(op="replace", path=selector_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=op_path, value=mso.sent))

        mso.existing = new_selector

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
