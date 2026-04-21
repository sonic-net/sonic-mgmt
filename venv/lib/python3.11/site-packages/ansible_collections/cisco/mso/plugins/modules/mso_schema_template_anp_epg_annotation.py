#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Samita Bhattacharjee (@samiib) <samita@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_epg_annotation
short_description: Manage EPG Annotations on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Endpoint Group (EPG) Annotations on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.0 (NDO v4.2) and later.
author:
- Samita Bhattacharjee (@samiib)
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
  anp:
    description:
    - The name of the Application Network Profile (ANP).
    type: str
    required: true
  epg:
    description:
    - The name of the EPG to manage.
    type: str
    required: true
  annotation_key:
    description:
    - The key of the Annotation object.
    type: str
    aliases: [ key ]
  annotation_value:
    description:
    - The value of the Annotation object.
    type: str
    aliases: [ value ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
notes:
- The O(schema), O(template), O(anp) and O(epg) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template) to create the schema and template.
  Use M(cisco.mso.mso_schema_template_anp) to create the ANP.
  Use M(cisco.mso.mso_schema_template_anp_epg) to create the EPG.
seealso:
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_anp_epg
"""

EXAMPLES = r"""
- name: Add an annotation with key and value
  cisco.mso.mso_schema_template_anp_epg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    annotation_key: annotation_key_1
    annotation_value: annotation_value_1
    state: present

- name: Update an annotation value with key
  cisco.mso.mso_schema_template_anp_epg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    annotation_key: annotation_key_1
    annotation_value: annotation_value_1_updated
    state: present

- name: Query a specific annotation with key
  cisco.mso.mso_schema_template_anp_epg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    annotation_key: annotation_key_1
    state: query
  register: query_one

- name: Query all annotations
  cisco.mso.mso_schema_template_anp_epg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    state: query
  register: query_all

- name: Delete an annotation
  cisco.mso.mso_schema_template_anp_epg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    annotation_key: annotation_key_1
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", required=True),
        annotation_key=dict(type="str", aliases=["key"], no_log=False),
        annotation_value=dict(type="str", aliases=["value"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["annotation_key"]],
            ["state", "present", ["annotation_key", "annotation_value"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    annotation_key = module.params.get("annotation_key")
    annotation_value = module.params.get("annotation_value")
    state = module.params.get("state")

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_epg(epg)

    if annotation_key:
        mso_schema.set_template_anp_epg_annotation(annotation_key, False)
        annotation = mso_schema.schema_objects.get("template_anp_epg_annotation")
        if annotation is not None:
            mso.existing = mso.previous = copy.deepcopy(annotation.details)  # Query a specific Annotation
    else:
        epg_object = mso_schema.schema_objects["template_anp_epg"]
        mso.existing = epg_object.details.get("tagAnnotations", [])  # Query all

    path = "/templates/{0}/anps/{1}/epgs/{2}/tagAnnotations".format(template, anp, epg)

    ops = []
    if state == "present":
        mso_values = {"tagKey": annotation_key, "tagValue": annotation_value}
        mso.sanitize(mso_values)
        if mso.existing:
            if annotation_value is not None and mso.existing.get("tagValue") != annotation_value:
                ops.append({"op": "replace", "path": "{0}/{1}".format(path, annotation.index), "value": mso_values})

        else:
            ops.append({"op": "add", "path": "{0}/-".format(path), "value": mso_values})
    elif state == "absent":
        if mso.existing:
            ops.append({"op": "remove", "path": "{0}/{1}".format(path, annotation.index)})

    if not module.check_mode and ops:
        mso.request(mso_schema.path, method="PATCH", data=ops)
        mso.existing = mso.proposed
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
