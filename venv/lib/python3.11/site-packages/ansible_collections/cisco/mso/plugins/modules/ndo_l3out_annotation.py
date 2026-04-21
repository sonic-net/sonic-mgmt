#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_annotation
short_description: Manage L3Outs Annotation on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Outs Annotation on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be a L3Out template.
    type: str
    aliases: [ l3out_template ]
    required: true
  l3out:
    description:
    - The name of the L3Out.
    type: str
    aliases: [ l3out_name ]
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
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the L3Out template.
- The O(l3out) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_template) to create the L3Out.
"""

EXAMPLES = r"""
- name: Add an annotation with key and value
  cisco.mso.ndo_l3out_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_l3out_template
    l3out: "L3OutAnnotation"
    annotation_key: "annotation_key_1"
    annotation_value: "annotation_value_1"
    state: present

- name: Update an annotation with value
  cisco.mso.ndo_l3out_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_l3out_template
    l3out: "L3OutAnnotation"
    annotation_key: "annotation_key_1_updated"
    annotation_value: "annotation_value_1"
    state: present

- name: Query a specific annotation with key
  cisco.mso.ndo_l3out_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_l3out_template
    l3out: "L3OutAnnotation"
    annotation_key: "annotation_key_1_updated"
    state: query
  register: query_one

- name: Query all annotations
  cisco.mso.ndo_l3out_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_l3out_template
    l3out: "L3OutAnnotation"
    state: query
  register: query_all

- name: Delete an annotation
  cisco.mso.ndo_l3out_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_l3out_template
    l3out: "L3OutAnnotation"
    annotation_key: "annotation_key_1_updated"
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair


def get_annotation_object(mso_template_object, l3out_name, annotation_key):
    l3outs = mso_template_object.template.get("l3outTemplate", {}).get("l3outs", [])
    l3out_object = mso_template_object.get_object_by_key_value_pairs("L3Outs", l3outs, [KVPair("name", l3out_name)], True)
    annotations = l3out_object.details.get("tagAnnotations", [])
    if annotation_key:
        annotation = mso_template_object.get_object_by_key_value_pairs("L3Out Annotations", annotations, [KVPair("tagKey", annotation_key)])
        return l3out_object, annotation

    return l3out_object, annotations


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["l3out_template"]),
        l3out=dict(type="str", required=True, aliases=["l3out_name"]),
        annotation_key=dict(type="str", aliases=["key"], no_log=False),
        annotation_value=dict(type="str", aliases=["value"]),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["annotation_key"]],
            ["state", "present", ["annotation_key", "annotation_value"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    l3out = module.params.get("l3out")
    annotation_key = module.params.get("annotation_key")
    annotation_value = module.params.get("annotation_value")
    state = module.params.get("state")

    l3out_template_object = MSOTemplate(mso, "l3out", template)
    l3out_template_object.validate_template("l3out")

    l3out_object, annotation = get_annotation_object(l3out_template_object, l3out, annotation_key)

    if annotation_key:
        if annotation is not None:
            mso.existing = mso.previous = copy.deepcopy(annotation.details)  # Query a specific Annotation
    else:
        mso.existing = annotation  # Query all

    path = "/l3outTemplate/l3outs/{0}/tagAnnotations".format(l3out_object.index)

    ops = []
    if state == "present":
        if mso.existing:
            proposed_payload = copy.deepcopy(mso.existing)
            if annotation_value and proposed_payload.get("tagValue") != annotation_value:
                ops.append(dict(op="replace", path="{0}/{1}/tagValue".format(path, annotation.index), value=annotation_value))
                proposed_payload["tagValue"] = annotation_value
            mso.sanitize(proposed_payload)
        else:
            payload = {"tagKey": annotation_key, "tagValue": annotation_value}
            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))
            mso.sanitize(payload)
    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, annotation.index)))

    if not module.check_mode and ops:
        l3out_template_object.template = mso.request(l3out_template_object.template_path, method="PATCH", data=ops)
        l3out_object, annotation = get_annotation_object(l3out_template_object, l3out, annotation_key)

        if annotation:
            mso.existing = annotation.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
