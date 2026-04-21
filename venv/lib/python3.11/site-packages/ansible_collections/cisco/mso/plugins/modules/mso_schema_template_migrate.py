#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_migrate
short_description: Migrate Bridge Domains (BDs) and EPGs between templates
description:
- Migrate BDs and EPGs between templates of same and different schemas.
author:
- Anvitha Jain (@anvitha-jain)
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
  bds:
    description:
    - The name of the BDs to migrate.
    type: list
    elements: str
  epgs:
    description:
    - The name of the EPGs and the ANP it is in to migrate.
    type: list
    elements: dict
    suboptions:
      epg:
        description:
        - The name of the EPG to migrate.
        type: str
        required: true
      anp:
        description:
        - The name of the anp to migrate.
        type: str
        required: true
  target_schema:
    description:
    - The name of the target_schema.
    type: str
    required: true
  target_template:
    description:
    - The name of the target_template.
    type: str
    required: true
  state:
    description:
    - Use C(present) for adding.
    type: str
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Migration of objects between templates of same schema
  mso_schema_template_migrate:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    target_schema: Schema 1
    target_template: Template 2
    bds:
      - BD
    epgs:
      - epg: EPG1
        anp: ANP
    state: present

- name: Migration of objects between templates of different schema
  mso_schema_template_migrate:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    target_schema: Schema 2
    target_template: Template 2
    bds:
      - BD
    epgs:
      - epg: EPG1
        anp: ANP
    state: present

- name: Migration of BD object between templates of same schema
  mso_schema_template_migrate:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    target_schema: Schema 1
    target_template: Template 2
    bds:
      - BD
      - BD1
    state: present

- name: Migration of BD object between templates of different schema
  mso_schema_template_migrate:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    target_schema: Schema 2
    target_template: Template 2
    bds:
      - BD
      - BD1
    state: present

- name: Migration of EPG objects between templates of same schema
  mso_schema_template_migrate:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    target_schema: Schema 2
    target_template: Template 2
    epgs:
      - epg: EPG1
        anp: ANP
      - epg: EPG2
        anp: ANP2
    state: present

- name: Migration of EPG objects between templates of different schema
  mso_schema_template_migrate:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    target_schema: Schema 2
    target_template: Template 2
    epgs:
      - epg: EPG1
        anp: ANP
      - epg: EPG2
        anp: ANP2
    state: present
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_object_migrate_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        bds=dict(type="list", elements="str"),
        epgs=dict(type="list", elements="dict", options=mso_object_migrate_spec()),
        target_schema=dict(type="str", required=True),
        target_template=dict(type="str", required=True),
        state=dict(type="str", default="present"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    target_schema = module.params.get("target_schema")
    target_template = module.params.get("target_template").replace(" ", "")
    bds = module.params.get("bds")
    epgs = module.params.get("epgs")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema_id
    schema_id = mso.lookup_schema(schema)

    target_schema_id = mso.lookup_schema(target_schema)

    if state == "present":
        if schema_id is not None:
            bds_payload = []
            if bds is not None:
                for bd in bds:
                    bds_payload.append(dict(name=bd))

            anp_dict = {}
            if epgs is not None:
                for epg in epgs:
                    if epg.get("anp") in anp_dict:
                        anp_dict[epg.get("anp")].append(dict(name=epg.get("epg")))
                    else:
                        anp_dict[epg.get("anp")] = [dict(name=epg.get("epg"))]

            anps_payload = []
            for anp, epgs_payload in anp_dict.items():
                anps_payload.append(dict(name=anp, epgs=epgs_payload))

            payload = dict(
                targetSchemaId=target_schema_id,
                targetTemplateName=target_template,
                bds=bds_payload,
                anps=anps_payload,
            )

            template = template.replace(" ", "%20")

            target_template = target_template.replace(" ", "%20")  # removes API error for extra space

            mso.existing = mso.request(path="migrate/schema/{0}/template/{1}".format(schema_id, template), method="POST", data=payload)

    mso.exit_json()


if __name__ == "__main__":
    main()
