#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_validate
short_description: Validate the schema before deploying it to site
description:
- This module is used to verify if a schema can be deployed to site without any error.
- This module can only be used on versions of MSO that are 3.3 or greater.
- Starting with MSO 3.3, the schema modules in this collection will skip some validation checks to allow part of the schema to be updated more easily.
- This module will check those validation after all changes have been made.
author:
- Anvitha Jain (@anvitha-jain)
version_added: "1.3.0"
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  state:
    description:
    - Use C(query) to validate deploying the schema.
    type: str
    default: query
    choices: [ query ]
seealso:
- module: cisco.mso.mso_schema
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Get Validation status
  mso_schema_validate:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    state: query
  register: query_validate
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        state=dict(type="str", default="query", choices=["query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    schema = module.params.get("schema")

    mso = MSOModule(module)

    mso.existing = mso.validate_schema(schema_id=mso.lookup_schema(schema))

    mso.exit_json()


if __name__ == "__main__":
    main()
