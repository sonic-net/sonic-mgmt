#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_version
short_description: Get version of MSO
description:
- Retrieve the code version of Cisco Multi-Site Orchestrator.
author:
- Lionel Hercot (@lhercot)
options:
  state:
    description:
    - Use C(query) for retrieving the version object.
    type: str
    choices: [ query ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Get MSO version
  cisco.mso.mso_version:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(state=dict(type="str", default="query", choices=["query"]))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    mso = MSOModule(module)

    path = "platform/version"

    # Query for mso.existing object
    mso.existing = mso.query_obj(path)
    mso.exit_json()


if __name__ == "__main__":
    main()
