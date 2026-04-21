#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2023, Raman Babich <ramanbabich@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: digital_ocean_project_resource_info
short_description: Gather information about DigitalOcean Project Resources
description:
    - This module can be used to gather information about Project Resources.
author: "Raman Babich (@raman-babich)"
version_added: 1.25.0

options:
  id:
    description:
      - Project ID that can be used to identify and reference a project.
      - If C(id) and C(name) are not specified default project will be used.
    type: str
  name:
    description:
      - Project name that can be used to identify and reference a project.
      - If C(id) and C(name) are not specified default project will be used.
    type: str

extends_documentation_fragment:
- community.digitalocean.digital_ocean
"""

EXAMPLES = r"""
- name: Get project resources by id
  community.digitalocean.digital_ocean_project_resource_info:
    id: cb1ef55e-3cd8-4c7c-aa5d-07c32bf41627

- name: Get project resources by name
  community.digitalocean.digital_ocean_project_resource_info:
    name: my-project-name

- name: Get default project resources
  community.digitalocean.digital_ocean_project_resource_info:
"""

RETURN = r"""
data:
  description: "DigitalOcean project resources information"
  elements: dict
  returned: success
  type: list
  sample:
    - urn: "do:droplet:13457723"
      assigned_at: "2018-09-28T19:26:37Z"
      links:
        self: "https://api.digitalocean.com/v2/droplets/13457723"
      status: "ok"
    - urn: "do:domain:example.com"
      assigned_at: "2019-03-31T16:24:14Z"
      links:
        self: "https://api.digitalocean.com/v2/domains/example.com"
      status: "ok"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
    DigitalOceanProjects,
)


def run(module):
    rest = DigitalOceanHelper(module)
    projects = DigitalOceanProjects(module, rest)
    if module.params["id"]:
        err_msg, resources = projects.get_resources_by_id(module.params["id"])
    elif module.params["name"]:
        err_msg, resources = projects.get_resources_by_name(module.params["name"])
    else:
        err_msg, resources = projects.get_resources_of_default()

    if err_msg:
        module.fail_json(msg=err_msg)
    module.exit_json(data=resources["resources"])


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        name=dict(type="str"),
        id=dict(type="str"),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[("id", "name")],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
