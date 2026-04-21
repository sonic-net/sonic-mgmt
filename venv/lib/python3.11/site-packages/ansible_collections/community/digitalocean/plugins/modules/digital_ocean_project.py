#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: digital_ocean_project
short_description: Manage a DigitalOcean project
description:
     - Manage a project in DigitalOcean
author: "Tyler Auerbeck (@tylerauerbeck)"
version_added: 1.6.0

options:
  state:
    description:
      - Indicate desired state of the target.
      - C(present) will create the project
      - C(absent) will delete the project, if it exists.
    default: present
    choices: ['present', 'absent']
    type: str
  oauth_token:
    description:
      - DigitalOcean OAuth token. Can be specified in C(DO_API_KEY), C(DO_API_TOKEN), or C(DO_OAUTH_TOKEN) environment variables
    aliases: ['API_TOKEN']
    type: str
    required: true
  environment:
    description:
      - The environment of the projects resources.
    choices: ['Development', 'Staging', 'Production']
    type: str
  is_default:
    description:
      - If true, all resources will be added to this project if no project is specified.
    default: False
    type: bool
  name:
    description:
      - The human-readable name for the project. The maximum length is 175 characters and the name must be unique.
    type: str
  id:
    description:
      - UUID of the project
    type: str
  purpose:
    description:
      - The purpose of the project. The maximum length is 255 characters
      - Required if state is C(present)
      - If not one of DO provided purposes, will be prefixed with C(Other)
      - DO provided purposes can be found below
      - C(Just trying out DigitalOcean)
      - C(Class project/Educational Purposes)
      - C(Website or blog)
      - C(Web Application)
      - C(Service or API)
      - C(Mobile Application)
      - C(Machine Learning/AI/Data Processing)
      - C(IoT)
      - C(Operational/Developer tooling)
    type: str
  description:
    description:
      - The description of the project. The maximum length is 255 characters.
    type: str
"""


EXAMPLES = r"""
# Creates a new project
- community.digitalocean.digital_ocean_project:
    name: "TestProj"
    state: "present"
    description: "This is a test project"
    purpose: "IoT"
    environment: "Development"

# Updates the existing project with the new environment
- community.digitalocean.digital_ocean_project:
    name: "TestProj"
    state: "present"
    description: "This is a test project"
    purpose: "IoT"
    environment: "Production"

# This renames an existing project by utilizing the id of the project
- community.digitalocean.digital_ocean_project:
    name: "TestProj2"
    id: "12312312-abcd-efgh-ijkl-123123123123"
    state: "present"
    description: "This is a test project"
    purpose: "IoT"
    environment: "Development"

# This creates a project that results with a purpose of "Other: My Prod App"
- community.digitalocean.digital_ocean_project:
    name: "ProdProj"
    state: "present"
    description: "This is a prod app"
    purpose: "My Prod App"
    environment: "Production"

# This removes a project
- community.digitalocean.digital_ocean_project:
    name: "ProdProj"
    state: "absent"
"""

RETURN = r"""
# Digital Ocean API info https://docs.digitalocean.com/reference/api/api-reference/#tag/Projects
data:
    description: a DigitalOcean Project
    returned: changed
    type: dict
    sample: {
        "project": {
            "created_at": "2021-05-28T00:00:00Z",
            "description": "This is a test description",
            "environment": "Development",
            "id": "12312312-abcd-efgh-1234-abcdefgh123",
            "is_default": false,
            "name": "Test123",
            "owner_id": 1234567,
            "owner_uuid": "12312312-1234-5678-abcdefghijklm",
            "purpose": "IoT",
            "updated_at": "2021-05-29T00:00:00Z",
        }
    }
"""

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


class DOProject(object):
    def __init__(self, module):
        self.rest = DigitalOceanHelper(module)
        self.module = module
        # pop the oauth token so we don't include it in the POST data
        self.module.params.pop("oauth_token")
        self.id = None
        self.name = None
        self.purpose = None
        self.description = None
        self.environment = None
        self.is_default = None

    def get_by_id(self, project_id):
        if not project_id:
            return None
        response = self.rest.get("projects/{0}".format(project_id))
        json_data = response.json
        if response.status_code == 200:
            project = json_data.get("project", None)
            if project is not None:
                self.id = project.get("id", None)
                self.name = project.get("name", None)
                self.purpose = project.get("purpose", None)
                self.description = project.get("description", None)
                self.environment = project.get("environment", None)
                self.is_default = project.get("is_default", None)
            return json_data
        return None

    def get_by_name(self, project_name):
        if not project_name:
            return None
        page = 1
        while page is not None:
            response = self.rest.get("projects?page={0}".format(page))
            json_data = response.json
            if response.status_code == 200:
                for project in json_data["projects"]:
                    if project.get("name", None) == project_name:
                        self.id = project.get("id", None)
                        self.name = project.get("name", None)
                        self.description = project.get("description", None)
                        self.purpose = project.get("purpose", None)
                        self.environment = project.get("environment", None)
                        self.is_default = project.get("is_default", None)
                        return {"project": project}
                if (
                    "links" in json_data
                    and "pages" in json_data["links"]
                    and "next" in json_data["links"]["pages"]
                ):
                    page += 1
                else:
                    page = None
        return None

    def get_project(self):
        json_data = self.get_by_id(self.module.params["id"])
        if not json_data:
            json_data = self.get_by_name(self.module.params["name"])
        return json_data

    def create(self, state):
        json_data = self.get_project()
        request_params = dict(self.module.params)

        if json_data is not None:
            changed = False
            valid_purpose = [
                "Just trying out DigitalOcean",
                "Class project/Educational Purposes",
                "Website or blog",
                "Web Application",
                "Service or API",
                "Mobile Application",
                "Machine Learning/AI/Data Processing",
                "IoT",
                "Operational/Developer tooling",
            ]
            for key in request_params.keys():
                if (
                    key == "purpose"
                    and request_params[key] is not None
                    and request_params[key] not in valid_purpose
                ):
                    param = "Other: " + request_params[key]
                else:
                    param = request_params[key]

                if json_data["project"][key] != param and param is not None:
                    changed = True

            if changed:
                response = self.rest.put(
                    "projects/{0}".format(json_data["project"]["id"]),
                    data=request_params,
                )
                if response.status_code != 200:
                    self.module.fail_json(changed=False, msg="Unable to update project")
                self.module.exit_json(changed=True, data=response.json)
            else:
                self.module.exit_json(changed=False, data=json_data)
        else:
            response = self.rest.post("projects", data=request_params)

            if response.status_code != 201:
                self.module.fail_json(changed=False, msg="Unable to create project")
            self.module.exit_json(changed=True, data=response.json)

    def delete(self):
        json_data = self.get_project()
        if json_data:
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            response = self.rest.delete(
                "projects/{0}".format(json_data["project"]["id"])
            )
            json_data = response.json
            if response.status_code == 204:
                self.module.exit_json(changed=True, msg="Project deleted")
            self.module.fail_json(changed=False, msg="Failed to delete project")
        else:
            self.module.exit_json(changed=False, msg="Project not found")


def core(module):
    state = module.params.pop("state")
    project = DOProject(module)
    if state == "present":
        project.create(state)
    elif state == "absent":
        project.delete()


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(choices=["present", "absent"], default="present", type="str"),
            oauth_token=dict(
                aliases=["API_TOKEN"],
                no_log=True,
                fallback=(
                    env_fallback,
                    ["DO_API_TOKEN", "DO_API_KEY", "DO_OAUTH_TOKEN"],
                ),
                required=True,
            ),
            name=dict(type="str"),
            id=dict(type="str"),
            description=dict(type="str"),
            purpose=dict(type="str"),
            is_default=dict(type="bool", default=False),
            environment=dict(
                choices=["Development", "Staging", "Production"], type="str"
            ),
        ),
        required_one_of=(["id", "name"],),
        required_if=(
            [
                ("state", "present", ["purpose"]),
            ]
        ),
    )

    core(module)


if __name__ == "__main__":
    main()
