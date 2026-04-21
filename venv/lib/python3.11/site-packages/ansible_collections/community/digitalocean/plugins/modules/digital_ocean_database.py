#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: Ansible Project
# Copyright: (c) 2021, Mark Mercado <mmercado@digitalocean.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: digital_ocean_database
short_description: Create and delete a DigitalOcean database
description:
  - Create and delete a database in DigitalOcean and optionally wait for it to be online.
  - DigitalOcean's managed database service simplifies the creation and management of highly available database clusters.
  - Currently, it offers support for PostgreSQL, Redis, MySQL, and MongoDB.
version_added: 1.3.0
author: "Mark Mercado (@mamercad)"
options:
  state:
    description:
      - Indicates the desired state of the target.
    default: present
    choices: ['present', 'absent']
    type: str
  id:
    description:
      - A unique ID that can be used to identify and reference a database cluster.
    type: int
    aliases: ['database_id']
  name:
    description:
      - A unique, human-readable name for the database cluster.
    type: str
    required: true
  engine:
    description:
      - A slug representing the database engine used for the cluster.
      - The possible values are C(pg) for PostgreSQL, C(mysql) for MySQL, C(redis) for Redis, and C(mongodb) for MongoDB.
    type: str
    required: true
    choices: ['pg', 'mysql', 'redis', 'mongodb']
  version:
    description:
      - A string representing the version of the database engine in use for the cluster.
      - For C(pg), versions are 10, 11 and 12.
      - For C(mysql), version is 8.
      - For C(redis), version is 5.
      - For C(mongodb), version is 4.
    type: str
  size:
    description:
      - The slug identifier representing the size of the nodes in the database cluster.
      - See U(https://docs.digitalocean.com/reference/api/api-reference/#operation/create_database_cluster) for supported sizes.
    type: str
    required: true
    aliases: ['size_id']
  region:
    description:
      - The slug identifier for the region where the database cluster is located.
    type: str
    required: true
    aliases: ['region_id']
  num_nodes:
    description:
      - The number of nodes in the database cluster.
      - Valid choices are 1, 2 or 3.
    type: int
    default: 1
    choices: [1, 2, 3]
  tags:
    description:
      - An array of tags that have been applied to the database cluster.
    type: list
    elements: str
  private_network_uuid:
    description:
      - A string specifying the UUID of the VPC to which the database cluster is assigned.
    type: str
  wait:
    description:
      - Wait for the database to be online before returning.
    required: False
    default: True
    type: bool
  wait_timeout:
    description:
      - How long before wait gives up, in seconds, when creating a database.
    default: 600
    type: int
  project_name:
    aliases: ["project"]
    description:
    - Project to assign the resource to (project name, not UUID).
    - Defaults to the default project of the account (empty string).
    - Currently only supported when creating databases.
    type: str
    required: false
    default: ""
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Create a Redis database
  community.digitalocean.digital_ocean_database:
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_KEY') }}"
    state: present
    name: testdatabase1
    engine: redis
    size: db-s-1vcpu-1gb
    region: nyc1
    num_nodes: 1
  register: my_database

- name: Create a Redis database (and assign to Project "test")
  community.digitalocean.digital_ocean_database:
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_KEY') }}"
    state: present
    name: testdatabase1
    engine: redis
    size: db-s-1vcpu-1gb
    region: nyc1
    num_nodes: 1
    project_name: test
  register: my_database
"""


RETURN = r"""
data:
  description: A DigitalOcean database
  returned: success
  type: dict
  sample:
    database:
      connection:
         database: ""
         host: testdatabase1-do-user-3097135-0.b.db.ondigitalocean.com
         password: REDACTED
         port: 25061
         protocol: rediss
         ssl: true
         uri: rediss://default:REDACTED@testdatabase1-do-user-3097135-0.b.db.ondigitalocean.com:25061
         user: default
      created_at: "2021-04-21T15:41:14Z"
      db_names: null
      engine: redis
      id: 37de10e4-808b-4f4b-b25f-7b5b3fd194ac
      maintenance_window:
         day: monday
         hour: 11:33:47
         pending: false
      name: testdatabase1
      num_nodes: 1
      private_connection:
         database: ""
         host: private-testdatabase1-do-user-3097135-0.b.db.ondigitalocean.com
         password: REDIS
         port: 25061
         protocol: rediss
         ssl: true
         uri: rediss://default:REDACTED@private-testdatabase1-do-user-3097135-0.b.db.ondigitalocean.com:25061
         user: default
      private_network_uuid: 0db3519b-9efc-414a-8868-8f2e6934688c,
      region: nyc1
      size: db-s-1vcpu-1gb
      status: online
      tags: null
      users: null
      version: 6
msg:
    description: Informational or error message encountered during execution
    returned: changed
    type: str
    sample: No project named test2 found
assign_status:
    description: Assignment status (ok, not_found, assigned, already_assigned, service_down)
    returned: changed
    type: str
    sample: assigned
resources:
    description: Resource assignment involved in project assignment
    returned: changed
    type: dict
    sample:
        assigned_at: '2021-10-25T17:39:38Z'
        links:
            self: https://api.digitalocean.com/v2/databases/126355fa-b147-40a6-850a-c44f5d2ad418
        status: assigned
        urn: do:dbaas:126355fa-b147-40a6-850a-c44f5d2ad418
"""


import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
    DigitalOceanProjects,
)


class DODatabase(object):
    def __init__(self, module):
        self.module = module
        self.rest = DigitalOceanHelper(module)
        if self.module.params.get("project_name"):
            # only load for non-default project assignments
            self.projects = DigitalOceanProjects(module, self.rest)
        # pop wait and wait_timeout so we don't include it in the POST data
        self.wait = self.module.params.pop("wait", True)
        self.wait_timeout = self.module.params.pop("wait_timeout", 600)
        # pop the oauth token so we don't include it in the POST data
        self.module.params.pop("oauth_token")
        self.id = None
        self.name = None
        self.engine = None
        self.version = None
        self.num_nodes = None
        self.region = None
        self.status = None
        self.size = None

    def get_by_id(self, database_id):
        if database_id is None:
            return None
        response = self.rest.get("databases/{0}".format(database_id))
        json_data = response.json
        if response.status_code == 200:
            database = json_data.get("database", None)
            if database is not None:
                self.id = database.get("id", None)
                self.name = database.get("name", None)
                self.engine = database.get("engine", None)
                self.version = database.get("version", None)
                self.num_nodes = database.get("num_nodes", None)
                self.region = database.get("region", None)
                self.status = database.get("status", None)
                self.size = database.get("size", None)
            return json_data
        return None

    def get_by_name(self, database_name):
        if database_name is None:
            return None
        page = 1
        while page is not None:
            response = self.rest.get("databases?page={0}".format(page))
            json_data = response.json
            if response.status_code == 200:
                databases = json_data.get("databases", None)
                if databases is None or not isinstance(databases, list):
                    return None
                for database in databases:
                    if database.get("name", None) == database_name:
                        self.id = database.get("id", None)
                        self.name = database.get("name", None)
                        self.engine = database.get("engine", None)
                        self.version = database.get("version", None)
                        self.status = database.get("status", None)
                        self.num_nodes = database.get("num_nodes", None)
                        self.region = database.get("region", None)
                        self.size = database.get("size", None)
                        return {"database": database}
                if (
                    "links" in json_data
                    and "pages" in json_data["links"]
                    and "next" in json_data["links"]["pages"]
                ):
                    page += 1
                else:
                    page = None
        return None

    def get_database(self):
        json_data = self.get_by_id(self.module.params["id"])
        if not json_data:
            json_data = self.get_by_name(self.module.params["name"])
        return json_data

    def ensure_online(self, database_id):
        end_time = time.monotonic() + self.wait_timeout
        while time.monotonic() < end_time:
            response = self.rest.get("databases/{0}".format(database_id))
            json_data = response.json
            database = json_data.get("database", None)
            if database is not None:
                status = database.get("status", None)
                if status is not None:
                    if status == "online":
                        return json_data
            time.sleep(10)
        self.module.fail_json(msg="Waiting for database online timeout")

    def create(self):
        json_data = self.get_database()

        if json_data is not None:
            database = json_data.get("database", None)
            if database is not None:
                self.module.exit_json(changed=False, data=json_data)
            else:
                self.module.fail_json(
                    changed=False, msg="Unexpected error, please file a bug"
                )

        if self.module.check_mode:
            self.module.exit_json(changed=True)

        request_params = dict(self.module.params)
        del request_params["id"]

        response = self.rest.post("databases", data=request_params)
        json_data = response.json
        if response.status_code >= 400:
            self.module.fail_json(changed=False, msg=json_data["message"])
        database = json_data.get("database", None)
        if database is None:
            self.module.fail_json(
                changed=False,
                msg="Unexpected error; please file a bug https://github.com/ansible-collections/community.digitalocean/issues",
            )

        database_id = database.get("id", None)
        if database_id is None:
            self.module.fail_json(
                changed=False,
                msg="Unexpected error; please file a bug https://github.com/ansible-collections/community.digitalocean/issues",
            )

        if self.wait:
            json_data = self.ensure_online(database_id)

        project_name = self.module.params.get("project_name")
        if project_name:  # empty string is the default project, skip project assignment
            urn = "do:dbaas:{0}".format(database_id)
            assign_status, error_message, resources = self.projects.assign_to_project(
                project_name, urn
            )
            self.module.exit_json(
                changed=True,
                data=json_data,
                msg=error_message,
                assign_status=assign_status,
                resources=resources,
            )
        else:
            self.module.exit_json(changed=True, data=json_data)

    def delete(self):
        json_data = self.get_database()
        if json_data is not None:
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            database = json_data.get("database", None)
            database_id = database.get("id", None)
            database_name = database.get("name", None)
            database_region = database.get("region", None)
            if database_id is not None:
                response = self.rest.delete("databases/{0}".format(database_id))
                json_data = response.json
                if response.status_code == 204:
                    self.module.exit_json(
                        changed=True,
                        msg="Deleted database {0} ({1}) in region {2}".format(
                            database_name, database_id, database_region
                        ),
                    )
                self.module.fail_json(
                    changed=False,
                    msg="Failed to delete database {0} ({1}) in region {2}: {3}".format(
                        database_name,
                        database_id,
                        database_region,
                        json_data["message"],
                    ),
                )
            else:
                self.module.fail_json(
                    changed=False, msg="Unexpected error, please file a bug"
                )
        else:
            self.module.exit_json(
                changed=False,
                msg="Database {0} in region {1} not found".format(
                    self.module.params["name"], self.module.params["region"]
                ),
            )


def run(module):
    state = module.params.pop("state")
    database = DODatabase(module)
    if state == "present":
        database.create()
    elif state == "absent":
        database.delete()


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        state=dict(choices=["present", "absent"], default="present"),
        id=dict(type="int", aliases=["database_id"]),
        name=dict(type="str", required=True),
        engine=dict(choices=["pg", "mysql", "redis", "mongodb"], required=True),
        version=dict(type="str"),
        size=dict(type="str", aliases=["size_id"], required=True),
        region=dict(type="str", aliases=["region_id"], required=True),
        num_nodes=dict(type="int", choices=[1, 2, 3], default=1),
        tags=dict(type="list", elements="str"),
        private_network_uuid=dict(type="str"),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(default=600, type="int"),
        project_name=dict(type="str", aliases=["project"], required=False, default=""),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(["id", "name"],),
        required_if=(
            [
                ("state", "present", ["name", "size", "engine", "region"]),
                ("state", "absent", ["name", "size", "engine", "region"]),
            ]
        ),
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
