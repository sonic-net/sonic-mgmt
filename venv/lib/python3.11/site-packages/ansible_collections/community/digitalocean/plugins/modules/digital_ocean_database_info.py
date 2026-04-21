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
module: digital_ocean_database_info
short_description: Gather information about DigitalOcean databases
description:
  - Gather information about DigitalOcean databases.
version_added: 1.3.0
author: "Mark Mercado (@mamercad)"
options:
  id:
    description:
      - A unique ID that can be used to identify and reference a database cluster.
    type: int
    aliases: ['database_id']
    required: false
  name:
    description:
      - A unique, human-readable name for the database cluster.
    type: str
    required: false
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Gather all DigitalOcean databases
  community.digitalocean.digital_ocean_database_info:
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_KEY') }}"
  register: my_databases
"""


RETURN = r"""
data:
  description: List of DigitalOcean databases
  returned: success
  type: list
  sample: [
    {
      "connection": {
        "database": "",
        "host": "testdatabase1-do-user-3097135-0.b.db.ondigitalocean.com",
        "password": "REDACTED",
        "port": 25061,
        "protocol":"rediss",
        "ssl": true,
        "uri": "rediss://default:REDACTED@testdatabase1-do-user-3097135-0.b.db.ondigitalocean.com:25061",
        "user": "default"
      },
      "created_at": "2021-04-21T15:41:14Z",
      "db_names": null,
      "engine": "redis",
      "id": "37de10e4-808b-4f4b-b25f-7b5b3fd194ac",
      "maintenance_window": {
        "day": "monday",
        "hour": "11:33:47",
        "pending": false
      },
      "name": "testdatabase1",
      "num_nodes": 1,
      "private_connection": {
        "database": "",
        "host": "private-testdatabase1-do-user-3097135-0.b.db.ondigitalocean.com",
        "password": "REDACTED",
        "port": 25061,
        "protocol": "rediss",
        "ssl": true,
        "uri": "rediss://default:REDACTED@private-testdatabase1-do-user-3097135-0.b.db.ondigitalocean.com:25061",
        "user": "default"
      },
      "private_network_uuid": "0db3519b-9efc-414a-8868-8f2e6934688c",
      "region": "nyc1",
      "size": "db-s-1vcpu-1gb",
      "status": "online",
      "tags": null,
      "users": null,
      "version": "6"
    },
    ...
  ]
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


class DODatabaseInfo(object):
    def __init__(self, module):
        self.module = module
        self.rest = DigitalOceanHelper(module)
        # pop the oauth token so we don't include it in the POST data
        self.module.params.pop("oauth_token")
        self.id = None
        self.name = None

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
                for database in json_data["databases"]:
                    if database.get("name", None) == database_name:
                        self.id = database.get("id", None)
                        self.name = database.get("name", None)
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

    def get_databases(self):
        all_databases = []
        page = 1
        while page is not None:
            response = self.rest.get("databases?page={0}".format(page))
            json_data = response.json
            if response.status_code == 200:
                databases = json_data.get("databases", None)
                if databases is not None and isinstance(databases, list):
                    all_databases.append(databases)
                if (
                    "links" in json_data
                    and "pages" in json_data["links"]
                    and "next" in json_data["links"]["pages"]
                ):
                    page += 1
                else:
                    page = None
        return {"databases": all_databases}


def run(module):
    id = module.params.get("id", None)
    name = module.params.get("name", None)

    database = DODatabaseInfo(module)

    if id is not None or name is not None:
        the_database = database.get_database()
        if the_database:  # Found it
            module.exit_json(changed=False, data=the_database)
        else:  # Didn't find it
            if id is not None and name is not None:
                module.fail_json(
                    change=False, msg="Database {0} ({1}) not found".format(id, name)
                )
            elif id is not None and name is None:
                module.fail_json(change=False, msg="Database {0} not found".format(id))
            elif id is None and name is not None:
                module.fail_json(
                    change=False, msg="Database {0} not found".format(name)
                )
    else:
        all_databases = database.get_databases()
        module.exit_json(changed=False, data=all_databases)


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        id=dict(type="int", aliases=["database_id"]),
        name=dict(type="str"),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
