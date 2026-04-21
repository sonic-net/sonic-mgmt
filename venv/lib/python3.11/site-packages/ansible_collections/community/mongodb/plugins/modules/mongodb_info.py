#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_info

short_description: Gather information about MongoDB instance.

description:
- Gather information about MongoDB instance.

author: Andrew Klychkov (@Andersson007)
version_added: "1.0.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  filter:
    description:
    - Limit the collected information by comma separated string or YAML list.
    - Allowable values are C(general), C(databases), C(total_size), C(parameters), C(users), C(roles).
    - By default, collects all subsets.
    - You can use '!' before value (for example, C(!users)) to exclude it from the information.
    - If you pass including and excluding values to the filter, for example, I(filter=!general,users),
      the excluding values, C(!general) in this case, will be ignored.
    required: no
    type: list
    elements: str

notes:
    - Requires the pymongo Python package on the remote host, version 4+.

requirements:
  - pymongo
'''

EXAMPLES = r'''
- name: Gather all supported information
  community.mongodb.mongodb_info:
    login_user: admin
    login_password: secret
  register: result

- name: Show gathered info
  debug:
    msg: '{{ result }}'

- name: Gather only information about databases and their total size
  community.mongodb.mongodb_info:
    login_user: admin
    login_password: secret
    filter: databases, total_size

- name: Gather all information except parameters
  community.mongodb.mongodb_info:
    login_user: admin
    login_password: secret
    filter: '!parameters'
'''

RETURN = r'''
general:
  description: General instance information.
  returned: always
  type: dict
  sample: {"allocator": "tcmalloc", "bits": 64, "storageEngines": ["biggie"], "version": "4.2.3", "maxBsonObjectSize": 16777216}
databases:
  description: Database information.
  returned: always
  type: dict
  sample: {"admin": {"empty": false, "sizeOnDisk": 245760}, "config": {"empty": false, "sizeOnDisk": 110592}}
total_size:
  description: Total size of all databases in bytes.
  returned: always
  type: int
  sample: 397312
users:
  description: User information.
  returned: always
  type: dict
  sample: { "db": {"new_user": {"_id": "config.new_user", "mechanisms": ["SCRAM-SHA-1", "SCRAM-SHA-256"], "roles": []}}}
roles:
  description: Role information.
  returned: always
  type: dict
  sample: { "db": {"restore": {"inheritedRoles": [], "isBuiltin": true, "roles": []}}}
parameters:
  description: Server parameters information.
  returned: always
  type: dict
  sample: {"maxOplogTruncationPointsAfterStartup": 100, "maxOplogTruncationPointsDuringStartup": 100, "maxSessions": 1000000}
'''

from uuid import UUID

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.six import iteritems
from ansible_collections.community.mongodb.plugins.module_utils.mongodb_common import (
    convert_bson_values_recur,
    get_mongodb_client,
    missing_required_lib,
    mongodb_common_argument_spec,
    mongo_auth,
    PYMONGO_IMP_ERR,
    pymongo_found,
)


class MongoDbInfo():
    """Class for gathering MongoDB instance information.

    Args:
        module (AnsibleModule): Object of AnsibleModule class.
        client (pymongo): pymongo client object to interact with the database.
    """
    def __init__(self, module, client):
        self.module = module
        self.client = client
        self.admin_db = self.client.admin
        self.info = {
            'general': {},
            'databases': {},
            'total_size': {},
            'parameters': {},
            'users': {},
            'roles': {},
        }

    def get_info(self, filter_):
        """Get MongoDB instance information and return it based on filter_.

        Args:
            filter_ (list): List of collected subsets (e.g., general, users, etc.),
                when it is empty, return all available information.
        """
        self.__collect()

        inc_list = []
        exc_list = []

        if filter_:
            partial_info = {}

            for fi in filter_:
                if fi.lstrip('!') not in self.info:
                    self.module.warn("filter element '%s' is not allowable, ignored" % fi)
                    continue

                if fi[0] == '!':
                    exc_list.append(fi.lstrip('!'))

                else:
                    inc_list.append(fi)

            if inc_list:
                for i in self.info:
                    if i in inc_list:
                        partial_info[i] = self.info[i]

            else:
                for i in self.info:
                    if i not in exc_list:
                        partial_info[i] = self.info[i]

            return partial_info

        else:
            return self.info

    def __collect(self):
        """Collect information."""
        # Get general info:
        self.info['general'] = self.client.server_info()

        # Get parameters:
        self.info['parameters'] = self.get_parameters_info()

        # Gather info about databases and their total size:
        self.info['databases'], self.info['total_size'] = self.get_db_info()

        for dbname, val in iteritems(self.info['databases']):
            # Gather info about users for each database:
            self.info['users'].update(self.get_users_info(dbname))

            # Gather info about roles for each database:
            self.info['roles'].update(self.get_roles_info(dbname))

        self.info = convert_bson_values_recur(self.info)

    def get_roles_info(self, dbname):
        """Gather information about roles.

        Args:
            dbname (str): Database name to get role info from.

        Returns a dictionary with role information for the given db.
        """
        db = self.client[dbname]
        result = db.command({'rolesInfo': 1, 'showBuiltinRoles': True})['roles']

        roles_dict = {}
        for elem in result:
            roles_dict[elem['role']] = {}
            for key, val in iteritems(elem):
                if key in ['role', 'db']:
                    continue

                roles_dict[elem['role']][key] = val

        return {dbname: roles_dict}

    def get_users_info(self, dbname):
        """Gather information about users.

        Args:
            dbname (str): Database name to get user info from.

        Returns a dictionary with user information for the given db.
        """
        db = self.client[dbname]
        result = db.command({'usersInfo': 1})['users']

        users_dict = {}
        for elem in result:
            users_dict[elem['user']] = {}
            for key, val in iteritems(elem):
                if key in ['user', 'db']:
                    continue

                if isinstance(val, UUID):
                    val = val.hex

                users_dict[elem['user']][key] = str(val)  # Force conversion to avoid: Refusing to deserialize an invalid UTF8 string value

        return {dbname: users_dict}

    def get_db_info(self):
        """Gather information about databases.

        Returns a dictionary with database information.
        """
        result = self.admin_db.command({'listDatabases': 1})
        total_size = int(result['totalSize'])
        result = result['databases']

        db_dict = {}
        for elem in result:
            db_dict[elem['name']] = {}
            for key, val in iteritems(elem):
                if key == 'name':
                    continue

                if key == 'sizeOnDisk':
                    val = int(val)

                db_dict[elem['name']][key] = val

        return db_dict, total_size

    def get_parameters_info(self):
        """Gather parameters information.

        Returns a dictionary with parameters.
        """
        return self.admin_db.command({'getParameter': '*'})


# ================
# Module execution
#
def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        filter=dict(type='list', elements='str', required=False)
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[['login_user', 'login_password']],
    )

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    filter_ = module.params['filter']

    if filter_:
        filter_ = [f.strip() for f in filter_]

    try:
        client = get_mongodb_client(module)
        client = mongo_auth(module, client)
    except Exception as excep:
        module.fail_json(msg='Unable to connect to MongoDB: %s' % to_native(excep))

    # Initialize an object and start main work:
    mongodb = MongoDbInfo(module, client)

    module.exit_json(changed=False, **mongodb.get_info(filter_))


if __name__ == '__main__':
    main()
