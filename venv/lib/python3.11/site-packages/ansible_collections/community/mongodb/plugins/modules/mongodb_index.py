#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Rhys Campbell (@rhysmeister) <rhys.james.campbell@googlemail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_index

short_description: Creates or drops indexes on MongoDB collections.

description:
  - Creates or drops indexes on MongoDB collections.
  - Supports multiple index options, i.e. unique, sparse and partial.
  - Validates existence of indexes by name only.

author: Rhys Campbell (@rhysmeister)
version_added: "1.0.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  indexes:
    description:
      - List of indexes to create or drop
    type: list
    elements: raw
    required: yes
  replica_set:
    description:
      - Replica set to connect to (automatically connects to primary for writes).
    type: str
notes:
    - Requires the pymongo Python package on the remote host, version 4+.

requirements:
  - pymongo
'''

EXAMPLES = r'''
- name: Create a single index on a collection
  community.mongodb.mongodb_index:
    login_user: admin
    login_password: secret
    indexes:
      - database: mydb
        collection: test
        keys:
          - username: 1
            last_login: -1
        options:
          name: myindex
        state: present

- name: Drop an index on a collection
  community.mongodb.mongodb_index:
    login_user: admin
    login_password: secret
    indexes:
      - database: mydb
        collection: test
        options:
          name: myindex
        state: absent

- name: Create multiple indexes
  community.mongodb.mongodb_index:
    login_user: admin
    login_password: secret
    indexes:
      - database: mydb
        collection: test
        keys:
          - username: 1
            last_login: -1
        options:
          name: myindex
        state: present
      - database: mydb
        collection: test
        keys:
          - email: 1
            last_login: -1
        options:
          name: myindex2
        state: present

- name: Add a unique index
  community.mongodb.mongodb_index:
    login_port: 27017
    login_user: admin
    login_password: secret
    login_database: "admin"
    indexes:
      - database: "test"
        collection: "rhys"
        keys:
          username: 1
        options:
          name: myuniqueindex
          unique: true
        state: present

- name: Add a ttl index
  community.mongodb.mongodb_index:
    login_port: 27017
    login_user: admin
    login_password: secret
    login_database: "admin"
    indexes:
      - database: "test"
        collection: "rhys"
        keys:
          created: 1
        options:
          name: myttlindex
          expireAfterSeconds: 3600
        state: present

- name: Add a sparse index
  community.mongodb.mongodb_index:
    login_port: 27017
    login_user: admin
    login_password: secret
    login_database: "admin"
    indexes:
      - database: "test"
        collection: "rhys"
        keys:
          last_login: -1
        options:
          name: mysparseindex
          sparse: true
        state: present

- name: Add a partial index
  community.mongodb.mongodb_index:
    login_port: 27017
    login_user: admin
    login_password: secret
    login_database: "admin"
    indexes:
      - database: "test"
        collection: "rhys"
        keys:
          last_login: -1
        options:
          name: mypartialindex
          partialFilterExpression:
            rating:
              $gt: 5
        state: present

- name: Add a index in the background (background option is deprecated from 4.2+)
  community.mongodb.mongodb_index:
    login_port: 27017
    login_user: admin
    login_password: secret
    login_database: "admin"
    indexes:
      - database: "test"
        collection: "rhys"
        options:
          name: idxbackground
        keys:
          username: -1
        backgroud: true
        state: present

- name: Check creating 5 index all with multiple options specified
  community.mongodb.mongodb_index:
    login_port: 27017
    login_user: admin
    login_password: secret
    login_database: "admin"
    indexes:
      - database: "test"
        collection: "indextest"
        options:
          name: "idx_unq_username"
          unique: true
        keys:
          username: -1
        state: present
      - database: "test"
        collection: "indextest"
        options:
          name: "idx_last_login"
          sparse: true
        keys:
          last_login: -1
        state: present
      - database: "test"
        collection: "indextest"
        options:
          name: "myindex"
        keys:
          first_name: 1
          last_name: -1
          city: 1
        state: present
      - database: "test"
        collection: partialtest
        options:
          name: "idx_partialtest"
          partialFilterExpression:
            rating:
              $gt: 5
        keys:
          rating: -1
          title: 1
        state: present
      - database: "test"
        collection: "wideindex"
        options:
          name: "mywideindex"
        keys:
          email: -1
          username: 1
          first_name: 1
          last_name: 1
          dob: -1
          city: 1
          last_login: -1
          review_count: 1
          rating_count: 1
          last_post: -1
        state: present
'''

RETURN = r'''
indexes_created:
  description: List of indexes created.
  returned: always
  type: list
  sample: ["myindex", "myindex2"]
indexes_dropped:
  description: List of indexes dropped.
  returned: always
  type: list
  sample: ["myindex", "myindex2"]
changed:
  description: Indicates the module has changed something.
  returned: When the module has changed something.
  type: bool
failed:
  description: Indicates the module has failed.
  returned: When the module has encountered an error.
  type: bool
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.mongodb.plugins.module_utils.mongodb_common import (
    missing_required_lib,
    mongodb_common_argument_spec,
    PYMONGO_IMP_ERR,
    pymongo_found,
    index_exists,
    create_index,
    drop_index,
    mongo_auth,
    get_mongodb_client,
)


def validate_module(module):
    '''
    Runs validation rules specific the mongodb_index module
    '''
    required_index_keys = [
        "database",
        "collection",
        "options",
        "state",
    ]
    indexes = module.params['indexes']

    if len(indexes) == 0:
        module.fail_json(msg="One or more indexes must be specified")
    if not all(isinstance(i, dict) for i in indexes):
        module.fail_json(msg="Indexes must be supplied as dictionaries")

    # Ensure keys are present in index spec
    for k in required_index_keys:
        for i in indexes:
            if k not in i.keys():
                module.fail_json(msg="Missing required index key {0}".format(k))

    # Check index subkeys look correct
    for i in indexes:
        if not isinstance(i["database"], str):
            module.fail_json(msg="database key should be str")
        elif not isinstance(i["collection"], str):
            module.fail_json(msg="collection key should be str")
        elif i["state"] == "present" and "keys" not in i.keys():
            module.fail_json(msg="keys must be supplied when state is present")
        elif i["state"] == "present" and not isinstance(i["keys"], dict):
            module.fail_json(msg="keys key should be dict")
        elif not isinstance(i["options"], dict):
            module.fail_json(msg="options key should be dict")
        elif "name" not in i["options"]:
            module.fail_json(msg="The options dict must contain a name field")
        elif i["state"] not in ["present", "absent"]:
            module.fail_json(msg="state must be one of present or absent")


# ================
# Module execution
#
def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        indexes=dict(type='list', elements='raw', required=True),
        replica_set=dict(type='str'),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[['login_user', 'login_password']],
    )

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    validate_module(module)

    indexes = module.params['indexes']

    client = get_mongodb_client(module)
    client = mongo_auth(module, client)

    # Pre flight checks done
    indexes_created = []
    indexes_dropped = []
    changed = None
    for i in indexes:
        try:
            idx = index_exists(client, i["database"], i["collection"], i["options"]["name"])
        except Exception as excep:
            module.fail_json(msg="Could not determine index status: {0}".format(str(excep)))
        if module.check_mode:
            if idx:
                if i["state"] == "present":
                    changed = False
                elif i["state"] == "absent":
                    indexes_dropped.append("{0}.{1}.{2}".format(i["database"],
                                                                i["collection"],
                                                                i["options"]["name"]))
                    changed = True
            else:
                if i["state"] == "present":
                    indexes_created.append("{0}.{1}.{2}".format(i["database"],
                                                                i["collection"],
                                                                i["options"]["name"]))
                    changed = True
                elif i["state"] == "absent":
                    changed = False
        else:
            if idx:
                if i["state"] == "present":
                    changed = False
                elif i["state"] == "absent":
                    try:
                        drop_index(client, i["database"], i["collection"],
                                   i["options"]["name"])
                        indexes_dropped.append("{0}.{1}.{2}".format(i["database"],
                                                                    i["collection"],
                                                                    i["options"]["name"]))
                        changed = True
                    except Exception as excep:
                        module.fail_json(msg="Error dropping index: {0}".format(str(excep)))

            else:
                if i["state"] == "present":
                    try:
                        create_index(client=client,
                                     database=i["database"],
                                     collection=i["collection"],
                                     keys=i["keys"],
                                     options=i["options"])
                        indexes_created.append("{0}.{1}.{2}".format(i["database"],
                                                                    i["collection"],
                                                                    i["options"]["name"]))
                        changed = True
                    except Exception as excep:
                        module.fail_json(msg="Error creating index: {0}".format(str(excep)))
                elif i["state"] == "absent":
                    changed = False

    module.exit_json(changed=changed,
                     indexes_created=indexes_created,
                     indexes_dropped=indexes_dropped)


if __name__ == '__main__':
    main()
