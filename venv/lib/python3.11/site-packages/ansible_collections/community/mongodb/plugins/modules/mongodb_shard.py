#!/usr/bin/python

# (c) 2018, Rhys Campbell <rhys.james.campbell@googlemail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: mongodb_shard
short_description: Add or remove shards from a MongoDB Cluster
description:
    -  Add or remove shards from a MongoDB Cluster.
author: Rhys Campbell (@rhysmeister)
version_added: "1.0.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  shard:
    description:
      - The shard connection string.
      - Should be supplied in the form <replicaset>/host:port as detailed in U(https://docs.mongodb.com/manual/tutorial/add-shards-to-shard-cluster/).
      - For example rs0/example1.mongodb.com:27017.
    required: true
    type: str
  sharded_databases:
    description:
      - Enable sharding on the listed database.
      - Can be supplied as a string or a list of strings.
      - Sharding cannot be disabled on a database.
      - Starting in MongoDB 6.0, the enableSharding command is no longer required to shard a collection and this parameter is ignored.
    required: false
    type: raw
  mongos_process:
    description:
      - Provide a custom name for the mongos process you are connecting to.
      - Most users can ignore this setting.
    required: false
    type: str
    default: "mongos"
  state:
    description:
      - Whether the shard should be present or absent from the Cluster.
    required: false
    type: str
    default: present
    choices:
      - "absent"
      - "present"

notes:
    - Requires the pymongo Python package on the remote host, version 4+.
requirements: [ pymongo ]
'''

EXAMPLES = '''
- name: Add a replicaset shard named rs1 with a member running on port 27018 on mongodb0.example.net
  community.mongodb.mongodb_shard:
    login_user: admin
    login_password: admin
    shard: "rs1/mongodb0.example.net:27018"
    state: present

- name: Add a standalone mongod shard running on port 27018 of mongodb0.example.net
  community.mongodb.mongodb_shard:
    login_user: admin
    login_password: admin
    shard: "mongodb0.example.net:27018"
    state: present

- name: To remove a shard called 'rs1'
  community.mongodb.mongodb_shard:
    login_user: admin
    login_password: admin
    shard: rs1
    state: absent

# Single node shard running on localhost
- name: Ensure shard rs0 exists
  community.mongodb.mongodb_shard:
    login_user: admin
    login_password: secret
    shard: "rs0/localhost:3001"
    state: present

# Single node shard running on localhost
- name: Ensure shard rs1 exists
  community.mongodb.mongodb_shard:
    login_user: admin
    login_password: secret
    shard: "rs1/localhost:3002"
    state: present

# Enable sharding on a few databases when creating the shard
- name: To remove a shard called 'rs1'
  community.mongodb.mongodb_shard:
    login_user: admin
    login_password: admin
    shard: rs1
    sharded_databases:
      - db1
      - db2
    state: present
'''

RETURN = '''
mongodb_shard:
    description: The name of the shard to create.
    returned: success
    type: str
sharded_enabled:
    description: Databases that have had sharding enabled during module execution.
    returned: success when sharding is enabled
    type: list
'''

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native
from ansible_collections.community.mongodb.plugins.module_utils.mongodb_common import (
    missing_required_lib,
    mongodb_common_argument_spec,
    mongo_auth,
    PYMONGO_IMP_ERR,
    pymongo_found,
    get_mongodb_client,
    check_srv_version
)


def shard_find(client, shard):
    """Check if a shard exists.

    Args:
        client (cursor): Mongodb cursor on admin database.
        shard (str): shard to check.

    Returns:
        dict: when user exists, False otherwise.
    """
    if '/' in shard:
        s = shard.split('/')[0]
    else:
        s = shard
    for shard in client["config"].shards.find({"_id": s}):
        return shard
    return False


def shard_add(client, shard):
    try:
        sh = client["admin"].command('addShard', shard)
    except Exception as excep:
        raise excep
    return sh


def shard_remove(client, shard):
    try:
        sh = client["admin"].command('removeShard', shard)
    except Exception as excep:
        raise excep
    return sh


def sharded_dbs(client):
    '''
    Returns the sharded databases
    Args:
        client (cursor): Mongodb cursor on admin database.
    Returns:
        a list of database names that are sharded
    '''
    sharded_databases = []
    for entry in client["config"].databases.find({"partitioned": True}, {"_id": 1}):
        sharded_databases.append(entry["_id"])
    return sharded_databases


def enable_database_sharding(client, database):
    '''
    Enables sharding on a database
    Args:
        client (cursor): Mongodb cursor on admin database.
    Returns:
        true on success, false on failure
    '''
    s = False
    db = client["admin"].command('enableSharding', database)
    if db:
        s = True
    return s


def any_dbs_to_shard(client, sharded_databases):
    '''
    Return a list of databases that need to have sharding enabled
    sharded_databases - Provided by module
    cluster_sharded_databases - List of sharded dbs from the mongos
    '''
    dbs_to_shard = []
    cluster_sharded_databases = sharded_dbs(client)
    for db in sharded_databases:
        if db not in cluster_sharded_databases:
            dbs_to_shard.append(db)
    return dbs_to_shard


# =========================================
# Module execution.
#


def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        mongos_process=dict(type='str', required=False, default="mongos"),
        shard=dict(type='str', required=True),
        sharded_databases=dict(type="raw", required=False),
        state=dict(type='str', required=False, default='present', choices=['absent', 'present'])
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[['login_user', 'login_password']],
    )

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    login_host = module.params['login_host']
    login_port = module.params['login_port']
    shard = module.params['shard']
    state = module.params['state']
    sharded_databases = module.params['sharded_databases']
    mongos_process = module.params['mongos_process']

    try:
        client = get_mongodb_client(module)
        client = mongo_auth(module, client)
    except Exception as excep:
        module.fail_json(msg='Unable to connect to MongoDB: %s' % to_native(excep))

    try:
        if client["admin"].command("serverStatus")["process"] != mongos_process:
            module.fail_json(msg="Process running on {0}:{1} is not a {2}".format(login_host, login_port, mongos_process))

        dbs_to_shard = []

        if sharded_databases is not None and int(check_srv_version(module, client)[0]) < 6:
            if isinstance(sharded_databases, str):
                sharded_databases = list(sharded_databases)
            dbs_to_shard = any_dbs_to_shard(client, sharded_databases)

        if module.check_mode:
            if state == "present":
                changed = False
                if not shard_find(client, shard) or len(dbs_to_shard) > 0:
                    changed = True
            elif state == "absent":
                if not shard_find(client, shard):
                    changed = False
                else:
                    changed = True
        else:
            if state == "present":
                if not shard_find(client, shard):
                    shard_add(client, shard)
                    changed = True
                else:
                    changed = False
                if len(dbs_to_shard) > 0:
                    for db in dbs_to_shard:
                        enable_database_sharding(client, db)
                    changed = True
            elif state == "absent":
                if shard_find(client, shard):
                    shard_remove(client, shard)
                    changed = True
                else:
                    changed = False
    except Exception as e:
        action = "add"
        if state == "absent":
            action = "remove"
        module.fail_json(msg='Unable to {0} shard: %s'.format(action) % to_native(e), exception=traceback.format_exc())

    result = {
        "changed": changed,
        "shard": shard,
    }
    if len(dbs_to_shard) > 0:
        result['sharded_enabled'] = dbs_to_shard

    module.exit_json(**result)


if __name__ == '__main__':
    main()
