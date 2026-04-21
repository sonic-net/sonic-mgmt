#!/usr/bin/python

# Copyright: (c) 2018, Rhys Campbell <rhys.james.campbell@googlemail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_replicaset
short_description: Initialises a MongoDB replicaset.
description:
  - Initialises a MongoDB replicaset in a new deployment.
  - Validates the replicaset name for existing deployments.
  - Advanced replicaset member (re)configuration possible (see examples).
  - Initialize the replicaset before adding users as per \
    [best practice](https://www.mongodb.com/docs/manual/tutorial/deploy-replica-set-with-keyfile-access-control/).
author: Rhys Campbell (@rhysmeister)
version_added: "1.0.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  replica_set:
    description:
    - Replicaset name.
    type: str
    default: rs0
  members:
    description:
    - Yaml list consisting of the replicaset members.
    - Csv string will also be accepted i.e. mongodb1:27017,mongodb2:27017,mongodb3:27017.
    - A dictionary can also be used to specify advanced replicaset member options.
    - If a port number is not provided then 27017 is assumed.
    type: list
    elements: raw
  validate:
    description:
    - Performs some basic validation on the provided replicaset config.
    type: bool
    default: yes
  arbiter_at_index:
    description:
    - Identifies the position of the member in the array that is an arbiter.
    type: int
  chaining_allowed:
    description:
    - When I(settings.chaining_allowed=true), the replicaset allows secondary members to replicate from other
      secondary members.
    - When I(settings.chaining_allowed=false), secondaries can replicate only from the primary.
    type: bool
    default: yes
  heartbeat_timeout_secs:
    description:
    - Number of seconds that the replicaset members wait for a successful heartbeat from each other.
    - If a member does not respond in time, other members mark the delinquent member as inaccessible.
    - The setting only applies when using I(protocol_version=0). When using I(protocol_version=1) the relevant
      setting is I(settings.election_timeout_millis).
    type: int
    default: 10
  election_timeout_millis:
    description:
    - The time limit in milliseconds for detecting when a replicaset's primary is unreachable.
    type: int
    default: 10000
  protocol_version:
    description: Version of the replicaset election protocol.
    type: int
    choices: [ 0, 1 ]
    default: 1
  reconfigure:
    description:
      - This feature is currently experimental. Please test your scenario thoroughly.
      - Consult the integration test file for supported scenarios - \
        [Integration tests](https://github.com/ansible-collections/community.mongodb/tree/master/tests/integration/targets/mongodb_replicaset/tasks). \
        See files prefixed with 330.
      - Whether to perform replicaset reconfiguration actions.
      - Only relevant when the replicaset already exists.
      - Only one member should be removed or added per invocation.
      - Members should be specific as either all strings or all dicts when reconfiguring.
      - Currently no support for replicaset settings document changes.
      - Please always specify ports in the replicaset list when using this feature or some operations may fail.
    type: bool
    default: false
  force:
    description:
      - Only relevant when reconfigure = true.
      - Specify true to force the available replica set members to accept the new configuration.
      - Force reconfiguration can result in unexpected or undesired behavior, including rollback of "majority" committed writes.
    type: bool
    default: false
  max_time_ms:
    description:
      - Specifies a cumulative time limit in milliseconds for processing the replicaset reconfiguration.
    type: int
    default: null
  debug:
    description:
      - Add additonal info for debug.
    type: bool
    default: false
  cluster_cmd:
    description:
      - Command the module should use to obtain information about the MongoDB node we are connecting to.
    type: str
    choices:
      - isMaster
      - hello
    default: hello
notes:
- Requires the pymongo Python package on the remote host, version 4+.. This
  can be installed using pip or the OS package manager.
  @see U(http://api.mongodb.org/python/current/installation.html)
requirements:
- pymongo
'''

EXAMPLES = r'''
# Create a replicaset called 'rs0' with the 3 provided members
- name: Ensure replicaset rs0 exists
  community.mongodb.mongodb_replicaset:
    login_host: localhost
    login_user: admin
    login_password: admin
    replica_set: rs0
    members:
    - mongodb1:27017
    - mongodb2:27017
    - mongodb3:27017
  when: groups.mongod.index(inventory_hostname) == 0

# Create two single-node replicasets on the localhost for testing
- name: Ensure replicaset rs0 exists
  community.mongodb.mongodb_replicaset:
    login_host: localhost
    login_port: 3001
    login_user: admin
    login_password: secret
    login_database: admin
    replica_set: rs0
    members: localhost:3001
    validate: no

- name: Ensure replicaset rs1 exists
  community.mongodb.mongodb_replicaset:
    login_host: localhost
    login_port: 3002
    login_user: admin
    login_password: secret
    login_database: admin
    replica_set: rs1
    members: localhost:3002
    validate: no

- name: Create a replicaset and use a custom priority for each member
  community.mongodb.mongodb_replicaset:
    login_host: localhost
    login_user: admin
    login_password: admin
    replica_set: rs0
    members:
    - host: "localhost:3001"
      priority: 1
    - host: "localhost:3002"
      priority: 0.5
    - host: "localhost:3003"
      priority: 0.5
  when: groups.mongod.index(inventory_hostname) == 0

- name: Create replicaset rs1 with options and member tags
  community.mongodb.mongodb_replicaset:
    login_host: localhost
    login_port: 3001
    login_database: admin
    replica_set: rs1
    members:
    - host: "localhost:3001"
      priority: 1
      tags:
        dc: "east"
        usage: "production"
    - host: "localhost:3002"
      priority: 1
      tags:
        dc: "east"
        usage: "production"
    - host: "localhost:3003"
      priority: 0
      hidden: true
      slaveDelay: 3600
      tags:
        dc: "west"
        usage: "reporting"

- name: Replicaset with one arbiter node (mongodb3 - index is zero-based)
  community.mongodb.mongodb_replicaset:
    login_user: admin
    login_password: admin
    replica_set: rs0
    members:
      - mongodb1:27017
      - mongodb2:27017
      - mongodb3:27017
    arbiter_at_index: 2
  when: groups.mongod.index(inventory_hostname) == 0

- name: Add a new member to a replicaset - Safe for pre-5.0 consult documentation - https://docs.mongodb.com/manual/tutorial/expand-replica-set/
  block:
    - name: Create replicaset with module - with dicts
      community.mongodb.mongodb_replicaset:
        replica_set: "rs0"
        members:
           - host: localhost:3001
           - host: localhost:3002
           - host: localhost:3003

    - name: Wait for the replicaset to stabilise
      community.mongodb.mongodb_status:
        replica_set: "rs0"
        poll: 5
        interval: 10

    - name: Remove a member from the replicaset
      community.mongodb.mongodb_replicaset:
        replica_set: "rs0"
        reconfigure: yes
        members:
           - host: localhost:3001
           - host: localhost:3002

    - name: Wait for the replicaset to stabilise after member removal
      community.mongodb.mongodb_status:
        replica_set: "rs0"
        validate: minimal
        poll: 5
        interval: 10

    - name: Add a member to the replicaset
      community.mongodb.mongodb_replicaset:
        replica_set: "rs0"
        reconfigure: yes
        members:
           - host: localhost:3001
           - host: localhost:3002
           - host: localhost:3004
             hidden: true
             votes: 0
             priority: 0

    - name: Wait for the replicaset to stabilise after member addition
      community.mongodb.mongodb_status:
        replica_set: "rs0"
        validate: minimal
        poll: 5
        interval: 30

    - name: Reconfigure the replicaset - Make member 3004 a normal voting member
      community.mongodb.mongodb_replicaset:
        replica_set: "rs0"
        reconfigure: yes
        members:
           - host: localhost:3001
           - host: localhost:3002
           - host: localhost:3004
             hidden: false
             votes: 1
             priority: 1

    - name: Wait for the replicaset to stabilise
      community.mongodb.mongodb_status:
        replica_set: "rs0"
        poll: 5
        interval: 30
'''

RETURN = r'''
mongodb_replicaset:
  description: The name of the replicaset that has been created.
  returned: success
  type: str
reconfigure:
  description: If a replicaset reconfiguration occured.
  returned: On rpelicaset reconfiguration
  type: bool
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.community.mongodb.plugins.module_utils.mongodb_common import (
    missing_required_lib,
    mongodb_common_argument_spec,
    mongo_auth,
    member_dicts_different,
    lists_are_different,
    PYMONGO_IMP_ERR,
    pymongo_found,
    get_mongodb_client,
)


def get_replicaset_config(client):
    conf = client.admin.command({'replSetGetConfig': 1})
    return conf['config']


def get_member_names(client):
    conf = get_replicaset_config(client)
    members = []
    for member in conf['members']:
        members.append(member['host'])
    return members


def modify_members(module, config, members):
    """
    Modifies the members section of the config document as appropriate.
    @module - Ansible module object
    @config - Replicaset config document from MongoDB
    @members - Members config from module
    """
    try:  # refactor repeated code
        from collections import OrderedDict
    except ImportError as excep:
        try:
            from ordereddict import OrderedDict
        except ImportError as excep:
            module.fail_json(msg='Cannot import OrderedDict class. You can probably install with: pip install ordereddict: %s'
                             % to_native(excep))
    new_member_config = []  # the list of dicts containing the members for the replicaset configuration document
    existing_members = []  # members that are staying in the config
    max_id = 0
    if all(isinstance(member, str) for member in members):
        for current_member in config['members']:
            if current_member["host"] in members:
                new_member_config.append(current_member)
                existing_members.append(current_member["host"])
                if current_member["_id"] > max_id:
                    max_id = current_member["_id"]
        member_additions = list(set(members) - set(existing_members))
        if len(member_additions) > 0:
            for member in member_additions:
                if ':' not in member:  # No port supplied. Assume 27017
                    member += ":27017"
                new_member_config.append(OrderedDict([("_id", max_id + 1), ("host", member)]))
                max_id += 1
        config["members"] = new_member_config
    elif all(isinstance(member, dict) for member in members):
        # We need to put the _id values in into the matching document and generate them for new hosts
        # TODO: https://docs.mongodb.com/manual/reference/replica-configuration/#mongodb-rsconf-rsconf.members-n-._id
        # Maybe we can add a new member id parameter value, stick with the incrementing for now
        # Perhaps even save this in the mongodb instance?

        # first get all the existing members of the replicaset
        new_member_config = []
        existing_members = {}
        matched_members = []  # members that have been supplied by the moduel and matched with existing members
        max_id = 0
        for member in config["members"]:
            existing_members[member["host"]] = member["_id"]
            if member["_id"] > max_id:
                max_id = member["_id"]
        # append existing members with the appropriate _id
        for member in members:
            if member["host"] in existing_members:
                member["_id"] = existing_members[member["host"]]
                matched_members.append(member["host"])
                new_member_config.append(member)
        for member in members:
            if member["host"] not in matched_members:  # new member , append and increment id
                max_id = max_id + 1
                member["_id"] = max_id
                new_member_config.append(member)
        config["members"] = new_member_config
    else:
        module.fail_json(msg="All items in members must be either of type dict of str")
    return config


def replicaset_reconfigure(module, client, config, force, max_time_ms):

    config['version'] += 1

    try:
        from collections import OrderedDict
    except ImportError as excep:
        try:
            from ordereddict import OrderedDict
        except ImportError as excep:
            module.fail_json(msg='Cannot import OrderedDict class. You can probably install with: pip install ordereddict: %s'
                             % to_native(excep))

    cmd_doc = OrderedDict([("replSetReconfig", config),
                           ("force", force)])
    if max_time_ms is not None:
        cmd_doc.update({"maxTimeMS": max_time_ms})

    client.admin.command(cmd_doc)
    # return result


def replicaset_find(client, cluster_cmd):
    """Check if a replicaset exists.

    Args:
        client (cursor): Mongodb cursor on admin database.
        cluster_cmd (str): Either isMaster or hello

    Returns:
        str: when the node is a member of a replicaset , False otherwise.
    """
    doc = client['admin'].command(cluster_cmd)
    if 'setName' in doc:
        return str(doc['setName'])
    return False


def replicaset_add(module, client, replica_set, members, arbiter_at_index, protocol_version,
                   chaining_allowed, heartbeat_timeout_secs, election_timeout_millis):

    try:
        from collections import OrderedDict
    except ImportError as excep:
        try:
            from ordereddict import OrderedDict
        except ImportError as excep:
            module.fail_json(msg='Cannot import OrderedDict class. You can probably install with: pip install ordereddict: %s'
                             % to_native(excep))

    members_dict_list = []
    index = 0
    settings = {
        "chainingAllowed": bool(chaining_allowed),
    }
    if protocol_version == 0:
        settings['heartbeatTimeoutSecs'] = heartbeat_timeout_secs
    else:
        settings['electionTimeoutMillis'] = election_timeout_millis
    for member in members:
        if isinstance(member, str):
            if ':' not in member:  # No port supplied. Assume 27017
                member += ":27017"
            members_dict_list.append(OrderedDict([("_id", int(index)), ("host", member)]))
            if index == arbiter_at_index:
                members_dict_list[index]['arbiterOnly'] = True
            index += 1
        elif isinstance(member, dict):
            hostname = member["host"]
            if ':' not in hostname:
                hostname += ":27017"
            members_dict_list.append(OrderedDict([("_id", int(index)), ("host", hostname)]))
            for key in list(member.keys()):
                if key != "host":
                    members_dict_list[index][key] = member[key]
            if index == arbiter_at_index:
                members_dict_list[index]['arbiterOnly'] = True
            index += 1
        else:
            raise ValueError("member should be a str or dict. Instead found: {0}".format(str(type(members))))

    conf = OrderedDict([("_id", replica_set),
                        ("protocolVersion", protocol_version),
                        ("members", members_dict_list),
                        ("settings", settings)])
    try:
        client["admin"].command('replSetInitiate', conf)
    except Exception as excep:
        raise Exception("Some problem {0} | {1}".format(str(excep), str(conf)))


def replicaset_remove(module, client, replica_set):
    raise NotImplementedError


def modify_members_flow(module, client, members, result):
    debug = module.params['debug']
    force = module.params['force']
    max_time_ms = module.params['max_time_ms']
    diff = False
    modified_config = None
    config = None

    try:
        config = get_replicaset_config(client)
    except Exception as excep:
        module.fail_json(msg="Unable to get replicaset configuration {0}".format(excep))

    if isinstance(members[0], str):
        diff = lists_are_different(members, get_member_names(client))
    elif isinstance(members[0], dict):
        diff = member_dicts_different(config, members)
    else:
        module.fail_json(msg="members must be either str or dict")
    if diff:
        if not module.check_mode:
            try:
                modified_config = modify_members(module, config, members)
                if debug:
                    result['config'] = str(config)
                    result['modified_config'] = str(modified_config)
                replicaset_reconfigure(module, client, modified_config, force, max_time_ms)
            except Exception as excep:
                module.fail_json(msg="Failed reconfiguring replicaset {0}, config doc {1}".format(excep, modified_config))
        result['changed'] = True
        result['msg'] = "replicaset reconfigured"
    else:
        result['changed'] = False
    return result

# =========================================
# Module execution.
#


def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        arbiter_at_index=dict(type='int'),
        chaining_allowed=dict(type='bool', default=True),
        election_timeout_millis=dict(type='int', default=10000),
        heartbeat_timeout_secs=dict(type='int', default=10),
        members=dict(type='list', elements='raw'),
        protocol_version=dict(type='int', default=1, choices=[0, 1]),
        replica_set=dict(type='str', default="rs0"),
        validate=dict(type='bool', default=True),
        reconfigure=dict(type='bool', default=False),
        force=dict(type='bool', default=False),
        max_time_ms=dict(type='int', default=None),
        debug=dict(type='bool', default=False),
        cluster_cmd=dict(type='str', choices=['isMaster', 'hello'], default='hello')
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[['login_user', 'login_password']],
    )

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    replica_set = module.params['replica_set']
    members = module.params['members']
    arbiter_at_index = module.params['arbiter_at_index']
    validate = module.params['validate']
    protocol_version = module.params['protocol_version']
    chaining_allowed = module.params['chaining_allowed']
    heartbeat_timeout_secs = module.params['heartbeat_timeout_secs']
    election_timeout_millis = module.params['election_timeout_millis']
    reconfigure = module.params['reconfigure']
    force = module.params['force']  # TODO tidy this stuff up
    max_time_ms = module.params['max_time_ms']
    debug = module.params['debug']
    cluster_cmd = module.params['cluster_cmd']

    # Count voting members
    voting_members = sum([1 if not isinstance(m, dict) or m.get("votes", 1) == 1 else 0 for m in members])

    if validate and reconfigure is False:
        if len(members) <= 2 or voting_members % 2 == 0:
            module.fail_json(msg="MongoDB Replicaset validation failed. Invalid number of replicaset members.")
        if arbiter_at_index is not None and len(members) - 1 < arbiter_at_index:
            module.fail_json(msg="MongoDB Replicaset validation failed. Invalid arbiter index.")

    result = dict(
        changed=False,
        replica_set=replica_set,
    )

    try:
        client = get_mongodb_client(module, directConnection=True)
    except Exception as e:
        module.fail_json(msg='Unable to connect to database: %s' % to_native(e))

    try:
        rs = replicaset_find(client, cluster_cmd)  # does not require auth
    except Exception as e:
        module.fail_json(msg='Unable to connect to query replicaset: %s' % to_native(e))

    if isinstance(rs, str):
        if replica_set == rs:
            if reconfigure:
                client = mongo_auth(module, client)
                result = modify_members_flow(module, client, members, result)
            else:
                result['changed'] = False
            result['replica_set'] = rs
            module.exit_json(**result)
        else:
            module.fail_json(msg="The replica_set name of {0} does not match the expected: {1}".format(rs, replica_set))
    else:  # replicaset does not exist

        # Some validation stuff
        if len(replica_set) == 0:
            module.fail_json(msg="Parameter replica_set must not be an empty string")

        if module.check_mode is False:
            try:
                replicaset_add(module, client, replica_set, members,
                               arbiter_at_index, protocol_version,
                               chaining_allowed, heartbeat_timeout_secs,
                               election_timeout_millis)
                result['changed'] = True
            except Exception as e:
                module.fail_json(msg='Unable to create replica_set: %s' % to_native(e))
        else:
            result['changed'] = True

        module.exit_json(**result)


if __name__ == '__main__':
    main()
