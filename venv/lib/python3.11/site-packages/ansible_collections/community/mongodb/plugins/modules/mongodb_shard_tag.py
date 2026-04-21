#!/usr/bin/python

# Copyright: (c) 2021, Rhys Campbell <rhyscampbell@blueiwn.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_shard_tag
short_description: Manage Shard Tags.
description:
  - Manage Shard Tags..
  - Add and remove shard tags.
author: Rhys Campbell (@rhysmeister)
version_added: "1.3.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  name:
    description:
      - The name of the tag.
    required: true
    type: str
  shard:
    description:
      - The name of the shard to assign or remove the tag from.
    required: true
    type: str
  state:
    description:
      - The state of the zone.
    required: false
    type: str
    choices:
      - "present"
      - "absent"
    default: "present"
  mongos_process:
    description:
      - Provide a custom name for the mongos process.
      - Most users can ignore this setting.
    required: false
    type: str
    default: "mongos"
notes:
  - Requires the pymongo Python package on the remote host, version 4+.. This
    can be installed using pip or the OS package manager.
    @see U(http://api.mongodb.org/python/current/installation.html)
requirements:
  - pymongo
'''

EXAMPLES = r'''
- name: Add the NYC tag to a shard called rs0
  community.mongodb.mongodb_shard_tag:
    name: "NYC"
    shard: "rs0"
    state: "present"

- name: Remove the NYC tag from rs0
  community.mongodb.mongodb_shard_tag:
    name: "NYC"
    shard: "rs0"
    state: "absent"
'''

RETURN = r'''
changed:
  description: True when a change has happened
  returned: success
  type: bool
msg:
  description: A short description of what happened.
  returned: failure
  type: str
failed:
  description: If something went wrong
  returned: failed
  type: bool
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.community.mongodb.plugins.module_utils.mongodb_common import (
    missing_required_lib,
    mongodb_common_argument_spec,
    mongo_auth,
    PYMONGO_IMP_ERR,
    pymongo_found,
    get_mongodb_client,
)

has_ordereddict = False
try:
    from collections import OrderedDict
    has_ordereddict = True
except ImportError as excep:
    try:
        from ordereddict import OrderedDict
        has_ordereddict = True
    except ImportError as excep:
        pass


def tag_exists(client, shard, tag):
    '''
    Returns True if the giventag is assign to the shard
    @client - MongoDB connection
    @tag - The zone to check for
    @shard - The shard name
    '''
    status = None
    result = client["config"].shards.find_one({"_id": shard, "tags": tag})
    if result:
        status = True
    else:
        status = False
    return status


def add_zone_tag(client, shard, tag):
    '''
    Adds a tag to a shard
    @client - MongoDB connection
    @shard - The shard name
    @tag - The tag or Zone name
    '''
    cmd_doc = OrderedDict([
        ('addShardToZone', shard),
        ('zone', tag),
    ])
    client['admin'].command(cmd_doc)


def remove_zone_tag(client, shard, tag):
    '''
    Remove a zone tag from a shard.
    @client - MongoDB connection
    @shard - The shard name
    @tag - The tag or Zone name
    '''
    cmd_doc = OrderedDict([
        ('removeShardFromZone', shard),
        ('zone', tag),
    ])
    client['admin'].command(cmd_doc)


def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        name=dict(type='str', required=True),
        shard=dict(type='str', required=True),
        mongos_process=dict(type='str', required=False, default="mongos"),
        state=dict(type='str', default="present", choices=["present", "absent"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[['login_user', 'login_password']],
    )

    if not has_ordereddict:
        module.fail_json(msg='Cannot import OrderedDict class. You can probably install with: pip install ordereddict')

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    state = module.params['state']
    tag = module.params['name']
    shard = module.params['shard']

    result = dict(
        changed=False,
    )

    try:
        client = get_mongodb_client(module)
        client = mongo_auth(module, client)
    except Exception as excep:
        module.fail_json(msg='Unable to connect to MongoDB: %s' % to_native(excep))

    try:
        if tag_exists(client, shard, tag):
            if state == "present":
                result['changed'] = False
                result['msg'] = "The tag {0} is already assigned to the shard {1}".format(tag, shard)
            elif state == "absent":
                if not module.check_mode:
                    remove_zone_tag(client, shard, tag)
                result['changed'] = True
                result['msg'] = "The tag {0} was removed from the shard {1}".format(tag, shard)
        else:
            if state == "present":
                if not module.check_mode:
                    add_zone_tag(client, shard, tag)
                result['changed'] = True
                result['msg'] = "The tag {0} was assigned to the shard {1}".format(tag, shard)
            elif state == "absent":
                result['changed'] = False
                result['msg'] = "The tag {0} is not assigned to the shard {1}".format(tag, shard)
    except Exception as excep:
        module.fail_json(msg="An error occurred: {0}".format(excep))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
