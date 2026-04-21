#!/usr/bin/python

# Copyright: (c) 2020, Rhys Campbell <rhys.james.campbell@googlemail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_balancer
short_description: Manages the MongoDB Sharded Cluster Balancer.
description:
  - Manages the MongoDB Sharded Cluster Balancer.
  - Start or stop the balancer.
  - Adjust the cluster chunksize.
  - Enable or disable autosplit.
  - Add or remove a balancer window.
author: Rhys Campbell (@rhysmeister)
version_added: "1.0.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  autosplit:
    description:
      - Disable or enable the autosplit flag in the config.settings collection.
      - From MongoDB 6.1 automatic chunk splitting is not performed so this parameter is not valid in this and later versions. See more see [enableAutoSplit](https://www.mongodb.com/docs/manual/reference/method/sh.enableAutoSplit/).  # noqa: E501
      - This parameter is deprecated and will be removed in a future release.
    required: false
    type: bool
  chunksize:
    description:
      - Control the size of chunks in the sharded cluster.
      - Value should be given in MB.
    required: false
    type: int
  state:
    description:
      - Manage the Balancer for the Cluster
    required: false
    type: str
    choices:
      - "started"
      - "stopped"
    default: "started"
  mongos_process:
    description:
      - Provide a custom name for the mongos process.
      - Most users can ignore this setting.
    required: false
    type: str
    default: "mongos"
  window:
    description:
      - Schedule the balancer window.
      - Provide the following dictionary keys start, stop, state
      - The state key should be "present" or "absent".
      - The start and stop keys are ignored when state is "absent".
      - start and stop should be strings in "HH:MM" format indicating the time bounds of the window.
    type: raw
    required: false
notes:
  - Requires the pymongo Python package on the remote host, version 4+. This
    can be installed using pip or the OS package manager. @see U(https://www.mongodb.com/docs/languages/python/pymongo-driver/current/get-started/download-and-install/)
requirements:
  - pymongo
'''

EXAMPLES = r'''
- name: Start the balancer
  community.mongodb.mongodb_balancer:
    state: started

- name: Stop the balancer and disable autosplit
  community.mongodb.mongodb_balancer:
    state: stopped
    autosplit: false

- name: Enable autosplit
  community.mongodb.mongodb_balancer:
    autosplit: true

- name: Change the default chunksize to 128MB
  community.mongodb.mongodb_balancer:
    chunksize: 128

- name: Add or update a balancing window
  community.mongodb.mongodb_balancer:
    window:
      start: "23:00"
      stop: "06:00"
      state: "present"

- name: Remove a balancing window
  community.mongodb.mongodb_balancer:
    window:
      state: "absent"
'''

RETURN = r'''
changed:
  description: Whether the balancer state or autosplit changed.
  returned: success
  type: bool
old_balancer_state:
  description: The previous state of the balancer
  returned: When balancer state is changed
  type: str
new_balancer_state:
  description: The new state of the balancer.
  returned: When balancer state is changed
  type: str
old_autosplit:
  description: The previous state of autosplit.
  returned: When autosplit is changed.
  type: str
new_autosplit:
  description: The new state of autosplit.
  returned: When autosplit is changed.
  type: str
old_chunksize:
  description: The previous value for chunksize.
  returned: When chunksize is changed.
  type: int
new_chunksize:
  description: The new value for chunksize.
  returned: When chunksize is changed.
  type: int
msg:
  description: A short description of what happened.
  returned: failure
  type: str
failed:
  description: If something went wrong
  returned: failed
  type: bool
'''

import time

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


def get_balancer_state(client):
    '''
    Gets the state of the MongoDB balancer. The config.settings collection does
    not exist until the balancer has been started for the first time
    { "_id" : "balancer", "mode" : "full", "stopped" : false }
    { "_id" : "autosplit", "enabled" : true }
    '''
    balancer_state = None
    result = client["config"].settings.find_one({"_id": "balancer"})
    if not result:
        balancer_state = "stopped"
    else:
        if result['stopped'] is False:
            balancer_state = "started"
        else:
            balancer_state = "stopped"
    return balancer_state


def stop_balancer(client):
    '''
    Stops MongoDB balancer
    '''
    cmd_doc = OrderedDict([
        ('balancerStop', 1),
        ('maxTimeMS', 60000)
    ])
    client['admin'].command(cmd_doc)
    time.sleep(1)


def start_balancer(client):
    '''
    Starts MongoDB balancer
    '''
    cmd_doc = OrderedDict([
        ('balancerStart', 1),
        ('maxTimeMS', 60000)
    ])
    client['admin'].command(cmd_doc)
    time.sleep(1)


def enable_autosplit(client):
    client["config"].settings.update_one({"_id": "autosplit"},
                                         {"$set": {"enabled": True}},
                                         upsert=True)


def disable_autosplit(client):
    client["config"].settings.update_one({"_id": "autosplit"},
                                         {"$set": {"enabled": False}},
                                         upsert=True)


def get_autosplit(client):
    autosplit = False
    result = client["config"].settings.find_one({"_id": "autosplit"})
    if result is not None:
        autosplit = result['enabled']
    return autosplit


def get_chunksize(client):
    '''
    Default chunksize is 64MB
    '''
    chunksize = None
    result = client["config"].settings.find_one({"_id": "chunksize"})
    if not result:
        chunksize = 64
    else:
        chunksize = result['value']
    return chunksize


def set_chunksize(client, chunksize):
    client["config"].settings.update_one({"_id": "chunksize"},
                                         {"$set": {"value": chunksize}},
                                         upsert=True)


def set_balancing_window(client, start, stop):
    s = False
    result = client["config"].settings.update_one({"_id": "balancer"},
                                                  {"$set": {
                                                      "activeWindow": {
                                                          "start": start,
                                                          "stop": stop}}},
                                                  upsert=True)
    if result.modified_count == 1 or result.upserted_id is not None:
        s = True
    return s


def remove_balancing_window(client):
    s = False
    result = client["config"].settings.update_one({"_id": "balancer"},
                                                  {"$unset": {"activeWindow": True}})
    if result.modified_count == 1:
        s = True
    return s


def balancing_window(client, start, stop):
    s = False
    if start is not None and stop is not None:
        result = client["config"].settings.find_one({"_id": "balancer",
                                                     "activeWindow.start": start,
                                                     "activeWindow.stop": stop})
    else:
        result = client["config"].settings.find_one({"_id": "balancer", "activeWindow": {"$exists": True}})
    if result:
        s = True
    return s


def validate_window(window, module):
    if window is not None:
        if 'state' not in window.keys():
            module.fail_json(msg="Balancing window state must be specified")
        elif window['state'] not in ['present', 'absent']:
            module.fail_json(msg="Balancing window state must be present or absent")
        elif window['state'] == "present" \
                and ("start" not in window.keys()
                     or "stop" not in window.keys()):
            module.fail_json(msg="Balancing window start and stop values must be specified")
    return True


def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        autosplit=dict(type='bool', default=None),
        chunksize=dict(type='int', default=None),
        mongos_process=dict(type='str', required=False, default="mongos"),
        state=dict(type='str', default="started", choices=["started", "stopped"]),
        window=dict(type='raw', default=None)
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

    login_host = module.params['login_host']
    login_port = module.params['login_port']
    balancer_state = module.params['state']
    autosplit = module.params['autosplit']
    chunksize = module.params['chunksize']
    mongos_process = module.params['mongos_process']
    window = module.params['window']

    # Validate window
    validate_window(window, module)

    result = dict(
        changed=False,
    )

    try:
        client = get_mongodb_client(module)
        client = mongo_auth(module, client)
    except Exception as excep:
        module.fail_json(msg='Unable to connect to MongoDB: %s' % to_native(excep))

    changed = False
    cluster_balancer_state = None
    cluster_autosplit = None
    cluster_chunksize = None
    old_balancer_state = None
    new_balancer_state = None
    old_autosplit = None
    new_autosplit = None
    old_chunksize = None
    new_chunksize = None

    try:

        if client["admin"].command("serverStatus")["process"] != mongos_process:
            module.fail_json(msg="Process running on {0}:{1} is not a {2}".format(login_host, login_port, mongos_process))

        cluster_balancer_state = get_balancer_state(client)
        if autosplit is not None:
            cluster_autosplit = get_autosplit(client)
        if chunksize is not None:
            cluster_chunksize = get_chunksize(client)

        if module.check_mode:
            if balancer_state != cluster_balancer_state:
                old_balancer_state = cluster_balancer_state
                new_balancer_state = balancer_state
                changed = True
            if (autosplit is not None
                    and autosplit != cluster_autosplit):
                old_autosplit = cluster_autosplit
                new_autosplit = autosplit
                changed = True
            if (chunksize is not None
                    and chunksize != cluster_chunksize):
                old_chunksize = cluster_chunksize
                new_chunksize = chunksize
                changed = True
            if window is not None:
                if balancing_window(client, window.get('start'), window.get('stop')):
                    if window['state'] == "present":
                        pass
                    else:
                        changed = True
                else:
                    if window['state'] == "present":
                        changed = True
                    else:
                        pass
        else:
            if balancer_state is not None \
                    and balancer_state != cluster_balancer_state:
                if balancer_state == "started":
                    start_balancer(client)
                    old_balancer_state = cluster_balancer_state
                    new_balancer_state = get_balancer_state(client)
                    changed = True
                else:
                    stop_balancer(client)
                    old_balancer_state = cluster_balancer_state
                    new_balancer_state = get_balancer_state(client)
                    changed = True
            if autosplit is not None \
                    and autosplit != cluster_autosplit:
                if autosplit:
                    enable_autosplit(client)
                    old_autosplit = cluster_autosplit
                    new_autosplit = autosplit
                    changed = True
                else:
                    disable_autosplit(client)
                    old_autosplit = cluster_autosplit
                    new_autosplit = autosplit
                    changed = True
            if (chunksize is not None
                    and chunksize != cluster_chunksize):
                set_chunksize(client, chunksize)
                old_chunksize = cluster_chunksize
                new_chunksize = chunksize
                changed = True
            if window is not None:
                if balancing_window(client, window.get('start'), window.get('stop')):
                    if window['state'] == "present":
                        pass
                    else:
                        remove_balancing_window(client)
                        changed = True
                else:
                    if window['state'] == "present":
                        set_balancing_window(client,
                                             window['start'],
                                             window['stop'])
                        changed = True
                    else:
                        pass
    except Exception as excep:
        result["msg"] = "An error occurred: {0}".format(excep)

    result['changed'] = changed
    if old_balancer_state is not None:
        result['old_balancer_state'] = old_balancer_state
        result['new_balancer_state'] = new_balancer_state
    if old_autosplit is not None:
        result['old_autosplit'] = old_autosplit
        result['new_autosplit'] = new_autosplit
    if old_chunksize is not None:
        result['old_chunksize'] = old_chunksize
        result['new_chunksize'] = new_chunksize

    module.exit_json(**result)


if __name__ == '__main__':
    main()
