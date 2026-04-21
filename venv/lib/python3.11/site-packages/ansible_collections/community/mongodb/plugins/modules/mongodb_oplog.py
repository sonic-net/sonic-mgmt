#!/usr/bin/python

# Copyright: (c) 2020, Rhys Campbell <rhys.james.campbell@googlemail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_oplog
short_description: Resizes the MongoDB oplog.
description:
  - Resizes the MongoDB oplog.
  - This module should only be used with MongoDB 3.6 and above.
  - Old MongoDB versions should use an alternative method.
  - Consult U(https://docs.mongodb.com/manual/tutorial/change-oplog-size) for further info.
author: Rhys Campbell (@rhysmeister)
version_added: "1.0.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  oplog_size_mb:
    description:
      - New size of the oplog in MB.
    type: int
    required: true
  compact:
    description:
      - Runs compact against the oplog.rs collection in the local database to reclaim disk space.
      - Performs no actions against PRIMARY members.
      - The MongoDB user must have the compact role on the local database for this feature to work.
    type: bool
    default: false
    required: false
notes:
  - Requires the pymongo Python package on the remote host, version 4+.. This
    can be installed using pip or the OS package manager.
    @see U(http://api.mongodb.org/python/current/installation.html)
requirements:
  - pymongo
'''

EXAMPLES = r'''
- name: Resize oplog to 16 gigabytes, or 16000 megabytes
  community.mongodb.mongodb_oplog:
    oplog_size_mb: 16000

- name: Resize oplog to 8 gigabytes and compact secondaries to reclaim space
  community.mongodb.mongodb_oplog:
    oplog_size_mb: 8000
    compact: true
'''

RETURN = r'''
changed:
  description: Whether the member oplog was modified.
  returned: success
  type: bool
compacted:
  description: Whether the member oplog was compacted.
  returned: success
  type: bool
msg:
  description: A short description of what happened.
  returned: success
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
    member_state,
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


def get_olplog_size(client):
    return int(client["local"].command("collStats", "oplog.rs")["maxSize"]) / 1024 / 1024


def set_oplog_size(client, oplog_size_mb):
    cmd_doc = OrderedDict([
        ('replSetResizeOplog', 1),
        ('size', oplog_size_mb)
    ])
    client["admin"].command(cmd_doc)


def compact_oplog(client):
    client["local"].command("compact", "oplog.rs")


def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        compact=dict(type='bool', default=False),
        oplog_size_mb=dict(type='int', required=True),
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

    oplog_size_mb = float(module.params['oplog_size_mb'])  # MongoDB 4.4 inists on a real
    compact = module.params['compact']

    result = dict(
        changed=False,
    )

    try:
        client = get_mongodb_client(module, directConnection=True)
        client = mongo_auth(module, client, directConnection=True)
    except Exception as excep:
        module.fail_json(msg='Unable to connect to MongoDB: %s' % to_native(excep))

    try:
        current_oplog_size = get_olplog_size(client)
    except Exception as excep:
        module.fail_json(msg='Unable to get current oplog size: %s' % to_native(excep))
    if oplog_size_mb == current_oplog_size:
        result["msg"] = "oplog_size_mb is already {0} mb".format(int(oplog_size_mb))
        result["compacted"] = False
    else:
        try:
            state = member_state(client)
        except Exception as excep:
            module.fail_json(msg='Unable to get member state: %s' % to_native(excep))
        if module.check_mode:
            result["changed"] = True
            result["msg"] = "oplog has been resized from {0} mb to {1} mb".format(int(current_oplog_size),
                                                                                  int(oplog_size_mb))
            if state == "SECONDARY" and compact and current_oplog_size > oplog_size_mb:
                result["compacted"] = True
            else:
                result["compacted"] = False
        else:
            try:
                set_oplog_size(client, oplog_size_mb)
                result["changed"] = True
                result["msg"] = "oplog has been resized from {0} mb to {1} mb".format(int(current_oplog_size),
                                                                                      int(oplog_size_mb))
            except Exception as excep:
                module.fail_json(msg='Unable to set oplog size: %s' % to_native(excep))
            if state == "SECONDARY" and compact and current_oplog_size > oplog_size_mb:
                try:
                    compact_oplog(client)
                    result["compacted"] = True
                except Exception as excep:
                    module.fail_json(msg='Error compacting member oplog: %s' % to_native(excep))
            else:
                result["compacted"] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
