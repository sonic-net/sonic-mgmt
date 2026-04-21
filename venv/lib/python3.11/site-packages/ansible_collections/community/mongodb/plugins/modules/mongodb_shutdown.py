#!/usr/bin/python

# Copyright: (c) 2020, Rhys Campbell <rhys.james.campbell@googlemail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_shutdown
short_description: Cleans up all database resources and then terminates the mongod/mongos process.
description:
  - Cleans up all database resources and then terminates the process.
author: Rhys Campbell (@rhysmeister)
version_added: "1.0.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  force:
    description:
      - Specify true to force the mongod to shut down.
      - Force shutdown interrupts any ongoing operations on the mongod and may result in unexpected behavior.
    type: bool
    default: false
  timeout:
    description:
    - The number of seconds the primary should wait for a secondary to catch up.
    type: int
    default: 10
notes:
- Requires the pymongo Python package on the remote host, version 4+.. This
  can be installed using pip or the OS package manager.
  @see U(http://api.mongodb.org/python/current/installation.html)
requirements:
  - pymongo
'''

EXAMPLES = r'''
- name: Attempt to perform a clean shutdown
  community.mongodb.mongodb_shutdown:

- name: Force shutdown with a timeout of 60 seconds
  community.mongodb.mongodb_shutdown:
    force: true
    timeout: 60
'''

RETURN = r'''
changed:
  description: Whether the member was shutdown.
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
    mongo_auth,
    PYMONGO_IMP_ERR,
    pymongo_found,
    get_mongodb_client,
)


def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        force=dict(type='bool', default=False),
        timeout=dict(type='int', default=10)
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[['login_user', 'login_password']],
    )

    try:
        from collections import OrderedDict
    except ImportError as excep:
        try:
            from ordereddict import OrderedDict
        except ImportError as excep:
            module.fail_json(msg='Cannot import OrderedDict class. You can probably install with: pip install ordereddict: %s'
                             % to_native(excep))

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    force = module.params['force']
    timeout = module.params['timeout']

    result = dict(
        changed=False,
    )

    try:
        client = get_mongodb_client(module, directConnection=True)
        client = mongo_auth(module, client, directConnection=True)
    except Exception as excep:
        module.fail_json(msg='Unable to connect to MongoDB: %s' % to_native(excep))

    try:
        cmd_doc = OrderedDict([
            ('shutdown', 1),
            ('force', force),
            ('timeoutSecs', timeout)
        ])
        client['admin'].command(cmd_doc)
        result["changed"] = True
        result["msg"] = "mongod process was terminated sucessfully"
    except Exception as excep:
        if "connection closed" in str(excep):
            result["changed"] = True
            result["msg"] = "mongod process was terminated sucessfully"
        else:
            result["msg"] = "An error occurred: {0}".format(excep)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
