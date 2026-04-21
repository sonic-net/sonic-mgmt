#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Loic Blot <loic.blot@unix-experience.fr>
# Sponsored by Infopro Digital. http://www.infopro-digital.com/
# Sponsored by E.T.A.I. http://www.etai.fr/
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_parameter
short_description: Change an administrative parameter on a MongoDB server
description:
    - Change an administrative parameter on a MongoDB server.
version_added: "1.0.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
    replica_set:
        description:
            - Replica set to connect to (automatically connects to primary for writes).
        type: str
    param:
        description:
            - MongoDB administrative parameter to modify.
        type: str
        required: true
    value:
        description:
            - MongoDB administrative parameter value to set.
        type: str
        required: true
    param_type:
        description:
            - Define the type of parameter value.
        default: str
        type: str
        choices: [int, str]

notes:
    - Requires the pymongo Python package on the remote host, version 4+.
    - This can be installed using pip or the OS package manager.
    - See also U(https://www.mongodb.com/docs/languages/python/pymongo-driver/current/get-started/download-and-install/)
requirements: [ "pymongo" ]
author: "Loic Blot (@nerzhul)"
'''

EXAMPLES = r'''
- name: Set MongoDB syncdelay to 60 (this is an int)
  community.mongodb.mongodb_parameter:
    param: syncdelay
    value: 60
    param_type: int
'''

RETURN = r'''
before:
    description: value before modification
    returned: success
    type: str
after:
    description: value after modification
    returned: success
    type: str
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
    OperationFailure,
    get_mongodb_client,
)

# =========================================
# Module execution.
#


def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        replica_set=dict(default=None),
        param=dict(required=True),
        value=dict(required=True),
        param_type=dict(default="str", choices=['str', 'int'])
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[['login_user', 'login_password']],
    )

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    param = module.params['param']
    param_type = module.params['param_type']
    value = module.params['value']

    # Verify parameter is coherent with specified type
    try:
        if param_type == 'int':
            value = int(value)
    except ValueError:
        module.fail_json(msg="value '%s' is not %s" % (value, param_type))

    try:
        client = get_mongodb_client(module, directConnection=True)
        client = mongo_auth(module, client, directConnection=True)
    except Exception as excep:
        module.fail_json(msg='Unable to connect to MongoDB: %s' % to_native(excep))

    db = client.admin

    try:
        after_value = db.command("setParameter", **{param: value})
    except OperationFailure as e:
        module.fail_json(msg="unable to change parameter: %s" % to_native(e), exception=traceback.format_exc())

    if "was" not in after_value:
        module.exit_json(changed=True, msg="Unable to determine old value, assume it changed.")
    else:
        module.exit_json(changed=(value != after_value["was"]), before=after_value["was"],
                         after=value)


if __name__ == '__main__':
    main()
