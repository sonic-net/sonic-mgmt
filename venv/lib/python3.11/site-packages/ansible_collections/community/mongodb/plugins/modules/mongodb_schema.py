#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Rhys Campbell (@rhysmeister) <rhyscampbell@bluewin.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: mongodb_schema

short_description: Manages MongoDB Document Schema Validators.

description:
- Manages MongoDB Document Schema Validators.
- Create, update and remove Validators on a collection.
- Supports the entire range of jsonSchema keywords.
- See [jsonSchema Available Keywords](https://docs.mongodb.com/manual/reference/operator/query/jsonSchema/#available-keywords) for details.

author: Rhys Campbell (@rhysmeister)
version_added: "1.3.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  db:
    description:
      - The database to work with.
    required: yes
    type: str
  collection:
    description:
      - The collection to work with.
    required: yes
    type: str
  required:
    description:
      - List of fields that are required.
    type: list
    elements: str
  properties:
    description:
      - Individual property specification.
    type: dict
    default: {}
  action:
    description:
      - The validation action for MongoDB to perform when handling invalid documents.
    type: str
    choices:
      - "error"
      - "warn"
    default: "error"
  level:
    description:
      - The validation level MongoDB should apply when updating existing documents.
    type: str
    choices:
      - "strict"
      - "moderate"
    default: "strict"
  replica_set:
    description:
      - Replicaset name.
    type: str
    default: null
  state:
    description:
      - The state of the validator.
    type: str
    choices:
      - "present"
      - "absent"
    default: "present"
  debug:
    description:
      - Enable additional debugging output.
    type: bool
    default: false

notes:
    - Requires the pymongo Python package on the remote host, version 4+.

requirements:
  - pymongo
'''

EXAMPLES = r'''
---
- name: Require that an email address field is in every document
  community.mongodb.mongodb_schema:
    collection: contacts
    db: rhys
    required:
      - email

- name: Remove a schema rule
  community.mongodb.mongodb_schema:
    collection: contacts
    db: rhys
    state: absent


- name: More advanced example using properties
  community.mongodb.mongodb_schema:
    collection: contacts
    db: rhys
    properties:
      email:
        maxLength: 150
        minLength: 5
      options:
        bsonType: array
        maxItems: 10
        minItems: 5
        uniqueItems: true
      status:
        bsonType: string
        description: "can only be ACTIVE or DISABLED"
        enum:
          - ACTIVE
          - DISABLED
      year:
        bsonType: int
        description: "must be an integer from 2021 to 3020"
        exclusiveMaximum: false
        maximum: 3020
        minimum: 2021
    required:
      - email
      - first_name
      - last_name
'''

RETURN = r'''
changed:
  description: If the module caused a change.
  returned: on success
  type: bool
msg:
  description: Status message.
  returned: always
  type: str
validator:
  description: The validator document as read from the instance.
  returned: when debug is true
  type: dict
module_config:
  description: The validator document as indicated by the module invocation.
  returned: when debug is true
  type: dict
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
import json


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


def get_validator(client, db, collection):
    validator = None
    cmd_doc = OrderedDict([
        ('listCollections', 1),
        ('filter', {"name": collection})
    ])
    doc = None
    results = client[db].command(cmd_doc)["cursor"]["firstBatch"]
    if len(results) > 0:
        doc = results[0]
    if doc is not None and 'options' in doc and 'validator' in doc['options']:
        validator = doc['options']['validator']["$jsonSchema"]
        if 'validationAction' in doc['options']:
            validator['validationAction'] = doc['options']['validationAction']
        if 'validationLevel' in doc['options']:
            validator['validationLevel'] = doc['options']['validationLevel']
    return validator


def validator_is_different(client, db, collection, required, properties, action, level):
    is_different = False
    validator = get_validator(client, db, collection)
    if validator is not None:
        if sorted(required) != sorted(validator.get('required', [])):
            is_different = True
        if action != validator.get('validationAction', 'error'):
            is_different = True
        if level != validator.get('validationLevel', 'strict'):
            is_different = True
        dict1 = json.dumps(properties, sort_keys=True)
        dict2 = json.dumps(validator.get('properties', {}), sort_keys=True)
        if dict1 != dict2:
            is_different = True
    else:
        is_different = True
    return is_different


def add_validator(client, db, collection, required, properties, action, level):
    cmd_doc = OrderedDict([
        ('collMod', collection),
        ('validator', {'$jsonSchema': {"bsonType": "object",
                                       "required": required,
                                       "properties": properties}}),
        ('validationAction', action),
        ('validationLevel', level)
    ])
    if collection not in client[db].list_collection_names():
        client[db].create_collection(collection)
    client[db].command(cmd_doc)


def remove_validator(client, db, collection):
    cmd_doc = OrderedDict([
        ('collMod', collection),
        ('validator', {}),
        ('validationLevel', "off")
    ])
    client[db].command(cmd_doc)


# ================
# Module execution
#

def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        db=dict(type='str', required=True),
        collection=dict(type='str', required=True),
        required=dict(type='list', elements='str'),
        properties=dict(type='dict', default={}),
        action=dict(type='str', choices=['error', 'warn'], default="error"),
        level=dict(type='str', choices=['strict', 'moderate'], default="strict"),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        debug=dict(type='bool', default=False),
        replica_set=dict(type='str', default=None),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[['login_user', 'login_password']],
        required_if=[("state", "present", ("db", "collection"))]
    )

    if not has_ordereddict:
        module.fail_json(msg='Cannot import OrderedDict class. You can probably install with: pip install ordereddict')

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    db = module.params['db']
    collection = module.params['collection']
    required = module.params['required']
    properties = module.params['properties']
    action = module.params['action']
    level = module.params['level']
    state = module.params['state']
    debug = module.params['debug']

    try:
        client = get_mongodb_client(module)
        client = mongo_auth(module, client)
    except Exception as e:
        module.fail_json(msg='Unable to connect to database: %s' % to_native(e))

    result = dict(
        changed=False,
    )

    validator = get_validator(client, db, collection)
    if state == "present":
        if validator is not None:
            diff = validator_is_different(client, db, collection, required,
                                          properties, action, level)
            if diff:
                if not module.check_mode:
                    add_validator(client,
                                  db,
                                  collection,
                                  required,
                                  properties,
                                  action,
                                  level)
                result['changed'] = True
                result['msg'] = "The validator was updated on the given collection"
            else:
                result['changed'] = False
                result['msg'] = "The validator exists as configured on the given collection"
        else:
            if not module.check_mode:
                add_validator(client,
                              db,
                              collection,
                              required,
                              properties,
                              action,
                              level)
            result['changed'] = True
            result['msg'] = "The validator has been added to the given collection"
    elif state == "absent":
        if validator is None:
            result['changed'] = False
            result['msg'] = "A validator does not exist on the given collection."
        else:
            if not module.check_mode:
                remove_validator(client, db, collection)
            result['changed'] = True
            result['msg'] = "The validator has been removed from the given collection"

    if debug:
        result['validator'] = validator
        result['module_config'] = {"required": required,
                                   "properties": properties,
                                   "validationAction": action,
                                   "validationLevel": level}

    module.exit_json(**result)


if __name__ == '__main__':
    main()
