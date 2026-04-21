#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Manage Infinibox export clients """

# pylint: disable=invalid-name,use-dict-literal,line-too-long,wrong-import-position, wrong-import-order

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_export_client
version_added: '2.3.0'
short_description: Create, Delete or Modify NFS Client(s) for existing exports on Infinibox
description:
    - This module creates, deletes or modifys NFS client(s) for existing exports on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  client:
    description:
      - Client IP or Range. Ranges can be defined as follows
        192.168.0.1-192.168.0.254.
    required: true
    type: str
  state:
    description:
      - Creates/Modifies client when present and removes when absent.
    required: false
    default: "present"
    choices: [ "stat", "present", "absent" ]
    type: str
  access_mode:
    description:
      - Read Write or Read Only Access.
    choices: [ "RW", "RO" ]
    default: "RW"
    required: false
    type: str
  no_root_squash:
    description:
      - Don't squash root user to anonymous. Will be set to "no" on creation if not specified explicitly.
    type: bool
    default: no
    required: false
  export:
    description:
      - Name of the export.
    required: true
    type: str
extends_documentation_fragment:
    - infinibox
requirements:
    - munch
'''

EXAMPLES = r'''
- name: Make sure nfs client 10.0.0.1 is configured for export. Allow root access
  infini_export_client:
    client: 10.0.0.1
    access_mode: RW
    no_root_squash: true
    export: /data
    state: present  # Default
    user: admin
    password: secret
    system: ibox001

- name: Add multiple clients with RO access. Squash root privileges
  infini_export_client:
    client: "{{ item }}"
    access_mode: RO
    no_root_squash: false
    export: /data
    user: admin
    password: secret
    system: ibox001
  with_items:
    - 10.0.0.2
    - 10.0.0.3
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

import traceback

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    get_export,
    merge_two_dicts,
)

MUNCH_IMPORT_ERROR = None
try:
    from munch import Munch, unmunchify
    HAS_MUNCH = True
except ImportError:
    MUNCH_IMPORT_ERROR = traceback.format_exc()
    HAS_MUNCH = False


@api_wrapper
def update_client(module, export):
    """
    Update export client list. Note that this will replace existing clients.
    """

    changed = False

    client = module.params['client']
    access_mode = module.params['access_mode']
    no_root_squash = module.params['no_root_squash']

    client_list = export.get_permissions()
    client_not_in_list = True

    for item in client_list:
        if item.client == client:  # Update client
            client_not_in_list = False
            if item.access != access_mode:
                item.access = access_mode
                changed = True
            if item.no_root_squash is not no_root_squash:
                item.no_root_squash = no_root_squash
                changed = True

    # If access_mode and/or no_root_squash not passed as arguments to the module,
    # use access_mode with RW value and set no_root_squash to False
    if client_not_in_list:  # Create client
        changed = True
        client_list.append(Munch(client=client, access=access_mode, no_root_squash=no_root_squash))

    if changed:
        for index, item in enumerate(client_list):
            client_list[index] = unmunchify(item)
        if not module.check_mode:
            export.update_permissions(client_list)

    return changed


@api_wrapper
def delete_client(module, export):
    """delete export client from client list"""
    if export is None and module.params['state'] == 'absent':
        module.exit_json(changed=False)

    changed = False

    client = module.params['client']
    client_list = export.get_permissions()

    for index, item in enumerate(client_list):
        if item.client == client:
            changed = True
            del client_list[index]

    if changed:
        for index, item in enumerate(client_list):
            client_list[index] = unmunchify(item)
        if not module.check_mode:
            export.update_permissions(client_list)

    return changed


def get_export_client_fields(export, client_name):
    """ Get export client fields """
    fields = export.get_fields()  # from_cache=True, raw_value=True)
    permissions = fields.get('permissions', None)
    for munched_perm in permissions:
        perm = unmunchify(munched_perm)
        if perm['client'] == client_name:  # Found client
            field_dict = dict(
                access_mode=perm['access'],
                no_root_squash=perm['no_root_squash'],
            )
            return field_dict
    raise AssertionError(f"No client {client_name} match to exports found")


def handle_stat(module):
    """ Execute the stat state """
    system = get_system(module)
    export = get_export(module, system)
    if not export:
        module.fail_json(msg=f"Export {module.params['export']} not found")
    client_name = module.params['client']
    field_dict = get_export_client_fields(export, client_name)
    result = dict(
        changed=False,
        msg='Export client stat found'
    )
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """ Execute the present state """
    system = get_system(module)
    export = get_export(module, system)
    if not export:
        msg = f"Export {module.params['export']} not found"
        module.fail_json(msg=msg)

    changed = update_client(module, export)
    msg = "Export client updated"
    module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    """ Execute the absent state """
    system = get_system(module)
    export = get_export(module, system)
    if not export:
        changed = False
        msg = "Export client already absent"
        module.exit_json(changed=False, msg=msg)
    else:
        changed = delete_client(module, export)
        msg = "Export client removed"
        module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    """ Execute a state """
    state = module.params['state']
    try:
        if state == 'stat':
            handle_stat(module)
        elif state == 'present':
            handle_present(module)
        elif state == 'absent':
            handle_absent(module)
        else:
            module.fail_json(msg=f'Internal handler error. Invalid state: {state}')
    finally:
        system = get_system(module)
        system.logout()


def main():
    """ Main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            client=dict(required=True),
            state=dict(default='present', choices=['stat', 'present', 'absent']),
            access_mode=dict(choices=['RO', 'RW'], default='RW', type="str"),
            no_root_squash=dict(type='bool', default='no'),
            export=dict(required=True)
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_MUNCH:
        module.fail_json(msg=missing_required_lib('munch'),
                         exception=MUNCH_IMPORT_ERROR)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    execute_state(module)


if __name__ == '__main__':
    main()
