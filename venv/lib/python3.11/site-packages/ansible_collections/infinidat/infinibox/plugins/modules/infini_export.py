#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,too-many-branches,too-many-locals,line-too-long,wrong-import-position

"""This module modifies exports on Infinibox."""

# Copyright: (c) 2024, Infinidat(info@infinidat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_export
version_added: '2.3.0'
short_description: Create, Delete or Modify NFS Exports on Infinibox
description:
    - This module creates, deletes or modifies NFS exports on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - Export name. Must start with a forward slash, e.g. name=/data.
    required: true
    type: str
  state:
    description:
      - Creates/Modifies export when present, removes when absent, or provides
        export details with stat.
    required: false
    default: "present"
    choices: [ "stat", "present", "absent" ]
    type: str
  client_list:
    description:
      - List of dictionaries with client entries. See examples.
        Check infini_export_client module to modify individual NFS client entries for export.
    required: false
    type: list
    elements: dict
  filesystem:
    description:
      - Name of exported file system.
    required: true
    type: str
extends_documentation_fragment:
    - infinibox
requirements:
    - munch
'''

EXAMPLES = r'''
- name: Export bar filesystem under foo pool as /data
  infini_export:
    name: /data01
    filesystem: foo
    state: present  # Default
    user: admin
    password: secret
    system: ibox001

- name: Get status of export bar filesystem under foo pool as /data
  infini_export:
    name: /data01
    filesystem: foo
    state: stat
    user: admin
    password: secret
    system: ibox001

- name: Remove export bar filesystem under foo pool as /data
  infini_export:
    name: /data01
    filesystem: foo
    state: absent
    user: admin
    password: secret
    system: ibox001

- name: Export and specify client list explicitly
  infini_export:
    name: /data02
    filesystem: foo
    client_list:
      - client: 192.168.0.2
        access: RW
        no_root_squash: true
      - client: 192.168.0.100
        access: RO
        no_root_squash: false
      - client: 192.168.0.10-192.168.0.20
        access: RO
        no_root_squash: false
    system: ibox001
    user: admin
    password: secret
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    get_filesystem,
    get_export,
    merge_two_dicts,
)

HAS_MUNCH = True
try:
    from munch import unmunchify
except ImportError:
    HAS_MUNCH = False


def transform(d):
    """ Create a frozen set from a normal set's items """
    return frozenset(d.items())


def create_export(module, export, filesystem, system):
    """ Create new export """
    if export:
        raise AssertionError(f"Export {export.get_name()} already exists")
    changed = False

    name = module.params['name']
    client_list = module.params['client_list']

    if not module.check_mode:
        export = system.exports.create(export_path=name, filesystem=filesystem)
        if client_list:
            export.update_permissions(client_list)
            changed = True
    return changed


@api_wrapper
def update_export(module, export):
    """ Update existing export """
    if not export:
        raise AssertionError(f"Export {export.get_name()} does not exist and cannot be updated")

    changed = False

    client_list = module.params['client_list']

    if client_list:
        # msg = "client_list: {0}, type: {1}".format(client_list, type(client_list))
        # module.fail_json(msg=msg)
        if set(map(transform, unmunchify(export.get_permissions()))) \
                != set(map(transform, client_list)):
            if not module.check_mode:
                export.update_permissions(client_list)
            changed = True
    return changed


@api_wrapper
def delete_export(module, export):
    """ Delete export """
    if not module.check_mode:
        export.delete()
    changed = True
    return changed


def get_export_fields(export):
    """ Return export fields dict """
    fields = export.get_fields()  # from_cache=True, raw_value=True)
    export_id = fields.get('id', None)
    permissions = fields.get('permissions', None)
    enabled = fields.get('enabled', None)
    field_dict = dict(
        id=export_id,
        permissions=permissions,
        enabled=enabled,
    )
    return field_dict


def handle_stat(module):
    """ Gather stats on export and return. Changed is always False. """
    name = module.params['name']
    filesystem_name = module.params['filesystem']
    system = get_system(module)
    export = get_export(module, system)
    if not export:
        module.fail_json(msg=f"Export '{name}' of file system '{filesystem_name}' not found")

    field_dict = get_export_fields(export)
    result = dict(
        changed=False,
        msg='File system stat found'
    )
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """ Handle present state """
    system = get_system(module)
    filesystem = get_filesystem(module, system)
    export = get_export(module, system)
    filesystem_name = module.params['filesystem']
    if not filesystem:
        module.fail_json(msg=f'File system {filesystem_name} not found')
    elif not export:
        changed = create_export(module, export, filesystem, system)
        module.exit_json(changed=changed, msg="File system export created")
    else:
        changed = update_export(module, export)
        module.exit_json(changed=changed, msg="File system export updated")


def handle_absent(module):
    """ Handle absent state """
    system = get_system(module)
    export = get_export(module, system)
    filesystem_name = module.params['filesystem']
    if not export:
        changed = False
        msg = "Export of {filesystem_name} already absent"
        module.exit_json(changed=changed, msg=msg)
    else:
        changed = delete_export(module, export)
        msg = f"Export of {filesystem_name} deleted"
        module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    """ Execute states """
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
            name=dict(required=True),
            state=dict(default='present', choices=['stat', 'present', 'absent']),
            filesystem=dict(required=True),
            client_list=dict(type='list', elements='dict')
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_MUNCH:
        module.fail_json(msg=missing_required_lib('munch'))

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    execute_state(module)


if __name__ == '__main__':
    main()
