#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-list-literal,use-dict-literal,line-too-long,wrong-import-position,multiple-statements

""" Manage hosts on Infinibox """

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_host
version_added: 2.3.0
short_description: Create, Delete or Modify Hosts on Infinibox
description:
    - This module creates, deletes or modifies hosts on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - Host Name
    type: str
    required: true
  state:
    description:
      - Creates/Modifies Host when present or removes when absent
    type: str
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Create new host
  infini_host:
    name: foo.example.com
    user: admin
    password: secret
    system: ibox001
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    get_host,
    unixMillisecondsToDate,
    merge_two_dicts,
)


@api_wrapper
def create_host(module, system):
    """ Create a host """
    changed = True
    if not module.check_mode:
        system.hosts.create(name=module.params['name'])
    return changed


@api_wrapper
def delete_host(module, host):
    """ Delete a host """
    changed = True
    if not module.check_mode:
        # May raise APICommandFailed if mapped, etc.
        host.delete()
    return changed


def get_host_fields(host):
    """ Get host fields """
    fields = host.get_fields(from_cache=True, raw_value=True)
    created_at, created_at_timezone = unixMillisecondsToDate(fields.get('created_at', None))
    field_dict = dict(
        created_at=created_at,
        created_at_timezone=created_at_timezone,
        id=host.id,
        iqns=[],
        luns=[],
        ports=[],
        wwns=[],
    )
    luns = host.get_luns()
    for lun in luns:
        field_dict['luns'].append({'lun_id': lun.id,
                                   'lun_volume_id': lun.volume.id,
                                   'lun_volume_name': lun.volume.get_name(),
                                   })
    ports = host.get_ports()
    for port in ports:
        if str(type(port)) == "<class 'infi.dtypes.wwn.WWN'>":
            field_dict['wwns'].append(str(port))
        if str(type(port)) == "<class 'infi.dtypes.iqn.IQN'>":
            field_dict['iqns'].append(str(port))
    return field_dict


def handle_stat(module):
    """ Handle the stat state """
    system = get_system(module)
    host = get_host(module, system)
    host_name = module.params["name"]
    if not host:
        module.fail_json(msg=f'Host {host_name} not found')
    field_dict = get_host_fields(host)
    result = dict(
        changed=False,
        msg=f'Host {host_name} stat found'
    )
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """ Handle the present state """
    system = get_system(module)
    host = get_host(module, system)
    host_name = module.params["name"]
    if not host:
        changed = create_host(module, system)
        msg = f'Host {host_name} created'
        module.exit_json(changed=changed, msg=msg)
    else:
        changed = False
        msg = f'Host {host_name} exists and does not need to be updated'
        module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    """ Handle the absent state """
    system = get_system(module)
    host = get_host(module, system)
    host_name = module.params["name"]
    if not host:
        msg = f"Host {host_name} already absent"
        module.exit_json(changed=False, msg=msg)
    else:
        changed = delete_host(module, host)
        msg = f"Host {host_name} removed"
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
            name=dict(required=True),
            state=dict(default='present', choices=['stat', 'present', 'absent']),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    execute_state(module)


if __name__ == '__main__':
    main()
