#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,line-too-long,wrong-import-position,too-many-branches

"""This module creates, deletes or modifies pools on Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_pool
version_added: '2.3.0'
short_description: Create, Delete and Modify Pools on Infinibox
description:
    - This module to creates, deletes or modifies pools on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - Pool Name
    required: true
    type: str
  state:
    description:
      - Creates/Modifies Pool when present or removes when absent
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
    type: str
  size:
    description:
      - Pool Physical Capacity in MB, GB or TB units.
        If pool size is not set on pool creation, size will be equal to 1TB.
        See examples.
    required: false
    type: str
  vsize:
    description:
      - Pool Virtual Capacity in MB, GB or TB units.
        If pool vsize is not set on pool creation, Virtual Capacity will be equal to Physical Capacity.
        See examples.
    required: false
    type: str
  ssd_cache:
    description:
      - Enable/Disable SSD Cache on Pool
    required: false
    default: yes
    type: bool
  compression:
    description:
      - Enable/Disable Compression on Pool
    required: false
    default: yes
    type: bool
  physical_capacity_warning:
    description:
      - Capacity, in percent, for a warning notification.
    required: false
    type: int
    default: 80
  physical_capacity_critical:
    description:
      - Capacity, in percent, for a critical notification.
    required: false
    type: int
    default: 90

notes:
  - Infinibox Admin level access is required for pool modifications
extends_documentation_fragment:
    - infinibox
requirements:
    - capacity
'''

EXAMPLES = r'''
- name: Make sure pool foo exists. Set pool physical capacity to 10TB
  infini_pool:
    name: foo
    size: 10TB
    vsize: 10TB
    user: admin
    password: secret
    system: ibox001

- name: Disable SSD Cache on pool
  infini_pool:
    name: foo
    ssd_cache: false
    user: admin
    password: secret
    system: ibox001

- name: Disable Compression on pool
  infini_pool:
    name: foo
    compression: false
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
    get_pool,
    get_system,
)


HAS_CAPACITY = True
try:
    from capacity import KiB, Capacity
except ImportError:
    HAS_CAPACITY = False


@api_wrapper
def create_pool(module, system):
    """ Create Pool """
    name = module.params['name']
    size = module.params['size']
    vsize = module.params['vsize']
    ssd_cache = module.params['ssd_cache']
    compression = module.params['compression']
    physical_capacity_warning = module.params['physical_capacity_warning']
    physical_capacity_critical = module.params['physical_capacity_critical']

    if not module.check_mode:
        if not size and not vsize:
            pool = system.pools.create(name=name, physical_capacity=Capacity('1TB'), virtual_capacity=Capacity('1TB'),
                                       physical_capacity_warning=physical_capacity_warning, physical_capacity_critical=physical_capacity_critical)
        elif size and not vsize:
            pool = system.pools.create(name=name, physical_capacity=Capacity(size), virtual_capacity=Capacity(size),
                                       physical_capacity_warning=physical_capacity_warning, physical_capacity_critical=physical_capacity_critical)
        elif not size and vsize:
            pool = system.pools.create(name=name, physical_capacity=Capacity('1TB'), virtual_capacity=Capacity(vsize),
                                       physical_capacity_warning=physical_capacity_warning, physical_capacity_critical=physical_capacity_critical)
        else:
            pool = system.pools.create(name=name, physical_capacity=Capacity(size), virtual_capacity=Capacity(vsize),
                                       physical_capacity_warning=physical_capacity_warning, physical_capacity_critical=physical_capacity_critical)
        # Default value of ssd_cache is True. Disable ssd caching if False
        if not ssd_cache:
            pool.update_ssd_enabled(ssd_cache)
        # Default value of compression is True. Disable compression if False
        if not compression:
            pool.update_compression_enabled(compression)

    module.exit_json(changed=True, msg='Pool created')


@api_wrapper
def update_pool(module, pool):
    """ Update Pool """
    changed = False

    size = module.params['size']
    vsize = module.params['vsize']
    ssd_cache = module.params['ssd_cache']
    compression = module.params['compression']

    # Roundup the capacity to mimic Infinibox behaviour
    if size:
        physical_capacity = Capacity(size).roundup(6 * 64 * KiB)
        if pool.get_physical_capacity() != physical_capacity:
            if not module.check_mode:
                pool.update_physical_capacity(physical_capacity)
            changed = True

    if vsize:
        virtual_capacity = Capacity(vsize).roundup(6 * 64 * KiB)
        if pool.get_virtual_capacity() != virtual_capacity:
            if not module.check_mode:
                pool.update_virtual_capacity(virtual_capacity)
            changed = True

    if pool.is_ssd_enabled() != ssd_cache:
        if not module.check_mode:
            pool.update_ssd_enabled(ssd_cache)
        changed = True

    if pool.is_compression_enabled() != compression:
        if not module.check_mode:
            pool.update_compression_enabled(compression)
            changed = True

    physical_capacity_critical = module.params.get('physical_capacity_critical')
    existing_physical_capacity_critical = pool.get_physical_capacity_critical()
    if physical_capacity_critical != existing_physical_capacity_critical:
        if not module.check_mode:
            pool.update_physical_capacity_critical(physical_capacity_critical)
            changed = True

    physical_capacity_warning = module.params.get('physical_capacity_warning')
    existing_physical_capacity_warning = pool.get_physical_capacity_warning()
    if physical_capacity_warning != existing_physical_capacity_warning:
        if not module.check_mode:
            pool.update_physical_capacity_warning(physical_capacity_warning)
            changed = True

    if changed:
        msg = 'Pool updated'
    else:
        msg = 'Pool did not require updating'
    module.exit_json(changed=changed, msg=msg)


@api_wrapper
def delete_pool(module, pool):
    """ Delete Pool """
    if not module.check_mode:
        pool.delete()
    msg = 'Pool deleted'
    module.exit_json(changed=True, msg=msg)


def handle_stat(module):
    """ Show details about a pool """
    system = get_system(module)
    pool = get_pool(module, system)

    name = module.params['name']
    if not pool:
        module.fail_json(msg=f'Pool {name} not found')
    fields = pool.get_fields()
    # print('fields: {0}'.format(fields))
    free_physical_capacity = fields.get('free_physical_capacity', None)
    pool_id = fields.get('id', None)
    physical_capacity_warning = pool.get_physical_capacity_warning()
    physical_capacity_critical = pool.get_physical_capacity_critical()
    physical_capacity = pool.get_physical_capacity()
    virtual_capacity = pool.get_virtual_capacity()

    result = dict(
        changed=False,
        free_physical_capacity=str(free_physical_capacity),
        physical_capacity_warning=physical_capacity_warning,
        physical_capacity_critical=physical_capacity_critical,
        physical_capacity=str(physical_capacity),
        virtual_capacity=str(virtual_capacity),
        ssd_cache=pool.is_ssd_enabled(),
        compression_enabled=pool.is_compression_enabled(),
        id=pool_id,
        msg='Pool stat found',
    )
    module.exit_json(**result)


def handle_present(module):
    """ Create pool """
    system = get_system(module)
    pool = get_pool(module, system)
    if not pool:
        create_pool(module, system)
        module.exit_json(changed=True, msg="Pool created")
    else:
        changed = update_pool(module, pool)
        module.exit_json(changed=changed, msg="Pool updated")


def handle_absent(module):
    """ Remove pool """
    system = get_system(module)
    pool = get_pool(module, system)
    if not pool:
        module.exit_json(changed=False, msg="Pool already absent")
    else:
        delete_pool(module, pool)
        module.exit_json(changed=True, msg="Pool removed")


def execute_state(module):
    """Determine which state function to execute and do so"""
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
            size=dict(),
            vsize=dict(),
            ssd_cache=dict(type='bool', default=True),
            compression=dict(type='bool', default=True),
            physical_capacity_warning=dict(type='int', default=80),
            physical_capacity_critical=dict(type='int', default=90),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    if not HAS_CAPACITY:
        module.fail_json(msg=missing_required_lib('capacity'))

    if module.params['size']:
        try:
            Capacity(module.params['size'])
        except Exception:  # pylint: disable=broad-exception-caught
            module.fail_json(msg='size (Physical Capacity) should be defined in MB, GB, TB or PB units')

    if module.params['vsize']:
        try:
            Capacity(module.params['vsize'])
        except Exception:  # pylint: disable=broad-exception-caught
            module.fail_json(msg='vsize (Virtual Capacity) should be defined in MB, GB, TB or PB units')

    execute_state(module)


if __name__ == '__main__':
    main()
