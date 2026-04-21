#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 by Uemit Seren <uemit.seren@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: subnet_pool
short_description: Create, update or delete a subnet pool from OpenStack
author: OpenStack Ansible SIG
description:
   - Create, update or delete a subnet pool from OpenStack.
options:
   address_scope:
     description:
        - ID or name of the address scope associated with this subnet pool.
     type: str
   default_prefix_length:
     description:
        - The prefix length to allocate when the cidr or prefixlen attributes
          are omitted when creating a subnet.
     type: int
   default_quota:
     description:
        - A per-project quota on the prefix space that can be allocated
          from the subnet pool for project subnets.
     type: int
   description:
     description: The subnet pool description.
     type: str
   extra_specs:
     description:
        - Dictionary with extra key/value pairs passed to the API.
     type: dict
   is_default:
     description:
        - Whether this subnet pool is the default.
     type: bool
   is_shared:
     description:
        - Whether this subnet pool is shared or not.
        - This attribute cannot be updated.
     type: bool
     aliases: ['shared']
   maximum_prefix_length:
     description:
        - The maximum prefix length that can be allocated from the subnet pool.
     type: int
   minimum_prefix_length:
     description:
        - The minimum prefix length that can be allocated from the subnet pool.
     type: int
   name:
     description:
        - Name to be give to the subnet pool.
        - This attribute cannot be updated.
     required: true
     type: str
   prefixes:
     description:
        - Subnet pool prefixes in CIDR notation.
     type: list
     elements: str
   project:
     description:
        - Name or ID of the project.
     type: str
   state:
     description:
        - Whether the subnet pool should be C(present) or C(absent).
     choices: ['present', 'absent']
     default: present
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create an subnet pool.
  openstack.cloud.subnet_pool:
    cloud: mycloud
    state: present
    name: my_subnet_pool
    prefixes:
        - 10.10.10.0/24

- name: Create a subnet pool for a given project.
  openstack.cloud.subnet_pool:
    cloud: mycloud
    state: present
    name: my_subnet_pool
    project: myproj
    prefixes:
        - 10.10.10.0/24

- name: Create a shared and default subnet pool in existing address scope
  openstack.cloud.subnet_pool:
    cloud: mycloud
    state: present
    name: my_subnet_pool
    address_scope: my_adress_scope
    is_default: True
    default_quota: 10
    maximum_prefix_length: 32
    minimum_prefix_length: 8
    default_prefix_length: 24
    is_shared: True
    prefixes:
        - 10.10.10.0/8

- name: Delete subnet poool.
  openstack.cloud.subnet_pool:
    cloud: mycloud
    state: absent
    name: my_subnet_pool
'''

RETURN = r'''
subnet_pool:
    description: Dictionary describing the subnet pool.
    returned: On success when I(state) is C(present).
    type: dict
    contains:
        address_scope_id:
            description: The address scope ID.
            type: str
            sample: "861174b82b43463c9edc5202aadc60ef"
        created_at:
            description: Timestamp when the subnet pool was created.
            type: str
            sample: ""
        default_prefix_length:
            description: The length of the prefix to allocate when the cidr or
                         prefixlen attributes are omitted when creating a
                         subnet.
            type: int
            sample: 32
        default_quota:
            description: The per-project quota on the prefix space that can be
                         allocated from the subnet pool for project subnets.
            type: int
            sample: 22
        description:
            description: The subnet pool description.
            type: str
            sample: "My test subnet pool."
        id:
            description: Subnet Pool ID.
            type: str
            sample: "474acfe5-be34-494c-b339-50f06aa143e4"
        ip_version:
            description: The IP version of the subnet pool 4 or 6.
            type: int
            sample: 4
        is_default:
            description: Indicates whether this is the default subnet pool.
            type: bool
            sample: false
        is_shared:
            description: Indicates whether this subnet pool is shared across
                         all projects.
            type: bool
            sample: false
        maximum_prefix_length:
            description: The maximum prefix length that can be allocated from
                         the subnet pool.
            type: int
            sample: 22
        minimum_prefix_length:
            description: The minimum prefix length that can be allocated from
                         the subnet pool.
            type: int
            sample: 8
        name:
            description: Subnet Pool name.
            type: str
            sample: "my_subnet_pool"
        prefixes:
            description: A list of subnet prefixes that are assigned to the
                         subnet pool.
            type: list
            sample: ['10.10.20.0/24', '10.20.10.0/24']
        project_id:
            description: The ID of the project.
            type: str
            sample: "861174b82b43463c9edc5202aadc60ef"
        revision_number:
            description: Revision number of the subnet pool.
            type: int
            sample: 5
        tags:
            description:  A list of associated tags.
            returned: success
            type: list
        tenant_id:
            description: The ID of the project. Deprecated.
            type: str
            sample: "861174b82b43463c9edc5202aadc60ef"
        updated_at:
            description: Timestamp when the subnet pool was last updated.
            type: str
            sample:
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class SubnetPoolModule(OpenStackModule):
    argument_spec = dict(
        address_scope=dict(),
        default_prefix_length=dict(type='int'),
        default_quota=dict(type='int'),
        description=dict(),
        extra_specs=dict(type='dict'),
        is_default=dict(type='bool'),
        is_shared=dict(type='bool', aliases=['shared']),
        maximum_prefix_length=dict(type='int'),
        minimum_prefix_length=dict(type='int'),
        name=dict(required=True),
        prefixes=dict(type='list', elements='str'),
        project=dict(),
        state=dict(default='present', choices=['absent', 'present']),
    )

    def run(self):
        state = self.params['state']

        name = self.params['name']
        subnet_pool = self.conn.network.find_subnet_pool(name)

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, subnet_pool))

        if state == 'present' and not subnet_pool:
            # Create subnet_pool
            subnet_pool = self._create()
            self.exit_json(changed=True,
                           subnet_pool=subnet_pool.to_dict(computed=False))

        elif state == 'present' and subnet_pool:
            # Update subnet_pool
            update = self._build_update(subnet_pool)
            if update:
                subnet_pool = self._update(subnet_pool, update)

            self.exit_json(changed=bool(update),
                           subnet_pool=subnet_pool.to_dict(computed=False))

        elif state == 'absent' and subnet_pool:
            # Delete subnet_pool
            self._delete(subnet_pool)
            self.exit_json(changed=True)

        elif state == 'absent' and not subnet_pool:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, subnet_pool):
        update = {}

        attributes = dict((k, self.params[k])
                          for k in ['default_prefix_length', 'default_quota',
                                    'description', 'is_default',
                                    'maximum_prefix_length',
                                    'minimum_prefix_length']
                          if self.params[k] is not None
                          and self.params[k] != subnet_pool[k])

        for k in ['prefixes']:
            if self.params[k] is not None \
               and set(self.params[k]) != set(subnet_pool[k]):
                attributes[k] = self.params[k]

        project_name_or_id = self.params['project']
        if project_name_or_id is not None:
            project = self.conn.identity.find_project(project_name_or_id,
                                                      ignore_missing=False)
            if subnet_pool['project_id'] != project.id:
                attributes['project_id'] = project.id

        address_scope_name_or_id = self.params['address_scope']
        if address_scope_name_or_id is not None:
            address_scope = self.conn.network.find_address_scope(
                address_scope_name_or_id, ignore_missing=False)
            if subnet_pool['address_scope_id'] != address_scope.id:
                attributes['address_scope_id'] = address_scope.id

        extra_specs = self.params['extra_specs']
        if extra_specs:
            duplicate_keys = set(attributes.keys()) & set(extra_specs.keys())
            if duplicate_keys:
                raise ValueError('Duplicate key(s) in extra_specs: {0}'
                                 .format(', '.join(list(duplicate_keys))))
            for k, v in extra_specs.items():
                if v != subnet_pool[k]:
                    attributes[k] = v

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['default_prefix_length', 'default_quota',
                                'description', 'is_default', 'is_shared',
                                'maximum_prefix_length',
                                'minimum_prefix_length', 'name', 'prefixes']
                      if self.params[k] is not None)

        project_name_or_id = self.params['project']
        if project_name_or_id is not None:
            project = self.conn.identity.find_project(project_name_or_id,
                                                      ignore_missing=False)
            kwargs['project_id'] = project.id

        address_scope_name_or_id = self.params['address_scope']
        if address_scope_name_or_id is not None:
            address_scope = self.conn.network.find_address_scope(
                address_scope_name_or_id, ignore_missing=False)
            kwargs['address_scope_id'] = address_scope.id

        extra_specs = self.params['extra_specs']
        if extra_specs:
            duplicate_keys = set(kwargs.keys()) & set(extra_specs.keys())
            if duplicate_keys:
                raise ValueError('Duplicate key(s) in extra_specs: {0}'
                                 .format(', '.join(list(duplicate_keys))))
            kwargs = dict(kwargs, **extra_specs)

        return self.conn.network.create_subnet_pool(**kwargs)

    def _delete(self, subnet_pool):
        self.conn.network.delete_subnet_pool(subnet_pool.id)

    def _update(self, subnet_pool, update):
        attributes = update.get('attributes')
        if attributes:
            subnet_pool = self.conn.network.update_subnet_pool(subnet_pool.id,
                                                               **attributes)

        return subnet_pool

    def _will_change(self, state, subnet_pool):
        if state == 'present' and not subnet_pool:
            return True
        elif state == 'present' and subnet_pool:
            return bool(self._build_update(subnet_pool))
        elif state == 'absent' and subnet_pool:
            return True
        else:
            # state == 'absent' and not subnet_pool:
            return False


def main():
    module = SubnetPoolModule()
    module()


if __name__ == '__main__':
    main()
