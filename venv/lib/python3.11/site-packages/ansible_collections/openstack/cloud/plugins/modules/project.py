#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 IBM Corporation
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: project
short_description: Manage OpenStack Identity (Keystone) projects
author: OpenStack Ansible SIG
description:
  - Create, update or delete a OpenStack Identity (Keystone) project.
options:
  name:
    description:
      - Name for the project.
      - This attribute cannot be updated.
    required: true
    type: str
  description:
    description:
      - Description for the project.
    type: str
  domain:
    description:
      - Domain name or id to create the project in if the cloud supports
        domains.
    aliases: ['domain_id']
    type: str
  extra_specs:
    description:
      - Additional properties to be associated with this project.
    type: dict
    aliases: ['properties']
  is_enabled:
    description:
      - Whether this project is enabled or not.
    aliases: ['enabled']
    type: bool
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create a project
  openstack.cloud.project:
    cloud: mycloud
    description: demodescription
    domain: demoid
    is_enabled: True
    name: demoproject
    extra_specs:
      internal_alias: demo_project
    state: present

- name: Delete a project
  openstack.cloud.project:
    cloud: mycloud
    endpoint_type: admin
    name: demoproject
    state: absent
'''

RETURN = r'''
project:
  description: Dictionary describing the project.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    description:
      description: Project description
      type: str
      sample: "demodescription"
    domain_id:
      description: Domain ID to which the project belongs
      type: str
      sample: "default"
    id:
      description: Project ID
      type: str
      sample: "f59382db809c43139982ca4189404650"
    is_domain:
      description: Indicates whether the project also acts as a domain.
      type: bool
    is_enabled:
      description: Indicates whether the project is enabled
      type: bool
    name:
      description: Project name
      type: str
      sample: "demoproject"
    options:
      description: The resource options for the project
      type: dict
    parent_id:
      description: The ID of the parent of the project
      type: str
    tags:
      description: A list of associated tags
      type: list
      elements: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityProjectModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        domain=dict(aliases=['domain_id']),
        extra_specs=dict(type='dict', aliases=['properties']),
        is_enabled=dict(type='bool', aliases=['enabled']),
        name=dict(required=True),
        state=dict(default='present', choices=['absent', 'present'])
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        state = self.params['state']

        project = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, project))

        if state == 'present' and not project:
            # Create project
            project = self._create()
            self.exit_json(changed=True,
                           project=project.to_dict(computed=False))

        elif state == 'present' and project:
            # Update project
            update = self._build_update(project)
            if update:
                project = self._update(project, update)

            self.exit_json(changed=bool(update),
                           project=project.to_dict(computed=False))

        elif state == 'absent' and project:
            # Delete project
            self._delete(project)
            self.exit_json(changed=True)

        elif state == 'absent' and not project:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, project):
        update = {}

        # Params name and domain are being used to find this project.

        non_updateable_keys = [k for k in []
                               if self.params[k] is not None
                               and self.params[k] != project[k]]

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['description', 'is_enabled']
                          if self.params[k] is not None
                          and self.params[k] != project[k])

        extra_specs = self.params['extra_specs']
        if extra_specs:
            duplicate_keys = set(attributes.keys()) & set(extra_specs.keys())
            if duplicate_keys:
                raise ValueError('Duplicate key(s) in extra_specs: {0}'
                                 .format(', '.join(list(duplicate_keys))))
            for k, v in extra_specs.items():
                if v != project[k]:
                    attributes[k] = v

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['description', 'is_enabled', 'name']
                      if self.params[k] is not None)

        domain_name_or_id = self.params['domain']
        if domain_name_or_id is not None:
            domain = self.conn.identity.find_domain(domain_name_or_id,
                                                    ignore_missing=False)
            kwargs['domain_id'] = domain.id

        extra_specs = self.params['extra_specs']
        if extra_specs:
            duplicate_keys = set(kwargs.keys()) & set(extra_specs.keys())
            if duplicate_keys:
                raise ValueError('Duplicate key(s) in extra_specs: {0}'
                                 .format(', '.join(list(duplicate_keys))))
            kwargs = dict(kwargs, **extra_specs)

        return self.conn.identity.create_project(**kwargs)

    def _delete(self, project):
        self.conn.identity.delete_project(project.id)

    def _find(self):
        name = self.params['name']
        kwargs = {}

        domain_name_or_id = self.params['domain']
        if domain_name_or_id is not None:
            domain = self.conn.identity.find_domain(domain_name_or_id,
                                                    ignore_missing=False)
            kwargs['domain_id'] = domain.id

        return self.conn.identity.find_project(name_or_id=name,
                                               **kwargs)

    def _update(self, project, update):
        attributes = update.get('attributes')
        if attributes:
            project = self.conn.identity.update_project(project.id,
                                                        **attributes)

        return project

    def _will_change(self, state, project):
        if state == 'present' and not project:
            return True
        elif state == 'present' and project:
            return bool(self._build_update(project))
        elif state == 'absent' and project:
            return True
        else:
            # state == 'absent' and not project:
            return False


def main():
    module = IdentityProjectModule()
    module()


if __name__ == '__main__':
    main()
