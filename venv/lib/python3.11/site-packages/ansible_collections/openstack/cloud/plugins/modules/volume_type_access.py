#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_type_access
short_description: Manage access to OpenStack block-storage volume type
author: OpenStack Ansible SIG
description:
    - Add or remove access to OpenStack block-storage volume type
options:
  name:
    description:
      - Name or ID of the block-storage volume type.
    required: true
    type: str
  project:
    description:
      - ID or Name of project to grant.
      - Allow I(project) to access private volume type (name or ID).
    type: str
    required: true
  project_domain:
     description:
       - Domain the project belongs to (name or ID).
       - This can be used in case collisions between project names exist.
     type: str
  state:
    description:
      - Indicate whether project should have access to volume type or not.
    default: present
    type: str
    choices: ['present', 'absent']
notes:
    - A volume type must not be private to manage project access.
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Grant access to volume type vol-type-001
  openstack.cloud.volume_type_access:
    cloud: devstack
    name: vol-type-001
    project: demo
    state: present

- name: Revoke access to volume type
  openstack.cloud.volume_type_access:
    cloud: devstack
    name: vol-type-001
    project: demo
    state: absent
'''

RETURN = '''
volume_type:
  description: Dictionary describing the volume type.
  returned: success
  type: dict
  contains:
    description:
      description: Description of the type.
      returned: success
      type: str
    extra_specs:
      description: A dict of extra specifications.
                   "capabilities" is a usual key.
      returned: success
      type: dict
    id:
      description: Volume type ID.
      returned: success
      type: str
    is_public:
      description: Volume type is accessible to the public.
      returned: success
      type: bool
    name:
      description: Volume type name.
      returned: success
      type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeTypeAccess(OpenStackModule):
    argument_spec = dict(
        name=dict(required=True),
        project=dict(required=True),
        project_domain=dict(),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        supports_check_mode=True,
    )

    # TODO: Merge with equal function from compute_flavor_access module.
    def _project_and_project_domain(self):
        project_name_or_id = self.params['project']
        project_domain_name_or_id = self.params['project_domain']

        if project_domain_name_or_id:
            domain_id = self.conn.identity.find_domain(
                project_domain_name_or_id, ignore_missing=False).id
        else:
            domain_id = None

        kwargs = dict() if domain_id is None else dict(domain_id=domain_id)

        if project_name_or_id:
            project_id = self.conn.identity.find_project(
                project_name_or_id, ignore_missing=False, *kwargs).id
        else:
            project_id = None

        return project_id, domain_id

    def run(self):
        name_or_id = self.params['name']

        # Workaround for an issue in openstacksdk where
        # self.conn.block_storage.find_type() will not
        # find private volume types.
        volume_types = \
            list(self.conn.block_storage.types(is_public=False)) \
            + list(self.conn.block_storage.types(is_public=True))

        volume_type = [volume_type for volume_type in volume_types
                       if volume_type.id == name_or_id
                       or volume_type.name == name_or_id][0]

        state = self.params['state']
        if state == 'present' and volume_type.is_public:
            raise ValueError('access can only be granted to private types')

        project_id, domain_id = self._project_and_project_domain()

        volume_type_access = \
            self.conn.block_storage.get_type_access(volume_type.id)
        project_ids = [access.get('project_id')
                       for access in volume_type_access]

        if (project_id in project_ids and state == 'present') \
           or (project_id not in project_ids and state == 'absent'):
            self.exit_json(changed=False,
                           volume_type=volume_type.to_dict(computed=False))

        if self.ansible.check_mode:
            self.exit_json(changed=True,
                           volume_type=volume_type.to_dict(computed=False))

        if project_id in project_ids:  # and state == 'absent'
            self.conn.block_storage.remove_type_access(volume_type.id,
                                                       project_id)
        else:  # project_id not in project_ids and state == 'present'
            self.conn.block_storage.add_type_access(volume_type.id,
                                                    project_id)

        self.exit_json(changed=True,
                       volume_type=volume_type.to_dict(computed=False))


def main():
    module = VolumeTypeAccess()
    module()


if __name__ == '__main__':
    main()
