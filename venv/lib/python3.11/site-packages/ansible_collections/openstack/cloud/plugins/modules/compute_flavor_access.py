#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: compute_flavor_access
short_description: Manage access to OpenStack compute flavors
author: OpenStack Ansible SIG
description:
    - Add or remove access to OpenStack compute flavor
options:
  name:
    description:
      - Name or ID of the compute flavor.
    required: true
    type: str
  project:
    description:
      - ID or Name of project to grant.
      - Allow I(project) to access private flavor (name or ID).
    type: str
    required: true
  project_domain:
     description:
       - Domain the project belongs to (name or ID).
       - This can be used in case collisions between project names exist.
     type: str
  state:
    description:
      - Indicate whether project should have access to compute flavor or not.
    default: present
    type: str
    choices: ['present', 'absent']
notes:
    - A compute flavor must be private to manage project access.
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Grant access to tiny flavor
  openstack.cloud.compute_flavor_access:
    cloud: devstack
    name: tiny
    project: demo
    state: present

- name: Revoke access to compute flavor
  openstack.cloud.compute_flavor_access:
    cloud: devstack
    name: tiny
    project: demo
    state: absent
'''

RETURN = '''
flavor:
  description: Dictionary describing the flavor.
  returned: On success when I(state) is 'present'
  type: dict
  contains:
    description:
      description: Description attached to flavor
      returned: success
      type: str
      sample: Example description
    disk:
      description: Size of local disk, in GB.
      returned: success
      type: int
      sample: 10
    ephemeral:
      description: Ephemeral space size, in GB.
      returned: success
      type: int
      sample: 10
    extra_specs:
      description: Flavor metadata
      returned: success
      type: dict
      sample:
        "quota:disk_read_iops_sec": 5000
        "aggregate_instance_extra_specs:pinned": false
    id:
      description: Flavor ID.
      returned: success
      type: str
      sample: "515256b8-7027-4d73-aa54-4e30a4a4a339"
    is_disabled:
      description: Whether the flavor is disabled
      returned: success
      type: bool
      sample: true
    is_public:
      description: Make flavor accessible to the public.
      returned: success
      type: bool
      sample: true
    name:
      description: Flavor name.
      returned: success
      type: str
      sample: "tiny"
    original_name:
      description: The name of this flavor when returned by server list/show
      type: str
      returned: success
    ram:
      description: Amount of memory, in MB.
      returned: success
      type: int
      sample: 1024
    rxtx_factor:
      description: |
        The bandwidth scaling factor this flavor receives on the network
      returned: success
      type: int
      sample: 100
    swap:
      description: Swap space size, in MB.
      returned: success
      type: int
      sample: 100
    vcpus:
      description: Number of virtual CPUs.
      returned: success
      type: int
      sample: 2
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ComputeFlavorAccess(OpenStackModule):
    argument_spec = dict(
        name=dict(required=True),
        project=dict(required=True),
        project_domain=dict(),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        supports_check_mode=True,
    )

    # TODO: Merge with equal function from volume_type_access module.
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
        flavor = self.conn.compute.find_flavor(name_or_id,
                                               ignore_missing=False)

        state = self.params['state']
        if state == 'present' and flavor.is_public:
            raise ValueError('access can only be granted to private flavors')

        project_id, domain_id = self._project_and_project_domain()

        flavor_access = self.conn.compute.get_flavor_access(flavor.id)
        project_ids = [access.get('tenant_id') for access in flavor_access]

        if (project_id in project_ids and state == 'present') \
           or (project_id not in project_ids and state == 'absent'):
            self.exit_json(changed=False,
                           flavor=flavor.to_dict(computed=False))

        if self.ansible.check_mode:
            self.exit_json(changed=True, flavor=flavor.to_dict(computed=False))

        if project_id in project_ids:  # and state == 'absent'
            self.conn.compute.flavor_remove_tenant_access(flavor.id,
                                                          project_id)
        else:  # project_id not in project_ids and state == 'present'
            self.conn.compute.flavor_add_tenant_access(flavor.id, project_id)

        self.exit_json(changed=True, flavor=flavor.to_dict(computed=False))


def main():
    module = ComputeFlavorAccess()
    module()


if __name__ == '__main__':
    main()
