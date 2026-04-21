#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 StackHPC Ltd.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
module: baremetal_deploy_template
short_description: Create/Delete Bare Metal deploy template Resources from OpenStack
author: OpenStack Ansible SIG
description:
    - Create, Update and Remove ironic deploy templates from OpenStack.
options:
    extra:
      description:
        - A set of one or more arbitrary metadata key and value pairs.
      type: dict
    id:
      description:
        - ID of the deploy template.
        - Will be auto-generated if not specified.
      type: str
      aliases: ['uuid']
    name:
      description:
        - Name of the deploy template.
        - Must be formatted as a trait name (see API reference).
        - Required when the deploy template is created, after which the
          name or ID may be used.
      type: str
    steps:
      description:
        - List of deploy steps to apply.
        - Required when the deploy template is created.
      type: list
      elements: dict
    state:
      description:
        - Indicates desired state of the resource
      choices: ['present', 'absent']
      default: present
      type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create Bare Metal deploy template
  openstack.cloud.baremetal_deploy_template:
    cloud: devstack
    state: present
    name: CUSTOM_FOO
    steps:
      - interface: bios
        step: apply_configuration
        args:
          settings:
            - name: LogicalProc
              value: Enabled
        priority: 110
    extra:
      something: extra
  register: result

- name: Delete Bare Metal deploy template
  openstack.cloud.baremetal_deploy_template:
    cloud: devstack
    state: absent
    id: 1a85ebca-22bf-42eb-ad9e-f640789b8098
  register: result

- name: Update Bare Metal deploy template
  openstack.cloud.baremetal_deploy_template:
    cloud: devstack
    state: present
    id: 1a85ebca-22bf-42eb-ad9e-f640789b8098
    extra:
      something: new
'''

RETURN = r'''
template:
    description: A deploy template dictionary, subset of the dictionary keys
                 listed below may be returned, depending on your cloud
                 provider.
    returned: success
    type: dict
    contains:
        created_at:
            description: Bare Metal deploy template created at timestamp.
            returned: success
            type: str
        extra:
            description: A set of one or more arbitrary metadata key and value
                         pairs.
            returned: success
            type: dict
        id:
            description: The UUID for the Baremetal Deploy Template resource.
            returned: success
            type: str
        links:
            description: A list of relative links, including the self and
                         bookmark links.
            returned: success
            type: list
        location:
            description: Cloud location of this resource (cloud, project,
                         region, zone)
            returned: success
            type: dict
        name:
            description: Bare Metal deploy template name.
            returned: success
            type: str
        steps:
            description: A list of deploy steps.
            returned: success
            type: list
            elements: dict
        updated_at:
            description: Bare Metal deploy template updated at timestamp.
            returned: success
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule
)


class BaremetalDeployTemplateModule(OpenStackModule):
    argument_spec = dict(
        extra=dict(type='dict'),
        id=dict(aliases=['uuid']),
        name=dict(),
        steps=dict(type='list', elements='dict'),
        state=dict(default='present', choices=['present', 'absent']),
    )

    module_kwargs = dict(
        required_one_of=[
            ('id', 'name'),
        ],
    )

    def run(self):
        template = self._find_deploy_template()
        state = self.params['state']
        if state == 'present':
            # create or update deploy template

            kwargs = {}
            for k in ['extra', 'id', 'name', 'steps']:
                if self.params[k] is not None:
                    kwargs[k] = self.params[k]

            changed = True
            if not template:
                # create deploy template
                template = self.conn.baremetal.create_deploy_template(**kwargs)
            else:
                # update deploy template
                updates = dict((k, v)
                               for k, v in kwargs.items()
                               if v != template[k])

                if updates:
                    template = \
                        self.conn.baremetal.update_deploy_template(template['id'], **updates)
                else:
                    changed = False

            self.exit_json(changed=changed, template=template.to_dict(computed=False))

        if state == 'absent':
            # remove deploy template
            if not template:
                self.exit_json(changed=False)

            template = self.conn.baremetal.delete_deploy_template(template['id'])
            self.exit_json(changed=True)

    def _find_deploy_template(self):
        id_or_name = self.params['id'] if self.params['id'] else self.params['name']
        try:
            return self.conn.baremetal.get_deploy_template(id_or_name)
        except self.sdk.exceptions.ResourceNotFound:
            return None


def main():
    module = BaremetalDeployTemplateModule()
    module()


if __name__ == "__main__":
    main()
