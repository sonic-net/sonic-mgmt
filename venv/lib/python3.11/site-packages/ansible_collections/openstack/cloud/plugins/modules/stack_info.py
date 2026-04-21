#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Sagi Shnaidman <sshnaidm@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: stack_info
short_description: Retrieve information about Heat stacks
author: OpenStack Ansible SIG
description:
  - Get information about Heat stack in OpenStack
options:
  name:
    description:
      - Name of the stack.
    type: str
  owner:
    description:
      - Name or ID of the parent stack.
    type: str
    aliases: ['owner_id']
  project:
    description:
      - Name or ID of the project.
    type: str
    aliases: ['project_id']
  status:
    description:
      - Status of the stack such as C(available)
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Fetch all Heat stacks
  openstack.cloud.stack_info:
    cloud: devstack

- name: Fetch a single Heat stack
  openstack.cloud.stack_info:
    cloud: devstack
    name: my_stack
'''

RETURN = r'''
stacks:
    description: List of dictionaries describing stacks.
    type: list
    elements: dict
    returned: always.
    contains:
        added:
            description: List of resource objects that will be added.
            type: list
        capabilities:
            description: AWS compatible template listing capabilities.
            type: list
        created_at:
            description: Time when created.
            type: str
            sample: "2016-07-05T17:38:12Z"
        deleted:
            description: A list of resource objects that will be deleted.
            type: list
        deleted_at:
            description: Time when the deleted.
            type: str
            sample: "2016-07-05T17:38:12Z"
        description:
            description: >
              Description of the Stack provided in the heat
              template.
            type: str
            sample: "HOT template to create a new instance and networks"
        environment:
            description: A JSON environment for the stack.
            type: dict
        environment_files:
            description: >
              An ordered list of names for environment files found
              in the files dict.
            type: list
        files:
            description: >
              Additional files referenced in the template or
              the environment
            type: dict
        files_container:
            description: >
              Name of swift container with child templates and
              files.
            type: str
        id:
            description: Stack ID.
            type: str
            sample: "97a3f543-8136-4570-920e-fd7605c989d6"
        is_rollback_disabled:
            description: Whether the stack will support a rollback.
            type: bool
        links:
            description: Links to the current Stack.
            type: list
            elements: dict
            sample: "[{'href': 'http://foo:8004/v1/7f6a/stacks/test-stack/
                     97a3f543-8136-4570-920e-fd7605c989d6']"
        name:
            description: Name of the Stack
            type: str
            sample: "test-stack"
        notification_topics:
            description: Stack related events.
            type: str
            sample: "HOT template to create a new instance and networks"
        outputs:
            description: Output returned by the Stack.
            type: list
            elements: dict
            sample: "[{'description': 'IP of server1 in private network',
                        'output_key': 'server1_private_ip',
                        'output_value': '10.1.10.103'}]"
        owner_id:
            description: The ID of the owner stack if any.
            type: str
        parameters:
            description: Parameters of the current Stack
            type: dict
            sample: "{'OS::project_id': '7f6a3a3e01164a4eb4eecb2ab7742101',
                        'OS::stack_id': '97a3f543-8136-4570-920e-fd7605c989d6',
                        'OS::stack_name': 'test-stack',
                        'stack_status': 'CREATE_COMPLETE',
                        'stack_status_reason':
                            'Stack CREATE completed successfully',
                        'status': 'COMPLETE',
                        'template_description':
                            'HOT template to create a new instance and nets',
                        'timeout_mins': 60,
                        'updated_time': null}"
        parent_id:
            description: The ID of the parent stack if any.
            type: str
        replaced:
            description: A list of resource objects that will be replaced.
            type: str
        status:
            description: stack status.
            type: str
        status_reason:
            description: >
              Explaining how the stack transits to its current
              status.
            type: str
        tags:
            description: A list of strings used as tags on the stack
            type: list
        template:
            description: A dict containing the template use for stack creation.
            type: dict
        template_description:
            description: Stack template description text.
            type: str
        template_url:
            description: The URL where a stack template can be found.
            type: str
        timeout_mins:
            description: Stack operation timeout in minutes.
            type: str
        unchanged:
            description: >
              A list of resource objects that will remain unchanged
              if a stack.
            type: list
        updated:
            description: >
              A list of resource objects that will have their
              properties updated.
            type: list
        updated_at:
            description: Timestamp of last update on the stack.
            type: str
        user_project_id:
            description: The ID of the user project created for this stack.
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class StackInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(),
        owner=dict(aliases=['owner_id']),
        project=dict(aliases=['project_id']),
        status=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = {}

        owner_name_or_id = self.params['owner']
        if owner_name_or_id:
            owner = self.conn.orchestration.find_stack(owner_name_or_id)
            if owner:
                kwargs['owner_id'] = owner['id']
            else:
                # Owner could not be found so return empty list of stacks
                # because *_info modules never raise errors on missing
                # resources
                self.exit_json(changed=False, stacks=[])

        project_name_or_id = self.params['project']
        if project_name_or_id:
            project = self.conn.identity.find_project(project_name_or_id)
            if project:
                kwargs['project_id'] = project['id']
            else:
                # Project could not be found so return empty list of stacks
                # because *_info modules never raise errors on missing
                # resources
                self.exit_json(changed=False, stacks=[])

        for k in ['name', 'status']:
            if self.params[k] is not None:
                kwargs[k] = self.params[k]

        stacks = []
        for stack in self.conn.orchestration.stacks(**kwargs):
            stack_obj = self.conn.orchestration.get_stack(stack.id)
            stacks.append(stack_obj.to_dict(computed=False))

        self.exit_json(changed=False, stacks=stacks)


def main():
    module = StackInfoModule()
    module()


if __name__ == '__main__':
    main()
