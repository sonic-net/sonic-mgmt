#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Mathieu Bultel <mbultel@redhat.com>
# (c) 2016, Steve Baker <sbaker@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: stack
short_description: Add/Remove Heat Stack
author: OpenStack Ansible SIG
description:
   - Add or Remove a Stack to an OpenStack Heat
options:
    environment:
      description:
        - List of environment files that should be used for the stack creation
      type: list
      elements: str
    name:
      description:
        - A name for the stack.
        - The value must be unique within a project.
        - The name must start with an ASCII letter and can contain ASCII
          letters, digits, underscores, periods, and hyphens. Specifically,
          the name must match the C(^[a-zA-Z][a-zA-Z0-9_.-]{0,254}$) regular
          expression.
        - When you delete or abandon a stack, its name will not become
          available for reuse until the deletion completes successfully.
      required: true
      type: str
    parameters:
      description:
        - Dictionary of parameters for the stack creation
      type: dict
      default: {}
    rollback:
      description:
        - Rollback stack creation
      type: bool
      default: false
    state:
      description:
        - Indicate desired state of the resource
      choices: ['present', 'absent']
      default: present
      type: str
    tags:
      description:
        - One or more simple string tags to associate with the stack.
        - To associate multiple tags with a stack, separate the tags with
          commas. For example, C(tag1,tag2).
      type: str
      aliases: ['tag']
    template:
      description:
        - Path of the template file to use for the stack creation
      type: str
    timeout:
      description:
        - Maximum number of seconds to wait for the stack creation
      default: 3600
      type: int
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: create stack
  openstack.cloud.stack:
    name: "teststack"
    tag: "tag1,tag2"
    state: present
    template: "/path/to/my_stack.yaml"
    environment:
    - /path/to/resource-registry.yaml
    - /path/to/environment.yaml
    parameters:
        bmc_flavor: m1.medium
        bmc_image: CentOS
        key_name: default
        node_count: 2
        name: undercloud
        image: CentOS
        my_flavor: m1.large
'''

RETURN = '''
stack:
    description: stack info
    type: dict
    returned: always
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


class StackModule(OpenStackModule):
    argument_spec = dict(
        environment=dict(type='list', elements='str'),
        name=dict(required=True),
        parameters=dict(default={}, type='dict'),
        rollback=dict(default=False, type='bool'),
        state=dict(default='present', choices=['absent', 'present']),
        tags=dict(aliases=['tag']),
        template=dict(),
        timeout=dict(default=3600, type='int'),
    )

    module_kwargs = dict(
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ('template',), True)]
    )

    def _system_state_change(self, stack, state):
        if state == 'present':
            # This method will always return True if state is present to
            # include the case of stack update as there is no simple way
            # to check if the stack will indeed be updated
            return True
        if state == 'absent' and stack:
            return True
        return False

    def run(self):
        state = self.params['state']
        name = self.params['name']

        # self.conn.get_stack() will not return stacks with status ==
        # DELETE_COMPLETE while self.conn.orchestration.find_stack() will
        # do so. A name of a stack which has been deleted completely can be
        # reused to create a new stack, hence we want self.conn.get_stack()'s
        # behaviour here.
        stack = self.conn.get_stack(name)

        if self.ansible.check_mode:
            self.exit_json(changed=self._system_state_change(stack, state))

        if state == 'present':
            # assume an existing stack always requires updates because there is
            # no simple way to check if stack will indeed have to be updated
            is_update = bool(stack)
            kwargs = dict(
                template_file=self.params['template'],
                environment_files=self.params['environment'],
                timeout=self.params['timeout'],
                rollback=self.params['rollback'],
                #
                # Always wait because we expect status to be
                # CREATE_COMPLETE or UPDATE_COMPLETE
                wait=True,
            )

            tags = self.params['tags']
            if tags is not None:
                kwargs['tags'] = tags

            extra_kwargs = self.params['parameters']
            dup_kwargs = set(kwargs.keys()) & set(extra_kwargs.keys())
            if dup_kwargs:
                raise ValueError('Duplicate key(s) {0} in parameters'
                                 .format(list(dup_kwargs)))
            kwargs = dict(kwargs, **extra_kwargs)

            if not is_update:
                stack = self.conn.create_stack(name, **kwargs)
            else:
                stack = self.conn.update_stack(name, **kwargs)

            stack = self.conn.orchestration.get_stack(stack['id'])
            self.exit_json(changed=True, stack=stack.to_dict(computed=False))
        elif state == 'absent':
            if not stack:
                self.exit_json(changed=False)
            else:
                self.conn.delete_stack(name_or_id=stack['id'],
                                       wait=self.params['wait'])
                self.exit_json(changed=True)


def main():
    module = StackModule()
    module()


if __name__ == '__main__':
    main()
