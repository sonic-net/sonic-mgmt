#!/usr/bin/python
#
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_compose_v2_run

short_description: Run command in a new container of a Compose service

version_added: 3.13.0

description:
  - Uses Docker Compose to run a command in a new container for a service.
  - This encapsulates C(docker compose run).
extends_documentation_fragment:
  - community.docker.compose_v2
  - community.docker.compose_v2.minimum_version
  - community.docker.docker.cli_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  idempotent:
    support: N/A
    details:
      - Whether the executed command is idempotent depends on the command.

options:
  service:
    description:
      - The service to run the command in.
    type: str
    required: true
  argv:
    type: list
    elements: str
    description:
      - The command to execute.
      - Since this is a list of arguments, no quoting is needed.
      - O(argv) or O(command) are mutually exclusive.
  command:
    type: str
    description:
      - The command to execute.
      - O(argv) or O(command) are mutually exclusive.
  build:
    description:
      - Build image before starting container.
      - Note that building can insert information into RV(stdout) or RV(stderr).
    type: bool
    default: false
  cap_add:
    description:
      - Linux capabilities to add to the container.
    type: list
    elements: str
  cap_drop:
    description:
      - Linux capabilities to drop from the container.
    type: list
    elements: str
  entrypoint:
    description:
      - Override the entrypoint of the container image.
    type: str
  interactive:
    description:
      - Whether to keep STDIN open even if not attached.
    type: bool
    default: true
  labels:
    description:
      - Add or override labels to the container.
    type: list
    elements: str
  name:
    description:
      - Assign a name to the container.
    type: str
  no_deps:
    description:
      - Do not start linked services.
    type: bool
    default: false
  publish:
    description:
      - Publish a container's port(s) to the host.
    type: list
    elements: str
  quiet_pull:
    description:
      - Pull without printing progress information.
      - Note that pulling can insert information into RV(stdout) or RV(stderr).
    type: bool
    default: false
  remove_orphans:
    description:
      - Remove containers for services not defined in the Compose file.
    type: bool
    default: false
  cleanup:
    description:
      - Automatically remove th econtainer when it exits.
      - Corresponds to the C(--rm) option of C(docker compose run).
    type: bool
    default: false
  service_ports:
    description:
      - Run command with all service's ports enabled and mapped to the host.
    type: bool
    default: false
  use_aliases:
    description:
      - Use the service's network C(useAliases) in the network(s) the container connects to.
    type: bool
    default: false
  volumes:
    description:
      - Bind mount one or more volumes.
    type: list
    elements: str
  chdir:
    type: str
    description:
      - The directory to run the command in.
  detach:
    description:
      - Whether to run the command synchronously (O(detach=false), default) or asynchronously (O(detach=true)).
      - If set to V(true), O(stdin) cannot be provided, and the return values RV(stdout), RV(stderr), and RV(rc) are not returned.
        Instead, the return value RV(container_id) is provided.
    type: bool
    default: false
  user:
    type: str
    description:
      - If specified, the user to execute this command with.
  stdin:
    type: str
    description:
      - Set the stdin of the command directly to the specified value.
      - Can only be used if O(detach=false).
  stdin_add_newline:
    type: bool
    default: true
    description:
      - If set to V(true), appends a newline to O(stdin).
  strip_empty_ends:
    type: bool
    default: true
    description:
      - Strip empty lines from the end of stdout/stderr in result.
  tty:
    type: bool
    default: true
    description:
      - Whether to allocate a TTY.
  env:
    description:
      - Dictionary of environment variables with their respective values to be passed to the command ran inside the container.
      - Values which might be parsed as numbers, booleans or other types by the YAML parser must be quoted (for example V("true"))
        in order to avoid data loss.
      - Please note that if you are passing values in with Jinja2 templates, like V("{{ value }}"), you need to add V(| string)
        to prevent Ansible to convert strings such as V("true") back to booleans. The correct way is to use V("{{ value |
        string }}").
    type: dict

author:
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.docker.docker_compose_v2

notes:
  - If you need to evaluate environment variables of the container in O(command) or O(argv), you need to pass the command
    through a shell, like O(command=/bin/sh -c "echo $ENV_VARIABLE"). The same needs to be done in case you want to use glob patterns
    or other shell features such as redirects.
"""

EXAMPLES = r"""
---
- name: Run a simple command (command)
  community.docker.docker_compose_v2_run:
    service: foo
    command: /bin/bash -c "ls -lah"
    chdir: /root
  register: result

- name: Print stdout
  ansible.builtin.debug:
    var: result.stdout

- name: Run a simple command (argv)
  community.docker.docker_compose_v2_run:
    service: foo
    argv:
      - /bin/bash
      - "-c"
      - "ls -lah > /dev/stderr"
    chdir: /root
  register: result

- name: Print stderr lines
  ansible.builtin.debug:
    var: result.stderr_lines
"""

RETURN = r"""
container_id:
  type: str
  returned: success and O(detach=true)
  description:
    - The ID of the created container.
stdout:
  type: str
  returned: success and O(detach=false)
  description:
    - The standard output of the container command.
stderr:
  type: str
  returned: success and O(detach=false)
  description:
    - The standard error output of the container command.
rc:
  type: int
  returned: success and O(detach=false)
  sample: 0
  description:
    - The exit code of the command.
"""

import shlex
import traceback

from ansible.module_utils.common.text.converters import to_text, to_native
from ansible_collections.community.docker.plugins.module_utils._six import string_types

from ansible_collections.community.docker.plugins.module_utils.common_cli import (
    AnsibleModuleDockerClient,
    DockerException,
)

from ansible_collections.community.docker.plugins.module_utils.compose_v2 import (
    BaseComposeManager,
    common_compose_argspec_ex,
)


class ExecManager(BaseComposeManager):
    def __init__(self, client):
        super(ExecManager, self).__init__(client)
        parameters = self.client.module.params

        self.service = parameters['service']
        self.build = parameters['build']
        self.cap_add = parameters['cap_add']
        self.cap_drop = parameters['cap_drop']
        self.entrypoint = parameters['entrypoint']
        self.interactive = parameters['interactive']
        self.labels = parameters['labels']
        self.name = parameters['name']
        self.no_deps = parameters['no_deps']
        self.publish = parameters['publish']
        self.quiet_pull = parameters['quiet_pull']
        self.remove_orphans = parameters['remove_orphans']
        self.do_cleanup = parameters['cleanup']
        self.service_ports = parameters['service_ports']
        self.use_aliases = parameters['use_aliases']
        self.volumes = parameters['volumes']
        self.chdir = parameters['chdir']
        self.detach = parameters['detach']
        self.user = parameters['user']
        self.stdin = parameters['stdin']
        self.strip_empty_ends = parameters['strip_empty_ends']
        self.tty = parameters['tty']
        self.env = parameters['env']

        self.argv = parameters['argv']
        if parameters['command'] is not None:
            self.argv = shlex.split(parameters['command'])

        if self.detach and self.stdin is not None:
            self.fail('If detach=true, stdin cannot be provided.')

        if self.stdin is not None and parameters['stdin_add_newline']:
            self.stdin += '\n'

        if self.env is not None:
            for name, value in list(self.env.items()):
                if not isinstance(value, string_types):
                    self.fail(
                        "Non-string value found for env option. Ambiguous env options must be "
                        "wrapped in quotes to avoid them being interpreted. Key: %s" % (name, )
                    )
                self.env[name] = to_text(value, errors='surrogate_or_strict')

    def get_run_cmd(self, dry_run, no_start=False):
        args = self.get_base_args(plain_progress=True) + ['run']
        if self.build:
            args.append('--build')
        if self.cap_add:
            for cap in self.cap_add:
                args.extend(['--cap-add', cap])
        if self.cap_drop:
            for cap in self.cap_drop:
                args.extend(['--cap-drop', cap])
        if self.entrypoint is not None:
            args.extend(['--entrypoint', self.entrypoint])
        if not self.interactive:
            args.append('--no-interactive')
        if self.labels:
            for label in self.labels:
                args.extend(['--label', label])
        if self.name is not None:
            args.extend(['--name', self.name])
        if self.no_deps:
            args.append('--no-deps')
        if self.publish:
            for publish in self.publish:
                args.extend(['--publish', publish])
        if self.quiet_pull:
            args.append('--quiet-pull')
        if self.remove_orphans:
            args.append('--remove-orphans')
        if self.do_cleanup:
            args.append('--rm')
        if self.service_ports:
            args.append('--service-ports')
        if self.use_aliases:
            args.append('--use-aliases')
        if self.volumes:
            for volume in self.volumes:
                args.extend(['--volume', volume])
        if self.chdir is not None:
            args.extend(['--workdir', self.chdir])
        if self.detach:
            args.extend(['--detach'])
        if self.user is not None:
            args.extend(['--user', self.user])
        if not self.tty:
            args.append('--no-TTY')
        if self.env:
            for name, value in list(self.env.items()):
                args.append('--env')
                args.append('{0}={1}'.format(name, value))
        args.append('--')
        args.append(self.service)
        if self.argv:
            args.extend(self.argv)
        return args

    def run(self):
        args = self.get_run_cmd(self.check_mode)
        kwargs = {
            'cwd': self.project_src,
        }
        if self.stdin is not None:
            kwargs['data'] = self.stdin.encode('utf-8')
        if self.detach:
            kwargs['check_rc'] = True
        rc, stdout, stderr = self.client.call_cli(*args, **kwargs)
        if self.detach:
            return {
                'container_id': stdout.strip(),
            }
        stdout = to_text(stdout)
        stderr = to_text(stderr)
        if self.strip_empty_ends:
            stdout = stdout.rstrip('\r\n')
            stderr = stderr.rstrip('\r\n')
        return {
            'changed': True,
            'rc': rc,
            'stdout': stdout,
            'stderr': stderr,
        }


def main():
    argument_spec = dict(
        service=dict(type='str', required=True),
        argv=dict(type='list', elements='str'),
        command=dict(type='str'),
        build=dict(type='bool', default=False),
        cap_add=dict(type='list', elements='str'),
        cap_drop=dict(type='list', elements='str'),
        entrypoint=dict(type='str'),
        interactive=dict(type='bool', default=True),
        labels=dict(type='list', elements='str'),
        name=dict(type='str'),
        no_deps=dict(type='bool', default=False),
        publish=dict(type='list', elements='str'),
        quiet_pull=dict(type='bool', default=False),
        remove_orphans=dict(type='bool', default=False),
        cleanup=dict(type='bool', default=False),
        service_ports=dict(type='bool', default=False),
        use_aliases=dict(type='bool', default=False),
        volumes=dict(type='list', elements='str'),
        chdir=dict(type='str'),
        detach=dict(type='bool', default=False),
        user=dict(type='str'),
        stdin=dict(type='str'),
        stdin_add_newline=dict(type='bool', default=True),
        strip_empty_ends=dict(type='bool', default=True),
        tty=dict(type='bool', default=True),
        env=dict(type='dict'),
    )
    argspec_ex = common_compose_argspec_ex()
    argument_spec.update(argspec_ex.pop('argspec'))

    client = AnsibleModuleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=False,
        needs_api_version=False,
        **argspec_ex
    )

    try:
        manager = ExecManager(client)
        result = manager.run()
        manager.cleanup()
        client.module.exit_json(**result)
    except DockerException as e:
        client.fail('An unexpected docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
