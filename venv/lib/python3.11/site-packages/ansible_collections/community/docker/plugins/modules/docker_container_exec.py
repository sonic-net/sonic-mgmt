#!/usr/bin/python
#
# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_container_exec

short_description: Execute command in a docker container

version_added: 1.5.0

description:
  - Executes a command in a Docker container.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
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
  container:
    type: str
    required: true
    description:
      - The name of the container to execute the command in.
  argv:
    type: list
    elements: str
    description:
      - The command to execute.
      - Since this is a list of arguments, no quoting is needed.
      - Exactly one of O(argv) or O(command) must be specified.
  command:
    type: str
    description:
      - The command to execute.
      - Exactly one of O(argv) or O(command) must be specified.
  chdir:
    type: str
    description:
      - The directory to run the command in.
  detach:
    description:
      - Whether to run the command synchronously (O(detach=false), default) or asynchronously (O(detach=true)).
      - If set to V(true), O(stdin) cannot be provided, and the return values RV(stdout), RV(stderr), and RV(rc) are not returned.
    type: bool
    default: false
    version_added: 2.1.0
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
    default: false
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
    version_added: 2.1.0

notes:
  - Does B(not work with TCP TLS sockets) when using O(stdin). This is caused by the inability to send C(close_notify) without
    closing the connection with Python's C(SSLSocket)s. See U(https://github.com/ansible-collections/community.docker/issues/605)
    for more information.
  - If you need to evaluate environment variables of the container in O(command) or O(argv), you need to pass the command
    through a shell, like O(command=/bin/sh -c "echo $ENV_VARIABLE"). The same needs to be done in case you want to use glob patterns
    or other shell features such as redirects.
author:
  - "Felix Fontein (@felixfontein)"

requirements:
  - "Docker API >= 1.25"
"""

EXAMPLES = r"""
---
- name: Run a simple command (command)
  community.docker.docker_container_exec:
    container: foo
    command: /bin/bash -c "ls -lah"
    chdir: /root
  register: result

- name: Print stdout
  ansible.builtin.debug:
    var: result.stdout

- name: Run a simple command (argv)
  community.docker.docker_container_exec:
    container: foo
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
exec_id:
  type: str
  returned: success and O(detach=true)
  sample: 249d9e3075655baf705ed8f40488c5e9434049cf3431976f1bfdb73741c574c5
  description:
    - The execution ID of the command.
  version_added: 2.1.0
"""

import shlex
import traceback

from ansible.module_utils.common.text.converters import to_text, to_bytes, to_native
from ansible_collections.community.docker.plugins.module_utils._six import string_types

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)

from ansible_collections.community.docker.plugins.module_utils.selectors import selectors

from ansible_collections.community.docker.plugins.module_utils.socket_handler import (
    DockerSocketHandlerModule,
)

from ansible_collections.community.docker.plugins.module_utils._api.errors import (
    APIError,
    DockerException,
    NotFound,
)
from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import format_environment


def main():
    argument_spec = dict(
        container=dict(type='str', required=True),
        argv=dict(type='list', elements='str'),
        command=dict(type='str'),
        chdir=dict(type='str'),
        detach=dict(type='bool', default=False),
        user=dict(type='str'),
        stdin=dict(type='str'),
        stdin_add_newline=dict(type='bool', default=True),
        strip_empty_ends=dict(type='bool', default=True),
        tty=dict(type='bool', default=False),
        env=dict(type='dict'),
    )

    option_minimal_versions = dict(
        chdir=dict(docker_api_version='1.35'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        option_minimal_versions=option_minimal_versions,
        mutually_exclusive=[('argv', 'command')],
        required_one_of=[('argv', 'command')],
    )

    container = client.module.params['container']
    argv = client.module.params['argv']
    command = client.module.params['command']
    chdir = client.module.params['chdir']
    detach = client.module.params['detach']
    user = client.module.params['user']
    stdin = client.module.params['stdin']
    strip_empty_ends = client.module.params['strip_empty_ends']
    tty = client.module.params['tty']
    env = client.module.params['env']

    if env is not None:
        for name, value in list(env.items()):
            if not isinstance(value, string_types):
                client.module.fail_json(
                    msg="Non-string value found for env option. Ambiguous env options must be "
                        "wrapped in quotes to avoid them being interpreted. Key: %s" % (name, ))
            env[name] = to_text(value, errors='surrogate_or_strict')

    if command is not None:
        argv = shlex.split(command)

    if detach and stdin is not None:
        client.module.fail_json(msg='If detach=true, stdin cannot be provided.')

    if stdin is not None and client.module.params['stdin_add_newline']:
        stdin += '\n'

    try:
        data = {
            'Container': container,
            'User': user or '',
            'Privileged': False,
            'Tty': False,
            'AttachStdin': bool(stdin),
            'AttachStdout': True,
            'AttachStderr': True,
            'Cmd': argv,
            'Env': format_environment(env) if env is not None else None,
        }
        if chdir is not None:
            data['WorkingDir'] = chdir

        exec_data = client.post_json_to_json('/containers/{0}/exec', container, data=data)
        exec_id = exec_data['Id']

        data = {
            'Tty': tty,
            'Detach': detach,
        }
        if detach:
            client.post_json_to_text('/exec/{0}/start', exec_id, data=data)
            client.module.exit_json(changed=True, exec_id=exec_id)

        else:
            if stdin and not detach:
                exec_socket = client.post_json_to_stream_socket('/exec/{0}/start', exec_id, data=data)
                try:
                    with DockerSocketHandlerModule(exec_socket, client.module, selectors) as exec_socket_handler:
                        if stdin:
                            exec_socket_handler.write(to_bytes(stdin))

                        stdout, stderr = exec_socket_handler.consume()
                finally:
                    exec_socket.close()
            else:
                stdout, stderr = client.post_json_to_stream('/exec/{0}/start', exec_id, data=data, stream=False, tty=tty, demux=True)

            result = client.get_json('/exec/{0}/json', exec_id)

            stdout = to_text(stdout or b'')
            stderr = to_text(stderr or b'')
            if strip_empty_ends:
                stdout = stdout.rstrip('\r\n')
                stderr = stderr.rstrip('\r\n')

            client.module.exit_json(
                changed=True,
                stdout=stdout,
                stderr=stderr,
                rc=result.get('ExitCode') or 0,
            )
    except NotFound:
        client.fail('Could not find container "{0}"'.format(container))
    except APIError as e:
        if e.response is not None and e.response.status_code == 409:
            client.fail('The container "{0}" has been paused ({1})'.format(container, to_native(e)))
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
