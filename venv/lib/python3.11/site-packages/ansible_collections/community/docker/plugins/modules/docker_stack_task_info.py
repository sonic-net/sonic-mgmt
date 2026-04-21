#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 Jose Angel Munoz (@imjoseangel)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r"""
module: docker_stack_task_info
author: "Jose Angel Munoz (@imjoseangel)"
short_description: Return information of the tasks on a docker stack
description:
  - Retrieve information on docker stacks tasks using the C(docker stack) command on the target node (see examples).
extends_documentation_fragment:
  - community.docker.docker.cli_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker
  - community.docker.attributes.info_module
  - community.docker.attributes.idempotent_not_modify_state
attributes:
  action_group:
    version_added: 3.6.0
options:
  name:
    description:
      - Stack name.
    type: str
    required: true
  docker_cli:
    version_added: 3.6.0
  docker_host:
    version_added: 3.6.0
  tls_hostname:
    version_added: 3.6.0
  api_version:
    version_added: 3.6.0
  ca_path:
    version_added: 3.6.0
  client_cert:
    version_added: 3.6.0
  client_key:
    version_added: 3.6.0
  tls:
    version_added: 3.6.0
  validate_certs:
    version_added: 3.6.0
  cli_context:
    version_added: 3.6.0
requirements:
  - Docker CLI tool C(docker)
"""

RETURN = r"""
results:
  description:
    - List of dictionaries containing the list of tasks associated to a stack name.
  sample:
    - CurrentState: Running
      DesiredState: Running
      Error: ""
      ID: 7wqv6m02ugkw
      Image: busybox
      Name: test_stack.1
      Node: swarm
      Ports: ""
  returned: always
  type: list
  elements: dict
"""

EXAMPLES = r"""
---
- name: Shows stack info
  community.docker.docker_stack_task_info:
    name: test_stack
  register: result

- name: Show results
  ansible.builtin.debug:
    var: result.results
"""

import json
import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_cli import (
    AnsibleModuleDockerClient,
    DockerException,
)


def docker_stack_task(module, stack_name):
    docker_bin = module.get_bin_path('docker', required=True)
    rc, out, err = module.run_command(
        [docker_bin, "stack", "ps", stack_name, "--format={{json .}}"])

    return rc, out.strip(), err.strip()


def main():
    client = AnsibleModuleDockerClient(
        argument_spec={
            'name': dict(type='str', required=True)
        },
        supports_check_mode=True,
    )

    try:
        name = client.module.params['name']
        rc, ret, stderr = client.call_cli_json_stream('stack', 'ps', name, '--format={{json .}}', check_rc=True)
        client.module.exit_json(
            changed=False,
            rc=rc,
            stdout='\n'.join([json.dumps(entry) for entry in ret]),
            stderr=to_native(stderr).strip(),
            results=ret,
        )
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())


if __name__ == "__main__":
    main()
