#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Dario Zanzico (git@dariozanzico.com)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_stack
author: "Dario Zanzico (@dariko)"
short_description: docker stack module
description:
  - Manage docker stacks using the C(docker stack) command on the target node (see examples).
extends_documentation_fragment:
  - community.docker.docker.cli_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  action_group:
    version_added: 3.6.0
  idempotent:
    support: full
options:
  name:
    description:
      - Stack name.
    type: str
    required: true
  state:
    description:
      - Service state.
    type: str
    default: "present"
    choices:
      - present
      - absent
  compose:
    description:
      - List of compose definitions. Any element may be a string referring to the path of the compose file on the target host
        or the YAML contents of a compose file nested as dictionary.
    type: list
    elements: raw
    default: []
  prune:
    description:
      - If true will add the C(--prune) option to the C(docker stack deploy) command. This will have docker remove the services
        not present in the current stack definition.
    type: bool
    default: false
  detach:
    description:
      - If V(false), the C(--detach=false) option is added to the C(docker stack deploy) command, allowing Docker to wait
        for tasks to converge before exiting.
      - If V(true) (default), Docker exits immediately instead of waiting for tasks to converge.
    type: bool
    default: true
    version_added: 4.1.0
  with_registry_auth:
    description:
      - If true will add the C(--with-registry-auth) option to the C(docker stack deploy) command. This will have docker send
        registry authentication details to Swarm agents.
    type: bool
    default: false
  resolve_image:
    description:
      - If set will add the C(--resolve-image) option to the C(docker stack deploy) command. This will have docker query the
        registry to resolve image digest and supported platforms. If not set, docker use "always" by default.
    type: str
    choices: ["always", "changed", "never"]
  absent_retries:
    description:
      - If larger than V(0) and O(state=absent) the module will retry up to O(absent_retries) times to delete the stack until
        all the resources have been effectively deleted. If the last try still reports the stack as not completely removed
        the module will fail.
    type: int
    default: 0
  absent_retries_interval:
    description:
      - Interval in seconds between consecutive O(absent_retries).
    type: int
    default: 1
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
  - jsondiff
  - pyyaml
"""

RETURN = r"""
stack_spec_diff:
  description: |-
    Dictionary containing the differences between the 'Spec' field
    of the stack services before and after applying the new stack
    definition.
  sample: >
    "stack_spec_diff":
    {'test_stack_test_service': {u'TaskTemplate': {u'ContainerSpec': {delete: [u'Env']}}}}
  returned: on change
  type: dict
"""

EXAMPLES = r"""
---
- name: Deploy stack from a compose file
  community.docker.docker_stack:
    state: present
    name: mystack
    compose:
      - /opt/docker-compose.yml

- name: Deploy stack from base compose file and override the web service
  community.docker.docker_stack:
    state: present
    name: mystack
    compose:
      - /opt/docker-compose.yml
      - version: '3'
        services:
          web:
            image: nginx:latest
            environment:
              ENVVAR: envvar

- name: Remove stack
  community.docker.docker_stack:
    name: mystack
    state: absent
"""


import json
import os
import tempfile
import traceback

from ansible_collections.community.docker.plugins.module_utils._six import string_types
from time import sleep

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_cli import (
    AnsibleModuleDockerClient,
    DockerException,
)

try:
    from jsondiff import diff as json_diff
    HAS_JSONDIFF = True
except ImportError:
    HAS_JSONDIFF = False

try:
    from yaml import dump as yaml_dump
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def docker_stack_services(client, stack_name):
    rc, out, err = client.call_cli("stack", "services", stack_name, "--format", "{{.Name}}")
    if to_native(err) == "Nothing found in stack: %s\n" % stack_name:
        return []
    return to_native(out).strip().split('\n')


def docker_service_inspect(client, service_name):
    rc, out, err = client.call_cli("service", "inspect", service_name)
    if rc != 0:
        return None
    else:
        ret = json.loads(out)[0]['Spec']
        return ret


def docker_stack_deploy(client, stack_name, compose_files):
    command = ["stack", "deploy"]
    if client.module.params["prune"]:
        command += ["--prune"]
    if not client.module.params["detach"]:
        command += ["--detach=false"]
    if client.module.params["with_registry_auth"]:
        command += ["--with-registry-auth"]
    if client.module.params["resolve_image"]:
        command += ["--resolve-image",
                    client.module.params["resolve_image"]]
    for compose_file in compose_files:
        command += ["--compose-file",
                    compose_file]
    command += [stack_name]
    rc, out, err = client.call_cli(*command)
    return rc, to_native(out), to_native(err)


def docker_stack_inspect(client, stack_name):
    ret = {}
    for service_name in docker_stack_services(client, stack_name):
        ret[service_name] = docker_service_inspect(client, service_name)
    return ret


def docker_stack_rm(client, stack_name, retries, interval):
    command = ["stack", "rm", stack_name]
    if not client.module.params["detach"]:
        command += ["--detach=false"]
    rc, out, err = client.call_cli(*command)

    while to_native(err) != "Nothing found in stack: %s\n" % stack_name and retries > 0:
        sleep(interval)
        retries = retries - 1
        rc, out, err = client.call_cli(*command)
    return rc, to_native(out), to_native(err)


def main():
    client = AnsibleModuleDockerClient(
        argument_spec={
            'name': dict(type='str', required=True),
            'compose': dict(type='list', elements='raw', default=[]),
            'prune': dict(type='bool', default=False),
            'detach': dict(type='bool', default=True),
            'with_registry_auth': dict(type='bool', default=False),
            'resolve_image': dict(type='str', choices=['always', 'changed', 'never']),
            'state': dict(type='str', default='present', choices=['present', 'absent']),
            'absent_retries': dict(type='int', default=0),
            'absent_retries_interval': dict(type='int', default=1)
        },
        supports_check_mode=False,
    )

    if not HAS_JSONDIFF:
        return client.fail("jsondiff is not installed, try 'pip install jsondiff'")

    if not HAS_YAML:
        return client.fail("yaml is not installed, try 'pip install pyyaml'")

    try:
        state = client.module.params['state']
        compose = client.module.params['compose']
        name = client.module.params['name']
        absent_retries = client.module.params['absent_retries']
        absent_retries_interval = client.module.params['absent_retries_interval']

        if state == 'present':
            if not compose:
                client.fail("compose parameter must be a list containing at least one element")

            compose_files = []
            for i, compose_def in enumerate(compose):
                if isinstance(compose_def, dict):
                    compose_file_fd, compose_file = tempfile.mkstemp()
                    client.module.add_cleanup_file(compose_file)
                    with os.fdopen(compose_file_fd, 'w') as stack_file:
                        compose_files.append(compose_file)
                        stack_file.write(yaml_dump(compose_def))
                elif isinstance(compose_def, string_types):
                    compose_files.append(compose_def)
                else:
                    client.fail("compose element '%s' must be a string or a dictionary" % compose_def)

            before_stack_services = docker_stack_inspect(client, name)

            rc, out, err = docker_stack_deploy(client, name, compose_files)

            after_stack_services = docker_stack_inspect(client, name)

            if rc != 0:
                client.fail("docker stack up deploy command failed", rc=rc, stdout=out, stderr=err)

            before_after_differences = json_diff(before_stack_services, after_stack_services)
            for k in before_after_differences.keys():
                if isinstance(before_after_differences[k], dict):
                    before_after_differences[k].pop('UpdatedAt', None)
                    before_after_differences[k].pop('Version', None)
                    if not list(before_after_differences[k].keys()):
                        before_after_differences.pop(k)

            if not before_after_differences:
                client.module.exit_json(
                    changed=False,
                    rc=rc,
                    stdout=out,
                    stderr=err,
                )
            else:
                client.module.exit_json(
                    changed=True,
                    rc=rc,
                    stdout=out,
                    stderr=err,
                    stack_spec_diff=json_diff(
                        before_stack_services,
                        after_stack_services,
                        dump=True,
                    ),
                )

        else:
            if docker_stack_services(client, name):
                rc, out, err = docker_stack_rm(client, name, absent_retries, absent_retries_interval)
                if rc != 0:
                    client.module.fail_json(
                        msg="'docker stack down' command failed",
                        rc=rc,
                        stdout=out,
                        stderr=err,
                    )
                else:
                    client.module.exit_json(
                        changed=True,
                        msg=out,
                        rc=rc,
                        stdout=out,
                        stderr=err,
                    )
            client.module.exit_json(changed=False)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())


if __name__ == "__main__":
    main()
