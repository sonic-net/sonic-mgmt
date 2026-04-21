#!/usr/bin/python
#
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_compose_v2_pull

short_description: Pull a Docker compose project

version_added: 3.6.0

description:
  - Uses Docker Compose to pull images for a project.
extends_documentation_fragment:
  - community.docker.compose_v2
  - community.docker.compose_v2.minimum_version
  - community.docker.docker.cli_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: full
    details:
      - If O(policy=always), the module will always indicate a change. Docker Compose does not give any information whether
        pulling would update the image or not.
  diff_mode:
    support: none
  idempotent:
    support: full

options:
  policy:
    description:
      - Whether to pull images before running. This is used when C(docker compose up) is ran.
      - V(always) ensures that the images are always pulled, even when already present on the Docker daemon.
      - V(missing) only pulls them when they are not present on the Docker daemon. This is only supported since Docker Compose
        2.22.0.
    type: str
    choices:
      - always
      - missing
    default: always
  ignore_buildable:
    description:
      - If set to V(true), will not pull images that can be built.
    type: bool
    default: false
    version_added: 3.12.0
  include_deps:
    description:
      - If set to V(true), also pull services that are declared as dependencies.
      - This only makes sense if O(services) is used.
    type: bool
    default: false
    version_added: 3.12.0
  services:
    description:
      - Specifies a subset of services to be targeted.
    type: list
    elements: str
    version_added: 3.12.0

author:
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.docker.docker_compose_v2
"""

EXAMPLES = r"""
---
- name: Pull images for flask project
  community.docker.docker_compose_v2_pull:
    project_src: /path/to/flask
"""

RETURN = r"""
actions:
  description:
    - A list of actions that have been applied.
  returned: success
  type: list
  elements: dict
  contains:
    what:
      description:
        - What kind of resource was changed.
      type: str
      sample: container
      choices:
        - image
        - unknown
    id:
      description:
        - The ID of the resource that was changed.
      type: str
      sample: container
    status:
      description:
        - The status change that happened.
      type: str
      sample: Pulling
      choices:
        - Pulling
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_cli import (
    AnsibleModuleDockerClient,
    DockerException,
)

from ansible_collections.community.docker.plugins.module_utils.compose_v2 import (
    BaseComposeManager,
    common_compose_argspec_ex,
)

from ansible_collections.community.docker.plugins.module_utils.version import LooseVersion


class PullManager(BaseComposeManager):
    def __init__(self, client):
        super(PullManager, self).__init__(client)
        parameters = self.client.module.params

        self.policy = parameters['policy']
        self.ignore_buildable = parameters['ignore_buildable']
        self.include_deps = parameters['include_deps']
        self.services = parameters['services'] or []

        if self.policy != 'always' and self.compose_version < LooseVersion('2.22.0'):
            # https://github.com/docker/compose/pull/10981 - 2.22.0
            self.fail('A pull policy other than always is only supported since Docker Compose 2.22.0. {0} has version {1}'.format(
                self.client.get_cli(), self.compose_version))
        if self.ignore_buildable and self.compose_version < LooseVersion('2.15.0'):
            # https://github.com/docker/compose/pull/10134 - 2.15.0
            self.fail('--ignore-buildable is only supported since Docker Compose 2.15.0. {0} has version {1}'.format(
                self.client.get_cli(), self.compose_version))

    def get_pull_cmd(self, dry_run, no_start=False):
        args = self.get_base_args() + ['pull']
        if self.policy != 'always':
            args.extend(['--policy', self.policy])
        if self.ignore_buildable:
            args.append('--ignore-buildable')
        if self.include_deps:
            args.append('--include-deps')
        if dry_run:
            args.append('--dry-run')
        args.append('--')
        for service in self.services:
            args.append(service)
        return args

    def run(self):
        result = dict()
        args = self.get_pull_cmd(self.check_mode)
        rc, stdout, stderr = self.client.call_cli(*args, cwd=self.project_src)
        events = self.parse_events(stderr, dry_run=self.check_mode, nonzero_rc=rc != 0)
        self.emit_warnings(events)
        self.update_result(result, events, stdout, stderr, ignore_service_pull_events=self.policy != 'missing' and not self.check_mode)
        self.update_failed(result, events, args, stdout, stderr, rc)
        self.cleanup_result(result)
        return result


def main():
    argument_spec = dict(
        policy=dict(type='str', choices=['always', 'missing'], default='always'),
        ignore_buildable=dict(type='bool', default=False),
        include_deps=dict(type='bool', default=False),
        services=dict(type='list', elements='str'),
    )
    argspec_ex = common_compose_argspec_ex()
    argument_spec.update(argspec_ex.pop('argspec'))

    client = AnsibleModuleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
        needs_api_version=False,
        **argspec_ex
    )

    try:
        manager = PullManager(client)
        result = manager.run()
        manager.cleanup()
        client.module.exit_json(**result)
    except DockerException as e:
        client.fail('An unexpected docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
