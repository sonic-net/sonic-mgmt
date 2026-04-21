#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_container_info

short_description: Retrieves facts about docker container

description:
  - Retrieves facts about a docker container.
  - Essentially returns the output of C(docker inspect <name>), similar to what M(community.docker.docker_container) returns
    for a non-absent container.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker
  - community.docker.attributes.info_module
  - community.docker.attributes.idempotent_not_modify_state

options:
  name:
    description:
      - The name of the container to inspect.
      - When identifying an existing container name may be a name or a long or short container ID.
    type: str
    required: true

author:
  - "Felix Fontein (@felixfontein)"

requirements:
  - "Docker API >= 1.25"
"""

EXAMPLES = r"""
---
- name: Get infos on container
  community.docker.docker_container_info:
    name: mydata
  register: result

- name: Does container exist?
  ansible.builtin.debug:
    msg: "The container {{ 'exists' if result.exists else 'does not exist' }}"

- name: Print information about container
  ansible.builtin.debug:
    var: result.container
  when: result.exists
"""

RETURN = r"""
exists:
  description:
    - Returns whether the container exists.
  type: bool
  returned: always
  sample: true
container:
  description:
    - Facts representing the current state of the container. Matches the docker inspection output.
    - Will be V(none) if container does not exist.
  returned: always
  type: dict
  sample: '{ "AppArmorProfile": "", "Args": [], "Config": { "AttachStderr": false, "AttachStdin": false, "AttachStdout": false,
    "Cmd": [ "/usr/bin/supervisord" ], "Domainname": "", "Entrypoint": null, "Env": [ "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ], "ExposedPorts": { "443/tcp": {}, "80/tcp": {} }, "Hostname": "8e47bf643eb9", "Image": "lnmp_nginx:v1", "Labels": {},
    "OnBuild": null, "OpenStdin": false, "StdinOnce": false, "Tty": false, "User": "", "Volumes": { "/tmp/lnmp/nginx-sites/logs/":
    {} }, ... }'
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)
from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        container = client.get_container(client.module.params['name'])

        client.module.exit_json(
            changed=False,
            exists=(True if container else False),
            container=container,
        )
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
