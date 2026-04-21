#!/usr/bin/python
# coding: utf-8
#
# Copyright 2017 Red Hat | Ansible, Alex Grönholm <alex.gronholm@nextday.fi>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_volume_info
short_description: Retrieve facts about Docker volumes
description:
  - Performs largely the same function as the C(docker volume inspect) CLI subcommand.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker
  - community.docker.attributes.info_module
  - community.docker.attributes.idempotent_not_modify_state

options:
  name:
    description:
      - Name of the volume to inspect.
    type: str
    required: true
    aliases:
      - volume_name

author:
  - Felix Fontein (@felixfontein)

requirements:
  - "Docker API >= 1.25"
"""

EXAMPLES = r"""
---
- name: Get infos on volume
  community.docker.docker_volume_info:
    name: mydata
  register: result

- name: Does volume exist?
  ansible.builtin.debug:
    msg: "The volume {{ 'exists' if result.exists else 'does not exist' }}"

- name: Print information about volume
  ansible.builtin.debug:
    var: result.volume
  when: result.exists
"""

RETURN = r"""
exists:
  description:
    - Returns whether the volume exists.
  type: bool
  returned: always
  sample: true
volume:
  description:
    - Volume inspection results for the affected volume.
    - Will be V(none) if volume does not exist.
  returned: success
  type: dict
  sample: '{ "CreatedAt": "2018-12-09T17:43:44+01:00", "Driver": "local", "Labels": null, "Mountpoint": "/var/lib/docker/volumes/ansible-test-bd3f6172/_data",
    "Name": "ansible-test-bd3f6172", "Options": {}, "Scope": "local" }'
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)
from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException, NotFound


def get_existing_volume(client, volume_name):
    try:
        return client.get_json('/volumes/{0}', volume_name)
    except NotFound as dummy:
        return None
    except Exception as exc:
        client.fail("Error inspecting volume: %s" % to_native(exc))


def main():
    argument_spec = dict(
        name=dict(type='str', required=True, aliases=['volume_name']),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        volume = get_existing_volume(client, client.module.params['name'])

        client.module.exit_json(
            changed=False,
            exists=(True if volume else False),
            volume=volume,
        )
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
