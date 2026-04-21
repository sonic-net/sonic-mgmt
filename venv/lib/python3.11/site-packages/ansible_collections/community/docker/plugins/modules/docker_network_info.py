#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_network_info

short_description: Retrieves facts about docker network

description:
  - Retrieves facts about a docker network.
  - Essentially returns the output of C(docker network inspect <name>), similar to what M(community.docker.docker_network)
    returns for a non-absent network.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker
  - community.docker.attributes.info_module
  - community.docker.attributes.idempotent_not_modify_state

options:
  name:
    description:
      - The name of the network to inspect.
      - When identifying an existing network name may be a name or a long or short network ID.
    type: str
    required: true

author:
  - "Dave Bendit (@DBendit)"

requirements:
  - "Docker API >= 1.25"
"""

EXAMPLES = r"""
---
- name: Get infos on network
  community.docker.docker_network_info:
    name: mydata
  register: result

- name: Does network exist?
  ansible.builtin.debug:
    msg: "The network {{ 'exists' if result.exists else 'does not exist' }}"

- name: Print information about network
  ansible.builtin.debug:
    var: result.network
  when: result.exists
"""

RETURN = r"""
exists:
  description:
    - Returns whether the network exists.
  type: bool
  returned: always
  sample: true
network:
  description:
    - Facts representing the current state of the network. Matches the docker inspection output.
    - Will be V(none) if network does not exist.
  returned: always
  type: dict
  sample: {
    "Attachable": false,
    "ConfigFrom": {"Network": ""},
    "ConfigOnly": false,
    "Containers": {},
    "Created": "2018-12-07T01:47:51.250835114-06:00",
    "Driver": "bridge",
    "EnableIPv6": false,
    "IPAM": {
      "Config": [
        {
          "Gateway": "192.168.96.1",
          "Subnet": "192.168.96.0/20",
        },
      ],
      "Driver": "default",
      "Options": null,
    },
    "Id": "0856968545f22026c41c2c7c3d448319d3b4a6a03a40b148b3ac4031696d1c0a",
    "Ingress": false,
    "Internal": false,
    "Labels": {},
    "Name": "ansible-test-f2700bba",
    "Options": {},
    "Scope": "local",
  }
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
        network = client.get_network(client.module.params['name'])

        client.module.exit_json(
            changed=False,
            exists=(True if network else False),
            network=network,
        )
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
