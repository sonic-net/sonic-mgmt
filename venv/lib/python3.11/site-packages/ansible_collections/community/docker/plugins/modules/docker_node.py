#!/usr/bin/python
#
# Copyright (c) 2019 Piotr Wojciechowski <piotr@it-playground.pl>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: docker_node
short_description: Manage Docker Swarm node
description:
  - Manages the Docker nodes through a Swarm Manager.
  - This module allows to change the node's role, its availability, and to modify, add or remove node labels.
extends_documentation_fragment:
  - community.docker.docker
  - community.docker.docker.docker_py_1_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  idempotent:
    support: full

options:
  hostname:
    description:
      - The hostname or ID of node as registered in Swarm.
      - If more than one node is registered using the same hostname the ID must be used, otherwise module will fail.
    type: str
    required: true
  labels:
    description:
      - User-defined key/value metadata that will be assigned as node attribute.
      - Label operations in this module apply to the docker swarm node specified by O(hostname). Use M(community.docker.docker_swarm)
        module to add/modify/remove swarm cluster labels.
      - The actual state of labels assigned to the node when module completes its work depends on O(labels_state) and O(labels_to_remove)
        parameters values. See description below.
    type: dict
  labels_state:
    description:
      - It defines the operation on the labels assigned to node and labels specified in O(labels) option.
      - Set to V(merge) to combine labels provided in O(labels) with those already assigned to the node. If no labels are
        assigned then it will add listed labels. For labels that are already assigned to the node, it will update their values.
        The labels not specified in O(labels) will remain unchanged. If O(labels) is empty then no changes will be made.
      - Set to V(replace) to replace all assigned labels with provided ones. If O(labels) is empty then all labels assigned
        to the node will be removed.
    type: str
    default: 'merge'
    choices:
      - merge
      - replace
  labels_to_remove:
    description:
      - List of labels that will be removed from the node configuration. The list has to contain only label names, not their
        values.
      - If the label provided on the list is not assigned to the node, the entry is ignored.
      - If the label is both on the O(labels_to_remove) and O(labels), then value provided in O(labels) remains assigned to
        the node.
      - If O(labels_state=replace) and O(labels) is not provided or empty then all labels assigned to node are removed and
        O(labels_to_remove) is ignored.
    type: list
    elements: str
  availability:
    description: Node availability to assign. If not provided then node availability remains unchanged.
    choices:
      - active
      - pause
      - drain
    type: str
  role:
    description: Node role to assign. If not provided then node role remains unchanged.
    choices:
      - manager
      - worker
    type: str

requirements:
  - "L(Docker SDK for Python,https://docker-py.readthedocs.io/en/stable/) >= 2.4.0"
  - Docker API >= 1.25
author:
  - Piotr Wojciechowski (@WojciechowskiPiotr)
  - Thierry Bouvet (@tbouvet)
"""

EXAMPLES = r"""
---
- name: Set node role
  community.docker.docker_node:
    hostname: mynode
    role: manager

- name: Set node availability
  community.docker.docker_node:
    hostname: mynode
    availability: drain

- name: Replace node labels with new labels
  community.docker.docker_node:
    hostname: mynode
    labels:
      key: value
    labels_state: replace

- name: Merge node labels and new labels
  community.docker.docker_node:
    hostname: mynode
    labels:
      key: value

- name: Remove all labels assigned to node
  community.docker.docker_node:
    hostname: mynode
    labels_state: replace

- name: Remove selected labels from the node
  community.docker.docker_node:
    hostname: mynode
    labels_to_remove:
      - key1
      - key2
"""

RETURN = r"""
node:
  description: Information about node after 'update' operation.
  returned: success
  type: dict
"""

import traceback

try:
    from docker.errors import DockerException, APIError
except ImportError:
    # missing Docker SDK for Python handled in ansible.module_utils.docker.common
    pass

from ansible_collections.community.docker.plugins.module_utils.common import (
    DockerBaseClass,
    RequestException,
)

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.swarm import AnsibleDockerSwarmClient
from ansible_collections.community.docker.plugins.module_utils.util import sanitize_labels


class TaskParameters(DockerBaseClass):
    def __init__(self, client):
        super(TaskParameters, self).__init__()

        # Spec
        self.name = None
        self.labels = None
        self.labels_state = None
        self.labels_to_remove = None

        # Node
        self.availability = None
        self.role = None

        for key, value in client.module.params.items():
            setattr(self, key, value)

        sanitize_labels(self.labels, "labels", client)


class SwarmNodeManager(DockerBaseClass):

    def __init__(self, client, results):

        super(SwarmNodeManager, self).__init__()

        self.client = client
        self.results = results
        self.check_mode = self.client.check_mode

        self.client.fail_task_if_not_swarm_manager()

        self.parameters = TaskParameters(client)

        self.node_update()

    def node_update(self):
        if not (self.client.check_if_swarm_node(node_id=self.parameters.hostname)):
            self.client.fail("This node is not part of a swarm.")
            return

        if self.client.check_if_swarm_node_is_down():
            self.client.fail("Can not update the node. The node is down.")

        try:
            node_info = self.client.inspect_node(node_id=self.parameters.hostname)
        except APIError as exc:
            self.client.fail("Failed to get node information for %s" % to_native(exc))

        changed = False
        node_spec = dict(
            Availability=self.parameters.availability,
            Role=self.parameters.role,
            Labels=self.parameters.labels,
        )

        if self.parameters.role is None:
            node_spec['Role'] = node_info['Spec']['Role']
        else:
            if not node_info['Spec']['Role'] == self.parameters.role:
                node_spec['Role'] = self.parameters.role
                changed = True

        if self.parameters.availability is None:
            node_spec['Availability'] = node_info['Spec']['Availability']
        else:
            if not node_info['Spec']['Availability'] == self.parameters.availability:
                node_info['Spec']['Availability'] = self.parameters.availability
                changed = True

        if self.parameters.labels_state == 'replace':
            if self.parameters.labels is None:
                node_spec['Labels'] = {}
                if node_info['Spec']['Labels']:
                    changed = True
            else:
                if (node_info['Spec']['Labels'] or {}) != self.parameters.labels:
                    node_spec['Labels'] = self.parameters.labels
                    changed = True
        elif self.parameters.labels_state == 'merge':
            node_spec['Labels'] = dict(node_info['Spec']['Labels'] or {})
            if self.parameters.labels is not None:
                for key, value in self.parameters.labels.items():
                    if node_spec['Labels'].get(key) != value:
                        node_spec['Labels'][key] = value
                        changed = True

            if self.parameters.labels_to_remove is not None:
                for key in self.parameters.labels_to_remove:
                    if self.parameters.labels is not None:
                        if not self.parameters.labels.get(key):
                            if node_spec['Labels'].get(key):
                                node_spec['Labels'].pop(key)
                                changed = True
                        else:
                            self.client.module.warn(
                                "Label '%s' listed both in 'labels' and 'labels_to_remove'. "
                                "Keeping the assigned label value."
                                % to_native(key))
                    else:
                        if node_spec['Labels'].get(key):
                            node_spec['Labels'].pop(key)
                            changed = True

        if changed is True:
            if not self.check_mode:
                try:
                    self.client.update_node(node_id=node_info['ID'], version=node_info['Version']['Index'],
                                            node_spec=node_spec)
                except APIError as exc:
                    self.client.fail("Failed to update node : %s" % to_native(exc))
            self.results['node'] = self.client.get_node_inspect(node_id=node_info['ID'])
            self.results['changed'] = changed
        else:
            self.results['node'] = node_info
            self.results['changed'] = changed


def main():
    argument_spec = dict(
        hostname=dict(type='str', required=True),
        labels=dict(type='dict'),
        labels_state=dict(type='str', default='merge', choices=['merge', 'replace']),
        labels_to_remove=dict(type='list', elements='str'),
        availability=dict(type='str', choices=['active', 'pause', 'drain']),
        role=dict(type='str', choices=['worker', 'manager']),
    )

    client = AnsibleDockerSwarmClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
        min_docker_version='2.4.0',
    )

    try:
        results = dict(
            changed=False,
        )

        SwarmNodeManager(client, results)
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when Docker SDK for Python tried to talk to the docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
