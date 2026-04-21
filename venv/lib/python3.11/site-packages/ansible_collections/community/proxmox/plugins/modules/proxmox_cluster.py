#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Florian Paul Azim Hoberg (@gyptazy) <florian.hoberg@credativ.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_cluster
version_added: 1.0.0
short_description: Create and join Proxmox VE clusters
description:
  - Create and join Proxmox VE clusters with PVE nodes.
author: Florian Paul Azim Hoberg (@gyptazy)
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
options:
  link0:
    description:
      - The first IP address to use for cluster communication.
    type: str
    required: false
  link1:
    description:
      - The second IP address to use for cluster communication.
    type: str
    required: false
  master_ip:
    description:
      - The IP address of the cluster master when joining the cluster.
    type: str
    required: false
  master_api_password:
    description:
      - Specify the password to authenticate with the master node.
      - Uses the api_password parameter if not specified.
    type: str
    required: false
  fingerprint:
    description:
      - The fingerprint of the cluster master when joining the cluster.
    type: str
    required: false
  cluster_name:
    description:
      - The cluster name to use for cluster creation.
    type: str
    required: false
  state:
    description:
      - Possible module state to perform the required steps within the Proxmox VE API.
    choices: ["present"]
    type: str
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Create a Proxmox VE Cluster
  community.proxmox.proxmox_cluster:
    state: present
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    link0: 10.10.1.1
    link1: 10.10.2.1
    cluster_name: "devcluster"

- name: Join a Proxmox VE Cluster
  community.proxmox.proxmox_cluster:
    state: present
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    master_ip: "{{ primary_node }}"
    fingerprint: "{{ cluster_fingerprint }}"
    cluster_name: "devcluster"

- name: Join a Proxmox VE Cluster with different API password
  community.proxmox.proxmox_cluster:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: "{{ joining_node_api_password }}"
    master_api_password: "{{ master_node_api_password }}"
    master_ip: "{{ primary_node }}"
    fingerprint: "{{ cluster_fingerprint }}"
    cluster_name: "devcluster"
"""

RETURN = r"""
cluster:
  description: The name of the cluster that was created or joined.
  returned: success
  type: str
  sample: "devcluster"
"""


import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec, ProxmoxAnsible)


class ProxmoxClusterAnsible(ProxmoxAnsible):
    def cluster_create(self):
        cluster_name = self.module.params.get("cluster_name") or self.module.params.get("api_host")
        payload = {"clustername": cluster_name}

        # Get cluster data
        cluster_data = self.proxmox_api.cluster.config.totem.get()
        # If we have data, check if we're already member of the desired cluster or a different one
        if cluster_data and 'cluster_name' in cluster_data and cluster_data['cluster_name'] is not None:
            if cluster_data['cluster_name'] == cluster_name:
                self.module.exit_json(changed=False, msg="Cluster '{}' already present.".format(cluster_name), cluster=cluster_name)
            else:
                self.module.fail_json(msg='Error creating cluster: Node is already part of a different cluster - "{}"!'.format(cluster_data['cluster_name']))

        if self.module.params.get("link0") is not None:
            payload["link0"] = self.module.params.get("link0")
        if self.module.params.get("link1") is not None:
            payload["link1"] = self.module.params.get("link1")

        if self.module.check_mode:
            self.module.exit_json(changed=True, msg="Cluster '{}' would be created (check mode).".format(cluster_name), cluster=cluster_name)
        else:
            try:
                self.proxmox_api.cluster.config.post(**payload)
            except Exception as e:
                self.module.fail_json(msg="Error while creating cluster: {}".format(str(e)))

            self.module.exit_json(changed=True, msg="Cluster '{}' created.".format(cluster_name), cluster=cluster_name)

    def cluster_join(self):
        cluster_name = self.module.params.get("cluster_name")
        payload = {}

        payload["hostname"] = self.module.params.get("master_ip")
        payload["fingerprint"] = self.module.params.get("fingerprint")
        payload["password"] = self.module.params.get("master_api_password") or self.module.params.get("api_password")

        if self.module.params.get("link0") is not None:
            payload["link0"] = self.module.params.get("link0")
        if self.module.params.get("link1") is not None:
            payload["link1"] = self.module.params.get("link1")
        is_in_cluster = True

        if self.module.check_mode:
            cluster_objects = self.proxmox_api.cluster.status.get()
            cluster_objects = cluster_objects[0]
            cluster_id = cluster_objects.get("nodeid")

            if cluster_id == 0:
                is_in_cluster = False

            if is_in_cluster:
                self.module.fail_json(msg="Error while joining cluster: Node is already part of a cluster!")
            else:
                self.module.exit_json(changed=True, msg="Node would join the cluster '{}' (check mode).".format(cluster_name), cluster=cluster_name)

        try:
            self.proxmox_api.cluster.config.join.post(**payload)

        except Exception as e:
            self.module.fail_json(msg="Error while joining the cluster: {}".format(str(e)))

        self.module.exit_json(changed=True, msg="Node joined the cluster.", cluster=cluster_name)


def proxmox_cluster_join_info_argument_spec():
    return dict()


def validate_cluster_name(module, min_length=1, max_length=15):
    cluster_name = module.params.get("cluster_name")

    if not (min_length <= len(cluster_name) <= max_length):
        module.fail_json(msg="Cluster name must be between {} and {} characters long.".format(min_length, max_length))

    if not re.match(r"^[a-zA-Z0-9\-]+$", cluster_name):
        module.fail_json(msg="Cluster name must contain only letters, digits, or hyphens.")


def main():
    module_args = proxmox_auth_argument_spec()

    cluster_args = dict(
        state=dict(default=None, choices=['present']),
        cluster_name=dict(type='str'),
        link0=dict(type='str'),
        link1=dict(type='str'),
        master_ip=dict(type='str'),
        master_api_password=dict(type='str', no_log=True),
        fingerprint=dict(type='str'),
    )
    module_args.update(cluster_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[('api_password', 'api_token_id')],
        required_together=[('api_token_id', 'api_token_secret')],
        supports_check_mode=True,
    )

    result = dict(
        changed=False
    )

    proxmox = ProxmoxClusterAnsible(module)
    validate_cluster_name(module)

    # The Proxmox VE API currently does not support leaving a cluster
    # or removing a node from a cluster. Therefore, we only support creating
    # and joining a cluster. (https://pve.proxmox.com/pve-docs/api-viewer/#/cluster/config/nodes)
    if module.params.get("state") == "present":
        if module.params.get("master_ip") and module.params.get("fingerprint"):
            cluster_action = proxmox.cluster_join()
        else:
            cluster_action = proxmox.cluster_create()
    else:
        cluster_action = {}

    result['proxmox_cluster'] = cluster_action
    module.exit_json(**result)


if __name__ == '__main__':
    main()
