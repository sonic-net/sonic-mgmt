#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Florian Paul Azim Hoberg (@gyptazy) <florian.hoberg@credativ.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_cluster_join_info
version_added: 1.0.0
short_description: Retrieve the join information of the Proxmox VE cluster
description:
  - Retrieve the join information of the Proxmox VE cluster.
author: Florian Paul Azim Hoberg (@gyptazy)
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
  - community.proxmox.attributes.info_module
"""

EXAMPLES = r"""
- name: List existing Proxmox VE cluster join information
  community.proxmox.proxmox_cluster_join_info:
    api_host: proxmox1
    api_user: root@pam
    api_password: "{{ password | default(omit) }}"
    api_token_id: "{{ token_id | default(omit) }}"
    api_token_secret: "{{ token_secret | default(omit) }}"
  register: proxmox_cluster_join
"""

RETURN = r"""
cluster_join:
  description: List of Proxmox VE nodes including the join information within the cluster.
  returned: always, but can be empty
  type: list
  elements: dict
  contains:
    config_digest:
      description: Digest of the cluster configuration.
      type: str
      sample: "aef68412f7976505ed083e6173b96274a281da25"
    nodelist:
      description: List of nodes in the cluster.
      type: list
      elements: dict
      contains:
        name:
          description: Node name.
          type: str
          sample: "pve2"
        nodeid:
          description: Node ID.
          type: str
          sample: "1"
        pve_addr:
          description: Proxmox VE address.
          type: str
          sample: "10.10.10.159"
        pve_fp:
          description: Proxmox VE fingerprint.
          type: str
          sample: "08:B5:B2:F9:EC:01:0B:D0:..."
        quorum_votes:
          description: Quorum votes assigned to the node.
          type: str
          sample: "1"
        ring0_addr:
          description: Address for ring0.
          type: str
          sample: "vmbr0"
    preferred_node:
      description: The preferred cluster node.
      type: str
      sample: "pve2"
    totem:
      description: Totem protocol configuration.
      type: dict
      contains:
        cluster_name:
          description: Cluster name from totem.
          type: str
          sample: "devcluster"
        config_version:
          description: Config version.
          type: str
          sample: "1"
        interface:
          description: Interface configuration.
          type: dict
        ip_version:
          description: IP version.
          type: str
          sample: "ipv4-6"
        link_mode:
          description: Link mode.
          type: str
          sample: "passive"
        secauth:
          description: Whether secure authentication is on.
          type: str
          sample: "on"
        version:
          description: Totem protocol version.
          type: str
          sample: "2"
"""


import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec, ProxmoxAnsible)


try:
    import proxmoxer
except ImportError:
    PROXMOXER_LIBRARY = False
    PROXMOXER_LIBRARY_IMPORT_ERROR = traceback.format_exc()
else:
    PROXMOXER_LIBRARY = True
    PROXMOXER_LIBRARY_IMPORT_ERROR = None


class ProxmoxClusterJoinInfoAnsible(ProxmoxAnsible):
    def get_cluster_join(self):
        try:
            return self.proxmox_api.cluster.config.join.get()
        except proxmoxer.core.ResourceException:
            self.module.fail_json(msg="Node is not part of a cluster and does not have any join information.")
        except Exception as e:
            self.module.fail_json(msg="Error obtaining cluster join information: {}".format(str(e)))


def proxmox_cluster_join_info_argument_spec():
    return dict()


def main():
    module_args = proxmox_auth_argument_spec()
    cluster_join_info_args = proxmox_cluster_join_info_argument_spec()
    module_args.update(cluster_join_info_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[('api_password', 'api_token_id')],
        required_together=[('api_token_id', 'api_token_secret')],
        supports_check_mode=True,
    )
    result = dict(
        changed=False
    )

    proxmox = ProxmoxClusterJoinInfoAnsible(module)

    cluster_join = proxmox.get_cluster_join()
    result['cluster_join'] = cluster_join

    module.exit_json(**result)


if __name__ == '__main__':
    main()
