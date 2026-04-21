#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cluster_info
short_description: Gathers information about one or more clusters
description:
    - >-
      Gathers information about one or more clusters.
      You can search for clusters based on the cluster name, datacenter name, or a combination of the two.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    cluster:
        description:
            - The name of the cluster on which to gather info.
            - At least one of O(datacenter) or O(cluster) is required.
        type: str
        required: false
        aliases: [cluster_name, name]
    datacenter:
        description:
            - The name of the datacenter.
            - At least one of O(datacenter) or O(cluster) is required.
        type: str
        required: false
        aliases: [datacenter_name]
    gather_tags:
        description:
            - If true, gather any tags attached to the cluster(s)
            - This has no affect if the O(schema) is set to V(vsphere). In that case, add 'tag' to O(properties) or leave O(properties) unset.
        type: bool
        default: false
        required: false
    schema:
        description:
            - Specify the output schema desired.
            - The V(summary) output schema is the legacy output from the module.
            - The V(vsphere) output schema is the vSphere API class definition.
        choices: ['summary', 'vsphere']
        default: 'summary'
        type: str
    properties:
        description:
            - If the schema is 'vsphere', gather these specific properties only
        type: list
        elements: str

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Gather Cluster Information
  vmware.vmware.cluster_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: datacenter
    cluster_name: my_cluster
  register: _out

- name: Gather Information About All Clusters In a Datacenter
  vmware.vmware.cluster_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: datacenter
  register: _out

- name: Gather Specific Properties About a Cluster
  vmware.vmware.cluster_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    cluster_name: my_cluster
    schema: vsphere
    properties:
      - name
      - configuration.dasConfig.enabled
      - summary.totalCpu
  register: _out
'''

RETURN = r'''
clusters:
    description:
        - A dictionary that describes the clusters found by the search parameters
        - The keys are the cluster names and the values are dictionaries with the cluster info.
    returned: On success
    type: dict
    sample: {
        "clusters": {
            "My-Cluster": {
                "datacenter": "My-Datacenter",
                "dpm_default_dpm_behavior": "automated",
                "dpm_enabled": false,
                "dpm_host_power_action_rate": 3,
                "drs_default_vm_behavior": "fullyAutomated",
                "drs_enable_vm_behavior_overrides": true,
                "drs_enabled": true,
                "drs_vmotion_rate": 3,
                "ha_admission_control_enabled": true,
                "ha_enabled": false,
                "ha_failover_level": 1,
                "ha_host_monitoring": "enabled",
                "ha_restart_priority": "medium",
                "ha_vm_failure_interval": 30,
                "ha_vm_max_failure_window": -1,
                "ha_vm_max_failures": 3,
                "ha_vm_min_up_time": 120,
                "ha_vm_monitoring": "vmMonitoringDisabled",
                "ha_vm_tools_monitoring": "vmMonitoringDisabled",
                "hosts": [
                    {
                        "folder": "/My-Datacenter/host/My-Cluster",
                        "name": "Esxi-1"
                    },
                    {
                        "folder": "/My-Datacenter/host/My-Cluster",
                        "name": "Esxi-2"
                    }
                ],
                "moid": "domain-c11",
                "resource_summary": {
                    "cpuCapacityMHz": 514080,
                    "cpuUsedMHz": 21241,
                    "memCapacityMB": 1832586,
                    "memUsedMB": 348366,
                    "pMemAvailableMB": 0,
                    "pMemCapacityMB": 0,
                    "storageCapacityMB": 12238642,
                    "storageUsedMB": 4562117
                },
                "tags": [],
                "vsan_auto_claim_storage": false,
                "vsan_enabled": false
            },
        }
    }
'''

try:
    from pyVmomi import vim
except ImportError:
    pass
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    rest_compatible_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils._facts import (
    ClusterFacts,
    vmware_obj_to_json
)


class ClusterInfo(ModulePyvmomiBase):
    def __init__(self, module):
        super(ClusterInfo, self).__init__(module)
        self.rest_client = None
        if module.params['gather_tags']:
            self.rest_client = ModuleRestBase(module)

    def get_clusters(self):
        """
        Gets clusters matching the search parameters input by the user.
        Returns: List of clusters to gather info about
        """
        datacenter, search_folder = None, None
        if self.params.get('datacenter'):
            datacenter = self.get_datacenter_by_name_or_moid(self.params.get('datacenter'), fail_on_missing=False)
            search_folder = datacenter.hostFolder

        if self.params.get('cluster'):
            _cluster = self.get_cluster_by_name_or_moid(self.params.get('cluster'), fail_on_missing=False, datacenter=datacenter)
            return [_cluster] if _cluster else []
        else:
            _clusters = self.get_all_objs_by_type(
                [vim.ClusterComputeResource],
                folder=search_folder,
                recurse=False
            )
            return _clusters

    def gather_info_for_clusters(self):
        """
        Gather information about one or more clusters
        """
        all_cluster_info = {}
        for cluster in self.get_clusters():
            cluster_info = {}
            if self.params['schema'] == 'summary':
                cluster_facts = ClusterFacts(cluster)
                cluster_info = cluster_facts.all_facts()
                cluster_info['tags'] = self._get_tags(cluster)
            else:
                try:
                    cluster_info = vmware_obj_to_json(cluster, self.params['properties'])
                except AttributeError as e:
                    self.module.fail_json(str(e))

            all_cluster_info[cluster.name] = cluster_info

        return all_cluster_info

    def _get_tags(self, cluster):
        """
        Gets the tags on a cluster. Tags are formatted as a list of dictionaries corresponding to each tag
        """
        output = []
        if not self.params.get('gather_tags'):
            return output

        tags = self.rest_client.get_tags_by_cluster_moid(cluster._moId)
        for tag in tags:
            output.append(self.rest_client.format_tag_identity_as_dict(tag))

        return output


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(), **dict(
                cluster=dict(type='str', aliases=['cluster_name', 'name']),
                datacenter=dict(type='str', aliases=['datacenter_name']),
                gather_tags=dict(type='bool', default=False),
                schema=dict(type='str', choices=['summary', 'vsphere'], default='summary'),
                properties=dict(type='list', elements='str'),
            )
        },
        supports_check_mode=True,
        required_one_of=[('cluster', 'datacenter')],
    )
    if module.params['schema'] != 'vsphere' and module.params.get('properties'):
        module.fail_json(msg="The option 'properties' is only valid when the schema is 'vsphere'")

    cluster_info = ClusterInfo(module)
    clusters = cluster_info.gather_info_for_clusters()
    module.exit_json(changed=False, clusters=clusters)


if __name__ == '__main__':
    main()
