#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cluster_drs_recommendations
short_description: Apply Distributed Resource Scheduler (DRS) recommendations on VMware vSphere clusters
description:
    - Applies DRS recommendations on VMware vSphere clusters.
    - >-
      DRS recommendations are made based on a variety of factors such as resource usage, host health, and some advanced settings like TryBalanceVmsPerHost.
      The cluster may not recommend moving a VM if the cost of moving the VM is greater than the benefit that would come after the move.
    - >-
      Recommendations may only be made if the VM can be vMotioned onto another host. Even if a host is clearly overloaded, if the VMs cannot move
      to another host then no recommendations will appear.
    - >-
      If you try manually vMotioning a VM through the GUI, vCenter will validate the vMotion options at each step. This can be useful when determining
      why a VM is not able to move to another host and why no recommendations are being made.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    cluster:
        description:
            - The name of the cluster to be managed.
        type: str
        required: true
        aliases: [ cluster_name ]
    datacenter:
        description:
            - The name of the datacenter.
        type: str
        required: true
        aliases: [ datacenter_name ]

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Apply DRS Recommendations for Cluster
  vmware.vmware.cluster_drs_recommendations:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: datacenter
    cluster_name: cluster
  delegate_to: localhost
'''

RETURN = r'''
cluster:
    description:
        - Information about the target cluster
    returned: On success
    type: dict
    sample:
        moid: cluster-79828,
        name: test-cluster
applied_recommendations:
    description:
        - List of dictionaries describing the applied recommendations
        - Each entry has a description, which is a string saying where servers were moved
        - Each entry has a task_result, which is a dictionary describing the vCenter task
    returned: always
    type: list
    sample: [
        {
            "description": "server1 will move from host1 to host2.",
            "task_result": {
                "completion_time": "2024-07-29T15:27:37.041577+00:00",
                "entity_name": "test-5fb1_cluster_drs_test",
                "error": null,
                "result": null,
                "state": "success"
            }
        },
        {
            "description": "server2 will move from host1 to host2.",
            "task_result": {
                "completion_time": "2024-07-29T15:27:37.041577+00:00",
                "entity_name": "test-5fb1_cluster_drs_test",
                "error": null,
                "result": null,
                "state": "success"
            }
        }
    ]
'''

try:
    from pyVmomi import vmodl
except ImportError:
    pass

from itertools import zip_longest
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import (
    TaskError,
    RunningTaskMonitor
)
from ansible.module_utils.common.text.converters import to_native


class VMwareCluster(ModulePyvmomiBase):
    def __init__(self, module):
        super(VMwareCluster, self).__init__(module)
        datacenter = self.get_datacenter_by_name_or_moid(self.params.get('datacenter'), fail_on_missing=True)
        self.cluster = self.get_cluster_by_name_or_moid(self.params.get('cluster'), fail_on_missing=True, datacenter=datacenter)

    def get_recommendations(self):
        """
        Refreshes the clusters current DRS recommendation list and returns them.
        Returns:
            list
        """
        self.cluster.RefreshRecommendation()
        return self.cluster.recommendation

    def apply_recommendations(self):
        """
        Applies any DRS recommendations that the cluster may have pending. Waits for all tasks to finish and returns
        information about the applied recommendation and tasks.
        Returns:
          list(dict())
          Example: [{description: str, task_result: dict}]
        """
        applied_recommendation_descriptions = []
        applied_recommendation_tasks = []
        for recommendation in self.cluster.recommendation:
            # since these are vmotion recommendations, there's only ever one action
            action = recommendation.action[0]
            applied_recommendation_descriptions.append(
                "%s will move from %s to %s." % (
                    action.target.name,
                    action.drsMigration.source.name,
                    action.drsMigration.destination.name
                )
            )

            if not self.module.check_mode:
                self.cluster.ApplyRecommendation(recommendation.key)
                # get the most recent task for the target VM, which should be the vmotion task we just triggered
                applied_recommendation_tasks.append(action.target.recentTask[0])

        task_results = self.__wait_for_recommendation_task_results(applied_recommendation_tasks)
        combined_results = zip_longest(applied_recommendation_descriptions, task_results, fillvalue=dict())
        return [dict(zip(['description', 'task_results'], res)) for res in combined_results]

    def __wait_for_recommendation_task_results(self, recommendation_tasks):
        """
        Waits for all tasks in a list of tasks to finish, then returns the task output
        Args:
            recommendation_tasks: list of vcenter task objects
        Returns:
          list(dict)
        """
        task_results = []
        for task in recommendation_tasks:
            try:
                _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
            except (vmodl.RuntimeFault, vmodl.MethodFault)as vmodl_fault:
                self.module.fail_json(msg=to_native(vmodl_fault.msg))
            except TaskError as task_e:
                self.module.fail_json(msg=to_native(task_e))
            except Exception as generic_exc:
                self.module.fail_json(msg="Failed to apply DRS recommendation due to exception %s" % to_native(generic_exc))
            task_results.append(task_result)

        return task_results


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                cluster=dict(type='str', required=True, aliases=['cluster_name']),
                datacenter=dict(type='str', required=True, aliases=['datacenter_name']),
            )
        },
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
        applied_recommendations=[],
        cluster=dict(
            name="",
            moid=""
        )
    )

    cluster_drs = VMwareCluster(module)
    result['cluster']['name'] = cluster_drs.cluster.name
    result['cluster']['moid'] = cluster_drs.cluster._GetMoId()

    recommendations = cluster_drs.get_recommendations()
    if recommendations:
        result['changed'] = True
        result['applied_recommendations'] = cluster_drs.apply_recommendations()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
