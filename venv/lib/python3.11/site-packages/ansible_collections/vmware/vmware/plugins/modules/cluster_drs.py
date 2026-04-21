#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cluster_drs
short_description: Manage Distributed Resource Scheduler (DRS) on VMware vSphere clusters
description:
    - Manages DRS on VMware vSphere clusters.
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
    enable:
        description:
            - Whether to enable DRS.
        type: bool
        default: true
    drs_enable_vm_behavior_overrides:
        description:
            - Whether DRS Behavior overrides for individual virtual machines are enabled.
            - If set to V(true), overrides O(drs_default_vm_behavior).
        type: bool
        default: true
    drs_default_vm_behavior:
        description:
            - Specifies the cluster-wide default DRS behavior for virtual machines.
            - If set to V(partiallyAutomated), vCenter generates recommendations for virtual machine migration and
                for the placement with a host, then automatically implements placement recommendations at power on.
            - If set to V(manual), then vCenter generates recommendations for virtual machine migration and
                for the placement with a host, but does not implement the recommendations automatically.
            - If set to V(fullyAutomated), then vCenter automates both the migration of virtual machines
                and their placement with a host at power on.
        type: str
        default: fullyAutomated
        choices: [ fullyAutomated, manual, partiallyAutomated ]
    drs_vmotion_rate:
        description:
            - Threshold for generated ClusterRecommendations ranging from V(1) (lowest) to V(5) (highest).
        type: int
        default: 3
        choices: [ 1, 2, 3, 4, 5 ]
    advanced_settings:
        description:
            - A dictionary of advanced DRS settings.
        default: {}
        type: dict
    predictive_drs:
        description:
            - In addition to real-time metrics, DRS will respond to forecasted metrics provided by vRealize Operations Manager.
            - You must also configure Predictive DRS in a version of vRealize Operations that supports this feature.
        type: bool
        default: false

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Enable DRS
  vmware.vmware.cluster_drs:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: datacenter
    cluster_name: cluster
    enable: true
  delegate_to: localhost

- name: Enable DRS and distribute a more even number of virtual machines across hosts for availability
  vmware.vmware.cluster_drs:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: datacenter
    cluster_name: cluster
    enable: true
    advanced_settings:
      'TryBalanceVmsPerHost': '1'
  delegate_to: localhost

- name: Enable DRS and set default VM behavior to partially automated
  vmware.vmware.cluster_drs:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter_name: DC0
    cluster_name: "{{ cluster_name }}"
    enable: true
    drs_default_vm_behavior: partiallyAutomated
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
result:
    description:
        - Information about the DRS config update task, if something changed
        - If nothing changed, an empty dictionary is returned
    returned: On success
    type: dict
    sample: {
        "result": {
            "completion_time": "2024-07-29T15:27:37.041577+00:00",
            "entity_name": "test-5fb1_cluster_drs_test",
            "error": null,
            "result": null,
            "state": "success"
        }
    }
'''

try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

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
from ansible_collections.vmware.vmware.plugins.module_utils._facts import (
    ClusterFacts
)
from ansible_collections.vmware.vmware.plugins.module_utils._advanced_settings import (
    AdvancedSettings
)
from ansible.module_utils.common.text.converters import to_native


class VMwareCluster(ModulePyvmomiBase):
    def __init__(self, module):
        super(VMwareCluster, self).__init__(module)

        datacenter = self.get_datacenter_by_name_or_moid(self.params.get('datacenter'), fail_on_missing=True)
        self.cluster = self.get_cluster_by_name_or_moid(self.params.get('cluster'), fail_on_missing=True, datacenter=datacenter)

        self.enable_drs = self.params.get('enable')
        self.drs_enable_vm_behavior_overrides = self.params.get('drs_enable_vm_behavior_overrides')
        self.drs_default_vm_behavior = self.params.get('drs_default_vm_behavior')
        self.predictive_drs = self.params.get('predictive_drs')

        _user_settings = AdvancedSettings.from_py_dict(self.params.get('advanced_settings'), cast_all_values_to_str=True)
        _live_settings = AdvancedSettings.from_vsphere_config(self.cluster.configurationEx.drsConfig.option)
        self.changed_advanced_settings = _user_settings.difference(_live_settings)

    @property
    def drs_vmotion_rate(self):
        """
        When applying or reading this rate from the vCenter config, the values are reversed. So
        for example, vCenter thinks 1 is the most aggressive when docs/UI say 5 is most aggressive.
        We present the scale seen in the docs/UI to the user and then adjust the value here to ensure
        vCenter behaves as intended.
        """
        return ClusterFacts.reverse_drs_or_dpm_rate(self.params.get('drs_vmotion_rate'))

    def check_drs_config_diff(self):
        """
        Check the active DRS configuration and determine if desired configuration is different.
        If the current DRS configuration is undefined for some reason, the error is caught
        and the function returns True.
        Returns:
            True if there is difference, else False
        """
        try:
            drs_config = self.cluster.configurationEx.drsConfig
            proactive_drs_config = self.cluster.configurationEx.proactiveDrsConfig

            if (drs_config.enabled != self.enable_drs or
                    drs_config.enableVmBehaviorOverrides != self.drs_enable_vm_behavior_overrides or
                    drs_config.defaultVmBehavior != self.drs_default_vm_behavior or
                    drs_config.vmotionRate != self.drs_vmotion_rate or
                    proactive_drs_config.enabled != self.predictive_drs):
                return True

        except AttributeError:
            return True

        if not self.changed_advanced_settings.is_empty():
            return True

        return False

    def __create_drs_config_spec(self):
        """
        Uses the class's attributes to create a new cluster DRS config spec
        """
        cluster_config_spec = vim.cluster.ConfigSpecEx()
        cluster_config_spec.drsConfig = vim.cluster.DrsConfigInfo()
        cluster_config_spec.proactiveDrsConfig = vim.cluster.ProactiveDrsConfigInfo()
        cluster_config_spec.drsConfig.enabled = self.enable_drs
        cluster_config_spec.drsConfig.enableVmBehaviorOverrides = self.drs_enable_vm_behavior_overrides
        cluster_config_spec.drsConfig.defaultVmBehavior = self.drs_default_vm_behavior
        cluster_config_spec.drsConfig.vmotionRate = self.drs_vmotion_rate
        cluster_config_spec.proactiveDrsConfig.enabled = self.predictive_drs

        if not self.changed_advanced_settings.is_empty():
            cluster_config_spec.drsConfig.option = self.changed_advanced_settings.to_vsphere_config()

        return cluster_config_spec

    def apply_drs_configuration(self):
        """
        Apply the class's attributes as a DRS config to the cluster
        """
        cluster_config_spec = self.__create_drs_config_spec()

        try:
            task = self.cluster.ReconfigureComputeResource_Task(cluster_config_spec, True)
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except (vmodl.RuntimeFault, vmodl.MethodFault)as vmodl_fault:
            self.module.fail_json(msg=to_native(vmodl_fault.msg))
        except TaskError as task_e:
            self.module.fail_json(msg=to_native(task_e))
        except Exception as generic_exc:
            self.module.fail_json(msg="Failed to update cluster due to exception %s" % to_native(generic_exc))

        return task_result


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                cluster=dict(type='str', required=True, aliases=['cluster_name']),
                datacenter=dict(type='str', required=True, aliases=['datacenter_name']),
                enable=dict(type='bool', default=True),
                drs_enable_vm_behavior_overrides=dict(type='bool', default=True),
                drs_default_vm_behavior=dict(
                    type='str',
                    choices=['fullyAutomated', 'manual', 'partiallyAutomated'],
                    default='fullyAutomated'
                ),
                drs_vmotion_rate=dict(type='int', choices=[1, 2, 3, 4, 5], default=ClusterFacts.DRS_DEFAULT_RATE),
                advanced_settings=dict(type='dict', required=False, default=dict()),
                predictive_drs=dict(type='bool', required=False, default=False),
            )
        },
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
        result={},
        cluster=dict(
            name="",
            moid=""
        )
    )

    cluster_drs = VMwareCluster(module)
    result['cluster']['name'] = cluster_drs.cluster.name
    result['cluster']['moid'] = cluster_drs.cluster._GetMoId()

    config_is_different = cluster_drs.check_drs_config_diff()
    if config_is_different:
        result['changed'] = True
        if not module.check_mode:
            result['result'] = cluster_drs.apply_drs_configuration()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
