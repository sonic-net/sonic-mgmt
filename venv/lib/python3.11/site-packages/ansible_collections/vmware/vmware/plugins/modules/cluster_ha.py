#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cluster_ha
short_description: Manage High Availability services (HA) on VMware vSphere clusters
description:
    - Manages HA on VMware vSphere clusters.
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
            - Whether to enable HA.
        type: bool
        default: true

    host_failure_response:
        description:
            - Configures how VM workflows should be managed if an ESXi host is in a failure state.
        type: dict
        suboptions:
            restart_vms:
                description:
                    - If true, HA will restart virtual machines after a host fails and comes back online.
                type: bool
                default: true
            default_vm_restart_priority:
                description:
                    - Set the default priority HA gives to a virtual machine if sufficient capacity is not available
                      to power on all failed virtual machines.
                    - Used only when O(vm_monitoring.mode) is V(vmAndAppMonitoring) or V(vmMonitoringOnly).
                type: str
                default: 'medium'
                choices: [ 'lowest', 'low', 'medium', 'high', 'highest' ]

    host_isolation_response:
        description:
            - Specify how VMs should be handled if an ESXi host determines it can no longer reach the rest of the cluster.
            - If set to V(none), no action is taken.
            - If set to V(powerOff), VMs are powered off via the hypervisor.
            - If set to V(shutdown), VMs are shut down via the guest operating system.
        type: str
        choices: ['none', 'powerOff', 'shutdown']
        default: 'none'

    advanced_settings:
        description:
            - A dictionary of advanced HA settings.
            - Allowed HA settings are more strict than VM allowed settings. If you get an error when managing them, compare
              your settings against the vSphere HA Advanced Options documentation.
        default: {}
        type: dict

    admission_control_policy:
        description:
            - Configures a the policy type used for HA admission control.
            - Admission control is a policy used by vSphere HA to ensure failover capacity within a cluster.
            - Raising the number of potential host failures will increase the availability constraints and capacity reserved.
        type: str
        choices: ['vm_slots', 'cluster_resource', 'dedicated_host']
        required: False

    admission_control_failover_level:
        description:
            - The number of host failures that should be tolerated by the cluster.
            - The maximum is one less than the total number of hosts.
            - If O(admission_control_policy) is V(dedicated_host), the default value is the number of dedicated failover hosts.
            - For all other O(admission_control_policy) values, the default value is 1.
        type: int
        required: false

    admission_control_cpu_reserve_percentage:
        description:
            - Percentage of CPU resources in the cluster to reserve for failover.
            - Only used if O(admission_control_policy) is V(cluster_resource).
            - >-
                By default, the O(admission_control_failover_level) is used by vSphere to
                automatically calculate this value. Setting this option overrides that behavior.
        type: int

    admission_control_memory_reserve_percentage:
        description:
            - Percentage of memory resources in the cluster to reserve for failover.
            - Only used if O(admission_control_policy) is V(cluster_resource).
            - >-
                By default, the O(admission_control_failover_level) is used by vSphere to
                automatically calculate this value. Setting this option overrides that behavior.
        type: int

    admission_control_dedicated_hosts:
        description:
            - List of ESXi hosts to use as dedicated failover hosts.
            - The list should be the names of ESXi hosts as seen in vCenter.
            - Required if (and only used if) O(admission_control_policy) is V(dedicated_host).
        type: list
        elements: str
        required: false

    vm_monitoring:
        description:
            - Configures how VMs are monitored to determine health status, and what actions should be taken
              if they are unhealthy.
        type: dict
        suboptions:
            mode:
                description:
                    - Sets the state of the virtual machine health monitoring service.
                    - If set to V(vmAndAppMonitoring), HA will respond to both VM and vApp heartbeat failures.
                    - If set to V(vmMonitoringDisabled), HA will only respond to vApp heartbeat failures.
                    - If set to V(vmMonitoringOnly), HA will only respond to VM heartbeat failures.
                type: str
                choices: ['vmAndAppMonitoring', 'vmMonitoringOnly', 'vmMonitoringDisabled']
                default: 'vmMonitoringDisabled'
            failure_interval:
                description:
                    - The number of seconds to wait after a VM heartbeat fails before declaring the VM as unhealthy.
                    - Valid only when O(vm_monitoring.mode) is V(vmAndAppMonitoring) or V(vmMonitoringOnly).
                type: int
                default: 30
            minimum_uptime:
                description:
                    - The number of seconds to wait for the VM's heartbeat to stabilize after it was powered reset.
                    - Valid only when O(vm_monitoring.mode) is V(vmAndAppMonitoring) or V(vmMonitoringOnly).
                type: int
                default: 120
            maximum_resets:
                description:
                    - The maximum number of automated resets allowed in response to a VM becoming unhealthy
                    - Valid only when O(vm_monitoring.mode) is V(vmAndAppMonitoring) or V(vmMonitoringOnly).
                type: int
                default: 3
            maximum_resets_window:
                description:
                    - The number of seconds during in which O(vm_monitoring.maximum_resets) resets
                      can occur before automated responses stop.
                    - Valid only when O(vm_monitoring.mode) is V(vmAndAppMonitoring) or V(vmMonitoringOnly).
                    - The default value of -1 specifies no window.
                type: int
                default: -1

    storage_apd_response:
        description:
            - Configures what steps are taken when storage All Paths Down (APD) events occur.
        type: dict
        suboptions:
            mode:
                description:
                    - Set the response in the event of All Paths Down (APD) for storage.
                    - APD differs from PDL, in that APD is assumed to be a transient outage and PDL is permanent.
                    - V(disabled) means no action will be taken
                    - V(warning) means no action will be taken, but events will be generated for logging purposes.
                    - V(restartConservative) means VMs will be powered off if  HA determines another host can support the VM.
                    - V(restartAggressive) means VMs will be powered off if HA determines the VM can be restarted on a different host,
                      or if HA cannot detect the resources on other hosts because of network connectivity loss.
                type: str
                default: 'warning'
                choices: [ 'disabled', 'warning', 'restartConservative', 'restartAggressive' ]
            delay:
                description:
                    - Set the response recovery delay time in seconds if storage is in an APD failure state.
                    - This is only used if O(storage_apd_response=restartConservative) or O(storage_apd_response=restartAggressive).
                type: int
                default: 180
            restart_vms:
                description:
                    - If true, VMs will be restarted when possible if storage is in an APD failure state.
                    - This is only used if O(storage_apd_response) is V(restartConservative) V(restartAggressive).
                type: bool
                default: true
    storage_pdl_response_mode:
        description:
            - Set the response in the event of permanent Device Loss (PDL) for storage.
            - APD differs from PDL, in that APD is assumed to be a transient outage and PDL is permanent.
            - V(disabled) means no action will be taken
            - V(warning) means no action will be taken, but events will be generated for logging purposes.
            - V(restart) means all VMs will be powered off. If hosts still have access to the datastore,
              affected VMs will be restarted on that host.
        type: str
        default: 'warning'
        choices: ['disabled', 'warning', 'restart']

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Enable HA With vCenter Defaults
  vmware.vmware.cluster_ha:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: DC01
    cluster: my-cluster

- name: Disable HA
  vmware.vmware.cluster_ha:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: DC01
    cluster: my-cluster
    enable: false

- name: Set HA Settings In Cluster
  vmware.vmware.cluster_ha:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: DC01
    cluster: my-cluster
    host_failure_response:
      restart_vms: true
      default_vm_restart_priority: low
    host_isolation_response: powerOff
    admission_control_policy: dedicated_host
    admission_control_dedicated_hosts:
      - DC0_C0_H0
      - DC0_C0_H1
    vm_monitoring:
      mode: vmAndAppMonitoring
    storage_apd_response:
      mode: restartConservative
      delay: 100
      restart_vms: true
    storage_pdl_response_mode: restart

# If you do not set a parameter and it has no default, the module will ignore
# the corresponding vCenter setting when checking for config diffs and applying new configs
- name: Only Manage Host Failure Settings
  vmware.vmware.cluster_ha:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: DC01
    cluster: my-cluster
    host_failure_response:
      restart_vms: true
      default_vm_restart_priority: low
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
        - Information about the HA config update task, if something changed
        - If nothing changed, an empty dictionary is returned
    returned: On success
    type: dict
    sample: {
        "result": {
            "completion_time": "2025-01-23T21:27:39.156434+00:00",
            "entity_name": "my-cluster-name",
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
from ansible_collections.vmware.vmware.plugins.module_utils._advanced_settings import (
    AdvancedSettings
)
from ansible.module_utils.common.text.converters import to_native


class VmwareCluster(ModulePyvmomiBase):
    def __init__(self, module):
        super(VmwareCluster, self).__init__(module)

        datacenter = self.get_datacenter_by_name_or_moid(self.params.get('datacenter'), fail_on_missing=True)
        self.cluster = self.get_cluster_by_name_or_moid(self.params.get('cluster'), fail_on_missing=True, datacenter=datacenter)
        self._cached_ac_failover_hosts = list()

        _user_settings = AdvancedSettings.from_py_dict(self.params.get('advanced_settings'), cast_all_values_to_str=True)
        _live_settings = AdvancedSettings.from_vsphere_config(self.cluster.configurationEx.dasConfig.option)
        self.changed_advanced_settings = _user_settings.difference(_live_settings)

    @property
    def storage_pdl_response_mode(self):
        if self.params['storage_pdl_response_mode'] == 'restart':
            return 'restartAggressive'
        return self.params['storage_pdl_response_mode']

    @property
    def host_failure_response_restart_vms(self):
        if self.params['host_failure_response']['restart_vms']:
            return 'enabled'
        return 'disabled'

    @property
    def storage_apd_restart_vms(self):
        if self.params['storage_apd_response']['restart_vms']:
            return 'reset'
        return 'none'

    @property
    def ac_failover_hosts(self):
        if self.params['admission_control_policy'] != 'dedicated_host':
            return []

        if self._cached_ac_failover_hosts:
            return self._cached_ac_failover_hosts

        all_hosts = {h.name: h for h in self.cluster.host}
        for host_name in self.params['admission_control_dedicated_hosts']:
            try:
                self._cached_ac_failover_hosts.append(all_hosts[host_name])
            except KeyError:
                self.module.fail_json(msg="Host %s is not a member of cluster %s." % (host_name, self.params.get('cluster')))
        self._cached_ac_failover_hosts.sort(key=lambda h: h.name)
        return self._cached_ac_failover_hosts

    @property
    def ac_cluster_resource_auto_compute_percentages(self):
        if self.params['admission_control_cpu_reserve_percentage'] or self.params['admission_control_memory_reserve_percentage']:
            return False

        return True

    @property
    def ac_failover_level(self):
        """
        Since this param requires admission_control_policy, we cannot have a default set in the module spec.
        Instead, the default value is calculated depending on the policy type selected by the user, which
        is mentioned in the param docs
        """
        if self.params.get('admission_control_failover_level'):
            return self.params.get('admission_control_failover_level')

        if self.params['admission_control_policy'] != 'dedicated_host':
            return 1

        return len(self.ac_failover_hosts)

    def check_apd_restart_params(self):
        if self.params['storage_apd_response']['mode'] in ('disabled', 'warning'):
            return False
        return True

    def check_ha_config_diff(self):
        """
        Check the active HA configuration and determine if desired configuration is different.
        If the current HA configuration is undefined for some reason, the error is caught
        and the function returns True.
        Returns:
            True if there is difference, else False
        """
        try:
            ha_config = self.cluster.configurationEx.dasConfig
        except AttributeError:
            return True

        if ha_config.enabled != self.params['enable']:
            return True

        if not self.params['enable']:
            return False

        if self.__check_host_failure_config_diff(ha_config):
            return True

        if self.__check_vm_monitoring_config_diff(ha_config):
            return True

        if self.__check_admission_control_config_diff(ha_config):
            return True

        if self.__check_storage_config_diff(ha_config):
            return True

        if not self.changed_advanced_settings.is_empty():
            return True

        return False

    def __check_host_failure_config_diff(self, ha_config):
        """
        Helper function to check the host_isolation* and host_failure* parameters
        Returns:
            True if there is difference, else False
        """
        if ha_config.defaultVmSettings.isolationResponse != self.params.get('host_isolation_response'):
            return True

        if not self.params['host_failure_response']:
            return False

        if (
            ha_config.defaultVmSettings.restartPriority != self.params['host_failure_response']['default_vm_restart_priority'] or
            ha_config.hostMonitoring != self.host_failure_response_restart_vms
        ):
            return True

        return False

    def __check_vm_monitoring_config_diff(self, ha_config):
        """
        Helper function to check the vm_monitoring parameters
        Returns:
            True if there is difference, else False
        """
        vm_params = self.params['vm_monitoring']
        if not vm_params:
            return False

        try:
            vm_config = ha_config.defaultVmSettings.vmToolsMonitoringSettings
        except AttributeError:
            return True

        if (
            vm_config.vmMonitoring != vm_params["mode"] or
            vm_config.failureInterval != vm_params["failure_interval"] or
            vm_config.minUpTime != vm_params["minimum_uptime"] or
            vm_config.maxFailures != vm_params["maximum_resets"] or
            vm_config.maxFailureWindow != vm_params["maximum_resets_window"]
        ):
            return True

        return False

    def __check_admission_control_config_diff(self, ha_config):
        """
        Helper function to check the admission_control* parameters
        Returns:
            True if there is difference, else False
        """
        if not self.params.get("admission_control_policy"):
            return False

        try:
            ac_config = ha_config.admissionControlPolicy
        except AttributeError:
            return True

        if ac_config.failoverLevel != self.ac_failover_level:
            return True

        policy_classes = {
            'vm_slots': vim.cluster.FailoverLevelAdmissionControlPolicy,
            'cluster_resource': vim.cluster.FailoverResourcesAdmissionControlPolicy,
            'dedicated_host': vim.cluster.FailoverHostAdmissionControlPolicy
        }
        if not isinstance(ac_config, policy_classes[self.params.get("admission_control_policy")]):
            return True

        if not ha_config.admissionControlEnabled:
            return True

        if self.params.get("admission_control_policy") == 'dedicated_host':
            ac_config.failoverHosts.sort(key=lambda h: h.name)
            if ac_config.failoverHosts != self.ac_failover_hosts:
                return True
            return False

        if self.__check_ac_config_cluster_resource_diff(ac_config=ac_config):
            return True

        return False

    def __check_ac_config_cluster_resource_diff(self, ac_config):
        """
        Another admission control helper function. Checks the parameters used when the control policy
        is cluster_resource
        Returns:
            True if there is difference, else False
        """
        if self.params.get("admission_control_policy") != 'cluster_resource':
            return False

        # if user does not set the cpu or mem reservations, we use auto computing.
        if self.ac_cluster_resource_auto_compute_percentages:
            # we use autocomputing and the config does not, so there is a diff
            return not ac_config.autoComputePercentages

        # we dont use autocomputing and the config does, so there is a diff
        if ac_config.autoComputePercentages:
            return True

        if (
            self.params.get('admission_control_cpu_reserve_percentage') and
            ac_config.cpuFailoverResourcesPercent != self.params.get('admission_control_cpu_reserve_percentage')
        ):
            return True
        if (
            self.params.get('admission_control_memory_reserve_percentage') and
            ac_config.memoryFailoverResourcesPercent != self.params.get('admission_control_memory_reserve_percentage')
        ):
            return True

        return False

    def __check_storage_config_diff(self, ha_config):
        """
        Helper function to check the storage* parameters
        Returns:
            True if there is difference, else False
        """
        try:
            storage_config = ha_config.defaultVmSettings.vmComponentProtectionSettings
        except AttributeError:
            return True

        # check the PDL response mode first
        if storage_config.vmStorageProtectionForPDL != self.storage_pdl_response_mode:
            return True

        apd_params = self.params['storage_apd_response']
        if not apd_params:
            return False

        if storage_config.vmStorageProtectionForAPD != apd_params['mode']:
            return True

        # if apd response is not taking any actions, we dont need to check the other options.
        if not self.check_apd_restart_params():
            return False

        # check the rest of the options for apd
        if (
            storage_config.vmTerminateDelayForAPDSec != apd_params['delay'] or
            storage_config.vmReactionOnAPDCleared != self.storage_apd_restart_vms
        ):
            return True

        return False

    def __create_ha_config_spec(self):
        """
        Uses the class's attributes to create a new cluster HA config spec
        """
        cluster_config_spec = vim.cluster.ConfigSpecEx()
        cluster_config_spec.dasConfig = vim.cluster.DasConfigInfo()
        cluster_config_spec.dasConfig.enabled = self.params['enable']
        if not self.params['enable']:
            return cluster_config_spec

        vm_monitor_spec = vim.cluster.VmToolsMonitoringSettings()
        das_vm_spec = vim.cluster.DasVmSettings()
        das_vm_spec.vmComponentProtectionSettings = vim.cluster.VmComponentProtectionSettings()

        self.__set_vm_monitoring_params(cluster_config_spec, vm_monitor_spec)
        das_vm_spec.vmToolsMonitoringSettings = vm_monitor_spec

        self.__set_host_failure_params(cluster_config_spec, das_vm_spec)
        self.__set_storage_params(cluster_config_spec, das_vm_spec)
        cluster_config_spec.dasConfig.defaultVmSettings = das_vm_spec

        self.__set_admission_control_config(cluster_config_spec)

        if not self.changed_advanced_settings.is_empty():
            cluster_config_spec.dasConfig.option = self.changed_advanced_settings.to_vsphere_config()

        return cluster_config_spec

    def __set_vm_monitoring_params(self, cluster_config_spec, vm_monitor_spec):
        """
        Helper function to create config spec for the vm_monitoring* parameters.
        If the parameter was never and no defaults are defined, these specs are skipped.
        Returns:
            None
        """
        vm_params = self.params['vm_monitoring']
        if not vm_params:
            return

        cluster_config_spec.dasConfig.vmMonitoring = vm_params['mode']
        vm_monitor_spec.enabled = True
        vm_monitor_spec.vmMonitoring = vm_params['mode']
        vm_monitor_spec.failureInterval = vm_params['failure_interval']
        vm_monitor_spec.minUpTime = vm_params['minimum_uptime']
        vm_monitor_spec.maxFailures = vm_params['maximum_resets']
        vm_monitor_spec.maxFailureWindow = vm_params['maximum_resets_window']

    def __set_host_failure_params(self, cluster_config_spec, das_vm_spec):
        """
        Helper function to create config spec for the host_* parameters.
        If the parameter was never and no defaults are defined, these specs are skipped.
        Returns:
            None
        """
        das_vm_spec.isolationResponse = self.params['host_isolation_response']

        if not self.params['host_failure_response']:
            return

        das_vm_spec.restartPriority = self.params['host_failure_response']['default_vm_restart_priority']
        cluster_config_spec.dasConfig.hostMonitoring = self.host_failure_response_restart_vms

    def __set_storage_params(self, cluster_config_spec, das_vm_spec):
        """
        Helper function to create config spec for the storage* parameters.
        If the parameter was never and no defaults are defined, these specs are skipped.
        Returns:
            None
        """
        das_vm_spec.vmComponentProtectionSettings.vmStorageProtectionForPDL = self.storage_pdl_response_mode
        if self.storage_pdl_response_mode == "disabled":
            cluster_config_spec.dasConfig.vmComponentProtecting = 'disabled'
        else:
            cluster_config_spec.dasConfig.vmComponentProtecting = 'enabled'

        if not self.params['storage_apd_response']:
            return

        if self.storage_pdl_response_mode == "disabled":
            cluster_config_spec.dasConfig.vmComponentProtecting = 'disabled'

        das_vm_spec.vmComponentProtectionSettings.vmStorageProtectionForAPD = self.params['storage_apd_response']['mode']

        if self.check_apd_restart_params():
            das_vm_spec.vmComponentProtectionSettings.vmTerminateDelayForAPDSec = self.params['storage_apd_response']['delay']
            das_vm_spec.vmComponentProtectionSettings.vmReactionOnAPDCleared = self.storage_apd_restart_vms

    def __set_admission_control_config(self, cluster_config_spec):
        """
        Helper function to create config spec for the admission_control* parameters.
        If the parameter was never and no defaults are defined, these specs are skipped.
        Returns:
            None
        """
        if not self.params.get('admission_control_policy'):
            return

        cluster_config_spec.dasConfig.admissionControlEnabled = True
        if self.params.get('admission_control_policy') == 'vm_slots':
            ac_policy_spec = vim.cluster.FailoverLevelAdmissionControlPolicy()

        elif self.params.get('admission_control_policy') == 'cluster_resource':
            ac_policy_spec = vim.cluster.FailoverResourcesAdmissionControlPolicy()
            ac_policy_spec.autoComputePercentages = self.ac_cluster_resource_auto_compute_percentages
            if not self.ac_cluster_resource_auto_compute_percentages:
                if self.params.get('admission_control_cpu_reserve_percentage'):
                    ac_policy_spec.cpuFailoverResourcesPercent = self.params.get('admission_control_cpu_reserve_percentage')
                if self.params.get('admission_control_memory_reserve_percentage'):
                    ac_policy_spec.memoryFailoverResourcesPercent = self.params.get('admission_control_memory_reserve_percentage')

        elif self.params.get('admission_control_policy') == 'dedicated_host':
            ac_policy_spec = vim.cluster.FailoverHostAdmissionControlPolicy()
            ac_policy_spec.failoverHosts = self.ac_failover_hosts

        ac_policy_spec.failoverLevel = self.ac_failover_level
        cluster_config_spec.dasConfig.admissionControlPolicy = ac_policy_spec

    def apply_ha_configuration(self):
        """
        Apply the class's attributes as a HA config to the cluster
        """
        cluster_config_spec = self.__create_ha_config_spec()

        try:
            task = self.cluster.ReconfigureComputeResource_Task(cluster_config_spec, True)
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except (vmodl.RuntimeFault, vmodl.MethodFault)as vmodl_fault:
            self.module.fail_json(msg=to_native(vmodl_fault.msg))
        except TaskError as task_e:
            if not self.changed_advanced_settings.is_empty():
                try:
                    self.module.fail_json(
                        msg="One or more advanced settings are invalid. Please refer to the vSphere documentation.",
                        invalid_settings=[e.value.strip() for e in task_e.parent_error.faultMessage[0].arg]
                    )
                except (KeyError, AttributeError):
                    pass
            self.module.fail_json(msg=to_native(task_e), task_e=task_e)
        except Exception as generic_exc:
            self.module.fail_json(msg="Failed to update cluster due to exception %s" % to_native(generic_exc))

        return task_result


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(),
            **dict(
                cluster=dict(type='str', required=True, aliases=['cluster_name']),
                datacenter=dict(type='str', required=True, aliases=['datacenter_name']),
                enable=dict(type='bool', default=True),

                host_failure_response=dict(type='dict', options=dict(
                    restart_vms=dict(type='bool', default=True),
                    default_vm_restart_priority=dict(type='str', default='medium', choices=['lowest', 'low', 'medium', 'high', 'highest']),
                )),

                host_isolation_response=dict(type='str', default='none', choices=['none', 'powerOff', 'shutdown']),
                advanced_settings=dict(type='dict', default=dict()),

                # HA VM Monitoring related parameters
                vm_monitoring=dict(type='dict', options=dict(
                    mode=dict(
                        type='str',
                        choices=['vmAndAppMonitoring', 'vmMonitoringOnly', 'vmMonitoringDisabled'],
                        default='vmMonitoringDisabled'
                    ),
                    failure_interval=dict(type='int', default=30),
                    minimum_uptime=dict(type='int', default=120),
                    maximum_resets=dict(type='int', default=3),
                    maximum_resets_window=dict(type='int', default=-1),
                )),

                # HA Admission Control related parameters
                admission_control_policy=dict(type='str', required=False, choices=['vm_slots', 'cluster_resource', 'dedicated_host']),
                admission_control_failover_level=dict(type='int'),
                admission_control_cpu_reserve_percentage=dict(type='int', required=False),
                admission_control_memory_reserve_percentage=dict(type='int', required=False),
                admission_control_dedicated_hosts=dict(type='list', elements='str', required=False),

                storage_pdl_response_mode=dict(type='str', choices=['disabled', 'warning', 'restart'], default='warning'),
                storage_apd_response=dict(type='dict', options=dict(
                    mode=dict(
                        type='str',
                        default='warning',
                        choices=['disabled', 'warning', 'restartConservative', 'restartAggressive']),
                    delay=dict(type='int', default=180),
                    restart_vms=dict(type='bool', default=True)
                )),
            )
        },
        supports_check_mode=True,
        required_if=[
            ('admission_control_policy', 'dedicated_host', ('admission_control_dedicated_hosts',), False)
        ],
        required_by={
            'admission_control_failover_level': 'admission_control_policy',
            'admission_control_cpu_reserve_percentage': 'admission_control_policy',
            'admission_control_memory_reserve_percentage': 'admission_control_policy',
            'admission_control_dedicated_hosts': 'admission_control_policy',
        }
    )

    result = dict(
        changed=False,
        result={},
        cluster=dict(
            name="",
            moid=""
        )
    )

    cluster_ha = VmwareCluster(module)
    result['cluster']['name'] = cluster_ha.cluster.name
    result['cluster']['moid'] = cluster_ha.cluster._GetMoId()

    config_is_different = cluster_ha.check_ha_config_diff()
    if config_is_different:
        result['changed'] = True
        if not module.check_mode:
            result['result'] = cluster_ha.apply_ha_configuration()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
