#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cluster
short_description: Manage VMware vSphere clusters
description:
    - Adds or removes VMware vSphere clusters.
    - >-
      To manage DRS, HA and VSAN related configurations, use the modules cluster_drs,
      community.vmware.vmware_cluster_ha and community.vmware.vmware_cluster_vsan.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    cluster:
      description:
        - The name of the cluster to be managed.
      type: str
      required: true
      aliases: [cluster_name, name]
    datacenter:
      description:
        - The name of the datacenter.
      type: str
      required: true
      aliases: [datacenter_name]
    state:
      description:
        - Create V(present) or remove V(absent) a VMware vSphere cluster.
      choices: [ absent, present ]
      default: present
      type: str

seealso:
    - module: vmware.vmware.cluster_drs
    - module: community.vmware.vmware_cluster_ha
    - module: community.vmware.vmware_cluster_vsan

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Create Cluster
  vmware.vmware.cluster:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: datacenter
    cluster_name: cluster

- name: Delete Cluster
  vmware.vmware.cluster:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: datacenter
    name: cluster
    state: absent
'''

RETURN = r'''
cluster:
    description:
        - Identifying information about the cluster
        - If the cluster was removed, only the name is returned
    returned: On success
    type: dict
    sample: {
        "cluster": {
            "moid": "domain-c111111",
            "name": "example-cluster"
        },
    }
'''

try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

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


class VMwareCluster(ModulePyvmomiBase):
    def __init__(self, module):
        super(VMwareCluster, self).__init__(module)
        self.datacenter_obj = None
        self.cluster_obj = None

    def update_state(self):
        """
        Creates or deletes a cluster depending on params. Includes error handling
        """
        try:
            if self.params['state'] == 'present':
                self.__create()
            elif self.params['state'] == 'absent':
                self.__destroy()
        except vmodl.fault.InvalidArgument as invalid_args:
            self.module.fail_json(msg="Cluster configuration specification"
                                      " is invalid : %s" % to_native(invalid_args.msg))
        except vim.fault.InvalidName as invalid_name:
            self.module.fail_json(msg="'%s' is an invalid name for a"
                                      " cluster : %s" % (self.params['cluster'],
                                                         to_native(invalid_name.msg)))
        except (vim.fault.VimFault, vmodl.RuntimeFault, vmodl.MethodFault) as _fault:
            self.module.fail_json(msg=to_native(_fault.msg))
        except Exception as generic_exc:
            self.module.fail_json(msg="Failed to process cluster"
                                      " due to exception %s" % to_native(generic_exc))

    def __create(self):
        """
        Creates a cluster
        """
        cluster_config_spec = vim.cluster.ConfigSpecEx()
        self.cluster_obj = self.datacenter_obj.hostFolder.CreateClusterEx(self.params['cluster'], cluster_config_spec)

    def __destroy(self):
        """
        Destroys a cluster
        """
        task = self.cluster_obj.Destroy_Task()
        try:
            _, _ = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except TaskError as e:
            self.module.fail_json(msg=to_native(e))
        self.cluster_obj = None

    def actual_state_matches_desired_state(self):
        """
        Checks if cluster exists and compares that to the desired state.
        Returns: True if cluster state matches desired state, False otherwise
        """
        self.datacenter_obj = self.get_datacenter_by_name_or_moid(self.params['datacenter'], fail_on_missing=True)
        self.cluster_obj = self.get_cluster_by_name_or_moid(
            identifier=self.params['cluster'],
            datacenter=self.datacenter_obj,
            fail_on_missing=False
        )

        if self.params['state'] == 'present' and self.cluster_obj:
            return True

        if self.params['state'] == 'absent' and not self.cluster_obj:
            return True

        return False

    def get_cluster_outputs(self):
        """
        Returns a dictionary with identifying information about the cluster, if one existed or exists.
        Returns: dict
        """
        out = {'name': self.params['cluster']}
        if self.cluster_obj:
            out['moid'] = self.cluster_obj._GetMoId()

        return out


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                cluster=dict(type='str', required=True, aliases=['cluster_name', 'name']),
                datacenter=dict(type='str', required=True, aliases=['datacenter_name']),
                state=dict(type='str', default='present', choices=['absent', 'present']),
            )
        },
        supports_check_mode=True,
    )

    vmware_cluster = VMwareCluster(module)
    if vmware_cluster.actual_state_matches_desired_state():
        module.exit_json(changed=False, cluster=vmware_cluster.get_cluster_outputs())

    if module.check_mode:
        module.exit_json(changed=True, cluster=vmware_cluster.get_cluster_outputs())

    vmware_cluster.update_state()
    module.exit_json(changed=True, cluster=vmware_cluster.get_cluster_outputs())


if __name__ == '__main__':
    main()
