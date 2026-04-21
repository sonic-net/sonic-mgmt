#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cluster_vcls
short_description: Manage the vCLS (vSphere Cluster Services) VM disk placement for this cluster.
description:
    - Overrides the default vCLS VM disk placement for this cluster.
    - >-
      Datastores may not be configured for vCLS if they are blocked by solutions where vCLS
      cannot be configured such as SRM or vSAN maintenance mode.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    cluster:
        description:
            - The name of the cluster to be managed.
        type: str
        required: true
        aliases: [cluster_name]
    datacenter:
        description:
            - The name of the datacenter where the cluster and datastores can be found.
            - If the cluster_name is unique for your environment, the datacenter is optional.
        type: str
        required: false
        aliases: [datacenter_name]
    allowed_datastores:
        description:
            - Exclusive list of the allowed datastores.
            - If there is an existing list configured in vCenter, it will be overridden by this value.
        type: list
        elements: str
        required: false
    datastores_to_add:
        description:
            - List of datastores to add to the vCLS config
            - >-
                The module will make sure these datastores are present in the config, and not change
                other datastores that are present.
        type: list
        elements: str
        required: false
        default: []
    datastores_to_remove:
        description:
            - List of datastores to remove from the vCLS config
            - >-
                The module will make sure these datastores are absent from the config, and not change
                other datastores that are present.
        type: list
        elements: str
        required: false
        default: []


extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Set Allowed vCLS Datastores
  vmware.vmware.cluster_vcls:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: datacenter
    cluster_name: cluster
    allowed_datastores:
      - ds1
      - ds2

- name: Make sure DS1 is Allowed and DS2 is Not
  vmware.vmware.cluster_vcls:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: datacenter
    cluster_name: cluster
    datastores_to_add:
      - ds1
    datastores_to_remove:
      - ds2
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
added_datastores:
    description: List of datastores that were added by this module. Empty if none had to be added
    returned: always
    type: list
    sample: [
        ds3
    ]
removed_datastores:
    description: List of datastores that were removed by this module. Empty if none had to be removed
    returned: always
    type: list
    sample: [
        ds4
    ]
allowed_datastores:
    description: Complete list of datastores that are in the active configuration (after the module has completed)
    returned: always
    type: list
    sample: [
        ds1
        ds2
        ds3
    ]
reconfig_task_result:
    description: Information about the vSphere task to re-configure vCLS
    returned: on change
    type: dict
    sample: {
        "completion_time": "2024-07-29T15:27:37.041577+00:00",
        "entity_name": "test-5fb1_cluster",
        "error": null,
        "result": null,
        "state": "success"
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


class VMwareClusterVcls(ModulePyvmomiBase):
    def __init__(self, module):
        super(VMwareClusterVcls, self).__init__(module)
        if module.params.get('datacenter'):
            datacenter = self.get_datacenter_by_name_or_moid(module.params['datacenter'], fail_on_missing=True)
        else:
            datacenter = None

        self.cluster = self.get_cluster_by_name_or_moid(module.params['cluster'], datacenter=datacenter, fail_on_missing=True)

    def get_current_configured_datastores(self):
        """
        Gets any currently allowed datastores from the active vCLS config
        Returns: set of allowed datastore names
        """
        allowed_datastores = set()
        if not hasattr(self.cluster.configurationEx, 'systemVMsConfig'):
            return allowed_datastores

        vcls_config = self.cluster.configurationEx.systemVMsConfig
        for ds in getattr(vcls_config, 'allowedDatastores', []):
            allowed_datastores.add(ds.name)

        return allowed_datastores

    def resolve_datastores_to_add_and_remove(self):
        """
        Check vCLS configuration diff
        Returns:
            Tuple of sets.
                index 0 contains the datastores that will be added,
                index 1 contains the datastores that will be removed
                index 2 contains the complete list of allowed datastores that will be applied
        """
        current_allowed_datastores = self.get_current_configured_datastores()
        if self.params['allowed_datastores'] is not None:
            new_allowed_datastores = set(self.params['allowed_datastores'])
        else:
            new_allowed_datastores = current_allowed_datastores\
                .union(set(self.params['datastores_to_add']))\
                .difference(set(self.params['datastores_to_remove']))

        datastores_to_add = new_allowed_datastores.difference(current_allowed_datastores)
        datastores_to_remove = current_allowed_datastores.difference(new_allowed_datastores)

        return datastores_to_add, datastores_to_remove, new_allowed_datastores

    def __add_datastore_to_config_spec(self, ds_name, cluster_config_spec):
        """
        Adds a datastore to the potential new vCLS spec. Causes a failure if the datastore does not exist.
        """
        allowed_datastore_spec = vim.cluster.DatastoreUpdateSpec()
        allowed_datastore_spec.datastore = self.get_datastore_by_name_or_moid(ds_name, fail_on_missing=True)
        allowed_datastore_spec.operation = 'add'
        cluster_config_spec.systemVMsConfig.allowedDatastores.append(allowed_datastore_spec)

    def __remove_datastore_from_config_spec(self, ds_name, cluster_config_spec):
        """
        Removes a datastore from the potential new vCLS spec
        """
        allowed_datastore_spec = vim.cluster.DatastoreUpdateSpec()
        allowed_datastore_spec.removeKey = self.get_datastore_by_name_or_moid(ds_name, fail_on_missing=False)
        allowed_datastore_spec.operation = 'remove'
        cluster_config_spec.systemVMsConfig.allowedDatastores.append(allowed_datastore_spec)

    def configure_vcls(self, datastores_to_add, datastores_to_remove):
        """
        Applies a vCLS configuration
        Args:
          datastores_to_add: A list of datastore names to add to the vCLS configuration
          datastores_to_remove: A list of datastore names to remove from the vCLS configuration

        """
        cluster_config_spec = vim.cluster.ConfigSpecEx()
        cluster_config_spec.systemVMsConfig = vim.cluster.SystemVMsConfigSpec()
        cluster_config_spec.systemVMsConfig.allowedDatastores = []

        # Build the Spec
        for ds_name in datastores_to_add:
            self.__add_datastore_to_config_spec(ds_name, cluster_config_spec)

        for ds_name in datastores_to_remove:
            self.__remove_datastore_from_config_spec(ds_name, cluster_config_spec)

        try:
            task = self.cluster.ReconfigureComputeResource_Task(cluster_config_spec, True)
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except (vmodl.MethodFault, vmodl.RuntimeFault, TaskError) as _fault:
            self.module.fail_json(msg=to_native(_fault.msg))
        except Exception as generic_exc:
            self.module.fail_json(
                msg="Failed to update cluster vCLS due to exception %s" % to_native(generic_exc)
            )

        return task_result


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                cluster=dict(type='str', required=True, aliases=['cluster_name']),
                datacenter=dict(type='str', required=False, aliases=['datacenter_name']),
                allowed_datastores=dict(type='list', elements='str'),
                datastores_to_add=dict(type='list', elements='str', default=[]),
                datastores_to_remove=dict(type='list', elements='str', default=[]),
            )
        },
        mutually_exclusive=[
            ('allowed_datastores', 'datastores_to_add'),
            ('allowed_datastores', 'datastores_to_remove'),
        ],
        required_one_of=[
            ('allowed_datastores', 'datastores_to_add', 'datastores_to_remove'),
        ],
        supports_check_mode=True,
    )

    results = dict(
        changed=False,
        added_datastores=[],
        removed_datastores=[],
        allowed_datastores=[],
        cluster=dict(
            name="",
            moid=""
        )
    )

    vmware_cluster_vcls = VMwareClusterVcls(module)
    results['cluster']['name'] = vmware_cluster_vcls.cluster.name
    results['cluster']['moid'] = vmware_cluster_vcls.cluster._GetMoId()

    ds_to_add, ds_to_remove, new_allowed_datastores = vmware_cluster_vcls.resolve_datastores_to_add_and_remove()
    results['allowed_datastores'] = new_allowed_datastores
    if ds_to_add or ds_to_remove:
        results['changed'] = True
        results['added_datastores'] = ds_to_add
        results['removed_datastores'] = ds_to_remove
        if not module.check_mode:
            results['reconfig_task_result'] = vmware_cluster_vcls.configure_vcls(ds_to_add, ds_to_remove)

    module.exit_json(**results)


if __name__ == '__main__':
    main()
