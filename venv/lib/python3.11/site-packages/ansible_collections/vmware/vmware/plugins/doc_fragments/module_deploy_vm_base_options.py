# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):
    # This document fragment serves as a base for all vmware deploy_* modules. It should be used in addition to
    # the base argument specs for pyvmomi or rest
    #
    # This vmware.vmware.base_options fragment covers the arg spec provided by the base_argument_spec() function
    DOCUMENTATION = r'''
options:
    datacenter:
        description:
            - The name or MOID of the datacenter to use when searching for and deploying resources.
        type: str
        required: true
        aliases: [datacenter_name]
    vm_name:
        description:
            - The name of the VM to deploy.
            - If you have multiple VMs with the same name, you should also supply O(vm_folder)
        type: str
        required: true
    vm_folder:
        description:
            - Virtual machine folder into which the virtual machine should be deployed.
            - This can be the absolute folder path, or a relative folder path under /<datacenter>/vm/.
              See the examples for more info.
            - This option is required if you have more than one VM with the same name in the datacenter.
            - Changing this option will result in the VM being redeployed, since it affects where the module looks
              for the deployed VM.
            - If not provided, the /<datacenter>/vm/ folder is used.
        type: str
        required: false
        aliases: [folder]
    folder_paths_are_absolute:
        description:
            - If true, any folder path parameters are treated as absolute paths.
            - If false, modules will try to intelligently determine if the path is absolute
              or relative.
            - This option is useful when your environment has a complex folder structure. By default,
              modules will try to intelligently determine if the path is absolute or relative.
              They may mistakenly prepend the datacenter name or other folder names, and this option
              can be used to avoid this.
        type: bool
        required: false
        default: false
    resource_pool:
        description:
            - The name or MOID of a resource pool into which the virtual machine should be deployed.
            - Changing this option will not result in the VM being redeployed (it does not affect idempotency).
            - O(resource_pool) and O(cluster) are mutually exclusive.
        type: str
        required: false
    cluster:
        description:
            - The name or MOID of the cluster where the VM should be deployed.
            - Changing this option will not result in the VM being redeployed (it does not affect idempotency).
            - O(resource_pool) and O(cluster) are mutually exclusive.
        type: str
        required: false
        aliases: [cluster_name]
    datastore:
        description:
            - Name or MOID of the datastore to store deployed VM and disk.
            - O(datastore) and O(datastore_cluster) are mutually exclusive.
        type: str
        required: false
    datastore_cluster:
        description:
            - Name or MOID of the datastore cluster to store deployed VM and disk.
            - Please make sure Storage DRS is active for recommended datastore from the given datastore cluster.
            - If Storage DRS is not enabled, datastore with largest free storage space is selected.
            - O(datastore) and O(datastore_cluster) are mutually exclusive.
        type: str
        required: false
'''
