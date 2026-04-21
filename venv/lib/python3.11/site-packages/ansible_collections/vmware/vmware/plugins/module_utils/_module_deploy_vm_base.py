# Copyright: (c) 2024, Ansible Cloud Team
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import abstractmethod
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import ModulePyvmomiBase
from ansible_collections.vmware.vmware.plugins.module_utils.vm.services._placement import VmPlacement, vm_placement_argument_spec

try:
    from pyVmomi import vim
except ImportError:
    pass


def vm_deploy_module_argument_spec():
    spec = vm_placement_argument_spec(omit_params=['folder', 'esxi_host'])
    spec.update(dict(
        vm_name=dict(type='str', required=True),
        vm_folder=dict(type='str', required=False, aliases=['folder'])
    ))
    spec['datacenter']['required'] = True
    return spec


class ModuleVmDeployBase(ModulePyvmomiBase):
    def __init__(self, module):
        super().__init__(module)
        self.placement_service = VmPlacement(module)
        self.datacenter = self.placement_service.get_datacenter()

    @property
    def datastore(self):
        return self.placement_service.get_datastore()

    @property
    def resource_pool(self):
        return self.placement_service.get_resource_pool()

    @property
    def vm_folder(self):
        return self.placement_service.get_folder(folder_param='vm_folder')

    @property
    def library_item_id(self):
        if self._library_item_id:
            return self._library_item_id

        if self.params['library_id']:
            library_id = self.params['library_id']
        elif self.params['library_name']:
            library_ids = self.rest_base.get_content_library_ids(
                name=self.params['library_name'],
                fail_on_missing=True
            )
            if len(library_ids) > 1:
                self.module.fail_json(msg=(
                    "Found multiple libraries with the name %s. Try specifying library_id instead" %
                    self.params['library_name']
                ))
            library_id = library_ids[0]
        else:
            library_id = None

        item_ids = self.rest_base.get_library_item_ids(
            name=self.params['library_item_name'],
            library_id=library_id,
            fail_on_missing=True
        )
        if len(item_ids) > 1:
            self.module.fail_json(msg=(
                "Found multiple library items with the name %s. Try specifying library_item_id, library_name, or library_id" %
                self.params['library_item_name']
            ))
        self._library_item_id = item_ids[0]
        return self._library_item_id

    def get_deployed_vm(self):
        vms = self.get_objs_by_name_or_moid(
            vimtype=[vim.VirtualMachine],
            name=self.params['vm_name'],
            search_root_folder=self.vm_folder
        )
        if vms:
            return vms[0]
        return None

    @abstractmethod
    def create_deploy_spec(self):
        raise NotImplementedError

    @abstractmethod
    def deploy(self):
        raise NotImplementedError
