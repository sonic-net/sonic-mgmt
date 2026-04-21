# Copyright: (c) 2024, Ansible Cloud Team
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

try:
    from pyVmomi import (
        vim,
        vmodl
    )
except ImportError:
    pass
    # handled in base class

from ansible_collections.vmware.vmware.plugins.module_utils.clients.pyvmomi import PyvmomiClient
from ansible_collections.vmware.vmware.plugins.module_utils._folder_paths import format_folder_path_as_vm_fq_path


class ModulePyvmomiBase(PyvmomiClient):
    def __init__(self, module):
        super().__init__(**module.params)
        self.module = module
        self.params = module.params

    def is_vcenter(self):
        """
        Check if given hostname is vCenter or ESXi host
        Returns: True if given connection is with vCenter server
                 False if given connection is with ESXi server

        """
        api_type = None
        try:
            api_type = self.content.about.apiType
        except (vmodl.RuntimeFault, vim.fault.VimFault) as exc:
            self.module.fail_json(msg="Failed to get status of vCenter server : %s" % exc.msg)

        if api_type == 'VirtualCenter':
            return True
        elif api_type == 'HostAgent':
            return False

    def get_objs_by_name_or_moid(self, vimtype, name, return_all=False, search_root_folder=None):
        """
        Get any vsphere objects associated with a given text name or MOID and vim type.
        Different objects have different unique-ness requirements for the name parameter, so
        you may get one or more objects back. The MOID should always be unique
        Args:
            vimtype: The type of object to search for
            name: The name or the ID of the object to search for
            return_all: If true, return all the objects that were found.
                        Useful when names must be unique
            search_root_folder: The folder object that should be used as the starting point
                                for searches. Useful for restricting search results to a
                                certain datacenter (search_root_folder=datacenter.hostFolder)
        Returns:
            list(object) or list() if no matches are found
        """
        identifier = name
        if not search_root_folder:
            search_root_folder = self.content.rootFolder
        if isinstance(vimtype, list):
            vimtype = vimtype[0]

        results = []
        for managed_object_ref in self.get_managed_object_references(vimtype, properties=['name'], folder=search_root_folder):
            if len(results) > 0 and not return_all:
                break

            obj_skeleton = managed_object_ref.obj
            if obj_skeleton._GetMoId() == identifier:
                vim_obj = self.create_vim_object_from_moid(obj_skeleton._GetMoId(), vimtype)
                results.append(vim_obj)
                continue

            for property in managed_object_ref.propSet:
                if property.name == "name" and property.val == identifier:
                    vim_obj = self.create_vim_object_from_moid(obj_skeleton._GetMoId(), vimtype)
                    results.append(vim_obj)
                    break

        return results

    def get_standard_portgroup_by_name_or_moid(self, identifier, fail_on_missing=False):
        """
        Get a portgroup from type 'STANDARD_PORTGROUP' based on name or MOID
        Args:
            identifier: The name or the ID of the portgroup
            fail_on_missing: If true, an error will be thrown if no networks are found
        Returns:
            The standard portgroup object
        """
        pg = self.get_objs_by_name_or_moid([vim.Network], identifier)
        if pg:
            return pg[0]
        if fail_on_missing:
            self.module.fail_json(msg="Unable to find standard portgroup with name or MOID %s" % identifier)
        return None

    def get_dvs_portgroup_by_name_or_moid(self, identifier, fail_on_missing=False):
        """
        Get a portgroup from type 'DISTRIBUTED_PORTGROUP' based on name or MOID
        Args:
            identifier: The name or the ID of the portgroup
            fail_on_missing: If true, an error will be thrown if no networks are found
        Returns:
            The distributed portgroup object
        """
        pg = self.get_objs_by_name_or_moid([vim.dvs.DistributedVirtualPortgroup], identifier)
        if pg:
            return pg[0]
        if fail_on_missing:
            self.module.fail_json(msg="Unable to find distributed portgroup with name or MOID %s" % identifier)
        return None

    def get_vms_using_params(
            self, name_param='name', uuid_param='uuid', moid_param='moid', fail_on_missing=False,
            name_match_param='name_match', use_instance_uuid_param='use_instance_uuid', folder_param='folder'):
        """
            Get the vms matching the common module params related to vm identification: name, uuid, or moid. Since
            MOID and UUID are unique identifiers, they are tried first. If they are not set, a search by name is tried
            which may give one or more vms.
            This also supports the 'name_match' parameter and the 'use_instance_uuid' parameters. The VM identification
            parameter keys can be changed if your module uses different keys, like vm_name instead of just name
            Args:
                name_param: Set the parameter key that corredsponds to the VM name
                uuid_param: Set the parameter key that corredsponds to the VM UUID
                moid_param: Set the parameter key that corredsponds to the VM MOID
                name_match_param: Set the parameter key that corredsponds to the name_match option
                use_instance_uuid_param: Set the parameter key that corredsponds use_instance_uuid option
                fail_on_missing: If true, an error will be thrown if no VMs are found
                folder_param: Set the parameter key that corresponds to the folder that contains the VM
            Returns:
                list(vm). In most cases a list of length 1 but when searching by name, you can get multiple matches.
        """
        _search_type, _search_id = self.__determine_search_param_type_and_id(
            name_param=name_param, uuid_param=uuid_param, moid_param=moid_param, fail_on_missing=fail_on_missing
        )
        if not _search_type:
            return []

        if _search_type == 'uuid':
            vms = [self.si.content.searchIndex.FindByUuid(
                instanceUuid=self.params.get(use_instance_uuid_param, True), uuid=self.params.get(_search_id), vmSearch=True
            )]

        else:
            folder = None
            if self.params.get(folder_param):
                if self.params.get('folder_paths_are_absolute'):
                    _fq_path = self.params.get(folder_param)
                else:
                    _fq_path = format_folder_path_as_vm_fq_path(self.params.get(folder_param), self.params.get('datacenter'))
                folder = self.get_folder_by_absolute_path(_fq_path, fail_on_missing=fail_on_missing)
            vms = self.get_objs_by_name_or_moid([vim.VirtualMachine], self.params.get(_search_id), return_all=True, search_root_folder=folder)

        if vms and _search_type == 'name' and self.params.get(name_match_param):
            if self.params.get(name_match_param) == 'first':
                return [vms[0]]
            elif self.params.get(name_match_param) == 'last':
                return [vms[-1]]
            else:
                self.module.fail_json(msg="Unrecognized name_match option '%s' " % self.params.get(name_match_param))

        if not vms and fail_on_missing:
            self.module.fail_json(msg="Unable to find VM with %s %s" % (_search_id, self.params.get(_search_id)))

        return vms

    def __determine_search_param_type_and_id(self, name_param, uuid_param, moid_param, fail_on_missing):
        """
        Helper function for get_vms_using_params. Tries to determine which of the VM identifying parameters should be
        used to search for matching VMs. Optionally throws an error if none of the params are valid.
        Returns:
          str, str: The type of identifier that was selected, and the parameter name for that identifier
        """
        if self.params.get(moid_param):
            return 'moid', moid_param
        elif self.params.get(uuid_param):
            return 'uuid', uuid_param
        elif self.params.get(name_param):
            return 'name', name_param

        if fail_on_missing:
            self.module.fail_json(msg=(
                "Could not find any supported VM identifier params (%s, %s, or %s)" %
                (name_param, uuid_param, moid_param)
            ))

        return None, None

    def get_folders_by_name_or_moid(self, identifier, fail_on_missing=False):
        """
            Get all folders with the given name or MOID. Names are not unique
            in a given cluster, so multiple folder objects can be returned
            Args:
                identifier: Name or MOID of the folder to search for
                fail_on_missing: If true, an error will be thrown if no folders are found
            Returns:
                list(folder object) or None
        """
        folder = self.get_objs_by_name_or_moid([vim.Folder], identifier, return_all=True)
        if not folder and fail_on_missing:
            self.module.fail_json(msg="Unable to find folder with name or MOID %s" % identifier)
        return folder

    def get_folder_by_absolute_path(self, folder_path, fail_on_missing=False):
        """
            Get a folder with the given path. Paths are unique when they are absolute so only
            one folder can be returned at most. An absolute path might look like
            'Datacenter Name/vm/my/folder/structure'
            Args:
                folder_path: The absolute path to a folder to search for
                fail_on_missing: If true, an error will be thrown if no folders are found
            Returns:
                folder object or None
        """
        folder = self.si.content.searchIndex.FindByInventoryPath(folder_path)

        if not folder and fail_on_missing:
            self.module.fail_json(msg="Unable to find folder with absolute path %s" % folder_path)
        return folder

    def get_datastore_by_name_or_moid(self, identifier, fail_on_missing=False):
        """
            Get the datastore matching the given name or MOID. Datastore names must be unique
            in a given cluster, so only one object is returned at most.
            Args:
                identifier: Name or MOID of the datastore to search for
                fail_on_missing: If true, an error will be thrown if no datastores are found
            Returns:
                datastore object or None
        """
        ds = self.get_objs_by_name_or_moid([vim.Datastore], identifier)
        if ds:
            return ds[0]
        if fail_on_missing:
            self.module.fail_json(msg="Unable to find datastore with name or MOID %s" % identifier)
        return None

    def get_datastore_cluster_by_name_or_moid(self, identifier, fail_on_missing=False, datacenter=None):
        """
            Get the datastore cluster matching the given name or MOID. Datastore cluster names must
            be unique in a given datacenter, so only one object is returned at most.
            Args:
                identifier: Name or MOID of the datastore cluster to search for
                fail_on_missing: If true, an error will be thrown if no clusters are found
                datacenter: The datacenter object to use as a filter when searching for clusters. If
                            not provided then all datacenters will be examined
            Returns:
                datastore cluster object or None

        """
        search_folder = None
        if datacenter and hasattr(datacenter, 'datastoreFolder'):
            search_folder = datacenter.datastoreFolder

        data_store_cluster = self.get_objs_by_name_or_moid(
            [vim.StoragePod],
            identifier,
            return_all=False,
            search_root_folder=search_folder
        )

        if data_store_cluster:
            return data_store_cluster[0]
        if fail_on_missing:
            self.module.fail_json(msg="Unable to find datastore cluster with name or MOID %s" % identifier)

        return None

    def get_resource_pool_by_name_or_moid(self, identifier, fail_on_missing=False):
        """
            Get the resource pool matching the given name or MOID. Pool names must be unique
            in a given cluster, so only one object is returned at most.
            Args:
                identifier: Name or MOID of the pool to search for
                fail_on_missing: If true, an error will be thrown if no pools are found
            Returns:
                resource pool object or None
        """
        pool = self.get_objs_by_name_or_moid([vim.ResourcePool], identifier)
        if pool:
            return pool[0]
        if fail_on_missing:
            self.module.fail_json(msg="Unable to find resource pool with name %s" % identifier)
        return None

    def get_all_vms(self, folder=None, recurse=True):
        """
            Get all virtual machines in a folder. Can recurse through folder tree if needed. If no folder
            is provided, then the datacenter root folder is used
            Args:
                folder: vim.Folder, the folder object to use as a base for the search. If
                        none is provided, the datacenter root will be used
                recurse: If true, the search will recurse through the folder structure
            Returns:
                list of vim.VirtualMachine
        """
        return self.get_all_objs_by_type([vim.VirtualMachine], folder=folder, recurse=recurse)

    def get_datacenter_by_name_or_moid(self, identifier, fail_on_missing=False):
        """
            Get the datacenter matching the given name or MOID. Datacenter names must be unique
            in a given vcenter, so only one object is returned at most.
            Args:
                identifier: Name or MOID of the datacenter to search for
                fail_on_missing: If true, an error will be thrown if no datacenters are found
            Returns:
                datacenter object or None
        """
        ds = self.get_objs_by_name_or_moid([vim.Datacenter], identifier)
        if ds:
            return ds[0]
        if fail_on_missing:
            self.module.fail_json(msg="Unable to find datacenter with name or MOID %s" % identifier)
        return None

    def get_cluster_by_name_or_moid(self, identifier, fail_on_missing=False, datacenter=None):
        """
            Get the cluster matching the given name or MOID. Cluster names must be unique
            in a given vcenter, so only one object is returned at most.
            Args:
                identifier: Name or MOID of the cluster to search for
                fail_on_missing: If true, an error will be thrown if no clusters are found
                datacenter: The datacenter object to use as a filter when searching for clusters. If
                            not provided then all datacenters will be examined
            Returns:
                cluster object or None
        """
        search_folder = None
        if datacenter and hasattr(datacenter, 'hostFolder'):
            search_folder = datacenter.hostFolder

        cluster = self.get_objs_by_name_or_moid(
            [vim.ClusterComputeResource],
            identifier,
            return_all=False,
            search_root_folder=search_folder
        )
        if cluster:
            return cluster[0]

        if fail_on_missing:
            self.module.fail_json(msg="Unable to find cluster with name or MOID %s" % identifier)

        return None

    def get_esxi_host_by_name_or_moid(self, identifier, fail_on_missing=False):
        """
            Get the ESXi host matching the given name or MOID. ESXi names must be unique in a
            vCenter, so at most one host is returned.
            Args:
                identifier: Name or MOID of the ESXi host to search for
                fail_on_missing: If true, an error will be thrown if no hosts are found
            Returns:
                esxi host object or None
        """
        esxi_host = self.get_objs_by_name_or_moid(
            [vim.HostSystem],
            identifier,
            return_all=False,
        )
        if esxi_host:
            return esxi_host[0]
        if fail_on_missing:
            self.module.fail_json(msg="Unable to find ESXi host with name or MOID %s" % identifier)

        return None

    def get_datastore_with_max_free_space(self, datastores):
        """
            Returns the datasotre object with the maximum amount of freespace from a list of datastores.
            Args:
                datastores: list of datastore managed objects

            Returns:
                Datastore object

        """
        datastore = None
        datastore_freespace = 0
        for ds in datastores:
            try:
                if ds.summary.freeSpace > datastore_freespace:
                    if ds.summary.maintenanceMode == 'normal' and ds.summary.accessible:
                        datastore = ds
                        datastore_freespace = ds.summary.freeSpace
            except AttributeError:
                continue

        return datastore
