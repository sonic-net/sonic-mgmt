# Copyright: (c) 2024, Ansible Cloud Team
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

try:
    from com.vmware.vapi.std_client import DynamicID
    from com.vmware.vcenter_client import (
        Folder,
        Datacenter,
        ResourcePool,
        VM,
        Cluster,
        Host,
        VM
    )
except ImportError:
    pass
    # handled in base class

from ansible_collections.vmware.vmware.plugins.module_utils.clients.rest import VmwareRestClient


class ModuleRestBase(VmwareRestClient):
    def __init__(self, module):
        super().__init__(**module.params)
        self.module = module
        self.params = module.params

    def get_vm_by_name(self, name):
        """
        Returns a VM object that matches the given name.

        Args:
            name (str): The name of VM to look for

        Returns:
            list(str): VM object matching the name provided. Returns None if no
            matches are found
        """
        vms = self.api_client.vcenter.VM.list(
            VM.FilterSpec(names=set([name]))
        )

        if len(vms) == 0:
            return None

        return vms[0]

    def get_content_library_ids(self, name=None, library_type=None, fail_on_missing=False):
        """
        Get all content library IDs. You can optionally provide a name or type to refine the search
        Args:
            name: str, The name of the library to search for. If None, no names are
                  filtered out of the search
            library_type: com.vmware.content_client.LibraryModel.LibraryType or None,
                          The type of library to search for. If None, all types are included
            fail_on_missing: If true, an error will be thrown if no libraries are found
        Returns:
            list(str), list of library IDs
        """
        if name or library_type:
            find_spec = self.library_service.FindSpec(name=name, type=library_type)
            item_ids = self.library_service.find(spec=find_spec)
            if not item_ids and fail_on_missing:
                self.module.fail_json(
                    "Unable to find library with search parameters"
                    "name %s and type %s" % (name or "'any'", library_type or "'any'")
                )
        else:
            item_ids = self.library_service.list()

        return item_ids

    def get_library_item_ids(self, name=None, library_id=None, fail_on_missing=False):
        """
        Get all content library item IDs. You can optionally provide a name or library ID
        to refine the search
        Args:
            name: str, The name of the library to search for. If None, no names are
                  filtered out of the search
            library_id: str, The ID of library to search inside. If None, all libraries are included
            fail_on_missing: If true, an error will be thrown if no items are found
        Returns:
            list(str), list of library item IDs
        """
        if name or library_id:
            find_spec = self.library_item_service.FindSpec(name=name, library_id=library_id)
            item_ids = self.library_item_service.find(spec=find_spec)
            if not item_ids and fail_on_missing:
                self.module.fail_json(
                    "Unable to find library items with search parameters"
                    "name %s and library ID %s" % (name or "'any'", library_id or "'any'")
                )
        else:
            item_ids = self.library_item_service.list()
        return item_ids

    def get_datacenter_by_name(self, datacenter_name):
        """
        Returns the identifier of a datacenter
        Note: The method assumes only one datacenter with the mentioned name.
        """
        if datacenter_name is None:
            return None

        filter_spec = Datacenter.FilterSpec(names=set([datacenter_name]))
        datacenter_summaries = self.api_client.vcenter.Datacenter.list(filter_spec)
        return datacenter_summaries[0].datacenter if len(datacenter_summaries) > 0 else None

    def get_datacenters_set_by_name(self, datacenter_name):
        datacenter = self.get_datacenter_by_name(datacenter_name)
        return set([datacenter]) if datacenter else set()

    def get_folder_by_name(self, folder_name, datacenter_name=None):
        """
        Returns the identifier of a folder
        with the mentioned names.
        """
        if folder_name is None:
            return None
        datacenters = self.get_datacenters_set_by_name(datacenter_name)
        filter_spec = Folder.FilterSpec(type=Folder.Type.VIRTUAL_MACHINE,
                                        names=set([folder_name]),
                                        datacenters=datacenters)
        folder_summaries = self.api_client.vcenter.Folder.list(filter_spec)
        return folder_summaries[0].folder if len(folder_summaries) > 0 else None

    def get_resource_pool_by_name(self, resourcepool_name, datacenter_name=None, cluster_name=None, host_name=None):
        """
        Returns the identifier of a resource pool
        with the mentioned names.
        """
        datacenters = self.get_datacenters_set_by_name(datacenter_name)
        clusters = None
        if cluster_name:
            clusters = self.get_cluster_by_name(cluster_name, datacenter_name)
            if clusters:
                clusters = set([clusters])
        hosts = None
        if host_name:
            hosts = self.get_host_by_name(host_name, datacenter_name)
            if hosts:
                hosts = set([hosts])
        names = set([resourcepool_name]) if resourcepool_name else None
        filter_spec = ResourcePool.FilterSpec(datacenters=datacenters,
                                              names=names,
                                              clusters=clusters)
        resource_pool_summaries = self.api_client.vcenter.ResourcePool.list(filter_spec)
        resource_pool = resource_pool_summaries[0].resource_pool if len(resource_pool_summaries) > 0 else None
        return resource_pool

    def get_cluster_by_name(self, cluster_name, datacenter_name=None):
        """
        Returns the identifier of a cluster
        with the mentioned names.
        """
        datacenters = self.get_datacenters_set_by_name(datacenter_name)
        names = set([cluster_name]) if cluster_name else None
        filter_spec = Cluster.FilterSpec(datacenters=datacenters, names=names)
        cluster_summaries = self.api_client.vcenter.Cluster.list(filter_spec)
        return cluster_summaries[0].cluster if len(cluster_summaries) > 0 else None

    def get_host_by_name(self, host_name, datacenter_name=None):
        """
        Returns the identifier of a Host
        with the mentioned names.
        """
        datacenters = self.get_datacenters_set_by_name(datacenter_name)
        names = set([host_name]) if host_name else None
        filter_spec = Host.FilterSpec(datacenters=datacenters, names=names)
        host_summaries = self.api_client.vcenter.Host.list(filter_spec)
        return host_summaries[0].host if len(host_summaries) > 0 else None

    def get_vm_obj_by_name(self, vm_name, datacenter_name=None):
        """
        Returns the identifier of a VM with the mentioned names.
        """
        datacenters = self.get_datacenters_set_by_name(datacenter_name)
        names = set([vm_name]) if vm_name else None
        filter_spec = VM.FilterSpec(datacenters=datacenters, names=names)
        vm_summaries = self.api_client.vcenter.VM.list(filter_spec)
        return vm_summaries[0].vm if len(vm_summaries) > 0 else None

    def obj_to_dict(self, vmware_obj, r):
        """
        Transform VMware SDK object to dictionary.
        Args:
            vmware_obj: Object to transform.
            r: Dictionary to fill with object data.
        """
        for k, v in vars(vmware_obj).items():
            if not k.startswith('_'):
                if hasattr(v, '__dict__') and not isinstance(v, str):
                    self.obj_to_dict(v, r[k])
                elif isinstance(v, int):
                    r[k] = int(v)
                else:
                    r[k] = str(v)

    def get_category_by_name(self, category_name=None):
        """
        Return category object by name
        Args:
            category_name: Name of category

        Returns: Category object if found else None
        """
        if not category_name:
            return None

        return self.search_svc_object_by_name(service=self.api_client.tagging.Category, svc_obj_name=category_name)

    def get_tag_by_category_id(self, tag_name=None, category_id=None):
        """
        Return tag object by category id
        Args:
            tag_name: Name of tag
            category_id: Id of category
        Returns: Tag object if found else None
        """
        if tag_name is None:
            return None

        if category_id is None:
            return self.search_svc_object_by_name(service=self.api_client.tagging.Tag, svc_obj_name=tag_name)

        result = None
        for tag_id in self.api_client.tagging.Tag.list_tags_for_category(category_id):
            tag_obj = self.api_client.tagging.Tag.get(tag_id)
            if tag_obj.name == tag_name:
                result = tag_obj
                break

        return result

    def get_tag_by_category_name(self, tag_name=None, category_name=None):
        """
        Return tag object by category name
        Args:
            tag_name: Name of tag
            category_id: Id of category
        Returns: Tag object if found else None
        """
        category_id = None
        if category_name is not None:
            category_obj = self.get_category_by_name(category_name=category_name)
            if category_obj is not None:
                category_id = category_obj.id

        return self.get_tag_by_category_id(tag_name=tag_name, category_id=category_id)

    def obj_to_dict(self, vmware_obj, r):
        """
        Transform VMware SDK object to dictionary.
        Args:
            vmware_obj: Object to transform.
            r: Dictionary to fill with object data.
        """
        for k, v in vars(vmware_obj).items():
            if not k.startswith('_'):
                if hasattr(v, '__dict__') and not isinstance(v, str):
                    self.obj_to_dict(v, r[k])
                elif isinstance(v, int):
                    r[k] = int(v)
                else:
                    r[k] = str(v)

    def set_param(self, param, cmp_fn, set_fn):
        """
        Since most of the check is similar to do. This method implement
        generic call for most of the parameters. It checks if parameter
        specified is different to one which is currently set and if yes,
        it will update it.

        param: AnsibleModule parameter name
        cmp_fn: function that compares the parameter value to any API call
        set_fn: function that is called if the cmd_fn is true
        """
        generic_param = self.params.get(param)
        if generic_param is None:
            return

        if cmp_fn(generic_param):
            self.changed = True
            if not self.module.check_mode:
                set_fn(generic_param)
        self.info[param] = generic_param

    def get_tags_by_cluster_moid(self, cluster_moid):
        """
        Get a list of tag objects attached to a cluster
        Args:
            cluster_moid: the cluster MOID to use to gather tags

        Returns:
            List of tag object associated with the given cluster
        """
        dobj = DynamicID(type='ClusterComputeResource', id=cluster_moid)
        return self.get_tags_for_dynamic_id_obj(dobj=dobj)

    def format_tag_identity_as_dict(self, tag_obj):
        """
        Takes a tag object and outputs a dictionary with identifying details about the tag,
        including name, category, and ID
        Args:
            tag: VMWare Tag Object
        Returns:
            dict
        """
        category_service = self.api_client.tagging.Category
        return {
            'id': tag_obj.id,
            'category_name': category_service.get(tag_obj.category_id).name,
            'name': tag_obj.name,
            'description': tag_obj.description,
            'category_id': tag_obj.category_id,
        }
