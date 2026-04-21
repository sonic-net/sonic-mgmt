"""
VM placement service for managing vSphere resource allocation.

This module provides the VmPlacement service, which handles the resolution and
caching of vSphere infrastructure objects needed for VM placement, such as
datacenters, clusters, hosts, datastores, and folders.
"""

from ansible_collections.vmware.vmware.plugins.module_utils._folder_paths import (
    format_folder_path_as_vm_fq_path,
)
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils.vm.services._abstract import (
    AbstractService,
)


def vm_placement_argument_spec(omit_params=None):
    """
    Generate argument specification for VM placement parameters.

    This function provides the standard set of parameters used for VM placement
    modules. It can optionally omit specific parameters when they are not
    needed for certain modules.

    Args:
        omit_params (list): List of parameter names to exclude from the specification

    Returns:
        dict: Ansible argument specification dictionary for VM placement parameters

    Example:
        Basic usage includes all placement parameters:
        vm_placement_argument_spec() -> includes folder, cluster, esxi_host, etc.

        Omitting specific parameters:
        vm_placement_argument_spec(['folder', 'cluster']) -> excludes folder and cluster
    """
    if omit_params is None:
        omit_params = []

    arg_spec = dict(
        folder=dict(type="str", required=False, aliases=["vm_folder"]),
        cluster=dict(type="str", required=False, aliases=["cluster_name"]),
        esxi_host=dict(type="str", required=False),
        resource_pool=dict(type="str", required=False),
        datacenter=dict(type="str", required=False, aliases=["datacenter_name"]),
        datastore=dict(type="str", required=False),
        datastore_cluster=dict(type="str", required=False),
        folder_paths_are_absolute=dict(type='bool', required=False, default=False),
    )
    for param in omit_params:
        if param in arg_spec:
            del arg_spec[param]

    return arg_spec


class VmPlacement(ModulePyvmomiBase, AbstractService):
    """
    Service for resolving and caching vSphere placement objects.

    This service handles the resolution of vSphere infrastructure objects
    needed for VM placement operations. It caches resolved objects to avoid
    redundant API calls and provides consistent access to placement resources.

    The service supports automatic selection of resources when alternatives
    are provided (e.g., datastore cluster -> specific datastore) and handles
    the complex relationships between vSphere objects.

    Cached objects include:
    - Datacenter: The vSphere datacenter containing the VM
    - Folder: The VM folder for organization
    - Datastore: The storage location for VM files. Can be derived from a specific datastore or a datastore cluster.
    - Resource Pool: The resource allocation pool
    - ESXi Host: The specific host for VM placement
    """

    def __init__(self, module):
        """
        Initialize the VM placement service.

        Args:
            module: Ansible module instance for parameter access and vSphere connectivity
        """
        ModulePyvmomiBase.__init__(self, module)
        self._datacenter = None
        self._folder = None
        self._datastore = None
        self._resource_pool = None
        self._esxi_host = None

    def get_datacenter(self, param="datacenter"):
        """
        Get the target datacenter for VM placement.

        Resolves and caches the datacenter object based on the module parameter.
        The datacenter serves as the root container for all other placement objects.

        Args:
            param (str): Name of the module parameter containing datacenter name/MOID

        Returns:
            vSphere datacenter object

        Side Effects:
            Caches the resolved datacenter in self._datacenter
        """
        if self._datacenter:
            return self._datacenter

        self._datacenter = self.get_datacenter_by_name_or_moid(
            self.params[param], fail_on_missing=True
        )
        return self._datacenter

    def get_datastore(
        self, datastore_param="datastore", datastore_cluster_param="datastore_cluster"
    ):
        """
        Get the target datastore for VM placement.

        Resolves and caches the datastore object. Can resolve from either a
        specific datastore name or automatically select from a datastore cluster
        based on available free space.

        Args:
            datastore_param (str): Name of the parameter containing datastore name/MOID
            datastore_cluster_param (str): Name of the parameter containing datastore cluster name/MOID

        Returns:
            vSphere datastore object or None if no datastore parameters provided

        Side Effects:
            Caches the resolved datastore in self._datastore.
            If using datastore cluster, selects datastore with maximum free space.
        """
        if self._datastore:
            return self._datastore

        if self.params.get(datastore_param):
            self._datastore = self.get_datastore_by_name_or_moid(
                self.params[datastore_param],
                fail_on_missing=True,
            )
        elif self.params.get(datastore_cluster_param):
            dsc = self.get_datastore_cluster_by_name_or_moid(
                self.params[datastore_cluster_param],
                fail_on_missing=True,
                datacenter=self.get_datacenter(),
            )
            datastore = self.get_datastore_with_max_free_space(dsc.childEntity)
            self._datastore = datastore

        return self._datastore

    def get_resource_pool(
        self, resource_pool_param="resource_pool", cluster_param="cluster"
    ):
        """
        Get the target resource pool for VM placement.

        Resolves and caches the resource pool object. Can resolve from either
        a specific resource pool name or use the default resource pool from
        a cluster.

        Args:
            resource_pool_param (str): Name of the parameter containing resource pool name/MOID
            cluster_param (str): Name of the parameter containing cluster name/MOID

        Returns:
            vSphere resource pool object or None if no resource pool parameters provided

        Side Effects:
            Caches the resolved resource pool in self._resource_pool.
            If using cluster, automatically uses the cluster's default resource pool.
        """
        if self._resource_pool:
            return self._resource_pool

        if self.params.get(resource_pool_param):
            self._resource_pool = self.get_resource_pool_by_name_or_moid(
                self.params[resource_pool_param], fail_on_missing=True
            )
        elif self.params.get(cluster_param):
            cluster = self.get_cluster_by_name_or_moid(
                self.params[cluster_param],
                fail_on_missing=True,
                datacenter=self.get_datacenter(),
            )
            self._resource_pool = cluster.resourcePool

        return self._resource_pool

    def get_folder(self, folder_param="folder", datacenter_param="datacenter", folder_paths_are_absolute_param="folder_paths_are_absolute"):
        """
        Get the target folder for VM placement.

        Resolves and caches the folder object for VM organization. If no folder
        is specified, uses the default VM folder in the datacenter.

        Args:
            folder_param (str): Name of the parameter containing folder path
            datacenter_param (str): Name of the parameter containing datacenter name

        Returns:
            vSphere folder object

        Side Effects:
            Caches the resolved folder in self._folder.
            Formats folder path as fully qualified VM path.
        """
        if self._folder:
            return self._folder
        if not self.params.get(folder_param):
            fq_folder = format_folder_path_as_vm_fq_path(
                "", self.params[datacenter_param]
            )
        elif self.params.get(folder_paths_are_absolute_param):
            fq_folder = self.params.get(folder_param)
        else:
            fq_folder = format_folder_path_as_vm_fq_path(
                self.params.get(folder_param), self.params[datacenter_param]
            )

        self._folder = self.get_folder_by_absolute_path(fq_folder, fail_on_missing=True)
        return self._folder

    def get_esxi_host(self, param="esxi_host"):
        """
        Get the target ESXi host for VM placement.

        Resolves and caches the ESXi host object for specific host placement.
        This is optional - VMs can be placed without specifying a specific host.

        Args:
            param (str): Name of the parameter containing ESXi host name/MOID

        Returns:
            vSphere ESXi host object or None if no host specified

        Side Effects:
            Caches the resolved host in self._esxi_host
        """
        if self._esxi_host or self.params[param] is None:
            return self._esxi_host

        self._esxi_host = self.get_esxi_host_by_name_or_moid(
            self.params[param], fail_on_missing=True
        )
        return self._esxi_host
