"""
Service for looking up and caching objects from vSphere.

This service is used to look up objects from vSphere so other modules can use them.
Unlike the placement service, this service does is not aware of parameters and has a less specific use case.
Objects are cached based on the identifier used to look them up, and the MOID (if it is different from the identifier).
"""

from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils.vm.services._abstract import (
    AbstractService,
)


class VsphereObjectCache(ModulePyvmomiBase, AbstractService):
    """
    Service for looking up and caching objects from vSphere.

    This service is used to look up objects from vSphere so other modules can use them.
    Unlike the placement service, this service does is not aware of parameters and has a less specific use case.
    Objects are cached based on the name and MOID of the object.
    """

    def __init__(self, module):
        """
        Initialize the service.

        Args:
            module: Ansible module instance for parameter access and vSphere connectivity
        """
        ModulePyvmomiBase.__init__(self, module)
        self._cache = {}

    def _cache_object(self, object_to_cache, cache_keys=None):
        if cache_keys is None:
            cache_keys = [object_to_cache.name, object_to_cache._GetMoId()]

        for key in cache_keys:
            self._cache[key] = object_to_cache

    def get_portgroup(self, portgroup_identifier):
        """
        Get the target portgroup for VM placement.

        Resolves and caches the portgroup object for VM placement.
        """
        if portgroup_identifier in self._cache:
            return self._cache[portgroup_identifier]

        # dvs portgroups are technically standard portgroups, so we need to check for dvs first and
        # then fallback to standard portgroups
        portgroup = self.get_dvs_portgroup_by_name_or_moid(
            portgroup_identifier, fail_on_missing=False
        )
        if not portgroup:
            portgroup = self.get_standard_portgroup_by_name_or_moid(
                portgroup_identifier, fail_on_missing=True
            )

        self._cache_object(portgroup)

        return portgroup

    def get_datastore(self, datastore_identifier):
        """
        Get the target datastore based on the name or MOID. If this is a datastore cluster,
        the datastore with the most free space will be returned.

        Resolves and caches the datastore object for VM or disk placement.
        """
        if datastore_identifier in self._cache:
            return self._cache[datastore_identifier]

        # Check if this is a DS cluster first
        datastore_cluster = self.get_datastore_cluster_by_name_or_moid(
            datastore_identifier, fail_on_missing=False
        )
        if datastore_cluster is not None:
            # look up the datastore with the most free space in the cluster. Cache it under the cluster's name/ID
            datastore = self.get_datastore_with_max_free_space(
                datastore_cluster.childEntity
            )
            self._cache_object(
                datastore,
                cache_keys=[datastore_cluster._GetMoId(), datastore_cluster.name],
            )

        else:
            datastore = self.get_datastore_by_name_or_moid(
                datastore_identifier, fail_on_missing=True
            )

        self._cache_object(datastore)
        return datastore
