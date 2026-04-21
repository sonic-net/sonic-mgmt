from dataclasses import asdict

try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..model.sdsb_storage_system_models import (
        SDSBHealthStatus,
        SDSBStorageSystemInfo,
        SDSBPfrestSavingEffectOfStorage,
    )
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from model.sdsb_storage_system_models import (
        SDSBHealthStatus,
        SDSBStorageSystemInfo,
        SDSBPfrestSavingEffectOfStorage,
    )
    from common.ansible_common import log_entry_exit


class SDSBStorageSystemProvisioner:

    def __init__(self, connection_info):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_STORAGE_SYSTEM
        )

    def sdsb_convert_to_storage_system(self, storage_cluster, health_status):
        health_status_list = []
        for hs in health_status.resources:
            hs_obj = SDSBHealthStatus(**hs)
            if hs_obj.type is None:
                hs_obj.type = ""
            if hs_obj.status is None:
                hs_obj.status = ""
            if hs_obj.protectionDomainId is None:
                hs_obj.protectionDomainId = ""
            health_status_list.append(asdict(hs_obj))
        storage_system = {}
        storage_system["clusterId"] = storage_cluster.id
        storage_system["clusterName"] = storage_cluster.nickname
        storage_system["healthStatuses"] = health_status_list
        storage_system["writeBackModeWithCacheProtection"] = (
            storage_cluster.writeBackModeWithCacheProtection
        )
        storage_system["numberOfTotalVolumes"] = (
            storage_cluster.numberOfTotalVolumes
            if storage_cluster.numberOfTotalVolumes is not None
            else -1
        )
        storage_system["numberOfTotalServers"] = (
            storage_cluster.numberOfTotalServers
            if storage_cluster.numberOfTotalServers is not None
            else -1
        )
        storage_system["numberOfTotalStorageNodes"] = (
            storage_cluster.numberOfReadyStorageNodes
            if storage_cluster.numberOfReadyStorageNodes is not None
            else -1
        )
        storage_system["numberOfFaultDomains"] = (
            storage_cluster.numberOfFaultDomains
            if storage_cluster.numberOfFaultDomains is not None
            else -1
        )
        storage_system["totalPoolCapacityInMb"] = (
            storage_cluster.totalPoolCapacity
            if storage_cluster.totalPoolCapacity is not None
            else -1
        )
        storage_system["usedPoolCapacityInMb"] = (
            storage_cluster.usedPoolCapacity
            if storage_cluster.usedPoolCapacity is not None
            else -1
        )
        storage_system["freePoolCapacityInMb"] = (
            storage_cluster.freePoolCapacity
            if storage_cluster.freePoolCapacity is not None
            else -1
        )
        tmp_saving_effects = SDSBPfrestSavingEffectOfStorage(
            **storage_cluster.savingEffects
        )
        storage_system["totalEfficiency"] = (
            tmp_saving_effects.totalEfficiency
            if tmp_saving_effects.totalEfficiency is not None
            else -1
        )
        storage_system["efficiencyDataReduction"] = (
            tmp_saving_effects.efficiencyDataReduction
            if tmp_saving_effects.efficiencyDataReduction is not None
            else -1
        )
        return storage_system

    @log_entry_exit
    def sdsb_get_storage_system(self):
        # Get storage cluster info
        storage_cluster = self.gateway.sdsb_get_storage_cluster_info()
        # Get health status
        health_status = self.gateway.sdsb_get_health_status()
        # Get drives
        drives = self.gateway.sdsb_get_drives_info()
        # Get ports
        ports = self.gateway.sdsb_get_ports()
        # Get pools
        pools = self.gateway.sdsb_get_pools()
        storage_system = self.sdsb_convert_to_storage_system(
            storage_cluster, health_status
        )
        version_info = self.gateway.sdsb_get_version()
        storage_system["numberOfDrives"] = len(drives.data)
        storage_system["numberOfComputePorts"] = len(ports.data)
        storage_system["numberOfStoragePools"] = len(pools.data)
        storage_system["apiVersion"] = version_info.get("apiVersion", None)
        storage_system["productName"] = version_info.get("productName", None)
        return SDSBStorageSystemInfo(**storage_system)
