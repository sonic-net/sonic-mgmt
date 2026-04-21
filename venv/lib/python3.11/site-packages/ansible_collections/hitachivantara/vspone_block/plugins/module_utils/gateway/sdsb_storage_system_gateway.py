try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..model.sdsb_storage_system_models import (
        SDSBPfrestStorageClusterInfo,
        SDSBPfrestHealthStatus,
        SDSBPfrestDriveList,
        SDSBPfrestDrive,
        SDSBPfrestPortList,
        SDSBPfrestPort,
        SDSBPfrestPoolList,
        SDSBPfrestPool,
    )
    from .gateway_manager import SDSBConnectionManager
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common import dicts_to_dataclass_list
    from model.sdsb_storage_system_models import (
        SDSBPfrestStorageClusterInfo,
        SDSBPfrestHealthStatus,
        SDSBPfrestDriveList,
        SDSBPfrestDrive,
        SDSBPfrestPortList,
        SDSBPfrestPort,
        SDSBPfrestPoolList,
        SDSBPfrestPool,
    )
    from .gateway_manager import SDSBConnectionManager
    from common.ansible_common import log_entry_exit

GET_VERSION = "configuration/version"


class SDSBStorageSystemDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def sdsb_get_storage_cluster_info(self):
        endPoint = SDSBlockEndpoints.GET_STORAGE_CLUSTER
        storage_cluster_info = self.connection_manager.get(endPoint)
        return SDSBPfrestStorageClusterInfo(**storage_cluster_info)

    @log_entry_exit
    def sdsb_get_health_status(self):
        # logger = Log()
        endPoint = SDSBlockEndpoints.GET_HEALTH_STATUS
        health_status = self.connection_manager.get(endPoint)
        return SDSBPfrestHealthStatus(**health_status)

    @log_entry_exit
    def sdsb_get_drives_info(self):
        endPoint = SDSBlockEndpoints.GET_DRIVES
        drives = self.connection_manager.get(endPoint)
        return SDSBPfrestDriveList(
            dicts_to_dataclass_list(drives["data"], SDSBPfrestDrive)
        )

    @log_entry_exit
    def sdsb_get_ports(self):
        endPoint = SDSBlockEndpoints.GET_PORTS
        ports = self.connection_manager.get(endPoint)
        return SDSBPfrestPortList(
            dicts_to_dataclass_list(ports["data"], SDSBPfrestPort)
        )

    @log_entry_exit
    def sdsb_get_pools(self):
        endPoint = SDSBlockEndpoints.GET_POOLS
        pools = self.connection_manager.get(endPoint)
        return SDSBPfrestPoolList(
            dicts_to_dataclass_list(pools["data"], SDSBPfrestPool)
        )

    @log_entry_exit
    def sdsb_get_version(self):
        endPoint = GET_VERSION
        response = self.connection_manager.get(endPoint)
        return response
