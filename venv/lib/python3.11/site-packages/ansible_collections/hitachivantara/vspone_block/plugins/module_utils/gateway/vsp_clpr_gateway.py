try:
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_clpr_models import (
        ClprInfo,
        ClprInfoList,
    )
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..common.hv_log import Log
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_clpr_models import (
        ClprInfo,
        ClprInfoList,
    )
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from common.hv_log import Log
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway

GET_CLPRS = "v1/objects/clprs"
GET_ONE_CLPR = "v1/objects/clprs/{}"
UPDATE_CLPR = "v1/objects/clprs/{}"
ASSIGN_LDEV = "v1/objects/ldevs/{}/actions/assign-clpr/invoke"
ASSIGN_PARITY = "v1/objects/parity-groups/{}/actions/assign-clpr/invoke"
GET_STORAGES_DIRECT = "v1/objects/storages"

logger = Log()


class VSPClprDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.serial = None

    @log_entry_exit
    def set_storage_serial_number(self, serial: str):
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.get_storage_serial()

    @log_entry_exit
    def get_storage_serial(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def get_all_clprs(self, spec):
        response = self.connection_manager.get(GET_CLPRS)
        logger.writeDebug(f"GW:get_local_copy_groups:response={response}")
        clpr_list = ClprInfoList(dicts_to_dataclass_list(response["data"], ClprInfo))
        return clpr_list

    @log_entry_exit
    def get_one_clpr_by_id(self, clpr_id: str):
        end_point = GET_ONE_CLPR.format(clpr_id)
        logger.writeDebug(f"GW:get_one_clpr_by_id:end_point={end_point}")
        if clpr_id is None:
            return None
        response = self.connection_manager.get(end_point)
        logger.writeDebug(f"GW:get_one_clpr_by_id:response={response}")

        return ClprInfo(**response)

    @log_entry_exit
    def create_clpr(self, spec):
        """Create a new CLPR"""
        payload = {
            "clprName": spec.clpr_name,
            "cacheMemoryCapacity": spec.cache_memory_capacity_mb,
        }
        response = self.connection_manager.post(GET_CLPRS, payload)
        logger.writeDebug("GW:create_clpr:response={}", response)
        if response:
            return response
        return None

    @log_entry_exit
    def update_clpr(self, spec):
        """Update CLPR configuration"""
        end_point = UPDATE_CLPR.format(spec.clpr_id)
        payload = {
            "clprName": spec.clpr_name,
            "cacheMemoryCapacity": spec.cache_memory_capacity_mb,
        }
        response = self.connection_manager.patch(end_point, payload)
        logger.writeDebug("GW:update_clpr:response={}", response)
        if response:
            return response
        return None

    @log_entry_exit
    def delete_clpr(self, spec):
        """Delete a CLPR"""
        end_point = GET_ONE_CLPR.format(spec.clpr_id)
        response = self.connection_manager.delete(end_point)
        logger.writeDebug("GW:delete_clpr:response={}", response)
        return response
