try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.sdsb_storage_pool_models import (
        SDSBStoragePoolInfo,
        SDSBStoragePoolInfoList,
    )
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.sdsb_storage_pool_models import (
        SDSBStoragePoolInfo,
        SDSBStoragePoolInfoList,
    )

EXPAND_STORAGE_POOL = "v1/objects/pools/{}/actions/expand/invoke"
GET_STORAGE_POOLS = "v1/objects/pools"
GET_STORAGE_POOLS_QUERY = "v1/objects/pools{}"
GET_STORAGE_POOLBY_NAME = "v1/objects/pools?name={}"
GET_STORAGE_POOL_BY_ID = "v1/objects/pools/{}"
EDIT_STORAGE_POOL_SETTINGS = "v1/objects/pools/{}"
UPDATE_STORAGE_POOL_ENCRYPTION = "v1/objects/encryption-units/pools/{}"

logger = Log()


class SDSBStoragePoolDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_storage_pools(self, names=None):
        end_point = GET_STORAGE_POOLS
        if names is not None and len(names) != 0:
            if len(names) == 1:
                query = f"?name={names[0]}"
            else:
                query = f"?names={','.join(names)}"

            end_point = GET_STORAGE_POOLS_QUERY.format(query)

        storage_pool_data = self.connection_manager.get(end_point)

        return SDSBStoragePoolInfoList(
            dicts_to_dataclass_list(storage_pool_data["data"], SDSBStoragePoolInfo)
        )

    @log_entry_exit
    def get_pools(self):
        end_point = GET_STORAGE_POOLS
        pool_data = self.connection_manager.get(end_point)
        return SDSBStoragePoolInfoList(
            dicts_to_dataclass_list(pool_data["data"], SDSBStoragePoolInfo)
        )

    @log_entry_exit
    def get_pool_by_name(self, name):
        end_point = GET_STORAGE_POOLBY_NAME.format(name)
        data = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_pool_by_name:data={} len={}", data, len(data.get("data"))
        )
        if data is not None and len(data.get("data")) > 0:
            return SDSBStoragePoolInfo(**data.get("data")[0])
        else:
            return None

    @log_entry_exit
    def get_storage_pool_by_id(self, id):
        end_point = GET_STORAGE_POOL_BY_ID.format(id)
        storage_pool_data = self.connection_manager.get(end_point)
        return SDSBStoragePoolInfo(**storage_pool_data)

    @log_entry_exit
    def expand_storage_pool(self, id, drive_ids):

        end_point = EXPAND_STORAGE_POOL.format(id)
        payload = {"driveIds": drive_ids}
        storage_pool = self.connection_manager.post(end_point, payload)
        return storage_pool

    @log_entry_exit
    def edit_storage_pool_settings(
        self, id, rebuild_capacity_policy, number_of_tolerable_drive_failures
    ):

        end_point = EDIT_STORAGE_POOL_SETTINGS.format(id)
        if rebuild_capacity_policy == "Variable":
            payload = {"rebuildCapacityPolicy": rebuild_capacity_policy}
        else:
            payload = {
                "rebuildCapacityPolicy": rebuild_capacity_policy,
                "rebuildCapacityResourceSetting": {
                    "numberOfTolerableDriveFailures": number_of_tolerable_drive_failures
                },
            }
        storage_pool = self.connection_manager.patch(end_point, payload)
        return storage_pool

    @log_entry_exit
    def update_storage_pool_encryption(self, id, is_encryption_enabled):
        end_point = UPDATE_STORAGE_POOL_ENCRYPTION.format(id)
        payload = {"isEncryptionEnabled": is_encryption_enabled}
        logger.writeDebug(
            "GW:update_storage_pool_encryption:endpoint={}, payload={}",
            end_point,
            payload,
        )
        storage_pool = self.connection_manager.patch(end_point, payload)
        return storage_pool
