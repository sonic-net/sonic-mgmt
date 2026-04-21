try:
    from ..common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.vsp_storage_pool_models import (
        VSPPfrestStoragePoolList,
        VSPPfrestStoragePool,
        VSPPfrestLdevList,
        VSPPfrestLdev,
        VSPPfrestStoragePoolExtendedList,
    )
    from ..common.uaig_constants import StoragePoolPayloadConst
    from ..common.hv_constants import PoolType

except ImportError:
    from common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.vsp_storage_pool_models import (
        VSPPfrestStoragePoolList,
        VSPPfrestStoragePool,
        VSPPfrestLdevList,
        VSPPfrestLdev,
        VSPPfrestStoragePoolExtendedList,
    )
    from common.uaig_constants import StoragePoolPayloadConst
    from common.hv_constants import PoolType


class VSPStoragePoolDirectGateway:

    def __init__(self, connection_info):
        self.connectionManager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )

    @log_entry_exit
    def get_all_storage_pools(self, extended_info=False):
        endPoint = Endpoints.GET_POOLS
        if extended_info:
            endPoint += "?detailInfoType=class"
        try:
            storagePoolsDict = self.connectionManager.get(endPoint)
            if extended_info:
                return VSPPfrestStoragePoolExtendedList().dump_to_object(
                    storagePoolsDict
                )
            return VSPPfrestStoragePoolList().dump_to_object(storagePoolsDict)
        except Exception as e:
            msg = "The specified value is not supported for the specified storage system. (parameter name = detailInfoType, specified value = class"
            if extended_info and msg in str(e):
                storagePoolsDict = self.connectionManager.get(Endpoints.GET_POOLS)
                return VSPPfrestStoragePoolList().dump_to_object(storagePoolsDict)
            raise e

    @log_entry_exit
    def get_storage_pool_by_id(self, pool_id):
        endPoint = Endpoints.GET_POOL.format(pool_id)
        try:
            poolDict = self.connectionManager.get(endPoint)
            return VSPPfrestStoragePool(**poolDict)
        except Exception as e:
            msg = "Specified object does not exist"
            if msg in str(e):
                return None
            raise e

    @log_entry_exit
    def get_ldevs(self, ldevs_query):
        endPoint = Endpoints.GET_LDEVS.format(ldevs_query)
        rest_dpvolumes = self.connectionManager.get(endPoint)
        return VSPPfrestLdevList(
            dicts_to_dataclass_list(rest_dpvolumes["data"], VSPPfrestLdev)
        )

    @log_entry_exit
    def create_storage_pool(self, spec):
        endPoint = Endpoints.POST_POOL
        payload = {}
        payload[StoragePoolPayloadConst.POOL_ID] = spec.pool_id
        payload[StoragePoolPayloadConst.POOL_NAME] = spec.name
        payload[StoragePoolPayloadConst.POOL_TYPE] = (
            PoolType.HDT if spec.type.upper() == PoolType.HRT else spec.type.upper()
        )

        if isinstance(spec.warning_threshold_rate, int):
            payload[StoragePoolPayloadConst.WARNING_THRESHOLD] = (
                spec.warning_threshold_rate
            )
            spec.warning_threshold_rate = None
        if isinstance(spec.depletion_threshold_rate, int):
            payload[StoragePoolPayloadConst.DEPLETION_THRESHOLD] = (
                spec.depletion_threshold_rate
            )
            spec.depletion_threshold_rate = None
        if spec.ldev_ids:
            payload[StoragePoolPayloadConst.LDEV_IDS] = spec.ldev_ids
        if spec.start_ldev_id:
            payload[StoragePoolPayloadConst.START_LDEV_ID] = spec.start_ldev_id
        if spec.end_ldev_id:
            payload[StoragePoolPayloadConst.END_LDEV_ID] = spec.end_ldev_id
        if spec.should_enable_deduplication:
            payload[StoragePoolPayloadConst.IS_ENABLE_DEDUPLICATION] = (
                spec.duplication_ldev_ids
            )

        url = self.connectionManager.post(endPoint, payload)
        pool_id = url.split("/")[-1]
        if spec.type.upper() == PoolType.HRT:
            spec.type = PoolType.RT
        else:
            spec.type = None
        try:
            spec.name = None  # reset name to None after creation
            self.change_storage_pool_settings(pool_id, spec)
        except Exception as e:
            self.delete_storage_pool(pool_id)
            raise e
        return pool_id

    @log_entry_exit
    def delete_storage_pool(self, pool_id):
        endPoint = Endpoints.GET_POOL.format(pool_id)
        return self.connectionManager.delete(endPoint)

    @log_entry_exit
    def update_storage_pool(self, pool_id, spec):
        endPoint = Endpoints.POOL_EXPAND.format(pool_id)
        payload = {
            StoragePoolPayloadConst.PARAMETERS: {
                StoragePoolPayloadConst.LDEV_IDS: spec.ldev_ids
            }
        }

        return self.connectionManager.post(endPoint, payload)

    @log_entry_exit
    def change_storage_pool_settings(self, pool_id, spec):
        endPoint = Endpoints.GET_POOL.format(pool_id)
        payload = {}
        # will add more parameters as needed

        if spec.name is not None:
            payload[StoragePoolPayloadConst.POOL_NAME] = spec.name
        if spec.type is not None:
            payload[StoragePoolPayloadConst.POOL_TYPE] = spec.type

        if spec.warning_threshold_rate is not None:
            payload[StoragePoolPayloadConst.WARNING_THRESHOLD] = (
                spec.warning_threshold_rate
            )
        if spec.depletion_threshold_rate is not None:
            payload[StoragePoolPayloadConst.DEPLETION_THRESHOLD] = (
                spec.depletion_threshold_rate
            )
        if spec.suspend_snapshot is not None:
            payload[StoragePoolPayloadConst.suspendSnapshot] = spec.suspend_snapshot
        if spec.virtual_volume_capacity_rate:
            payload[StoragePoolPayloadConst.virtualVolumeCapacityRate] = (
                spec.virtual_volume_capacity_rate
            )
        if spec.monitoring_mode is not None:
            payload[StoragePoolPayloadConst.monitoringMode] = spec.monitoring_mode

        if spec.blocking_mode is not None:
            payload[StoragePoolPayloadConst.blockingMode] = spec.blocking_mode

        if spec.tier is not None:
            payload[StoragePoolPayloadConst.tier] = {}
            payload[StoragePoolPayloadConst.tier][
                StoragePoolPayloadConst.tierNumber
            ] = spec.tier.tier_number
            payload[StoragePoolPayloadConst.tier][
                StoragePoolPayloadConst.tablespaceRate
            ] = spec.tier.table_space_rate
            payload[StoragePoolPayloadConst.tier][
                StoragePoolPayloadConst.bufferRate
            ] = spec.tier.buffer_rate

        if not payload:

            return False
        unused = self.connectionManager.patch(endPoint, payload)
        return True

    @log_entry_exit
    def perform_performance_monitor(self, pool_id, operation_type):
        payload = {
            StoragePoolPayloadConst.PARAMETERS: {
                StoragePoolPayloadConst.OPERATION_TYPE: operation_type
            },
        }
        endPoint = Endpoints.PERFORMANCE_MONITORING.format(pool_id)
        return self.connectionManager.post(endPoint, payload)

    @log_entry_exit
    def perform_tier_location(self, pool_id, operation_type):
        payload = {
            StoragePoolPayloadConst.PARAMETERS: {
                StoragePoolPayloadConst.OPERATION_TYPE: operation_type
            },
        }
        endPoint = Endpoints.TIER_LOCATION.format(pool_id)
        return self.connectionManager.post(endPoint, payload)

    @log_entry_exit
    def restore_storage_pool(self, pool_id):
        endPoint = Endpoints.RESTORE_POOL.format(pool_id)
        return self.connectionManager.post(endPoint, None)

    @log_entry_exit
    def initialize_capacity_savings(self, pool_id):
        endPoint = Endpoints.INITIALIZE_CAPACITY_SAVINGS.format(pool_id)
        return self.connectionManager.post(endPoint, None)
