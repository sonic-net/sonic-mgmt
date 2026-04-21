try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log

logger = Log()


class SDSBStoragePoolProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_STORAGE_POOL
        )

    @log_entry_exit
    def expand_storage_pool(self, id, drive_ids):
        return self.gateway.expand_storage_pool(id, drive_ids)

    @log_entry_exit
    def edit_storage_pool_settings(
        self, id, rebuild_capacity_policy, number_of_tolerable_drive_failures
    ):
        return self.gateway.edit_storage_pool_settings(
            id, rebuild_capacity_policy, number_of_tolerable_drive_failures
        )

    @log_entry_exit
    def get_storage_pools(self, names=None):
        return self.gateway.get_storage_pools(names)

    @log_entry_exit
    def get_storage_pool_by_id(self, id):
        return self.gateway.get_storage_pool_by_id(id)

    @log_entry_exit
    def get_pool_by_name(self, name):
        return self.gateway.get_pool_by_name(name)

    @log_entry_exit
    def get_pool_id_by_pool_name(self, name):
        names = [name]
        storage_pool = self.gateway.get_storage_pools(names)
        logger.writeDebug("PV:get_pool_id_by_pool_name:storage_pool={}", storage_pool)
        if storage_pool is None or len(storage_pool.data) == 0:
            return None
        return storage_pool.data[0].id

    @log_entry_exit
    def get_pool_by_pool_name(self, name):
        names = [name]
        storage_pool = self.gateway.get_storage_pools(names)
        logger.writeDebug("PV:get_pool_id_by_pool_name:storage_pool={}", storage_pool)
        if storage_pool is None or len(storage_pool.data) == 0:
            return None
        return storage_pool.data[0]

    @log_entry_exit
    def update_storage_pool_encryption(self, id, is_encryption_enabled):
        response = self.gateway.update_storage_pool_encryption(
            id, is_encryption_enabled
        )
        # Handle dataclass object conversion if needed
        if hasattr(response, "camel_to_snake_dict"):
            return response.camel_to_snake_dict()
        return response
