try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBStorageNodeProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_STORAGE_NODE
        )

    @log_entry_exit
    def get_storage_nodes(self, spec=None):
        if spec is None:
            return self.gateway.get_storage_nodes()
        else:
            if spec.id:
                storage_node = self.get_storage_node_by_id(spec.id)
                return storage_node
            return self.gateway.get_storage_nodes(
                spec.fault_domain_id,
                spec.name,
                spec.cluster_role,
                spec.protection_domain_id,
            )

    @log_entry_exit
    def get_storage_node_by_id(self, id):
        try:
            return self.gateway.get_storage_node_by_id(id)
        except Exception as ex:
            logger.writeError("PV:get_storage_node_by_id:Exception={}", ex)
            return None

    @log_entry_exit
    def get_node_id_by_node_name(self, name):
        storage_node = self.gateway.get_storage_nodes(name=name)
        logger.writeDebug("PV:get_node_id_by_node_name:storage_node={}", storage_node)
        if storage_node is None or len(storage_node.data) == 0:
            return None
        return storage_node.data[0].id

    @log_entry_exit
    def block_node_for_maintenance(self, id):
        return self.gateway.block_node_for_maintenance(id)

    @log_entry_exit
    def restore_from_maintenance(self, id):
        return self.gateway.restore_from_maintenance(id)

    @log_entry_exit
    def edit_capacity_management_settings(self, id, is_capacity_balancing_enabled):
        return self.gateway.edit_capacity_settings_of_a_storage_node(
            id, is_capacity_balancing_enabled
        )
