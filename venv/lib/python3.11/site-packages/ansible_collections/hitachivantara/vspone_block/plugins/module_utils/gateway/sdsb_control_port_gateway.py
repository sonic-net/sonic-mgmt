try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_utils import convert_keys_to_snake_case

except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.sdsb_utils import convert_keys_to_snake_case

logger = Log()


class SDSBBlockControlPortDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_control_ports(self, spec=None):

        end_point = SDSBlockEndpoints.GET_CONTROL_PORTS

        if spec is not None:
            if spec.id:
                end_point = SDSBlockEndpoints.GET_CONTROL_PORTS_ID.format(spec.id)
                logger.writeDebug("GW:get_internode_ports:end_point={}", end_point)

        control_ports = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_control_ports:data={}", control_ports)

        converted = convert_keys_to_snake_case(control_ports)
        return converted

    @log_entry_exit
    def get_internode_ports(self, spec=None):

        end_point = SDSBlockEndpoints.GET_INTERNODE_PORTS

        if spec is not None:
            if spec.id:
                end_point = SDSBlockEndpoints.GET_INTERNODE_PORTS_ID.format(spec.id)
                logger.writeDebug("GW:get_internode_ports:end_point={}", end_point)

        internode_ports = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_internode_ports:data={}", internode_ports)

        converted = convert_keys_to_snake_case(internode_ports)
        return converted

    @log_entry_exit
    def get_storage_node_network_settings(self, spec=None):

        end_point = SDSBlockEndpoints.GET_STORAGE_NODE_NETWORK_SETTINGS

        if spec is not None:
            if spec.id:
                end_point = (
                    SDSBlockEndpoints.GET_STORAGE_NODE_NETWORK_SETTINGS_ID.format(
                        spec.id
                    )
                )
                logger.writeDebug(
                    "GW:get_storage_node_network_settings:end_point={}", end_point
                )

        settings = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_storage_node_network_settings:data={}", settings)

        converted = convert_keys_to_snake_case(settings)
        return converted
