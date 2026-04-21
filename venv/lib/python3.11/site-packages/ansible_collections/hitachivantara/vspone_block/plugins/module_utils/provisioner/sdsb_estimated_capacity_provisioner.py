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


class SDSBEstimatedCapacityProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_ESTIMATED_CAPACITY
        )

    @log_entry_exit
    def get_estimated_capacity_for_specified_configuration(self, spec=None):
        response = self.gateway.get_estimated_capacity_for_specified_configuration(
            spec.id,
            spec.number_of_storage_nodes,
            spec.number_of_drives,
            spec.number_of_tolerable_drive_failures,
        )
        return response

    @log_entry_exit
    def get_estimated_capacity_for_updated_configuration(self, spec=None):
        response = self.gateway.get_estimated_capacity_for_updated_configuration(
            spec.id,
            spec.number_of_storage_nodes,
            spec.number_of_drives,
            spec.number_of_tolerable_drive_failures,
        )
        return response
