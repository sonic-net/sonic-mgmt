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


class SDSBCapacityManagementSettingsProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_CAPACITY_MGMT_SETTING
        )

    @log_entry_exit
    def get_capacity_management_settings(self, spec=None):
        storage_controller_id = None
        if spec and spec.storage_controller_id:
            storage_controller_id = spec.storage_controller_id
        response = self.gateway.get_capacity_management_settings(storage_controller_id)
        return response
