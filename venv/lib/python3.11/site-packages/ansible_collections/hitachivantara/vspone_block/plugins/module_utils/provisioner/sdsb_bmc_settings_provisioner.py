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


class SDSBBmcSettingsProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_BMC_ACCESS_SETTING
        )

    @log_entry_exit
    def get_bmc_settings_for_all_storage_nodes(self):
        bmc_settings = self.gateway.get_bmc_settings_for_all_storage_nodes()
        result = bmc_settings.get("data", [])
        return result

    @log_entry_exit
    def get_bmc_settings_for_one_storage_node(self, id):
        try:
            result = self.gateway.get_bmc_settings_for_one_storage_node(id)
            return [result]
        except Exception as e:
            logger.writeException(e)
            return []

    @log_entry_exit
    def update_bmc_settings(self, id, bmc_name=None, bmc_user=None, bmc_password=None):
        return self.gateway.update_bmc_settings(id, bmc_name, bmc_user, bmc_password)
