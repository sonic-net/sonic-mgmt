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


class SDSBClusterInformationProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_CLUSTER_INFORMATION
        )

    @log_entry_exit
    def get_storage_time_settings(self):
        settings = self.gateway.get_storage_time_settings()
        return settings

    @log_entry_exit
    def get_storage_network_settings(self):
        settings = self.gateway.get_storage_network_settings()
        return settings

    @log_entry_exit
    def get_protection_domain_settings(self):
        settings = self.gateway.get_protection_domain_settings()
        return settings

    @log_entry_exit
    def get_protection_domain_by_id(self, id):
        try:
            pd = self.gateway.get_protection_domain_by_id(id)
            return pd
        except Exception as e:
            logger.writeException(e)
            return {}
