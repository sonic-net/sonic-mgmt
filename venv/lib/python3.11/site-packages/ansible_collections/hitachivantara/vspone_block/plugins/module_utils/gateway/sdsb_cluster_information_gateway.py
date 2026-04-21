try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_utils import convert_keys_to_snake_case, replace_nulls

except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.sdsb_utils import convert_keys_to_snake_case, replace_nulls

GET_PROTECTION_DOMAIN_BY_ID = "v1/objects/protection-domains/{}"
logger = Log()


class SDSBBlockClusterInformationDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_storage_time_settings(self):

        end_point = SDSBlockEndpoints.GET_STORAGE_TIME_SETTINGS

        time = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_storage_time_settings:data={}", time)

        converted = convert_keys_to_snake_case(time)
        return converted

    @log_entry_exit
    def get_storage_network_settings(self):

        end_point = SDSBlockEndpoints.GET_STORAGE_NETWORK_SETTING

        settings = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_storage_network_settings:data={}", settings)

        converted = convert_keys_to_snake_case(settings)
        return converted

    @log_entry_exit
    def get_protection_domain_settings(self):

        end_point = SDSBlockEndpoints.GET_PROCTECTION_DOMAINS

        settings = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_protection_domain_settings:data={}", settings)

        converted = convert_keys_to_snake_case(settings)
        return converted

    @log_entry_exit
    def get_protection_domain_by_id(self, id):
        end_point = GET_PROTECTION_DOMAIN_BY_ID.format(id)
        response = self.connection_manager.get(end_point)
        converted = convert_keys_to_snake_case(response)
        logger.writeDebug(
            f"GW:get_protection_domain_by_id:response = {response} converted = {converted}"
        )
        return replace_nulls(converted)
