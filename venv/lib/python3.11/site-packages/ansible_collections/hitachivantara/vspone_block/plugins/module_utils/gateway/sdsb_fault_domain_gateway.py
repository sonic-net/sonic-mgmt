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


class SDSBBlockFaultDomainDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_fault_domains(self, spec=None):

        end_point = SDSBlockEndpoints.GET_FAULT_DOMAINS

        if spec is not None:
            if spec.id:
                end_point = SDSBlockEndpoints.GET_FAULT_DOMAINS_ID.format(spec.id)
                logger.writeDebug("GW:get_drives:end_point={}", end_point)

        fault_domain = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_drives:data={}", fault_domain)

        converted = convert_keys_to_snake_case(fault_domain)
        return converted
