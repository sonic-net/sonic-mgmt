try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_utils import convert_keys_to_snake_case

except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.sdsb_utils import convert_keys_to_snake_case

GET_ESTIMATED_CAPACITY_FOR_SPECIFIED_CONFIG = (
    "v1/objects/pools/{}/estimated-capacity-for-specified-configuration{}"
)
GET_ESTIMATED_CAPACITY_FOR_UPDATED_CONFIG = (
    "v1/objects/pools/{}/estimated-capacity-for-updated-configuration{}"
)

logger = Log()


class SDSBEstimatedCapacityGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_query_parameters(
        self,
        number_of_storage_nodes=None,
        number_of_drives=None,
        number_of_tolerable_drive_failures=None,
    ):
        params = {}
        if number_of_storage_nodes is not None:
            params["numberOfStorageNodes"] = number_of_storage_nodes
        if number_of_drives is not None:
            params["numberOfDrives"] = number_of_drives
        if number_of_tolerable_drive_failures is not None:
            params["numberOfTolerableDriveFailures"] = (
                number_of_tolerable_drive_failures
            )

        query = ""
        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            query = "?" + "&".join(query_parts)

        return query

    @log_entry_exit
    def get_estimated_capacity_for_specified_configuration(
        self,
        id,
        number_of_storage_nodes=None,
        number_of_drives=None,
        number_of_tolerable_drive_failures=None,
    ):
        query = self.get_query_parameters(
            number_of_storage_nodes,
            number_of_drives,
            number_of_tolerable_drive_failures,
        )
        end_point = GET_ESTIMATED_CAPACITY_FOR_SPECIFIED_CONFIG.format(id, query)
        logger.writeDebug(
            "GW:get_estimated_capacity_for_specified_configuration:end_point={}",
            end_point,
        )

        response = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_estimated_capacity_for_specified_configuration:response={}",
            response,
        )

        converted = convert_keys_to_snake_case(response)
        logger.writeDebug(
            "GW:get_estimated_capacity_for_specified_configuration:converted={}",
            converted,
        )
        return converted

    @log_entry_exit
    def get_estimated_capacity_for_updated_configuration(
        self,
        id,
        number_of_storage_nodes=None,
        number_of_drives=None,
        number_of_tolerable_drive_failures=None,
    ):
        query = self.get_query_parameters(
            number_of_storage_nodes,
            number_of_drives,
            number_of_tolerable_drive_failures,
        )
        end_point = GET_ESTIMATED_CAPACITY_FOR_UPDATED_CONFIG.format(id, query)
        logger.writeDebug(
            "GW:get_estimated_capacity_for_updated_configuration:end_point={}",
            end_point,
        )

        response = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_estimated_capacity_for_updated_configuration:response={}", response
        )

        converted = convert_keys_to_snake_case(response)
        logger.writeDebug(
            "GW:get_estimated_capacity_for_updated_configuration:converted={}",
            converted,
        )
        return converted
