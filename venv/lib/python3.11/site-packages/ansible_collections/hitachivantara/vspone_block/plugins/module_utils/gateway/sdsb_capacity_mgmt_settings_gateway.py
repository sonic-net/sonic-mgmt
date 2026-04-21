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

GET_CAPACITY_SETTINGS = "v1/objects/capacity-settings"
GET_CAPACITY_SETTINGS_QUERY = "v1/objects/capacity-settings?storageControllerId={}"

GET_STORAGE_CONTROLLER_BY_ID = "v1/objects/storage-controllers/{}"
UPDATE_STORAGE_CONTROLLERS_SETTINGS = (
    "v1/objects/storage-controllers/actions/configure/invoke"
)

logger = Log()


class SDSBCapacityMgmtSettingGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_capacity_management_settings(self, storage_controller_id=None):

        end_point = GET_CAPACITY_SETTINGS

        if storage_controller_id:
            end_point = GET_CAPACITY_SETTINGS_QUERY.format(storage_controller_id)
            logger.writeDebug(
                "GW:get_capacity_management_settings:end_point={}", end_point
            )

        response = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_capacity_management_settings:response={}", response)

        converted = convert_keys_to_snake_case(response)
        logger.writeDebug("GW:get_capacity_management_settings:converted={}", converted)
        return converted
