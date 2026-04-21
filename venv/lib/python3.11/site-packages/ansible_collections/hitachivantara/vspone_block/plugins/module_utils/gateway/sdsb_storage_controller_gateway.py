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

GET_STORAGE_CONTROLLERS = "v1/objects/storage-controllers"
GET_STORAGE_CONTROLLER_BY_ID = "v1/objects/storage-controllers/{}"
UPDATE_STORAGE_CONTROLLERS_SETTINGS = (
    "v1/objects/storage-controllers/actions/configure/invoke"
)

logger = Log()


class SDSBStorageControllerDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_storage_controllers(self, spec=None):

        end_point = GET_STORAGE_CONTROLLERS

        if spec is not None:
            if spec.id:
                end_point = GET_STORAGE_CONTROLLER_BY_ID.format(spec.id)
                logger.writeDebug("GW:get_storage_controllers:end_point={}", end_point)

        storage_controller = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_storage_controllers:data={}", storage_controller)

        converted = convert_keys_to_snake_case(storage_controller)
        logger.writeDebug("GW:get_storage_controllers:converted={}", converted)
        return converted

    @log_entry_exit
    def get_storage_controller_by_id(self, id):
        end_point = GET_STORAGE_CONTROLLER_BY_ID.format(id)
        logger.writeDebug("GW:get_storage_controller_by_id:end_point={}", end_point)
        storage_controller = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_storage_controller_by_id:data={}", storage_controller)
        converted = convert_keys_to_snake_case(storage_controller)
        logger.writeDebug("GW:get_storage_controller_by_id:converted={}", converted)
        return converted

    @log_entry_exit
    def update_storage_controller_settings(
        self, id=None, is_detailed_logging_mode=None
    ):
        logger.writeDebug(
            f"GW:update_storage_controller_settings:id= {id} mode = {is_detailed_logging_mode}"
        )
        end_point = UPDATE_STORAGE_CONTROLLERS_SETTINGS
        params = {}
        if id:
            params["storageControllerId"] = id
        if is_detailed_logging_mode:
            params["isDetailedLoggingMode"] = True
        else:
            params["isDetailedLoggingMode"] = False
        resp = self.connection_manager.post(end_point, data=params)
        logger.writeDebug(f"GW:update_storage_controller_settings:resp={resp}")
        return resp
