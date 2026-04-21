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

GET_SOFTWARE_UPDATE_FILE = "v1/objects/storage/software-update-file"
STOP_UPDATING_STORAGE_SOFTWARE = (
    "v1/objects/storage/actions/stop-software-update/invoke"
)
UPDATE_OR_DOWNGRADE_SOFTWARE = "v1/objects/storage/actions/update-software/invoke"
UPLOAD_SOFTWARE_UPDATE_FILE = (
    "v1/objects/storage/actions/upload-software-update-file/invoke"
)

logger = Log()


class SDSBSoftwareUpdateGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_software_update_file(self):

        end_point = GET_SOFTWARE_UPDATE_FILE
        software_update = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_software_update_file:data={}", software_update)

        converted = convert_keys_to_snake_case(software_update)
        logger.writeDebug("GW:get_software_update_file:converted={}", converted)
        return converted

    @log_entry_exit
    def stop_updating_storage_software(self):
        end_point = STOP_UPDATING_STORAGE_SOFTWARE
        resp = self.connection_manager.post(end_point, data=None)
        logger.writeDebug(f"GW:stop_updating_storage_software:resp={resp}")
        return resp

    @log_entry_exit
    def downgrade_storage_software(self):
        end_point = UPDATE_OR_DOWNGRADE_SOFTWARE
        payload = {
            "mode": "Non-disruptive",
            "downgrade": True,
        }
        resp = self.connection_manager.post(end_point, data=payload, long_running=True)
        logger.writeDebug(f"GW:downgrade_storage_software:resp={resp}")
        return resp

    @log_entry_exit
    def update_storage_software(self):
        end_point = UPDATE_OR_DOWNGRADE_SOFTWARE
        payload = {
            "mode": "Non-disruptive",
        }
        resp = self.connection_manager.post(end_point, data=payload, long_running=True)
        logger.writeDebug(f"GW:update_storage_software:resp={resp}")
        return resp

    @log_entry_exit
    def upload_software_update_file(self, software_update_file):
        end_point = UPLOAD_SOFTWARE_UPDATE_FILE
        resp = self.connection_manager.upload_software_update_file(
            end_point, software_update_file
        )
        logger.writeDebug(f"GW:upload_software_update_file:resp={resp}")
        return
