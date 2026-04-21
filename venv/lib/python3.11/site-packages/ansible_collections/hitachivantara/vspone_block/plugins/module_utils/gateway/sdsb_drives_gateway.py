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

GET_DRIVES = "v1/objects/drives"
GET_DRIVE_BY_ID = "v1/objects/drives/{}"
CONTROL_LOCATOR_LED_DRIVE = "v1/objects/drives/{}/actions/control-locator-led/invoke"
REMOVE_DRIVE = "v1/objects/drives/{}/actions/remove/invoke"

logger = Log()


class SDSBBlockDrivesDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_drives(self, spec=None):
        end_point = GET_DRIVES

        # Build query based on provided parameters
        params = {}
        if spec.status_summary:
            params["statusSummary"] = spec.status_summary
        if spec.status:
            params["status"] = spec.status
        if spec.storage_node_id:
            params["storageNodeId"] = spec.storage_node_id
        if spec.locator_led_status:
            params["locatorLedStatus"] = spec.locator_led_status

        # Construct query string
        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            end_point = end_point + "?" + "&".join(query_parts)

        logger.writeDebug("GW:get_drives:end_point={}", end_point)
        drives = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_drives:data={}", drives)

        converted = convert_keys_to_snake_case(drives)
        return converted

    @log_entry_exit
    def get_drive_by_id(self, id):
        end_point = GET_DRIVE_BY_ID.format(id)
        response = self.connection_manager.get(end_point)
        converted = convert_keys_to_snake_case(response)
        logger.writeDebug(
            f"GW:get_drive_by_id:response = {response} converted = {converted}"
        )
        return converted

    @log_entry_exit
    def remove_drive(self, id):
        end_point = REMOVE_DRIVE.format(id)
        response = self.connection_manager.post(end_point, data=None)
        return response

    @log_entry_exit
    def control_locator_led(self, id, turn_on=False):
        end_point = CONTROL_LOCATOR_LED_DRIVE.format(id)
        operation_type = "TurnOff"
        if turn_on:
            operation_type = "TurnOn"
        payload = {"operationType": operation_type}
        response = self.connection_manager.post(end_point, data=payload)
        return response
