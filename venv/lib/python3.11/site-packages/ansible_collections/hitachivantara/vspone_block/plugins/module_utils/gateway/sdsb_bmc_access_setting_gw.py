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

GET_BMC_SETTING_FOR_STORAGE_NODES = "v1/objects/storage-node-bmc-access-settings"
GET_BMC_SETTING_FOR_ONE_STORAGE_NODE = "v1/objects/storage-node-bmc-access-settings/{}"
EDIT_BMC_SETTING_FOR_ONE_STORAGE_NODE = "v1/objects/storage-node-bmc-access-settings/{}"

logger = Log()


class SDSBBlockBmcAccessSettingGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_bmc_settings_for_all_storage_nodes(self):

        end_point = GET_BMC_SETTING_FOR_STORAGE_NODES
        bmc_settings = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_bmc_settings:data={}", bmc_settings)

        converted = convert_keys_to_snake_case(bmc_settings)
        return converted

    @log_entry_exit
    def get_bmc_settings_for_one_storage_node(self, id):
        end_point = GET_BMC_SETTING_FOR_ONE_STORAGE_NODE.format(id)
        logger.writeDebug(
            "GW:get_bmc_settings_for_all_storage_nodes:end_point={}", end_point
        )
        bmc_settings = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_bmc_settings:data={}", bmc_settings)

        converted = convert_keys_to_snake_case(bmc_settings)
        return converted

    @log_entry_exit
    def update_bmc_settings(self, id, bmc_name=None, bmc_user=None, bmc_password=None):
        end_point = EDIT_BMC_SETTING_FOR_ONE_STORAGE_NODE.format(id)
        logger.writeDebug(
            "GW:get_bmc_settings_for_all_storage_nodes:end_point={}", end_point
        )
        payload = {}
        if bmc_name:
            payload["bmcName"] = bmc_name
        if bmc_user:
            payload["bmcUser"] = bmc_user
        if bmc_password:
            payload["bmcPassword"] = bmc_password
        bmc_settings = self.connection_manager.patch(end_point, data=payload)
        logger.writeDebug("GW:get_bmc_settings:data={}", bmc_settings)

        converted = convert_keys_to_snake_case(bmc_settings)
        return converted
