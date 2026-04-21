try:

    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_storage_system_models import (
        VSPChannelBoardInfoList,
        VSPAlertInfoList,
    )
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.vsp_storage_system_models import (
        VSPChannelBoardInfoList,
        VSPAlertInfoList,
    )
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway


GET_CHANNEL_BOARDS = "v1/objects/channel-boards"
GET_ALERTS = "v1/objects/alerts{}"
GET_HW_INSTALLED = "v1/objects/components/instance"
GET_HW_INSTALLED_WITH_CLASS = "v1/objects/components/instance?componentOption=class"

logger = Log()


class VSPStorageSystemMonitorGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.address = connection_info.address
        self.connection_info = connection_info

    @log_entry_exit
    def set_storage_serial_number(self, serial=None):
        if serial:
            self.serial = serial
            logger.writeDebug(f"GW:set_serial={self.serial}")

    @log_entry_exit
    def get_channel_boards(self):
        end_point = GET_CHANNEL_BOARDS
        c_boards = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_channel_boards:channel_boards={}",
            c_boards,
        )
        result = VSPChannelBoardInfoList().dump_to_object(c_boards)
        return result

    @log_entry_exit
    def get_alerts(self, alert_type, start=None, count=None):
        q_params = f"?type={alert_type}"
        if start:
            q_params = q_params + f"&start={start}"
        if count:
            q_params = q_params + f"&count={count}"
        end_point = GET_ALERTS.format(q_params)
        alerts = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_alerts:alerts={}",
            alerts,
        )
        result = VSPAlertInfoList().dump_to_object(alerts)
        return result

    @log_entry_exit
    def is_pegasus(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        return storage_gw.is_pegasus()

    @log_entry_exit
    def get_hw_installed(self, component_option=False):
        end_point = GET_HW_INSTALLED
        hw_installed = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_hw_installed:hw_installed={}",
            hw_installed,
        )
        result = hw_installed
        if self.is_pegasus():
            return result
        else:
            if component_option is True:
                end_point = GET_HW_INSTALLED_WITH_CLASS
                hw_installed = self.connection_manager.get(end_point)
                logger.writeDebug(
                    "GW:get_hw_installed_with_class:hw_installed={}",
                    hw_installed,
                )
                result = result | hw_installed
            return result
