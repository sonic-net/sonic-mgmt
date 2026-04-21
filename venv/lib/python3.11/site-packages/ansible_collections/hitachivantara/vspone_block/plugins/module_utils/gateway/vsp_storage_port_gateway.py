try:
    from ..common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.vsp_storage_port_models import (
        PortInfo,
        ShortPortInfo,
        ShortPortInfoList,
        PingInfo,
    )
    from ..common.vsp_constants import VSPPortSetting
except ImportError:
    from common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.vsp_storage_port_models import (
        PortInfo,
        ShortPortInfo,
        ShortPortInfoList,
        PingInfo,
    )
    from common.vsp_constants import VSPPortSetting

logger = Log()


class VSPStoragePortDirectGateway:

    def __init__(self, connection_info):
        self.connectionManager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.serial = None

    @log_entry_exit
    def set_serial(self, serial):
        self.serial = serial

    @log_entry_exit
    def get_all_storage_ports(self):
        endPoint = Endpoints.GET_PORTS_DETAILS
        portsInfo = self.connectionManager.get(endPoint)
        return ShortPortInfoList(
            dicts_to_dataclass_list(portsInfo["data"], ShortPortInfo)
        )

    @log_entry_exit
    def get_single_storage_port(self, port_id: str) -> PortInfo:
        endPoint = Endpoints.GET_ONE_PORT_WITH_MODE.format(port_id)
        portInfo = self.connectionManager.get(endPoint)
        return PortInfo(**portInfo)

    @log_entry_exit
    def sending_ping_command_to_host(self, port: str, host_ip: str):
        endPoint = Endpoints.SEND_PING_COMMAND.format(port)

        data = {
            "parameters": {
                VSPPortSetting.HOST_IP_ADDRESS: host_ip,
            }
        }
        ping_response = self.connectionManager.post_without_job(endPoint, data)
        return PingInfo(**ping_response)

    @log_entry_exit
    def change_port_settings(self, spec) -> None:
        endPoint = Endpoints.UPDATE_PORT.format(spec.port)
        data = {}
        if spec.port_attribute is not None:
            data[VSPPortSetting.PORT_ATTRIBUTE] = spec.port_attribute
        if spec.port_mode is not None:
            data[VSPPortSetting.PORT_MODE] = spec.port_mode
        if spec.port_speed is not None:
            data[VSPPortSetting.PORT_SPEED] = spec.port_speed
        if spec.fabric_mode is not None:
            data[VSPPortSetting.FABRIC_MODE] = spec.fabric_mode
        if spec.port_connection is not None:
            data[VSPPortSetting.PORT_CONNECTION] = spec.port_connection
        if spec.enable_port_security is not None:
            data[VSPPortSetting.LUN_SECURITY_SETTING] = spec.enable_port_security
        return self.connectionManager.patch(endPoint, data)
