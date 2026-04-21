try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
    )
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
    )

logger = Log()


class VSPStorageSystemMonitorProvisioner:

    def __init__(self, connection_info, serial):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_STORAGE_MONITOR
        )
        self.connection_info = connection_info
        self.serial = serial
        if self.serial is None:
            self.serial = self.get_storage_serial_number()
        self.gateway.set_storage_serial_number(serial)

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def get_channel_boards(self):
        resp = self.gateway.get_channel_boards()
        return resp

    @log_entry_exit
    def is_pegasus(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        return storage_gw.is_pegasus()

    @log_entry_exit
    def get_alerts(self, spec):
        resp = self.gateway.get_alerts(
            spec.alert_type, spec.alert_start_number, spec.alert_count
        )
        return resp

    @log_entry_exit
    def get_hw_installed(self, spec):
        resp = self.gateway.get_hw_installed(spec.include_component_option)
        return resp
