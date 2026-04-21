try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit


logger = Log()


class VSPCmdDevProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_CMD_DEV
        )
        self.vol_gw = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )
        self.connection_info = connection_info
        self.serial = serial
        if serial:
            self.gateway.set_serial(serial)

    @log_entry_exit
    def get_ldev_by_id(self, ldev_id):
        """Get LDEV by ID"""
        ldev = self.vol_gw.get_volume_by_id(ldev_id)
        logger.writeDebug(f"PROV:get_volume_by_id:ldev: {ldev}")
        return ldev

    @log_entry_exit
    def create_command_device(self, spec):
        """Create Command Device"""
        self.gateway.create_command_device(spec)
        return spec

    @log_entry_exit
    def delete_command_device(self, ldev_id):
        """Delete Command Device"""
        self.gateway.delete_command_device(ldev_id)
        return ldev_id

    @log_entry_exit
    def is_pegasus(self):
        return self.gateway.is_pegasus()
