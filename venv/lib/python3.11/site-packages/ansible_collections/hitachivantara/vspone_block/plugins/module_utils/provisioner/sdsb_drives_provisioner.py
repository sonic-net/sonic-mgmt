try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log

logger = Log()


class SDSBBlockDrivesProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_BLOCK_DRIVES
        )

    @log_entry_exit
    def get_drives(self, spec=None):
        drives = self.gateway.get_drives(spec)
        return drives

    @log_entry_exit
    def get_drive_by_id(self, id):
        try:
            drive = self.gateway.get_drive_by_id(id)
            return drive
        except Exception as e:
            logger.writeException(e)
            return None

    @log_entry_exit
    def remove_drive(self, id):
        try:
            drive = self.gateway.remove_drive(id)
            return drive
        except Exception as e:
            logger.writeException(e)
            return None

    @log_entry_exit
    def control_locator_led(self, id, turn_on=False):
        try:
            drive = self.gateway.control_locator_led(id, turn_on)
            return drive
        except Exception as e:
            logger.writeException(e)
            return None
