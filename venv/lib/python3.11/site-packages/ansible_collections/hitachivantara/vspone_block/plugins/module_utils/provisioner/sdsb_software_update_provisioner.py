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


class SDSBSoftwareUpdateProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_SOFTWARE_UPDATE
        )

    @log_entry_exit
    def get_software_update_file(self):
        software_update = self.gateway.get_software_update_file()
        return software_update

    @log_entry_exit
    def stop_updating_storage_software(self):
        return self.gateway.stop_updating_storage_software()

    @log_entry_exit
    def downgrade_storage_software(self):
        return self.gateway.downgrade_storage_software()

    @log_entry_exit
    def update_storage_software(self):
        return self.gateway.update_storage_software()

    @log_entry_exit
    def upload_software_update_file(self, software_update_file):
        return self.gateway.upload_software_update_file(software_update_file)
