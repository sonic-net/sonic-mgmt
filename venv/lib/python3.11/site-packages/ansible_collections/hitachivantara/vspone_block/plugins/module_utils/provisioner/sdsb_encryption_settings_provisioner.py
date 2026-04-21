try:
    from ..gateway.sdsb_encryption_settings_gateway import SDSBEncryptionSettingsGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.sdsb_encryption_settings_gateway import SDSBEncryptionSettingsGateway
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBEncryptionSettingsProvisioner:

    def __init__(self, connection_info):
        self.gateway = SDSBEncryptionSettingsGateway(connection_info)

    @log_entry_exit
    def get_encryption_environment_settings(self):
        logger.writeDebug("PR:get_encryption_environment_settings")
        return self.gateway.get_encryption_environment_settings()

    @log_entry_exit
    def update_encryption_settings(self, settings_spec):
        logger.writeDebug("PR:update_encryption_settings:spec={}", settings_spec)
        self.gateway.update_encryption_settings(settings_spec)
        return self.gateway.get_encryption_environment_settings().camel_to_snake_dict()
