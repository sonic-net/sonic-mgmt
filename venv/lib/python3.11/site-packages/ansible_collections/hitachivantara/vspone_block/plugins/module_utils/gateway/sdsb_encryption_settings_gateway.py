try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.sdsb_encryption_key_models import (
        EncryptionKeyResponse,
    )
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

GET_ENCRYPTION_ENVIRONMENT_SETTINGS = "v1/objects/encryption-settings"
UPDATE_ENCRYPTION_ENVIRONMENT_SETTINGS = "v1/objects/encryption-settings"

logger = Log()


class SDSBEncryptionSettingsGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_encryption_environment_settings(self):
        end_point = GET_ENCRYPTION_ENVIRONMENT_SETTINGS
        environment_settings = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_encryption_environment_settings:data={}", environment_settings
        )

        return EncryptionKeyResponse(**environment_settings)

    @log_entry_exit
    def update_encryption_settings(self, settings_spec):
        end_point = UPDATE_ENCRYPTION_ENVIRONMENT_SETTINGS
        logger.writeDebug("GW:update_encryption_settings:spec={}", settings_spec)

        payload = {}
        if settings_spec.is_encryption_enabled is not None:
            payload["isEnabled"] = settings_spec.is_encryption_enabled

        logger.writeDebug("GW:update_encryption_settings:payload={}", payload)
        response = self.connection_manager.patch(end_point, payload)
        logger.writeDebug("GW:update_encryption_settings:response={}", response)

        return response
