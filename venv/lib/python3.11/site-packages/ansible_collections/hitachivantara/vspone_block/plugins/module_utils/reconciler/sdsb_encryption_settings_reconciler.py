try:
    from ..provisioner.sdsb_encryption_settings_provisioner import (
        SDSBEncryptionSettingsProvisioner,
    )
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import StateValue

except ImportError:
    from provisioner.sdsb_encryption_settings_provisioner import (
        SDSBEncryptionSettingsProvisioner,
    )
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.hv_constants import StateValue

logger = Log()


class SDSBEncryptionSettingsReconciler:

    def __init__(self, connection_info):
        self.provisioner = SDSBEncryptionSettingsProvisioner(connection_info)
        self.connection_info = connection_info

    @log_entry_exit
    def reconcile(self, state: str, spec):
        logger.writeDebug("RC:reconcile:state={}, spec={}", state, spec)

        if state == StateValue.PRESENT:
            return self._handle_update_encryption_settings(spec)
        raise Exception(f"Unsupported state: {state}")

    def _handle_update_encryption_settings(self, spec):
        current_settings = self.provisioner.get_encryption_environment_settings()
        desired_state = spec.is_encryption_enabled
        current_state = current_settings.isEnabled

        if current_state != desired_state:
            response = self.provisioner.update_encryption_settings(spec)
            self.connection_info.changed = True
            return response
        else:
            self.connection_info.changed = False
            return current_settings.camel_to_snake_dict()

    @log_entry_exit
    def get_encryption_environment_settings(self):
        logger.writeDebug("RC:get_encryption_environment_settings")
        return (
            self.provisioner.get_encryption_environment_settings().camel_to_snake_dict()
        )
