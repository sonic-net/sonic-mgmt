try:
    from ..provisioner.sdsb_encryption_key_provisioner import (
        SDSBEncryptionKeyProvisioner,
    )
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import StateValue

except ImportError:
    from provisioner.sdsb_encryption_key_provisioner import SDSBEncryptionKeyProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.hv_constants import StateValue

logger = Log()


class SDSBEncryptionKeyReconciler:

    def __init__(self, connection_info):
        self.provisioner = SDSBEncryptionKeyProvisioner(connection_info)
        self.connection_info = connection_info

    @log_entry_exit
    def reconcile(self, state: str, spec):
        logger.writeDebug("RC:reconcile:state={}, spec={}", state, spec)

        state_handlers = {
            StateValue.PRESENT: self._handle_create_encryption_key,
            StateValue.ABSENT: self._handle_delete_encryption_key,
        }

        handler = state_handlers.get(state)
        if handler:
            return handler(spec)
        raise Exception(f"Unsupported state: {state}")

    def _handle_create_encryption_key(self, spec):
        try:
            en_keys_before = self.get_encryption_keys()
            id_set_before = {item["id"] for item in en_keys_before}
            response = self.provisioner.create_encryption_key(spec)
            self.connection_info.changed = True
            if response != "encryption-keys":
                return "Some thing went wrong, please check the log file."
            else:
                en_keys_after = self.get_encryption_keys()
                id_set_after = {item["id"] for item in en_keys_after}
                new_id_set = id_set_after - id_set_before
                return self.get_encryption_keys_for_a_set(new_id_set)
        except Exception as e:
            return f"Could not create Encryption key. Cause = {str(e)}"

    def get_encryption_keys_for_a_set(self, id_set):
        ret_list = []
        for item in id_set:
            en_key = self.get_encryption_key(item)
            ret_list.append(en_key)
        return ret_list

    def _handle_delete_encryption_key(self, spec):
        try:
            self.provisioner.get_encryption_key(spec.id)
            self.provisioner.delete_encryption_key(spec.id)
            self.connection_info.changed = True
            return f"Encryption key {spec.id} deleted successfully."
        except Exception as e:
            if "404" in str(e) or "Not Found" in str(e):
                self.connection_info.changed = False
                return f"Encryption key {spec.id} does not exist."

    @log_entry_exit
    def get_encryption_keys(self):
        logger.writeDebug("RC:get_encryption_keys")
        return self.provisioner.get_encryption_keys()

    @log_entry_exit
    def get_encryption_keys_facts(self, spec):
        return self.provisioner.get_encryption_keys_facts(spec)

    @log_entry_exit
    def get_encryption_key(self, key_id):
        logger.writeDebug("RC:get_encryption_key:key_id={}", key_id)
        return self.provisioner.get_encryption_key(key_id)

    @log_entry_exit
    def get_encryption_key_count(self):
        logger.writeDebug("RC:get_encryption_key_count")
        return self.provisioner.get_encryption_key_count()

    @log_entry_exit
    def get_encryption_environment_settings(self):
        logger.writeDebug("RC:get_encryption_environment_settings")
        return self.provisioner.get_encryption_environment_settings()

    @log_entry_exit
    def update_encryption_settings(self, settings_spec):
        logger.writeDebug("RC:update_encryption_settings:spec={}", settings_spec)

        # Check current settings for idempotency
        current_settings = self.provisioner.get_encryption_environment_settings()
        logger.writeDebug("RC:update_encryption_settings:current={}", current_settings)

        # Check if already in desired state
        if current_settings.get("is_enabled") == settings_spec.is_encryption_enabled:
            logger.writeDebug("RC:update_encryption_settings:already_in_desired_state")
            self.connection_info.changed = False
            return current_settings

        # Update settings
        response = self.provisioner.update_encryption_settings(settings_spec)
        self.connection_info.changed = True
        return response
