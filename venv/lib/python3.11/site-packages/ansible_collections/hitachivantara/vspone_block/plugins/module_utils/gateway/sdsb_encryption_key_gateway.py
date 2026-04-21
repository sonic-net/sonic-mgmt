try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit, dicts_to_dataclass_list
    from ..model.sdsb_encryption_key_models import (
        EncryptionKeyInfo,
        EncryptionKeyInfoList,
        EncryptionKeyResponse,
        EncryptionKeyInfoSpec,
    )

except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit, dicts_to_dataclass_list
    from model.sdsb_encryption_key_models import (
        EncryptionKeyInfo,
        EncryptionKeyInfoList,
        EncryptionKeyResponse,
        EncryptionKeyInfoSpec,
    )

GET_ENCRYPTION_KEYS = "v1/objects/encryption-keys"
GET_ENCRYPTION_KEY = "v1/objects/encryption-keys/{}"
GET_ENCRYPTION_KEY_COUNT = "v1/objects/encryption-key-counts"
GET_ENCRYPTION_ENVIRONMENT_SETTINGS = "v1/objects/encryption-settings"
UPDATE_ENCRYPTION_ENVIRONMENT_SETTINGS = "v1/objects/encryption-settings"
CREATE_ENCRYPTION_KEY = "v1/objects/encryption-keys"
DELETE_ENCRYPTION_KEY = "v1/objects/encryption-keys/{}"

logger = Log()


class SDSBEncryptionKeyGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_encryption_keys(self):
        end_point = GET_ENCRYPTION_KEYS
        encryption_keys = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_encryption_keys:data={}", encryption_keys)

        if encryption_keys.get("data"):
            return EncryptionKeyInfoList(
                dicts_to_dataclass_list(encryption_keys["data"], EncryptionKeyInfo)
            )
        return EncryptionKeyInfoList([])

    @log_entry_exit
    def get_encryption_keys_in_details(self, spec: EncryptionKeyInfoSpec = None):
        end_point = GET_ENCRYPTION_KEYS
        if spec is not None:
            query_params = spec.generate_request_params()
            if query_params:
                end_point += "?" + query_params
        encryption_keys = self.connection_manager.get(end_point)

        return EncryptionKeyInfoList().dump_to_object(encryption_keys)

    @log_entry_exit
    def get_encryption_key(self, key_id):
        end_point = GET_ENCRYPTION_KEY.format(key_id)
        logger.writeDebug("GW:get_encryption_key:end_point={}", end_point)
        encryption_key = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_encryption_key:data={}", encryption_key)

        return EncryptionKeyInfo(**encryption_key)

    @log_entry_exit
    def get_encryption_key_by_id(self, key_id):
        end_point = GET_ENCRYPTION_KEY.format(key_id)
        logger.writeDebug("GW:get_encryption_key:end_point={}", end_point)
        encryption_key = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_encryption_key:data={}", encryption_key)

        return EncryptionKeyInfo(**encryption_key)

    @log_entry_exit
    def get_encryption_key_count(self):
        end_point = GET_ENCRYPTION_KEY_COUNT
        encryption_key_count = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_encryption_key_count:data={}", encryption_key_count)

        return encryption_key_count

    @log_entry_exit
    def get_encryption_environment_settings(self):
        end_point = GET_ENCRYPTION_ENVIRONMENT_SETTINGS
        environment_settings = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_encryption_environment_settings:data={}", environment_settings
        )

        return EncryptionKeyResponse(**environment_settings)

    @log_entry_exit
    def create_encryption_key(self, key_spec):
        end_point = CREATE_ENCRYPTION_KEY
        logger.writeDebug("GW:create_encryption_key:spec={}", key_spec)

        # Build payload with only non-None values in camelCase
        payload = {}
        if key_spec.number_of_keys is not None:
            payload["numberOfKeys"] = key_spec.number_of_keys

        logger.writeDebug("GW:create_encryption_key:payload={}", payload)
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:create_encryption_key:response={}", response)

        return response

    @log_entry_exit
    def delete_encryption_key(self, key_id):
        end_point = DELETE_ENCRYPTION_KEY.format(key_id)
        logger.writeDebug("GW:delete_encryption_key:key_id={}", key_id)
        response = self.connection_manager.delete(end_point)
        logger.writeDebug("GW:delete_encryption_key:response={}", response)

        return response

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
