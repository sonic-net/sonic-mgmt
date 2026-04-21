try:
    from ..gateway.sdsb_encryption_key_gateway import SDSBEncryptionKeyGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_constants import EncryptionConstants

except ImportError:
    from gateway.sdsb_encryption_key_gateway import SDSBEncryptionKeyGateway
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.sdsb_constants import EncryptionConstants

logger = Log()


def _transform_encryption_environment_settings(raw_response):
    """Transform encryption environment settings response to match user story specification"""
    # Handle both possible response structures
    if EncryptionConstants.ENCRYPTION_SETTINGS in raw_response:
        settings = raw_response[EncryptionConstants.ENCRYPTION_SETTINGS]
        transformed_response = {
            EncryptionConstants.IS_ENABLED: settings.get(
                EncryptionConstants.IS_ENABLED, False
            ),
            EncryptionConstants.IS_ENCRYPTION_KEY_MANAGEMENT_SERVER_IN_USE: settings.get(
                EncryptionConstants.KMS, False
            ),
            EncryptionConstants.FREE_KEYS_WARNING_THRESHOLD: settings.get(
                EncryptionConstants.WARNING_THRESHOLD_OF_FREE_KEYS, 0
            ),
        }
        return transformed_response
    elif (
        EncryptionConstants.IS_ENABLED in raw_response
        or EncryptionConstants.KMS in raw_response
        or EncryptionConstants.WARNING_THRESHOLD_OF_FREE_KEYS in raw_response
    ):
        # Direct response structure
        transformed_response = {
            EncryptionConstants.IS_ENABLED: raw_response.get(
                EncryptionConstants.IS_ENABLED, False
            ),
            EncryptionConstants.IS_ENCRYPTION_KEY_MANAGEMENT_SERVER_IN_USE: raw_response.get(
                EncryptionConstants.KMS, False
            ),
            EncryptionConstants.FREE_KEYS_WARNING_THRESHOLD: raw_response.get(
                EncryptionConstants.WARNING_THRESHOLD_OF_FREE_KEYS, 0
            ),
        }
        return transformed_response

    return raw_response


class SDSBEncryptionKeyProvisioner:

    def __init__(self, connection_info):
        self.gateway = SDSBEncryptionKeyGateway(connection_info)

    @log_entry_exit
    def get_encryption_keys(self):
        logger.writeDebug("PR:get_encryption_keys")
        encryption_keys = self.gateway.get_encryption_keys()
        return encryption_keys.data_to_snake_case_list()

    @log_entry_exit
    def get_encryption_keys_facts(self, spec):
        if spec is not None and spec.id is not None:
            logger.writeDebug("PR:get_encryption_keys_facts:spec id={}", spec.id)
            try:
                return self.get_encryption_key_by_id(spec.id).camel_to_snake_dict()
            except Exception as e:
                logger.writeDebug("PR:get_encryption_keys_facts:exception={}", e)
                return {}
        encryption_keys = self.gateway.get_encryption_keys_in_details(spec)
        return encryption_keys.data_to_snake_case_list()

    @log_entry_exit
    def get_encryption_key(self, key_id):
        logger.writeDebug("PR:get_encryption_key:key_id={}", key_id)

        encryption_key = self.gateway.get_encryption_key_by_id(key_id)
        return encryption_key.camel_to_snake_dict()

    @log_entry_exit
    def get_encryption_key_by_id(self, key_id):
        logger.writeDebug("PR:get_encryption_key:key_id={}", key_id)

        encryption_key = self.gateway.get_encryption_key(key_id)
        return encryption_key

    @log_entry_exit
    def get_encryption_key_count(self):
        logger.writeDebug("PR:get_encryption_key_count")
        raw_response = self.gateway.get_encryption_key_count()

        # Transform field names to match user story specification
        # Handle both possible response structures
        if EncryptionConstants.ENCRYPTION_KEY_COUNTS in raw_response:
            counts = raw_response[EncryptionConstants.ENCRYPTION_KEY_COUNTS]
            transformed_response = {
                EncryptionConstants.TOTAL_ALLOCATED_ENCRYPTION_TARGETS: counts.get(
                    EncryptionConstants.DEK, 0
                ),
                EncryptionConstants.TOTAL_UNALLOCATED_ENCRYPTION_TARGETS: counts.get(
                    EncryptionConstants.FREE, 0
                ),
            }
            return transformed_response
        elif (
            EncryptionConstants.DEK in raw_response
            and EncryptionConstants.FREE in raw_response
        ):
            # Direct response structure
            transformed_response = {
                EncryptionConstants.TOTAL_ALLOCATED_ENCRYPTION_TARGETS: raw_response.get(
                    EncryptionConstants.DEK, 0
                ),
                EncryptionConstants.TOTAL_UNALLOCATED_ENCRYPTION_TARGETS: raw_response.get(
                    EncryptionConstants.FREE, 0
                ),
            }
            return transformed_response

        return raw_response

    @log_entry_exit
    def get_encryption_environment_settings(self):
        logger.writeDebug("PR:get_encryption_environment_settings")
        raw_response = self.gateway.get_encryption_environment_settings()
        return raw_response.camel_to_snake_dict()

    @log_entry_exit
    def create_encryption_key(self, key_spec):
        logger.writeDebug("PR:create_encryption_key:spec={}", key_spec)
        return self.gateway.create_encryption_key(key_spec)

    @log_entry_exit
    def delete_encryption_key(self, key_id):
        logger.writeDebug("PR:delete_encryption_key:key_id={}", key_id)
        return self.gateway.delete_encryption_key(key_id)

    @log_entry_exit
    def update_encryption_settings(self, settings_spec):
        logger.writeDebug("PR:update_encryption_settings:spec={}", settings_spec)
        unsued = self.gateway.update_encryption_settings(settings_spec)
        return self.gateway.get_encryption_environment_settings().camel_to_snake_dict()
