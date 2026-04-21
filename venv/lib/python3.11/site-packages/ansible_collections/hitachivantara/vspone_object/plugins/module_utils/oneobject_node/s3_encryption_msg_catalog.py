from enum import Enum


class S3EncryptionMsgCatalog(Enum):
    ERR_SET_ENCRYPTION_MODE = "Failed to set encryptionMode. Error: {}."
    ERR_INVALID_S3_ENCRYPTION = "\'encryptionMode\' (string) field is required and cannot be blank, whitespace, or None"
    ERR_UNSUPPORTED_S3_ENCRYPTION = "Unsupported \'encryptionMode\': {}. Possible values are INTERNAL, EXTERNAL or DISABLED."
