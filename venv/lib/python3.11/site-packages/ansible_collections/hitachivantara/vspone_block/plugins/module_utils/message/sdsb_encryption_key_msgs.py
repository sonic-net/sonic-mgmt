from enum import Enum


class SDSBEncryptionKeyValidationMsg(Enum):
    KEY_NOT_FOUND = "Encryption key not found with the specified ID."
    INVALID_KEY_ID = "Invalid encryption key ID format."
    INVALID_NUMBER_OF_KEYS = "Number of keys must be between 1 and 4096."
