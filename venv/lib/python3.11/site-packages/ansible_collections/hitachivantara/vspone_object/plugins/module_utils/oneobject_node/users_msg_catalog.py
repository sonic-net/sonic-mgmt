from enum import Enum


class UsersMsgCatalog(Enum):
    ERR_GENERATE_REVOKE_S3_CREDENTIALS = "Failed to {} S3 credentials. Error: {}."
    ERR_INVALID_OPERATION = "\'operation\' (string) field is required and cannot be blank, whitespace, or None. Allowed value: GENERATE_CREDS."
    ERR_UUID_EMPTY = "\'user_uuid\' (string) field cannot be blank, whitespace, or empty."
    ERR_ID_EMPTY = "\'id\' (string) field cannot be blank, whitespace, or empty."
    ERR_ID_NOT_EXIST = "S3 user id {} does not exist"
    ERR_INVALID_ID_VALUE = "S3 user id {} is invalid."
