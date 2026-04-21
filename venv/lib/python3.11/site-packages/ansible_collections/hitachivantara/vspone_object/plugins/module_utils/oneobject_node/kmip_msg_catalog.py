from enum import Enum


class KmipMsgCatalog(Enum):
    ERR_EMPTY_SPEC = "\'spec\' (dict) field is required and cannot be empty or None."
    ERR_INVALID_OPERATION = (
        "\'operation\' (string) field is required and cannot be blank, whitespace, or None. "
        "Allowed values: present, absent, promote, modify."
    )
    ERR_NAME_EMPTY = "\'name\' (string) field cannot be blank, whitespace, or empty."
    ERR_HOST_EMPTY = "\'host\' (string) field cannot be blank, whitespace, or empty."
    ERR_PORT_EMPTY = "\'port\' (int) field cannot be blank, whitespace, or empty."
    ERR_KMIP_PROTOCOL_EMPTY = "\'kmip_protocol\' (string) field cannot be blank, whitespace, or empty."
    ERR_HTTPS_CIPHERS_EMPTY = "\'https_ciphers\' (string) field cannot be blank, whitespace, or empty."
    ERR_OP_KMIP = "Failed to {} KMIP server. Error: {}."
