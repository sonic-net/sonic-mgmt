from enum import Enum


class StoragePortFailedMsg(Enum):
    CHANGE_SETTING_FAILED = "Failed to change the port settings. "


class VSPStoragePortValidateMsg(Enum):
    PORT_ATTRIBUTE_ONLY = "The port_attribute attribute cannot be specified at the same time as any other attribute."
    INVALID_PORT_ATTRIBUTE = "The port_attribute {} is invalid. It must be one of the following: {}. Case insensitive."
    PORT_MODE_ONLY = "The port_mode attribute cannot be specified at the same time as any other attribute."
    INVALID_PORT_MODE = "The port_mode {} is invalid. It must be one of the following: {}. Case insensitive."
    INVALID_PORT_CONNECTIONS = "The port_connection {} is invalid. It must be one of the following: {}. Case insensitive."
    INVALID_PORT_SPEED = (
        "The port_speed {} is invalid. Valid values are 'AUT' and 'nG', "
        "where n is a number between 1 to 999 and G can be omitted. Case insensitive."
    )
    FABRIC_MODE_PORT_CONN_TOGETHER = (
        "The fabric_mode and port_connection attributes must be specified together."
    )
    PORT_MODE_LUN_SECURITY_COMBINATION = "The port_mode and enable_port_security parameters cannot be used together. Use one or the other."
    VALID_PORT_ID = "The port parameter is invalid. The value must be provided in the format of 'CLx-PORTx'."
