from enum import Enum


class SerialNumberMsgCatalog(Enum):
    ERR_SET_SERIAL_NUM = "Failed to set serial number. Error: {}."
    ERR_INVALID_SERIAL_NUM = "\'serial_number\' (string) field is required and cannot be blank, whitespace, or None"
