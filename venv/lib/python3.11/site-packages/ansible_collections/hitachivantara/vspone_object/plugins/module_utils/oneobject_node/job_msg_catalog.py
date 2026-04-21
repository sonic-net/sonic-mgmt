from enum import Enum


class JobMsgCatalog(Enum):
    ERR_CREATE_JOB = "Failed to create job. Error: {}."
    ERR_CANCEL_JOB = "Failed to cancel job. Error: {}."
    ERR_EMPTY_SPEC = "\'spec\' (dict) field is required and cannot be blank, whitespace, or None."
    ERR_INVALID_SPEC = "{} is required and cannot be blank, whitespace, or None."
    ERR_INVALID_SERIAL_NUM = "\'serial_number\' (string) field is required and cannot be blank, whitespace, or None."
    ERR_INVALID_STATE = "Invalid state: {}. Valid states are 'present' or 'absent'."
