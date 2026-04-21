from enum import Enum


class VSPCmdDevValidateMsg(Enum):
    LDEV_NOT_FOUND = "LDEV with id {} not found."
    LDEV_NOT_DEFINED = "LDEV with id {} is not defined."
