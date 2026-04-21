from enum import Enum


class SDSBSessionValidationMsg(Enum):
    INVALID_ALIVE_TIME = "The 'alive_time' value must be between 1 and 300."
    ID_MISSING_FOR_DELETE = "You must specify 'id' for the 'delete' operation."
