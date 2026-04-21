from enum import Enum


class SDSBJobValidationMsg(Enum):

    INVALID_COUNT = (
        "Invalid count information provided. It must be in the range 1 to 100."
    )
