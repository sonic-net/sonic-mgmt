from enum import Enum


class SDSBEventLogValidationMsg(Enum):

    BOTH_SEVERITY_SPECIFIED = "Specify either severity or severity_ge — not both."
