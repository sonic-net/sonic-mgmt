from enum import Enum


class SDSBPortValidationMsg(Enum):
    INVALID_PORT_TYPE = "Invalid port_type provided in the spec. Valid port_type in the spec are : compute, control, and internode."
    INVALID_INPUT = "The input is invalid - protocol or ID must be specified."
