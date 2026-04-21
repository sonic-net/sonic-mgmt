from enum import Enum


class SDSBRemoteIscsiPortValidationMsg(Enum):

    ID_REQD = "Id is required for this operation."
    REQD_INPUT_MISSING = (
        "One or more required input parameters are missing. The required input parameters for this operation are: "
        "local_port, remote_ip_address, remote_port, remote_serial, remote_storage_system_type."
    )
