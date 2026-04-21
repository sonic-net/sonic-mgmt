from enum import Enum


class SDSBRemotePathGroupValidationMsg(Enum):

    ID_REQD = "Id is required for this operation."
    REQD_INPUT_MISSING = (
        "One or more required input parameters are missing for create operation. The required input parameters for this operation are: "
        "'local_port', 'remote_port', 'remote_serial', 'remote_storage_system_type', 'path_group_id'."
    )
    REQD_INPUT_MISSING_FOR_UPDATE = "Required input parameter 'remote_io_timeout_in_sec' is missing for update operation."
    REQD_INPUT_MISSING_FOR_PATH_OPERATION = (
        "One or more required input parameters are missing. The required input parameters for this operation are: "
        "'local_port', 'remote_port'."
    )
    INVALID_REMOTE_SERIAL = "Invalid value for 'remote_serial'. It must be a 6-digit numeric string (e.g., '810045')."
    INVALID_PORT = "Invalid value for '{}'. It must be in CLx-y format."
    INVALID_PATH_GROUP_ID = "The 'path_group_id' value must be between 1 and 255."
    INVALID_TIMEOUT_VALUE = (
        "The 'remote_io_timeout_in_sec' value must be between 10 and 80."
    )
