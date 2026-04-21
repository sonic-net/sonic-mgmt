from enum import Enum


class SDSBBmcConnectionValidationMsg(Enum):
    NOT_SUPPORTED_ON_CLOUD = "This operation is only supported for bare metal."
    BOTH_ID_AND_NAME_NONE = (
        "Both id and name fields are null, you must specify one of them."
    )
    BOTH_BMC_NAME_AND_USERNAME_REQD = (
        "One or both of the required fields bmc_name and bmc_user are missing."
    )
