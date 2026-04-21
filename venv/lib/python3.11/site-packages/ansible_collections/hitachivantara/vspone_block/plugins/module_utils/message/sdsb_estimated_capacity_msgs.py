from enum import Enum


class SDSBEstimatedCapacityValidateMsg(Enum):
    ONE_INPUT_NEEDED = (
        "You must specify at least one of the following inputs: "
        "number_of_storage_nodes, number_of_drives, or number_of_tolerable_drive_failures."
    )
    POOL_ID_OR_NAME_REQUIRED = "Either id or name is required. Specify one of them."
    ONLY_SUPPORTED_FOR_AWS = "This feature is available only with a Floating base license and for the AWS cloud model."
    BOTH_ID_AND_NAME_NONE = (
        "Both id and name fields are null, you must specify one of them."
    )
    ENSURE_FLOATING_BASE_LIC = " Ensure you have Floating base license."
    WRONG_POOL_ID = "Wrong pool id given, did not find storage pool with that ID."
    STORAGE_POOL_NOT_FOUND = "Did not find storage pool named {}."
