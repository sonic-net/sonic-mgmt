from enum import Enum


class DynamicPoolValidationMsg(Enum):
    """
    Validation messages for DDP Pools.
    """

    DYNAMIC_POOL_NAME = "DDP Pool name is a required field, which is missing."
    DYNAMIC_POOL_NOT_FOUND_BY_ID = "Could not find DDP Pool by id {}."
    DYNAMIC_POOL_NOT_FOUND = "Could not find DDP Pool"
    DYNAMIC_POOL_ALREADY_EXISTS = "DDP Pool with name {} already exists."
    DYNAMIC_POOL_NOT_SUPPORTED = "DDP Pool is not supported for this device type."
    INVALID_DYNAMIC_POOL_NAME = (
        "Invalid DDP Pool name {}."
        " It should start with an alphabet and can contain only alphabets, numbers, hyphen, and underscore."
    )
    DYNAMIC_POOL_DELETED = "DDP Pool deleted successfully."
    DRIVE_COUNT_RANGE = "Drive count should be between 9 to 32 or 65 to 72."
    DRIVES_REQUIRED = "drives are required for DDP Pool creation."
    DRIVES_REQUIRED_TO_EXPAND = "drives are required for DDP Pool expand."
    POOL_NAME_REQUIRED = "pool_name is required for DDP Pool creation."
    POOL_ID_REQUIRED = "pool_id or pool_name is required for DDP Pool deletion."
    ALLOWED_STORAGE_MODEL = "DDP Pool is supported only for VSP One storage Models."
    DDP_DRIVES_NOT_VALID = "Disk drives are not valid or not available, Please check the drive type code, The drive code is {}"
    DDP_DRIVES_NOT_VALID_COUNT = "Disk drives are not available, Please check the drive count, available count is {} for drive code {}"
    NO_FREE_DRIVES = "No free drives available for DDP Pool creation."
    DDP_DRIVES_TYPE_CODE_REQUIRED = (
        "Drive type code is required for DDP Pool creation.when drives are provided."
    )
    NOT_ENOUGH_DRIVES = "Not enough drives available for DDP Pool creation for the given drive code {} ."
    NO_FREE_DRIVES_AVAILABLE = "No free drives available for DDP Pool expansion."
    WARNING_THRESHOLD_REQUIRED = "threshold_warning and threshold_depletion both are required when threshold settings provided."
    WARNING_THRESHOLD_GREATER = (
        "threshold_depletion should be greater than threshold_warning."
    )
    WARNING_THRESHOLD_OUT_OF_RANGE = (
        " Specify the threshold value as an integer from 1 through 100."
    )
