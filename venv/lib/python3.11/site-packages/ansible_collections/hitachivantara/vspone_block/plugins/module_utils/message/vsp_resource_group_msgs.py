from enum import Enum


class VSPResourceGroupValidateMsg(Enum):
    NO_RG_ID_OR_RG_NAME = (
        "Either resource group id or resource group name should be provided."
    )
    BOTH_RG_ID_AND_RG_NAME = (
        "Both resource group id and resource group name cannot be provided. "
        "For creating a new resource group, provide only name. For updating an "
        "existing resource group, you can provide either id or name, but providing id is recommended."
    )
    INVALID_RG_NAME = "Invalid Resource Group Name provided. Specify a Resource Group Name consisting of 1 to 32 characters."
    NO_LOCK_WITH_RG_ID_OR_RG_NAME = "Resource group id or resource group name should not be provided with is_locked."
    NO_QUERY_WITH_RG_ID_OR_RG_NAME = (
        "Resource group id or resource group name should not be provided with query."
    )
    INVALID_START_LDEV_ID = (
        "Invalid start_ldev provided. Supported values are 0 to 65278."
    )
    END_LDEV_ID_REQUIRED = "end_ldev is required when start_ldev is provided."
    INVALID_END_LDEV_ID = "Invalid end_ldev provided. Supported values are 1 to 65279."
    END_LDEV_LESS_START_LDEV = "end_ldev should be greater than start_ldev."
    NO_START_END_LDEV_AND_LDEV_IDS = (
        "Can't provide start_ldev and end_ldev (range) with ldev_ids."
    )
    START_LDEV_ID_REQUIRED = "start_ldev is required when end_ldev is provided."
    INVALID_QUERY = "Invalid query provided: {}. Supported values are {}."
    CONTRADICT_INFO = "Contradicting information provided in the spec. During create, remove task was specified."
    INVALID_VIRTUAL_STORAGE_DEVICE_ID = "Invalid virtual_storage_device_id provided. Minimum number of characters 12 needed."
    INVALID_RG_ID = "An unsupported or invalid resource group ID has been provided. Provide values in the range of 1 to 1023."
    INVALID_LDEV_ID = "Invalid ldev_ids provided. Supported values are 0 to 65279."
    INVALID_NVM_SUBSYSTEM_ID = (
        "Invalid nvm_subsystem_ids provided. Supported values are 0 to 2047."
    )
    STORAGE_POOL_IDS_ALONE_NOT_ALLOWED = "storage_pool_ids should not be provided alone. It should be provided with some other query attributes."

    LOCK_REQUIRED = "is_resource_group_locked  is required."
    LOCK_TOKEN_REQUIRED = (
        "lock_token is required when is_resource_group_locked is set to false."
    )
    INVALID_RG_TIMEOUT = (
        "Invalid lock timeout provided. Supported values are 0 to 7200."
    )
    RG_NAME_REQD_LOCK_UNLOCK = "Resource group name is required for lock/unlock operation for gateway connection."
    RG_NOT_FOUND = "Resource Group not found."
    RG_LOCK_FAILED = "Resource Group lock failed."
    RG_UNLOCK_FAILED = "Resource Group unlock failed."
    RG_ALREADY_UNLOCKED = "Resource Group is already unlocked."
    INVALID_VIRTUAL_STORAGE_MODEL = "Invalid virtual_storage_model provided. Model {} is not supported for gateway connection type."
    UPDATED_RG_INFO_NOT_RCVD = (
        "Updated Resource Group information not received from Gateway after 5 retries."
        "Ansible retries every 30 seconds, so waited for 2.5 minutes."
    )
    LDEVS_LIST_AND_RANGE_NOT_ALLOWED = "If you specify this attribute, you cannot specify the start_ldev attribute or the end_ldev attribute."
