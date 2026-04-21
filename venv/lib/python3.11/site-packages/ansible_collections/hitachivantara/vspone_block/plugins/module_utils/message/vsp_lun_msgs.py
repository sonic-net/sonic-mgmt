from enum import Enum


class VSPVolumeMessage(Enum):
    pass


class VSPVolumeMSG(Enum):
    ONLY_SUPPORTED_ON_PEGASUS = (
        "This module is only supported on VSP One B2x models and VSP E series."
    )
    MISSING_VOLUME_ID_FOR_DELETION = "Missing volume ID for deletion."
    VOLUME_DELETED_SUCCESS = "Volume deleted successfully."
    VOLUME_DELETE_FAILED = "Failed to delete volume: "
    MULTIPLE_VOLUMES_CREATED = "Multiple volumes created with IDs: {ids}"
    VOLUME_CREATED_UPDATED_SUCCESS = "Volume created/updated successfully."
    POOL_ID_REQUIRED = "Pool ID is required to create a volume."
    CAPACITY_REQUIRED = "Capacity is required to create a volume."
    SAVING_SETTING_REQUIRED = "Capacity saving is required to create a volume."
    NICKNAME_REQUIRED = "Nickname base name is required to create a volume."
    VOLUME_ID_REQUIRED_FOR_QOS = "Volume ID is required to update QoS settings."
    QOS_SETTINGS_REQUIRED = "QoS settings are required to update."
    VOLUME_NOT_FOUND_OR_NO_QOS = (
        "Volume with ID {volume_id} not found or has no QoS settings."
    )
    QOS_UPDATED_SUCCESS = "QoS settings updated successfully."
    QOS_ALREADY_UP_TO_DATE = "QoS settings are already up to date."
    FAILED_TO_UPDATE_QOS = "Failed to update QoS settings: {} "
    FAILED_TO_UPDATE_VOLUME_SETTINGS = "Failed to update volume settings: "
    VOLUME_SETTINGS_UPDATED_SUCCESS = "Volume settings updated successfully."
    FAILED_TO_EXPAND_VOLUME_CAPACITY = "Failed to expand volume capacity: "
    VOLUME_CAPACITY_EXPANDED_SUCCESS = "Volume capacity expanded successfully."
    MISSING_VOLUME_ID_FOR_OPERATION = "Missing volume ID to perform the operation."
    MISSING_SERVER_ISD_FOR_OPERATION = (
        "server_ids is required to attach servers to volumes."
    )
    VOLUME_NOT_FOUND = "Volume with ID {volume_id} not found."
    ATTACHED_SERVER_SUCCESS = "Attached volumes to servers successfully."
    ATTACHED_SERVER_FAILED = "Failed to attach servers to volume: "
    SERVER_ATTACHED_SUCCESS = "Server(s) attached to volume successfully."
    DETACHED_SERVER_SUCCESS = "Detached servers {} to volume successfully."
    DETACHED_SERVER_FAILED = "Failed to detach server(s) from volume: "
    SERVER_DETACHED_SUCCESS = "Server(s) detached from volume successfully."
    SERVER_ALREADY_ATTACHED = (
        "One or more specified server IDs are already attached to the volume."
    )
    SERVER_ALREADY_DETACHED = (
        "One or more specified server IDs are already detached from the volume."
    )

    # Example usage in the class (replace string literals with enum values):
    # spec.comments.append(VSPVolumeMSG.VOLUME_DELETED_SUCCESS.value)
    # raise Exception(VSPVolumeMSG.POOL_ID_REQUIRED.value)


class VSPVolValidationMsg(Enum):
    NOT_POOL_ID_OR_PARITY_ID = (
        "either pool_id or parity_group or external_parity_group should be provided."
    )
    LUN_REQUIRED = "ldev_id is required for absent state to delete."
    COUNT_VALUE = "The parameter 'count' must be a whole number greater than zero."
    END_LDEV_AND_COUNT = "Ambiguous parameters, count and end_ldev_id cannot co-exist."
    POOL_ID_OR_PARITY_ID = "pool_id or parity_group is mandatory for new ldev creation."
    SIZE_REQUIRED = "size is mandatory for new ldev creation."
    SIZE_INT_REQUIRED = (
        "provide integer value for the size with unit. e.g. 5GB, 2TB, etc."
    )
    VALID_SIZE = "size is less than actual volume size of the ldev, Please provide with more than the actual size."
    LDEV_ID_OUT_OF_RANGE = "ldev id is out of range to create, Please specify within the range of 0 to 65535."
    VLDEV_ID_OUT_OF_RANGE = (
        "vldev id is out of range, Please specify within the range of 0 to 65535."
    )
    MAX_LDEV_ID_OUT_OF_RANGE = (
        "ldev id is out of range, Please specify within the range of 0 to 65535."
    )
    START_LDEV_LESS_END = "end_ldev_id can't be less then start_ldev_id."
    BOTH_API_TOKEN_USER_DETAILS = (
        "either api_token or user credential is required, both can't be provided"
    )
    BOTH_PARITY_GRP_TIERING = (
        "Tiering policy is not applicable if volume is not dynamic pool"
    )
    VLDEVID_META_RSRC = "Volume is in meta resource, vldev_id is not applicable."
    NOT_API_TOKEN_USER_DETAILS = "api_token is required"
    DIRECT_API_TOKEN_ERROR = (
        "api_token should not be present when connection type is 'direct'"
    )
    VOLUME_NOT_FOUND = "Volume not found for the given ldev id {}"
    VOLUME_NOT_FOUND_BY_NAME = "Volume not found for the given ldev name {}"
    POOL_ID_PARITY_GROUP = "pool_id, parity_group and external_parity_group are mutually exclusive for volume creation. Please provide only one of them."
    POOL_ID_OR_PARITY_GROUP = (
        "Either pool id or parity group is required for volume creation."
    )
    BOTH_PARITY_GROUPS_SPECIFIED = "Both parity_group and external_parity_group are specified. Please provide only one of them."
    NO_FREE_LDEV = "No free ldevs available in the storage device."
    NO_FREE_LDEV_PER_COUNT = (
        "No free ldevs available in the storage device for the count {} specified."
    )
    PATH_EXIST = "A path is defined in the volume. Use force=true in the spec to delete a volume with a path."
    SUBSCRIBER_ID_NOT_NUMERIC = "subscriber_id should have only numeric values."

    NVM_SUBSYSTEM_DOES_NOT_EXIST = "NVM subsystem {} does not exist."
    CONTRADICT_INFO = "Contradicting information provided in the spec. Volume name does not exist in the system, and spec.state is set to remove_host_nqn."
    VOLUME_HAS_PATH = (
        "This ldev can't be deleted. It might be connected to host groups or "
        "might be added to the NVM Subsystem as a namespace. Use force=true to "
        "delete this ldev."
    )
    LDEV_NOT_FOUND_IN_NVM = "Did not find ldev_id {} in NVM subsystem {}."
    INVALID_LDEV_NAME_LEN = "Invalid volume name length. Number of characters in volume name should be between 1 to 24."
    VOL_NOT_FOUND = "Volume not found."
    QUERY_NOT_LIST = "Query must be provided as a list of strings."
    INVALID_QUERY = "Invalid query provided: {}. Supported values are {}."
    INVALID_CAPACITY_SAVING = (
        "Invalid capacity_saving value '{}' provided. Supported values are {}."
    )
    INVALID_START_LDEV_ID = (
        "Invalid start_ldev_id provided. Supported values are 0 to 65278."
    )
    END_LDEV_ID_REQUIRED = "end_ldev_id is required when start_ldev_id is provided."
    INVALID_END_LDEV_ID = (
        "Invalid end_ldev_id provided. Supported values are 1 to 65279."
    )
    END_LDEV_LESS_START_LDEV = "end_ldev_id should be greater than start_ldev_id."
    START_LDEV_ID_REQUIRED = "start_ldev_id is required when end_ldev_id is provided."

    PARALLEL_EXE_LDEV_ID_NOT_ALLOWED = "ldev_id attribute cannot be specified at the same time as the is_parallel_execution_enabled attribute."
    PARALLEL_EXE_PG_ID_NOT_ALLOWED = "parity_group_id attribute cannot be specified at the same time as the is_parallel_execution_enabled attribute."
    PARALLEL_EXE_EXT_PG_ID_NOT_ALLOWED = "external_parity_group attribute cannot be specified at the same time as the is_parallel_execution_enabled attribute."
    LDEV_ID_NOT_IN_START_END_LDEV = (
        "ldev_id should be in the range of start_ldev_id and end_ldev_id."
    )
    CLPR_ID_REQUIRED = "clpr_id is required for assign_ state."
    COUNT_END_LDEV_MUTUALLY_EXCLUSIVE = (
        "count and end_ldev_id are mutually exclusive.Please provide only one of them."
    )
    END_LDEV_SHOULD_BE_GREATER = "end_ldev_id should be greater than start_ldev_id."
    BOTH_LDEV_VLDEV_ID_REQD = (
        "Both ldev_id and vldev_id are required for this operation."
    )
