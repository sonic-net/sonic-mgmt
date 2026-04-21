from enum import Enum


class VSPStoragePoolValidateMsg(Enum):
    EMPTY_POOL_ID = "pool_id is empty. Specify a value for pool_id or remove the parameter from the playbook."
    BOTH_POOL_ID_AND_NAME = "Both id and name are specified. Specify only one of them."
    POOL_ID_OR_NAME_REQUIRED = (
        "Either id or pool_name is required. Specify one of them."
    )
    POOL_NAME_REQUIRED = (
        "pool_name is required for pool creation. Specify a value for pool_name."
    )
    PG_ID_CAPACITY = "missing both capacity and parity_group_id in pool_volumes. Specify both values or pool_volumes parameter"
    MISSING_CAPACITY = "capacity is missing in pool_volumes. Specify the capacity value for {} parity_group_id."
    MISSING_PG_ID = "parity_group_id is missing in pool_volumes. Specify the parity_group_id where capacity is {}."
    POOL_SIZE_MIN = "The capacity must be at least 8GB."
    POOL_DOES_NOT_EXIST = "The specified pool does not exist."
    OPERATION_TYPE_REQUIRED = "The operation_type is required for tier relocate and performance monitoring operations."
    POOL_TYPE_REQUIRED = "The type of the pool is required for new pool creation."
    POOL_VOLUME_REQUIRED = "Pool volumes are required for new pool creation."
    POOL_ID_EXHAUSTED = "The pool id is exhausted. No more pools can be created."
    DEDUPLICATION_NOT_ENABLED = "Deduplication is not allowed for this storage system."
    NO_DUP_VOLUMES = "No Free ldev ids are available for duplication."
    UCP_SYSTEM_NOT_AVAILABLE = "Could not find serial number {} in the UAI Gateway. Please try again or provide the correct serial number."
    DEDUPLICATION_NOT_SUPPORTED = (
        "Deduplication is not supported for this storage system."
    )
    SPECIFY_ONE = "Specify only one of pool_volumes, ldev_ids, or range (start_ldev_id and end_ldev_id)."
    NO_MORE_THAN_64_LDEVS = "Specify a number such that the range indicated by the start_ldev_id and end_ldev_id attributes consists of no more than 64 LDEVs."


class StoragePoolInfoMsg(Enum):
    POOL_DELETED = "Storage pool has been deleted successfully."
    POOL_CREATED = "Storage pool {} has been created successfully."
    POOL_UPDATED = "Storage pool {} has been updated successfully."
    TIER_OPERATION_SUCCESS = "Tier relocation {} successfully"
    PERFORMANCE_MONITOR_UPDATE = "Performance monitor {} successfully."
    CAPACITY_SAVING_INITIATED = "Capacity saving has been initiated successfully."
    RESTORE_DONE = "Storage pool restored successfully."
    PERFORMANCE_MONITORING_IN_PROGRESS = (
        "Performance monitoring is already in progress. "
        "Please wait until it finishes before starting a new one or stop the current one."
    )
    TIER_RELOCATION_IN_PROGRESS = (
        "Tier relocation is already in progress. "
        "Please wait until it finishes before starting a new one or stop the current one."
    )
    PM_ALREADY_STOPPED = (
        "Performance monitoring is already stopped. "
        "Please start it before trying to stop it again."
    )
    TIER_RELOCATION_ALREADY_STOPPED = (
        "Tier relocation is already stopped. "
        "Please start it before trying to stop it again."
    )
