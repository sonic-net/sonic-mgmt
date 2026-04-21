from enum import Enum


class SDSBVolumeMessage(Enum):
    pass


class SDSBVolValidationMsg(Enum):

    SAVING_SETTING = (
        "This module only accepts Disabled or Compression for capacity_saving field."
    )
    CAPACITY = "capacity must be provided while creating a volume."
    CAPACITY_UNITS = "This module only accepts MB, GB, or TB for capacity field."
    POOL_NAME_EMPTY = "pool_name must be provided while creating a volume."
    POOL_NAME_NOT_FOUND = "Pool name {0} not found."
    NO_NAME_ID = "Either volume ID or volume name must be provided."
    VOL_ID_ABSENT = "Could not find volume with ID {0}."
    VOLUME_NOT_FOUND = "Could not find volume with name {0}."
    NO_SPEC = "Specifications for the volume are not provided."
    COMPUTE_NODES_EXIST = (
        "Ensure all compute node names provided in the spec are present in the system."
    )
    INVALID_CAPACITY = "Volume capacity specified is less than the actual volume capacity. Provide a capacity greater than the actual capacity."
    CONTRADICT_INFO = "Contradicting information provided in the spec. Volume name does not exist in the system, and spec.state is set to remove_compute_node."
    POOL_VPS_BOTH = "pool_name cannot be specified together with vps_name or vps_id. Please provide the correct parameter."
    POOL_OR_VPS_ID = "Either pool_name, vps_name, or vps_id must be specified. Please provide the correct parameter."
    QOS_UPPER_LIMIT_IOPS_OUT_OF_RANGE = (
        "upper_limit_for_iops must be -1 or 100 to 2147483647."
    )
    QOS_UPPER_LIMIT_XFER_RATE_OUT_OF_RANGE = (
        "upper_limit_for_transfer_rate_mb_per_sec must be -1 or 1 to 2097151."
    )
    QOS_UPPER_ALERT_ALLOWABLE_TIME_OUT_OF_RANGE = (
        "upper_alert_allowable_time_in_sec must be -1 or 1 to 600."
    )
