from enum import Enum


class HurFailedMsg(Enum):
    PAIR_CREATION_FAILED = "Failed to create the HUR pair."
    PAIR_RESIZE_FAILED = "Failed to resize the HUR pair."
    PAIR_SPLIT_FAILED = "Failed to split the HUR pair."
    PAIR_SWAP_SPLIT_FAILED = "Failed to swap split the HUR pair."
    PAIR_SWAP_RESYNC_FAILED = "Failed to swap resync the HUR pair."
    PAIR_RESYNC_FAILED = "Failed to resync the HUR pair."
    PAIR_DELETION_FAILED = "Failed to delete the HUR pair."
    SECONDARY_TAKEOVER_FAILED = "Failed to take over the secondary volume."

    SEC_VOLUME_DELETE_FAILED = "Failed to delete the secondary volume."
    SEC_VOLUME_OPERATION_FAILED = "Failed to perform operation on the secondary volume."


class VSPHurValidateMsg(Enum):
    PRIMARY_VOLUME_ID = "primary_volume_id is a required field, which is missing."
    MIRROR_UNIT_ID = "mirror_unit_id is a required field, which is missing."
    SECONDARY_STORAGE_SN = (
        "secondary_storage_serial_number is a required field, which is missing."
    )
    SECONDARY_POOL_ID = "secondary_pool_id is a required field, which is missing."
    SECONDARY_HOSTGROUPS = "secondary_hostgroup is a required field, which is missing."
    SECONDARY_HOSTGROUPS_ID = (
        "secondary_hostgroup.id is a required field, which is missing."
    )
    SECONDARY_HOSTGROUPS_NAME = (
        "secondary_hostgroup.name is a required field, which is missing."
    )
    SECONDARY_HOSTGROUPS_PORT = (
        "secondary_hostgroup.port is a required field, which is missing."
    )
    PRIMARY_JOURNAL_ID = (
        "primary_volume_journal_id is a required field, which is missing."
    )
    SECONDARY_JOURNAL_ID = (
        "secondary_volume_journal_id is a required field, which is missing."
    )

    INVALID_CTG_BOTH_NONE = "Either consistency_group_id or allocate_new_consistency_group must be specified"
    INVALID_CTG_NONE = "consistency_group_id must be specified if allocate_new_consistency_group is false"
    INVALID_CG_NEW = "allocate_new_consistency_group cannot be true if consistency_group_id is specified"
    INVALID_CG_ID = (
        "Invalid consistency_group_id provided. Supported values are 0 to 255."
    )
    NO_PRIMARY_VOLUME_FOUND = "Could not find primary_volume_id {}."
    NO_RESYNC_NEEDED = (
        "HUR pair with primary_volume_id {} on storage system {} and "
        "secondary_volume_id {} on storage system {} is already in PAIR status. "
        "Resynchronization is not needed."
    )
    ALREADY_SPLIT_PAIR = (
        "HUR pair with primary_volume_id {} on storage system {} and "
        "secondary_volume_id {} on storage system {} is already a split pair. "
        "Split is not needed."
    )
    PRIMARY_VOLUME_ID_DOES_NOT_EXIST = (
        "HUR pair with primary_volume_id {} is no longer in the system."
    )
    HUR_PAIR_ALREADY_EXIST = (
        "HUR pair with primary_volume_id {} and mirror_unit_id {} already exist."
    )
    PRIMARY_VOLUME_AND_MU_ID_WRONG = "primary_volume_id {} and mirror_unit_id {} combination is wrong, pair not found. Provide correct values."
    PRIMARY_VOLUME_ID_NO_PATH = "primary_volume_id {} does not have any path, ensure it is attached to at least one hostgroup."
    NO_HUR_PAIR_FOUND = "Could not find the HUR pair associated with copy_pair_name {}."
    HUR_PAIR_NOT_FOUND_SIMPLE = "HUR pair is not found."
    NO_LOCAL_DEVICE_NAME_FOUND = "Incorrect local_device_group_name for existing copy_group {}. Provide correct existing value {}."
    NO_REMOTE_DEVICE_NAME_FOUND = "Incorrect remote_device_group_name for existing copy_group {}. Provide correct existing value {}."
    NEW_VOLUME_SIZE = (
        "new_volume_size is a required field for resize operation, which is missing."
    )
    EXPAND_VOLUME_FAILED = "Failed to expand the volume. Ensure System Option Mode ( SOM ) 1198 is enabled and 1199 is disabled."
    REDUCE_VOLUME_SIZE_NOT_SUPPORTED = "Shrink/reduce volume size is not supported."
    SECONDARY_RANGE_ID_INVALID = "Please specify both begin_secondary_volume_id and end_secondary_volume_id. Specifying either one is not supported."
    EXPAND_PVOL_FAILED = "Failed to perform operation for primary volume {}."
    EXPAND_SVOL_FAILED = "Failed to perform operation for secondary volume {}."
    PAIR_NOT_IN_SSWS_STATE = (
        "HUR pair {} is not in SSWS state. Operation is not allowed."
    )
    SECONDARY_VOLUME_ID_OUT_OF_RANGE = "provisioned_secondary_volume_id does not lie between begin_secondary_volume_id and end_secondary_volume_id."
    HUR_OPERATION_FAILED = "HUR operation failed with response: {}"
