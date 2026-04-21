from enum import Enum


class TrueCopyFailedMsg(Enum):
    PAIR_CREATION_FAILED = "Failed to create the TrueCopy pair."
    PAIR_RESIZE_FAILED = "Failed to resize the TrueCopy pair."
    PAIR_SPLIT_FAILED = "Failed to split the TrueCopy pair."
    PAIR_SWAP_SPLIT_FAILED = "Failed to swap split the TrueCopy pair."
    PAIR_SWAP_RESYNC_FAILED = "Failed to swap resync the TrueCopy pair."
    PAIR_RESYNC_FAILED = "Failed to resync the TrueCopy pair."
    DELETE_PAIR_FAILED = "Failed to delete the Truecopy pair."

    SEC_VOLUME_DELETE_FAILED = "Failed to delete the secondary volume."
    SEC_VOLUME_OPERATION_FAILED = "Failed to perform operation on the secondary volume."


class VSPTrueCopyValidateMsg(Enum):
    PRIMARY_VOLUME_ID = "primary_volume_id is a required field, which is missing."
    SECONDARY_VOLUME_ID = "secondary_volume_id is a required field, which is missing."
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
    COPY_GROUP_NAME = "copy_group_name is a required field, which is missing."
    COPY_PAIR_NAME = "copy_pair_name is a required field, which is missing."

    INVALID_CG_ID = (
        "Invalid consistency_group_id provided. Supported values are 0 to 255."
    )
    NO_RESYNC_NEEDED = (
        "TrueCopy pair with primary_volume_id {} on storage system {} and "
        "secondary_volume_id {} on storage system {} is already in PAIR status. "
        "Resynchronization is not needed."
    )
    ALREADY_SPLIT_PAIR = (
        "TrueCopy pair with primary_volume_id {} on storage system {} and "
        "secondary_volume_id {} on storage system {} is already a split pair. "
        "Split is not needed."
    )
    NO_PRIMARY_VOLUME_FOUND = "Could not find primary_volume_id {}."
    PRIMARY_VOLUME_ID_DOES_NOT_EXIST = "Could not find primary_volume_id {}."
    REMOTE_REP_DID_NOT_FIND_PORT = "Could not find the port {}."
    REMOTE_REP_NO_MORE_PORTS_AVAILABLE = "No more ports available to create default hostgroup for remote replication pairs."
    PRIMARY_VOLUME_ID_NO_PATH = "primary_volume_id {} does not have any path, ensure it is attached to at least one hostgroup."
    NO_TC_PAIR_FOR_PRIMARY_VOLUME_ID = (
        "Could not find the truecopy pair associated with primary_volume_id {}."
    )

    NO_TC_PAIR_FOUND_FOR_INPUTS = (
        "Could not find TrueCopy pair for the input parameters supplied."
    )
    NO_REMOTE_HG_FOUND = (
        "Could not find hostgroups specified in the spec on secondary storage."
    )
    NO_REMOTE_ISCSI_FOUND = (
        "Could not find iscsi targets specified in the spec on secondary storage."
    )
    HG_SUBSCRIBER_ID_MISMATCH = (
        "Provided subscriber_id {} and hostgroup subscriber Id {} did not match."
    )
    NO_SUB_PROVIDED_HG_HAS_SUB = (
        "No subscriber_id provided, but the hostgroup belongs to a subscriber."
    )
    PVOL_ISCSI_MISSING = "Pvol {} does not belong to any iscsi target. Please check the hostgroup configuration for primary storage."
    PORT_SUBSCRIBER_ID_MISMATCH = (
        "Provided subscriber_id {} and port subscriber Id {} did not match."
    )
    NO_SUB_PROVIDED_PORT_HAS_SUB = (
        "No subscriber_id provided, but the port belongs to a subscriber."
    )
    WRONG_PORT_PROVIDED = "{}'s port type is {} and port mode is {}. Ensure provided port's port type is FIBRE and port mode is SCSI."

    INVALID_COPY_GROUP_NAME = "Invalid copy_group_name provided. Specify a copy group name consisting of 1 to 29 characters."
    INVALID_COPY_PAIR_NAME = "Invalid copy_pair_name provided. Specify a copy pair name consisting of 1 to 31 characters."
    INVALID_PG_ID = "Invalid path_group_id provided. Supported values are 0 to 255."
    INVALID_LOCAL_DEVICE_GROUP_NAME = "Invalid local_device_group_name provided. Specify a local device group name consisting of 1 to 31 characters."
    INVALID_REMOTE_DEVICE_GROUP_NAME = "Invalid remote_device_group_name provided. Specify a remote device group name consisting of 1 to 31 characters."
    INVALID_CP_VALUE = "Invalid copy_pace value provided. Supported values are: {}."
    SECONDARY_CONNECTION_INFO = "secondary_connection_info is a required field for direct connect, which is missing."
    COPY_GROUP_NAME_NOT_FOUND = "Did not find copy group with name {}."
    INVALID_EMULATION_TYPE = "Found 'NOT DEFINED' emulation_type for the primary volume, that indicates the LDEV is not implemented."
    DELETE_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED = "For direct connect, delete of TrueCopy pair by primary_volume_id is not supported for model {}."
    SPLIT_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED = "For direct connect, split of TrueCopy pair by primary_volume_id is not supported for model {}."
    SWAP_SPLIT_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED = "For direct connect, swap split of TrueCopy pair by primary_volume_id is not supported for model {}."
    RESYNC_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED = "For direct connect, resync of TrueCopy pair by primary_volume_id is not supported for model {}."
    SWAP_RESYNC_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED = "For direct connect, resync of TrueCopy pair by primary_volume_id is not supported for model {}."
    MUST_PSUS = "Truecopy pair must be in split(PSUS) state."

    NEW_VOLUME_SIZE = (
        "new_volume_size is a required field for resize operation, which is missing."
    )
    EXPAND_VOLUME_FAILED = "Failed to expand the volume. Ensure System Option Mode (SOM) 1198 is enabled and 1199 is disabled."
    INVALID_VOLUME_SIZE = "Invalid new_volume_size provided. Specify new_volume_size with unit consisting of 3 to 14 characters."
    SECONDARY_STORAGE_SN_NEEDED = (
        "secondary_storage_serial_number is a required field, which is missing."
    )
    EXPAND_VOLUME_FAILED_EXISTING_PAIR = (
        "Failed to expand the volume. The copy pair {} might have been created before System Option Mode (SOM) 1198 was enabled and 1199 was disabled."
        "Please try again by performing operations  [split → resync → split → resync] on the copy pair."
    )
    REDUCE_VOLUME_SIZE_NOT_SUPPORTED = "Shrink/reduce volume size is not supported."
    SEC_PORT_NOT_FOUND = (
        "Could not find the port {} for the host group on secondary storage system."
    )
    SECONDARY_RANGE_ID_INVALID = "Please specify both begin_secondary_volume_id and end_secondary_volume_id. Specifying either one is not supported."

    PVOL_ID_OR_CP_NAME_NEEDED_WITH_CG_NAME = "Please provide either primary_volume_id or copy_pair_name with copy_group_name."
    NO_REMOTE_NVME_FOUND = "Could not find NVMe subsystem {} secondary storage."
    SECONDARY_HOSTGROUPS_OR_NVME = "Either specify secondary_hostgroup or secondary_nvm_subsystems or secondary_iscsi_targets all cannot be empty."
    NVMSUBSYSTEM_DIFFER = "A pair cannot be created because the NVM subsystem ID {} specified for S-VOL differs from the NVM subsystem ID {} for the P-VOL."
    PVOL_NAMESPACE_MISSING = (
        "A pair cannot be created because there does not exist a namespace for PVOL {}"
    )
    PVOL_VLDEV_MISSING = "A GAD pair cannot be created because the primary volume {} does not have a virtual LDEV ID"
    EXPAND_PVOL_FAILED = "Failed to perform operation for primary volume {}."
    EXPAND_SVOL_FAILED = "Failed to perform operation for secondary volume {}."
    NO_FREE_LDEV_IN_RANGE = "No free LDEV found in the range {} - {}."
    SECONDARY_VOLUME_ID_OUT_OF_RANGE = "provisioned_secondary_volume_id does not lie between begin_secondary_volume_id and end_secondary_volume_id."
    BOTH_HGS_ARE_SPECIFIED = (
        "Both secondary_hostgroups and secondary_hostgroup are specified. "
        "Use secondary_hostgroups only, secondary_hostgroup is there for backward compatibility."
    )
