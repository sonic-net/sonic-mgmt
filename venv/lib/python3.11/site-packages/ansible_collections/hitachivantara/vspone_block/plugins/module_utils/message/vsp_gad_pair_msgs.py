from enum import Enum


class GADFailedMsg(Enum):
    PAIR_CREATION_FAILED = "Failed to create the GAD pair."
    PAIR_RESIZE_FAILED = "Failed to resize the GAD pair."
    PAIR_SPLIT_FAILED = "Failed to split the GAD pair."
    PAIR_SWAP_SPLIT_FAILED = "Failed to swap split the GAD pair."
    PAIR_SWAP_RESYNC_FAILED = "Failed to swap resync the GAD pair."
    PAIR_RESYNC_FAILED = "Failed to resync the GAD pair."

    SEC_VOLUME_DELETE_FAILED = "Failed to delete the secondary volume."
    SEC_VOLUME_OPERATION_FAILED = "Failed to perform operation on the secondary volume."


class GADPairValidateMSG(Enum):
    """
    Enum class for GAD pair validation messages
    """

    GAD_PAIR_NOT_FOUND = "GAD pair with id {} not found."
    GAD_PAIR_NOT_FOUND_SIMPLE = "GAD pair is not found."
    DELETE_GAD_PAIR_SUCCESS = "GAD pair deleted successfully."
    DELETE_GAD_FAIL_SPLIT_DIRECT = (
        "To delete the GAD pair, it must be in the split state."
    )
    DELETE_GAD_FAIL_SPLIT_GW = "To delete the GAD pair, it must be in the PAIR state."
    PRIMARY_STORAGE_SN = "Primary storage serial number is required."
    SECONDARY_STORAGE_SN = "Secondary storage serial number is required."
    PRIMARY_VOLUME_ID = "Primary volume id is required."
    SECONDARY_POOL_ID = "Secondary pool id is required."
    REMOTE_UCP_SYSTEM = "Remote UCP system is required."
    SECONDARY_HOSTGROUPS = "Secondary hostgroups id is missing."
    SECONDARY_HOSTGROUPS_OR_NVME = (
        "Either specify Secondary hostgroups, NVM subsystem or Iscsi target details."
    )
    HOSTGROUPS_ID = "{} Hostgroups id is missing."
    HOSTGROUPS_NAME = "{} Hostgroups name is missing."
    HOSTGROUPS_PORT = "{} Hostgroups port is missing."
    HG_RES_GRP_ID = "{} Hostgroups resource_group_id is missing."
    SECONDARY_SYSTEM_NT_FOUND = "Secondary storage system not found or not on boarded."
    SECONDARy_SYSTEM_CANNOT_BE_SAME = (
        "Secondary storage system cannot be same as primary storage system."
    )
    INCONSISTENCY_GROUP = "consistency_group_id and allocate_new_consistency_group can't be present at the same time. provide only one."
    NO_PRIMARY_VOLUME_FOUND = "Primary volume {} not found."
    PRIMARY_HG_NOT_FOUND = "Primary hostgroup with names {} not found."
    SEC_HG_NOT_FOUND = "Secondary hostgroup with names {} not found."
    NO_REMOTE_HG_FOUND = "Remote hostgroup is not found."
    NO_PAIR_FOR_PRIMARY_VOLUME_ID = (
        "Could not find the GAD pair associated with primary_volume_id {}."
    )
    NO_SWAP_SPLIT_WITH_CTG = "The swap_split operation is not supported for GAD pairs that are part of a consistency group."
    NEW_VOLUME_SIZE = (
        "new_volume_size is a required field for resize operation, which is missing."
    )
    EXPAND_VOLUME_FAILED = "Failed to expand the volume. Ensure System Option Mode (SOM) 1198 is enabled and 1199 is disabled."
    EXPAND_PVOL_FAILED = "Failed to perform operation for primary volume {}."
    EXPAND_SVOL_FAILED = "Failed to perform operation for secondary volume {}."
    NO_GAD_PAIR_FOUND_FOR_INPUTS = (
        "Could not find GAD pair for the input parameters supplied."
    )
    NO_REMOTE_HGS_FOUND = "Specified host groups not found on secondary storage."
    NO_REMOTE_ISCSI_FOUND = "Specified iSCSI targets not found on secondary storage."
    RG_DID_NOT_MATCH = (
        "Resource Group ID for secondary volume and the hostgroups did not match."
    )
    QUORUM_DISK_ID = "quorum_disk_id is a required field, which is missing."
