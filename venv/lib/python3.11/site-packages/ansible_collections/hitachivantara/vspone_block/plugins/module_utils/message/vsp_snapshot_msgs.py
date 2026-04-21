from enum import Enum


class VSPSnapShotValidateMsg(Enum):
    PVOL_VALID_RANGE = "Specify a decimal (base 10) number equal to or greater than 0 for primary_volume_id."
    MU_VALID_RANGE = "Specify a value in the range from 0 to 1023 for mirror_unit_id."
    MU_VALID_PVOL_VALUE = "primary_volume_id is required to filter mirror_unit_id."
    SNAPSHOT_GRP_NAME = "snapshot_group_name is required for the new snapshot creation."
    SNAPSHOT_GRP_NAME_SPLIT = (
        "snapshot_group_name is required for the direct connection auto-split mode."
    )
    MU_PVOL_REQUIRED = "primary_volume_id and mirror_unit_id is required for the 'absent', 'sync', 'restore','split'."
    PVOL_REQUIRED = "primary_volume_id is required for the 'split' mode."
    POOL_ID_REQUIRED = (
        "pool_id or mirror_unit_id is required when the state is 'split'."
    )
    DATA_REDUCTION_SHARE = "Data reduction share is not enabled on the volume to create advanced snapshot pair."
    PROVIDE_SAME_POOL_ID = "When creating a Thin Image Advanced pair, specify the pool ID of the HDP pool to which the P-VOL belongs."
    DATA_REDUCTION_FORCE_COPY = "Data reduction force copy is not enabled on the volume to create snapshot pair when data reduction mode is enabled."
    DATA_REDUCTION_FORCE_COPY_SNAP_MODE = "Either can_cascade or is_clone must be true when Data reduction force copy is enabled."
    CONSISTENCY_GROUP = "Either specify the consistency_group_id or allocate_consistency_group must be true."
    SVOL_NOT_FOUND = "Specified S-VOL not found."
    PVOL_NOT_FOUND = "Specified primary_volume_id not found."
    PVOL_IS_NOT_IN_HG = "P-VOL is not in the host group, please add the P-VOL to the host group and try again."
    SNAPSHOT_NOT_FOUND = "Snapshot not found."
    SNAPSHOT_GROUP_NOT_FOUND = "Snapshot group not found."
    NO_SNAPSHOTS_FOUND = "No snapshots found."
    MU_ID_NOT_FOUND_IN_TASK = "Mirror Unit ID not found in task information."
    MIRROR_UNIT_ID_NOT_FOUND = "Mirror Unit ID not found."
    PVOL_REQUIRED_FOR_DEL = "primary_volume_id is required for the 'absent' state."
    MU_PVOL_REQUIRED_FOR_REG_DEL = (
        "primary_volume_id and mirror_unit_id is required for the 'absent' state, "
        "when deleting a regular snapshot. mirror_unit_id is not required when deleing by snapshot tree."
    )
