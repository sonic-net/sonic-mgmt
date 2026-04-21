from enum import Enum


class SDSSnapShotsMsgs(Enum):
    ALL_VALUES_NOT_BE_PRESENT = "Exactly one of master_volume_id, master_volume_name, snapshot_volume_id, or snapshot_volume_name must be provided."
    NAME_SNAPSHOT_VOLUME = "If a name is provided, it must be for the master volume, not the snapshot volume."
    SNAPSHOT_VOLUME_OPERATION_TYPE = "If a snapshot volume is specified, operation_type must be provided to change the status."
    MASTER_VOLUME_NAME_NOT_FOUND = "Master volume with name {} not found."
    SNAPSHOT_VOLUME_NAME_NOT_FOUND = "Snapshot volume with name {} not found."
    SNAPSHOT_NOT_FOUND = "Given Snapshot details not found."
    VPS_NAME_NOT_FOUND = "VPS with name {} not found."
    SNAPSHOT_VOLUME_NOT_FOUND = "Snapshots volume with master_volume_id {} not found."
    MASTER_VOLUME_NAME_AND_ID = (
        "Either master_volume_name or master_volume_id must be provided."
    )
    RESTORE_MSG = "Snapshot restored successfully."
    DELETE_MSG = "Snapshot deleted successfully."
    SNAPSHOT_CREATED = "Snapshot created successfully."
