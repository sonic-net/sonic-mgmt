from enum import Enum


class VSPParityGroupValidateMsg(Enum):
    EMPTY_PARITY_GROUP_ID = "parity_group_id is empty. Specify a value for parity_group_id or remove the parameter from the playbook."
    NO_PARITY_GROUP_ID = (
        "Could not find the parity group associated with parity_group_id {}."
    )
    NO_DISK_DRIVE_ID = (
        "Could not find the disk drive associated with drive_location_id {}."
    )
    FEATURE_NOT_SUPPORTED = (
        "Changing drive settings feature is not supported on this storage system."
    )
