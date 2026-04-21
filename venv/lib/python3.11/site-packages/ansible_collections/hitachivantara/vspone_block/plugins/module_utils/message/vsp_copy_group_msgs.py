from enum import Enum


class CopyGroupFailedMsg(Enum):
    NOT_SUPPORTED_FOR_UAI_GATEWAY = (
        "Copy group {} operation is not supported by UAI Gateway."
    )
    NOT_SUPPORTED_FOR_TC_GAD = (
        "Copy group {} operation is only supported for HUR pairs."
    )


class VSPCopyGroupsValidateMsg(Enum):
    SECONDARY_CONNECTION_INFO = "secondary_connection_info is a required field for direct connect, which is missing."
    COPY_GROUP_NOT_FOUND = "Could not find remote copy group by name {}."
    LOCAL_COPY_GROUP_NOT_FOUND = "Could not find local copy group by name {}."
    GROUP_SPLIT_FAILED = "Failed to split the copy group."
    GROUP_RESYNC_FAILED = "Failed to resync the copy group."
    GROUP_RESTORE_FAILED = "Failed to restore the copy group."
    GROUP_DELETE_FAILED = "Failed to delete the copy group."
    NO_PVOL_DEVICE_NAME_FOUND = "Incorrect primary_volume_device_group_name for existing copy_group {}. Provide correct existing value {}."
    NO_SVOL_DEVICE_NAME_FOUND = "Incorrect secondary_volume_device_group_name for existing copy_group {}. Provide correct existing value {}."

    LOCAL_COPY_GROUP_NAME_REQD = "When primary_volume_device_group_name and secondary_volume_device_group_name are specified, you must specify name."
    LOCAL_COPY_GROUP_BOTH_PVOL_SVOL_DEVICE_REQD = "Both primary_volume_device_group_name and secondary_volume_device_group_name must be specified together."
