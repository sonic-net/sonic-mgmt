from enum import Enum


class SDSBDriveValidationMsg(Enum):

    DRIVE_NOT_FOUND = "Could not find the drive with id {}."
    REMOVE_DRIVE_OPERATION_FAILED = "Could not do the operation on the drive. A drive whose status is other than Blockage cannot be removed."
    LED_DRIVE_OPERATION_FAILED = "Could not do the operation on the drive."
