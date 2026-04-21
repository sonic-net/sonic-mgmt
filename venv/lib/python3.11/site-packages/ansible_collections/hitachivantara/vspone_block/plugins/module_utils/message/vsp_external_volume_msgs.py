from enum import Enum


class VSPSExternalVolumeValidateMsg(Enum):
    LDEV_REQUIRED = "External Volume ldev_id parameter is mandatory."
    NO_EXT_VOL = "No External Storage Volumes in the system."
    EXT_VOL_NOT_FOUND = "External Storage Volume is not found."
    NOT_FOUND = "ldev_id is not found, may have been deleted."
    NO_PATHGRP = "Unable to find the external path group."
    NO_PARITYGRP = "Unable to find the external parity group."
    PROVISIONED = "ldev_id is already provisioned with an internal ldev."
    ASSOCIATED_ANOTHER = "ldev_id is already associated with another external volume."
    EXTERNAL_VOLUME_NOT_FOUND = "External Volume is not found for ldev_id {}."
    REQUIRED_FOR_CREATE = (
        "For create operation, external_storage_serial and external_ldev_id parameters "
        "are mandatory fields, both of them are not provided."
    )
    LDEV_REQUIRED_FOR_DELETE = (
        "For delete operation, ldev_id parameter is mandatory, which is not provided."
    )
    EXTERNAL_PARITY_GROUP_REQUIRED_FOR_DISCONNECT = "For disconnect operation, external_parity_group parameter is mandatory, which is not provided."
