from enum import Enum


class VSPIscsiTargetMessage(Enum):
    PORT_TYPE_INVALID = "The port type is not valid for this operation."
    PORTS_PARAMETER_INVALID = "iSCSI target does not exist; cannot create iSCSI targets without ports parameter."
    ISCSI_TARGET_HAS_BEEN_DELETED = (
        "ISCSI target not found. (Perhaps it has already been deleted)"
    )
    IQN_IS_NOT_IN_ISCSI_TARGET = "The IQN initiator is not in the iSCSI target."
    LUN_IS_NOT_IN_ISCSI_TARGET = "The LUN is not in the iSCSI target."
    CHAP_USER_IS_NOT_IN_ISCSI_TARGET = "The CHAP user is not in the iSCSI target."
    SPEC_STATE_INVALID = "The spec state parameter is invalid."
    LDEVS_PRESENT = "The iSCSI target has LDEVs presented. Make sure to unpresent all LDEV prior to deleting the iSCSI target."
    RESOURCE_PRESENT = "The resource is already present."
    CATCH_MSG_ISCSI_TARGET = "The specified target alias cannot be registered because it is already used on the same port"
    RELEASE_HOST_RESERVE = "Release host reservation status is done"
    RELEASE_HOST_RESERVE_LU = (
        "Release host reservation status is done for the logical unit {}"
    )
    ADD_LUN_FAILED = "Failed to add LUN {} error: {}"


class VSPIscsiTargetValidationMsg(Enum):
    IQN_OUT_OF_RANGE = (
        "The IQN initiator is out of range. Specify a value in the range of 5 to 223."
    )
    ISCSI_NAME_OUT_OF_RANGE = "The iSCSI target name is out of range. Specify a value in the range of 1 to 32."
    CHAP_USER_NAME_OUT_OF_RANGE = (
        "The CHAP user name is out of range. Specify a value in the range of 1 to 223."
    )
    CHAP_SECRET_OUT_OF_RANGE = (
        "The CHAP secret is out of range. Specify a value in the range of 12 to 32."
    )
    LUN_OUT_OF_RANGE = (
        "The LUN is out of range. Specify a value in the range of 1 to 65535."
    )
    PORT_OUT_OF_RANGE = (
        "The port is out of range. Specify a value in the range of 1 to 256."
    )
    HOST_MODE_OUT_OF_RANGE = (
        "The host mode is out of range. Specify a value in the range of 1 to 256."
    )
