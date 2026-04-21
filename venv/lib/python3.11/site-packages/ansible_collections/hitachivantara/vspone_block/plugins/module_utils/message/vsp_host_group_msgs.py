from enum import Enum


class VSPHostGroupMessage(Enum):
    IGNORE_WWNS = "The parameter wwns is ignored."
    IGNORE_LUNS = "The parameter ldevs is ignored."
    PORT_TYPE_INVALID = "The port type is not valid for this operation."
    PORTS_PARAMETER_INVALID = (
        "Host group does not exist; cannot create host groups without port parameter."
    )
    HG_HAS_BEEN_DELETED = "Host group not found. (Perhaps it has already been deleted)"
    LUN_IS_NOT_IN_HG = "The LDEV is not in the host group."
    SPEC_STATE_INVALID = "The spec state parameter is invalid."
    LDEVS_PRESENT = "Hostgroup has ldevs presented. Make sure to unpresent all ldev prior deleting hostgroup."
    PORT_NOT_IN_SYSTEM = "Port {} is not in the storage system."
    WWNS_INVALID = "Input wwns is invalid. It must be an array."
    DELETE_SUCCESSFULLY = "Hostgroup {} is deleted successfully."
    HG_NAME_EMPTY = "The host group name parameter cannot be empty."
    HG_CREATE_FAILED = "Host group create failed. "
    HG_IN_META_NOT_AVAILABLE = "Host group in meta resource not available."
    PRIORITY_LEVEL_SET_FOR_ALUA = (
        "Asymmetric access priority level is set for ALUA host group. "
    )
    FAILED_TO_SET_PRIORITY_LEVEL = (
        "Failed to set asymmetric access priority level for ALUA host group."
    )
    RELEASE_HOST_RESERVE_SUCCESS = "Host reservation released successfully."
    RELEASE_HOST_RESERVE_SUCCESS_FOR_LU = (
        "Host reservation released successfully for LU path {}."
    )
    RELEASE_HOST_RESERVE_FAILED = "Failed to release host reservation."
    WWN_NICKNAME_SET = "WWN nickname set successfully for host group {} with wwn {}."
    WWN_NICKNAME_SET_FAILED = (
        "Failed to set wwn nickname for host group {} with wwn {} error: {}"
    )
    ADD_WWN_SUCCESS = "WWN {} added successfully to host group {}."
    REMOVE_WWN_SUCCESS = "WWN {} removed successfully from host group {}."
    REMOVE_WWN_FAILED = "Failed to remove wwn {} from host group {} error: {}"
    ADD_LUN_SUCCESS = (
        "LUN {} was successfully added to the host group {}. It may take a few minutes for the LDEV to appear in the lun_path."
        "If it doesn't show up immediately, wait a bit and then run hostgroup facts to check again."
    )
    REMOVE_LUN_SUCCESS = "LUN {} removed successfully from host group {}."
    ADD_LUN_FAILED = "Failed to add LUN {} to host group {} error: {}"
    REMOVE_LUN_FAILED = "Failed to remove LUN {} from host group {} error: {}"


class VSPHostGroupValidationMsg(Enum):
    HG_NAME_OUT_OF_RANGE = "The host group name is out of range. Specify a value in the range from 1 to 64."
    LUN_OUT_OF_RANGE = (
        "The lun is out of range. Specify a value in the range from 1 to 65535."
    )
    PORT_OUT_OF_RANGE = (
        "The port is out of range. Specify a value in the range from 1 to 256."
    )
    HOST_MODE_OUT_OF_RANGE = (
        "The host mode is out of range. Specify a value in the range from 1 to 256."
    )
    HOST_MODE_OPTION_OUT_OF_RANGE = "The host mode option is out of range. Specify a value in the range from 0 to 999."
    WWN_OUT_OF_RANGE = (
        "The wwn is out of range. Specify a value in the range from 1 to 256."
    )
    INVALID_PARAM_LDEVS = (
        "The ldevs input parameter is incorrect, please correct and try again."
    )
