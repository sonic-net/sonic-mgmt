from enum import Enum


class VSPUserGroupFailedMsg(Enum):
    UPDATE_FAILED = "Failed to update user group information."
    DELETE_FAILED = "Failed to delete user group."


class VSPUserGroupValidateMsg(Enum):
    USER_GROUP_NOT_FOUND = "User Group not found."
    USER_GROUP_DELETE_SUCCSESS = "User Group deleted successfully."
    NO_UG_ID_OR_UG_NAME = "Either user group id or user group name must be provided."
    INVALID_UG_NAME = "Invalid user group name provided. Specify a name consisting of {} to {} characters."
    INVALID_RG_ID = (
        "Invalid resource group ID provided. Provide values in the range of 0 to 1023."
    )
    INVALID_ROLE_NAME = "Invalid role name provided. Valid role names are: {}."
    USER_GROUP_NAME_REQD = "User group name is required for user group creation."
    ROLE_NAME_MUST_BE_LIST = "Role names must be provided as a list."
    RG_NAME_MUST_BE_LIST = "Resource group IDs must be provided as a list of integers."
    INVALID_SPEC_STATE_FOR_ROLES = "Invalid state provided for role names. Valid states are: 'add_role', 'remove_role'."
    INVALID_SPEC_STATE_FOR_RGS = "Invalid state provided for resource groups. Valid states are: 'add_resource_group', 'remove_resource_group'."
    INVALID_SPEC_STATE = "Invalid state provided. Valid states are: 'add_resource_group', 'remove_resource_group', 'add_role', 'remove_role'."
