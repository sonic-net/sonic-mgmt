from enum import Enum


class VSPUserFailedMsg(Enum):
    UPDATE_FAILED = "Failed to update user information. "
    DELETE_FAILED = "Failed to delete user account. "


class VSPUserValidateMsg(Enum):
    USER_NOT_FOUND = "User not found."
    USER_DELETE_SUCCSESS = "User deleted successfully."
    NO_USER_ID_OR_USER_NAME = "Either user id or user name must be provided."
    INVALID_USER_NAME = (
        "Invalid user name provided. Specify a name consisting of {} to {} characters."
    )
    INVALID_PASS_LEN = "Invalid password provided. Specify a password consisting of {} to {} characters."
    INVALID_USER_GROUPS = "Exceeded maximum number of user groups. Maximum number of user groups that can be specified is 8."
    USER_NAME_REQD = "User name is required for user creation."
    AUTH_REQD = "Authentication type is required for user creation."
    PASS_REQD = "Password is required for local authentication."
    GROUP_NAME_MUST_BE_LIST = "Group names must be provided as a list."
    PASSWORD_SAME = "New password must be different from the old password."
